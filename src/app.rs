//! The application runtime: connecting to NFD, registering routes,
//! dispatching Interests to handlers, and expressing Interests as a
//! consumer.
//!
//! [`App`] is a builder that only exposes route/lifecycle configuration
//! before [`App::start`] is called; once started, it owns the
//! connection to NFD and runs until shutdown or an unrecoverable error.
//! [`AppHandler`] is the handle every route and lifecycle callback
//! receives to talk back to the running app; see
//! [`crate::verifier`] for how incoming Interests and outgoing Data are
//! accepted or rejected.
//!
//! ```rust,no_run
//! use ndn_app::{
//!     app::{App, AppHandler},
//!     verifier::ForbidUnsigned,
//! };
//! use ndn_protocol::{Data, DigestSha256, Interest};
//!
//! async fn hello(_handler: AppHandler, interest: Interest<()>, _ctx: ()) -> Option<Data<()>> {
//!     Some(Data::new(interest.name().clone(), ()))
//! }
//!
//! async fn on_start(mut handler: AppHandler, _ctx: ()) {
//!     // AppHandler lets lifecycle callbacks act as consumers too.
//!     let interest = Interest::<()>::new(
//!         ndn_protocol::Name::from_str("hello").unwrap(),
//!     );
//!     let _ = handler.express_interest(interest, ForbidUnsigned).await;
//! }
//!
//! # async fn run() {
//! App::new(DigestSha256::new(), ())
//!     .on_start(on_start)
//!     .route("hello", ForbidUnsigned, hello)
//!     .start()
//!     .await
//!     .unwrap();
//! # }
//! ```

use std::{
    collections::BTreeMap, future::Future, marker::PhantomData, pin::Pin, sync::Arc, time::Duration,
};

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use log::{debug, error, info, trace, warn};
use ndn_ndnlp::{FragCount, FragIndex, Fragment, LpPacket, Packet, Sequence};
use ndn_nfd_mgmt::{make_command, ControlParameters, ControlResponse};
use ndn_protocol::{
    signature::{KnownVerifiers, SignMethod, ToVerifier},
    Data, Interest, Name, SignSettings,
};
use ndn_tlv::{NonNegativeInteger, TlvDecode, TlvEncode};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter},
    net::UnixStream,
    sync::{self, broadcast, mpsc, RwLock},
};
use tokio_util::sync::CancellationToken;
use type_map::concurrent::TypeMap;

use crate::{
    error::Error,
    util::add_bytes,
    verifier::{DataVerifier, InterestVerifier},
    DataExt, Result, ToName,
};

#[derive(Debug, Clone)]
enum Connector {
    Unix(String),
}

// The four items below (InterestCallbackErased, InterestCallbackFunction,
// IntoInterestCallbackFunction, InterestCallback) exist to let App::route
// accept an ordinary `async fn(AppHandler, Interest<P>, Context) -> Option<Data<O>>`
// for any P: TlvDecode and O: TlvEncode, while App itself stores a single
// BTreeMap<Name, RouteHandler<Context>> whose entries don't carry P or O as
// type parameters. InterestCallbackFunction<Params, Context, F> wraps a
// closure to remember its P/O in its own type, InterestCallback erases that
// down to a common associated-type interface, and InterestCallbackErased
// erases it further to a single non-generic `run` that decodes raw
// application parameter bytes into P and encodes the handler's O back into
// bytes at the boundary. Without this, every route's handler type would need
// to appear in App's own type parameters.
#[async_trait]
trait InterestCallbackErased<Context> {
    async fn run(
        &self,
        handler: AppHandler,
        interest: Interest<Bytes>,
        context: Context,
    ) -> std::result::Result<Option<Data<Bytes>>, ()>;
}

#[async_trait]
impl<Context, Params, Output, T> InterestCallbackErased<Context> for T
where
    Self: Sync,
    T: InterestCallback<Context, Params = Params, Output = Output>,
    Context: Send + 'static,
    Params: TlvDecode + Send,
    Output: TlvEncode,
{
    async fn run(
        &self,
        handler: AppHandler,
        interest: Interest<Bytes>,
        context: Context,
    ) -> std::result::Result<Option<Data<Bytes>>, ()> {
        // Distinguish "no application parameters were sent" (fine, decodes
        // to a default/empty value) from "application parameters were sent
        // but didn't decode as this route's Params type" (a malformed
        // request, not something the handler should see).
        let has_params = interest.application_parameters().is_some();
        let input_interest = interest.decode_application_parameters();
        if has_params && input_interest.application_parameters().is_none() {
            return Err(());
        }
        Ok(
            InterestCallback::run(self, handler, input_interest, context)
                .await
                .map(|x| x.encode_content()),
        )
    }
}

struct InterestCallbackFunction<Input, Context, F> {
    f: F,
    _input: PhantomData<fn() -> Input>,
    _context: PhantomData<fn() -> Context>,
}

trait IntoInterestCallbackFunction<Input, Context>: Sized {
    fn into_interest_callback_function(self) -> InterestCallbackFunction<Input, Context, Self> {
        InterestCallbackFunction {
            f: self,
            _input: PhantomData,
            _context: PhantomData,
        }
    }
}

impl<F, G, Params, Context, Output> IntoInterestCallbackFunction<Params, Context> for F
where
    F: Fn(AppHandler, Interest<Params>, Context) -> G,
    G: Future<Output = Option<Data<Output>>> + Send + 'static,
{
}

trait InterestCallback<Context> {
    type Params;
    type Output;
    fn run(
        &self,
        handler: AppHandler,
        interest: Interest<Self::Params>,
        context: Context,
    ) -> Pin<Box<dyn Future<Output = Option<Data<Self::Output>>> + Send + 'static>>;
}

impl<F, G, Context, Params, Output> InterestCallback<Context>
    for InterestCallbackFunction<Params, Context, F>
where
    Params: TlvDecode,
    Output: TlvEncode,
    F: Fn(AppHandler, Interest<Params>, Context) -> G,
    G: Future<Output = Option<Data<Output>>> + Send + 'static,
{
    type Params = Params;
    type Output = Output;

    fn run(
        &self,
        handler: AppHandler,
        interest: Interest<Self::Params>,
        context: Context,
    ) -> Pin<Box<(dyn Future<Output = Option<Data<Self::Output>>> + Send)>> {
        Box::pin((self.f)(handler, interest, context))
    }
}

trait OnStartFn<Context> {
    fn run(
        &self,
        handler: AppHandler,
        context: Context,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

impl<F, G, Context> OnStartFn<Context> for F
where
    F: Send + Sync,
    F: Fn(AppHandler, Context) -> G,
    G: Future<Output = ()> + 'static + Send,
{
    fn run(
        &self,
        handler: AppHandler,
        context: Context,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(self(handler, context))
    }
}

/// A single registered route: the verifier that gates it and the
/// type-erased handler that runs once the verifier accepts an Interest.
pub struct RouteHandler<Context> {
    callback: Box<dyn InterestCallbackErased<Context> + Send + Sync>,
    verifier: Box<dyn InterestVerifier + Send + Sync>,
}

// App is a typestate builder: `Routes` is `BTreeMap<...>` before `start()`
// and `Arc<RwLock<BTreeMap<...>>>` after. UninitialisedApp only implements
// `.route()` / `.on_start()` / `.mtu()`, and InitialisedApp only implements
// the running event loop, so it's impossible to register a route (or call
// `.start()` twice) on an app that's already running; the compiler rejects
// it rather than it needing a runtime check.
// This is not relevant in application code, as start() fully consumes the `App`.
type InitialisedApp<Signer, Context, Verifiers> =
    App<Signer, Context, Verifiers, Arc<RwLock<BTreeMap<Name, RouteHandler<Context>>>>>;

type UninitialisedApp<Signer, Context, Verifiers> =
    App<Signer, Context, Verifiers, BTreeMap<Name, RouteHandler<Context>>>;

/// The application builder and, once started, runtime.
///
/// Construct with [`App::new`], configure with [`App::route`],
/// [`App::on_start`], and [`App::mtu`], then call [`App::start`] to
/// connect to NFD and begin serving. See the [module docs](self) for a
/// full example.
pub struct App<Signer, Context, KnownVerifiers, Routes> {
    routes: Routes,
    on_start: Option<Box<dyn OnStartFn<Context>>>,
    connector: Connector,
    signer: Arc<RwLock<Signer>>,
    verifier_context: Arc<RwLock<TypeMap>>,
    context: Context,
    mtu: usize,
    known_verifiers: Arc<KnownVerifiers>,
}

struct InterestToSend<T> {
    interest: Interest<T>,
    sign: bool,
    notifier: tokio::sync::oneshot::Sender<Name>,
}

/// The handle passed into every route and lifecycle callback, giving
/// application code a way to act as a consumer (express Interests, wait
/// for the matching Data or NACK) and to shut the app down.
///
/// Cloning is cheap: every clone shares the same underlying channels and
/// connection, so handing a clone to a spawned task or storing one in
/// application state doesn't create a second connection to NFD.
#[derive(Clone)]
pub struct AppHandler {
    interest_sender: mpsc::Sender<InterestToSend<Bytes>>,
    in_handler: broadcast::Sender<Packet>,
    verifier_context: Arc<RwLock<TypeMap>>,
    known_verifiers: Arc<dyn ToVerifier + Send + Sync + 'static>,
    shutdown_token: CancellationToken,
}

impl AppHandler {
    /// Signals the running [`App`] to stop. The current call to
    /// [`App::start`] returns `Ok(())` once background tasks notice the
    /// cancellation and exit; in-flight route handlers are not
    /// interrupted.
    pub fn shutdown(&self) {
        self.shutdown_token.cancel();
    }

    /// Signs `interest` and expresses it, returning the resulting Data
    /// once it passes `verifier`, or an error on NACK, verification
    /// failure, or timeout (see [`crate::error::Error`]).
    pub async fn express_interest<T>(
        &mut self,
        interest: impl std::borrow::BorrowMut<Interest<T>>,
        verifier: impl DataVerifier,
    ) -> Result<Data<Bytes>>
    where
        T: TlvEncode + TlvDecode + Clone,
    {
        self.express_interest_impl(interest, verifier, true).await
    }

    /// Same as [`AppHandler::express_interest`], but sends the Interest
    /// unsigned. Used internally by verifiers (see
    /// [`crate::verifier::RequireValidSignature`]) to fetch certificates
    /// without those fetches needing a signature of their own, and
    /// available to application code for the same reason: fetching
    /// public data that doesn't require proving the requester's
    /// identity.
    pub async fn express_interest_unsigned<T>(
        &mut self,
        interest: impl std::borrow::BorrowMut<Interest<T>>,
        verifier: impl DataVerifier,
    ) -> Result<Data<Bytes>>
    where
        T: TlvEncode + TlvDecode + Clone,
    {
        self.express_interest_impl(interest, verifier, false).await
    }

    async fn express_interest_impl<T>(
        &mut self,
        mut interest: impl std::borrow::BorrowMut<Interest<T>>,
        verifier: impl DataVerifier,
        sign: bool,
    ) -> Result<Data<Bytes>>
    where
        T: TlvEncode + TlvDecode + Clone,
    {
        let mut interest = interest
            .borrow_mut()
            .clone()
            .encode_application_parameters();
        let (notifier_sender, notifier_receiver) = sync::oneshot::channel();
        self.interest_sender
            .send(InterestToSend {
                interest: interest.clone(),
                sign,
                notifier: notifier_sender,
            })
            .await
            .map_err(|_| Error::ConnectionClosed)?;

        let signed_name = notifier_receiver
            .await
            .unwrap_or_else(|_| interest.name().clone());

        interest.set_name(signed_name.clone());

        let lifetime = interest.interest_lifetime().map(u64::from).unwrap_or(3_000);
        let wait_for_data = async {
            let mut in_receiver = self.in_handler.subscribe();
            while let Ok(packet) = in_receiver.recv().await {
                match packet {
                    Packet::Data(packet) => {
                        if packet.matches_interest(&interest) {
                            if verifier
                                .verify(
                                    &packet,
                                    Arc::clone(&self.verifier_context),
                                    self.clone(),
                                    &*self.known_verifiers,
                                )
                                .await
                            {
                                return Ok(packet);
                            } else {
                                warn!(
                                    "Data packet for {} failed verification.",
                                    interest.name().to_uri()
                                );
                                return Err(Error::VerificationFailed);
                            }
                        }
                    }
                    Packet::LpPacket(packet) => {
                        if packet.is_nack() {
                            let Some(nack_interest) = packet
                                .fragment()
                                .map(|mut x| Interest::<Bytes>::decode(&mut x).ok())
                                .flatten()
                            else {
                                continue;
                            };

                            if nack_interest.name() == &signed_name {
                                debug!(
                                    "Received NACK when requesting {}",
                                    interest.name().to_uri()
                                );
                                return Err(Error::NackReceived);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(Error::ConnectionClosed)
        };
        match tokio::time::timeout(Duration::from_millis(lifetime), wait_for_data).await {
            Ok(x) => x,
            Err(x) => {
                debug!("Request for {} timed out", interest.name().to_uri());
                Err(x.into())
            }
        }
    }
}

impl<Signer, Context> UninitialisedApp<Signer, Context, KnownVerifiers>
where
    Signer: SignMethod + Send + Sync + 'static,
    Context: Clone + Send + 'static,
{
    /// Starts building an app that signs outgoing Data with `signer` and
    /// clones `context` into every route and lifecycle callback.
    ///
    /// The NFD socket path is fixed to `/var/run/nfd/nfd.sock`, the
    /// standard location for a local NFD install; it isn't configurable.
    pub fn new(signer: Signer, context: Context) -> Self {
        Self {
            routes: BTreeMap::new(),
            connector: Connector::Unix("/var/run/nfd/nfd.sock".to_string()),
            signer: Arc::new(RwLock::new(signer)),
            on_start: None,
            verifier_context: Arc::new(RwLock::new(TypeMap::new())),
            context,
            mtu: 8800,
            known_verifiers: Arc::new(KnownVerifiers),
        }
    }
}

impl<Signer, Context, Verifiers> UninitialisedApp<Signer, Context, Verifiers>
where
    Signer: SignMethod + Send + Sync + 'static,
    Context: Clone + Send + 'static,
    Verifiers: ToVerifier + Send + Sync + 'static,
{
    /// Registers `func` to handle Interests whose name has `name` as a
    /// prefix, gated by `verifier`. Routes are stored in `Name` order and
    /// matched in reverse, so where more than one registered prefix
    /// matches an incoming Interest, the route that sorts last is tried
    /// first (see the dispatch loop this feeds into, in `App::start`).
    #[allow(private_bounds)]
    pub fn route<Callback, Verifier, Params, Output, G>(
        mut self,
        name: impl ToName,
        verifier: Verifier,
        func: Callback,
    ) -> Self
    where
        Callback: IntoInterestCallbackFunction<Params, Context> + Send + Sync + 'static,
        Callback: Fn(AppHandler, Interest<Params>, Context) -> G,
        G: Future<Output = Option<Data<Output>>> + Send + 'static,
        Verifier: InterestVerifier + Send + Sync + 'static,
        Params: TlvDecode + Send + 'static,
        Output: TlvEncode + 'static,
    {
        self.routes.insert(
            name.to_name(),
            RouteHandler {
                callback: Box::new(func.into_interest_callback_function()),
                verifier: Box::new(verifier),
            },
        );
        self
    }

    /// Registers `on_start` to run once routes are registered with NFD
    /// and the app is ready to serve. This is the usual place to kick
    /// off consumer-side work, since it's the first point at which
    /// `AppHandler` is available.
    #[allow(private_bounds)]
    pub fn on_start<F>(mut self, on_start: F) -> Self
    where
        F: OnStartFn<Context> + 'static,
    {
        self.on_start = Some(Box::new(on_start));
        self
    }

    /// Sets the maximum packet size in bytes before NDNLPv2 fragmentation
    /// kicks in on send (default 8800, matching NDN's usual default MTU).
    pub fn mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// Connects to NFD, registers all configured routes, runs
    /// `on_start`, and then serves until [`AppHandler::shutdown`] is
    /// called or an unrecoverable connection error occurs.
    pub async fn start(self) -> Result<()> {
        self.initialise().start().await
    }

    fn initialise(self) -> InitialisedApp<Signer, Context, Verifiers> {
        App {
            routes: Arc::new(RwLock::new(self.routes)),
            on_start: self.on_start,
            connector: self.connector,
            signer: self.signer,
            verifier_context: self.verifier_context,
            context: self.context,
            mtu: self.mtu,
            known_verifiers: self.known_verifiers,
        }
    }
}

impl<Signer, Context, Verifiers> InitialisedApp<Signer, Context, Verifiers>
where
    Signer: SignMethod + Send + Sync + 'static,
    Context: Clone + Send + 'static,
    Verifiers: ToVerifier + Send + Sync + 'static,
{
    /// Matches an incoming Interest against registered routes and drives
    /// it through verification and the handler, sending back Data or a
    /// NACK. Spawned as its own task per Interest by the main loop in
    /// [`InitialisedApp::start`], so a slow handler for one Interest
    /// doesn't hold up dispatch of the next.
    ///
    /// Routes are tried most-specific-first (see [`UninitialisedApp::route`])
    /// and matching stops at the first route whose prefix matches,
    /// whether or not that route ends up accepting the Interest; an
    /// Interest that fails one route's verifier is NACKed rather than
    /// falling through to try a less specific route.
    async fn handle_interest(
        interest: Interest<Bytes>,
        routes: Arc<RwLock<BTreeMap<Name, RouteHandler<Context>>>>,
        verifier_context: Arc<RwLock<TypeMap>>,
        app_handler: AppHandler,
        signer: Arc<RwLock<Signer>>,
        out_sender: mpsc::Sender<Packet>,
        context: Context,
        known_verifiers: Arc<Verifiers>,
    ) -> Result<()> {
        let routes = routes.read().await;
        let interest_uri = interest.name().to_uri();
        trace!("Received interest for {interest_uri}");
        let mut matching_route_found = false;
        for (route, route_handler) in routes.iter().rev() {
            trace!("Checking against route {}", route.to_uri());
            if interest.name().has_prefix(route) {
                matching_route_found = true;
                if !route_handler
                    .verifier
                    .verify(
                        &interest,
                        Arc::clone(&verifier_context),
                        app_handler.clone(),
                        &*known_verifiers,
                    )
                    .await
                {
                    info!("Verification failed for request for {interest_uri}");
                    let nack = Packet::make_nack(interest);
                    out_sender
                        .send(nack)
                        .await
                        .map_err(|_| Error::ConnectionClosed)?;
                    break;
                }
                if let Ok(ret) = route_handler
                    .callback
                    .run(app_handler.clone(), interest.clone(), context.clone()) // TODO
                    .await
                {
                    if let Some(mut ret) = ret {
                        if !ret.is_signed() {
                            let mut signer = signer.write().await;
                            ret.sign(&mut *signer);
                        }
                        out_sender
                            .send(Packet::Data(ret))
                            .await
                            .map_err(|_| Error::ConnectionClosed)?;
                    } else {
                        let nack = Packet::make_nack(interest);
                        out_sender
                            .send(nack)
                            .await
                            .map_err(|_| Error::ConnectionClosed)?;
                    }
                    break;
                } else {
                    debug!("Interest application parameter decoding failed for {interest_uri}");
                }
            }
        }
        if !matching_route_found {
            debug!("Interest for {interest_uri} matches no routes");
        }
        Ok(())
    }

    /// Connects to NFD, spawns the read/write/interest-sending
    /// background tasks, registers every route, runs `on_start`, and
    /// then loops handling incoming packets until shutdown.
    ///
    /// Route registration happens with a per-route retry loop (see the
    /// call to [`register_route`] below): NFD may not have finished
    /// starting up, or a management Interest may simply be dropped, so a
    /// registration that doesn't get a response within a few seconds is
    /// retried rather than treated as a fatal error immediately.
    async fn start(mut self) -> Result<()> {
        let (reader, writer): (
            Box<dyn AsyncRead + Unpin + Send>,
            Box<dyn AsyncWrite + Unpin + Send>,
        ) = match self.connector.clone() {
            Connector::Unix(path) => {
                let sock = UnixStream::connect(path)
                    .await
                    .map_err(|_| Error::ConnectionFailed)?;
                let (reader, writer) = sock.into_split();
                (
                    Box::new(BufReader::new(reader)),
                    Box::new(BufWriter::new(writer)),
                )
            }
        };

        let shutdown_token = CancellationToken::new();

        // Outgoing data sync
        let (out_sender, out_receiver) = mpsc::channel(128);
        // Incoming data distribution
        let (in_sender, mut in_receiver) = broadcast::channel(128);

        tokio::spawn(write_thread(
            writer,
            out_receiver,
            self.mtu,
            shutdown_token.clone(),
        ));
        tokio::spawn(read_thread(
            reader,
            in_sender.clone(),
            shutdown_token.clone(),
        ));

        for (route, _) in self.routes.read().await.iter() {
            loop {
                let res = tokio::time::timeout(
                    Duration::from_secs(3),
                    register_route(
                        Arc::clone(&self.signer),
                        in_sender.subscribe(),
                        out_sender.clone(),
                        route.clone(),
                    ),
                )
                .await;

                match res {
                    Ok(Ok(())) => break,
                    Ok(Err(x)) => {
                        error!("Route registration had an error: {}", x);
                        return Err(x);
                    }
                    Err(_) => {
                        warn!("Route registration timed out");
                        continue;
                    }
                }
            }
        }

        let (interest_sender, interest_receiver) = mpsc::channel(128);

        tokio::spawn(interest_thread(
            out_sender.clone(),
            interest_receiver,
            Arc::clone(&self.signer),
            shutdown_token.clone(),
        ));

        let app_handler = AppHandler {
            interest_sender,
            in_handler: in_sender.clone(),
            verifier_context: Arc::clone(&self.verifier_context),
            known_verifiers: Arc::<Verifiers>::clone(&self.known_verifiers),
            shutdown_token: shutdown_token.clone(),
        };

        if let Some(on_start) = self.on_start.take() {
            tokio::spawn(on_start.run(app_handler.clone(), self.context.clone()));
        }

        let mut partial_packet: Vec<Bytes> = Vec::new();
        let mut partial_count = 0;
        let mut last_seq = BytesMut::new();

        'main_loop: loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    return Ok(());
                }
                received = in_receiver.recv() => {
                    match received {
                        Ok(packet) => match packet {
                            Packet::Interest(interest) => {
                                tokio::spawn(Self::handle_interest(
                                    interest.clone(),
                                    Arc::clone(&self.routes),
                                    Arc::clone(&self.verifier_context),
                                    app_handler.clone(),
                                    Arc::clone(&self.signer),
                                    out_sender.clone(),
                                    self.context.clone(),
                                    Arc::clone(&self.known_verifiers),
                                ));
                            }
                            Packet::LpPacket(packet) => {
                                for header in packet.other_headers() {
                                    if header.is_critical() {
                                        // Unknown critical header - packet must be dropped
                                        continue 'main_loop;
                                    }
                                }

                                if let Some((frag_idx, frag_cnt)) = packet.frag_info() {
                                    // sequence number is required
                                    let (Some(seq), Some(fragment)) = (packet.seq_num(), packet.fragment())
                                    else {
                                        partial_packet.clear();
                                        partial_count = 0;
                                        continue 'main_loop;
                                    };

                                    // Wrong fragment index
                                    if frag_idx.as_usize() != partial_packet.len() {
                                        partial_packet.clear();
                                        partial_count = 0;
                                        continue 'main_loop;
                                    }
                                    // New fragment
                                    if frag_idx.as_usize() == 0 {
                                        partial_count = frag_cnt.into();
                                        partial_packet.clear();
                                        partial_packet.reserve(frag_cnt.as_usize());
                                        last_seq = BytesMut::from(&seq[..]);
                                    // Wrong total fragment number
                                    } else if partial_count != frag_cnt.as_u64() {
                                        partial_packet.clear();
                                        partial_count = 0;
                                        continue 'main_loop;
                                    } else {
                                        add_bytes(&mut last_seq, 1);
                                        // Sequence number not consecutive
                                        if last_seq != seq {
                                            add_bytes(&mut last_seq, -1);
                                            partial_packet.clear();
                                            partial_count = 0;
                                            continue 'main_loop;
                                        }
                                    }

                                    partial_packet.push(fragment);
                                    if frag_idx == frag_cnt {
                                        let total_size: usize = partial_packet.iter().map(Bytes::len).sum();
                                        let mut data = BytesMut::with_capacity(total_size);

                                        for fragment in &partial_packet {
                                            data.put(fragment.clone());
                                        }
                                        partial_packet.clear();
                                        partial_count = 0;

                                        let packet = Packet::decode(&mut data.freeze());
                                        debug!("Reconstituted packet: {packet:#?}");
                                    }
                                }
                            }
                            _ => {}
                        },
                        Err(broadcast::error::RecvError::Closed) => return Err(Error::ConnectionClosed),
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Dropped {n} packets in routing handler");
                        }
                    }
                }
            }
        }
    }
}

/// Signs and forwards Interests queued by [`AppHandler::express_interest`]
/// and [`AppHandler::express_interest_unsigned`].
///
/// This runs as its own task, rather than signing inline in
/// `AppHandler`, because signing needs exclusive access to the shared
/// signer; funneling every outgoing Interest through one task avoids
/// taking the signer's lock from arbitrarily many concurrent callers.
/// The signed name is sent back over `notifier` before the Interest is
/// handed to `write_thread`, since signing can change the Interest's
/// name (it appends a digest component) and the caller needs the final
/// name to match incoming Data against.
async fn interest_thread(
    sender: mpsc::Sender<Packet>,
    mut interest_receiver: mpsc::Receiver<InterestToSend<Bytes>>,
    signer: Arc<RwLock<impl SignMethod>>,
    shutdown_token: CancellationToken,
) -> Result<()> {
    let _shutdown_guard = shutdown_token.drop_guard();
    while let Some(mut interest_to_send) = interest_receiver.recv().await {
        if interest_to_send.sign && !interest_to_send.interest.is_signed() {
            let mut signer = signer.write().await;
            interest_to_send
                .interest
                .sign(&mut *signer, SignSettings::default()); // TODO: SignSettings
        }
        let _ = interest_to_send
            .notifier
            .send(interest_to_send.interest.name().clone());
        sender
            .send(Packet::Interest(interest_to_send.interest))
            .await
            .map_err(|_| Error::ConnectionClosed)?;
    }
    Err(Error::ConnectionClosed)
}

/// Serializes and writes every outgoing packet, splitting into NDNLPv2
/// fragments when a packet is larger than `mtu`.
///
/// All writes to the connection funnel through this one task so packets
/// aren't interleaved on the wire by concurrent writers; `AppHandler`
/// and route handlers only ever hand packets to `out_sender` rather than
/// writing directly. Fragments share one sequence number space (`seq_num`,
/// incremented per fragment, not per packet) since that's what lets the
/// receiving side detect gaps and out-of-order fragments during
/// reassembly.
async fn write_thread(
    mut writer: impl AsyncWrite + Unpin,
    mut receiver: mpsc::Receiver<Packet>,
    mtu: usize,
    shutdown_token: CancellationToken,
) -> Result<()> {
    let _shutdown_guard = shutdown_token.drop_guard();
    let mut seq_num = BytesMut::from(&[0; 8][..]);

    while let Some(packet) = receiver.recv().await {
        let mut data = packet.encode();

        if data.len() > mtu {
            let header = LpPacket {
                sequence: Some(Sequence(seq_num.clone().freeze())),
                frag_index: Some(FragIndex(NonNegativeInteger::U64(0))),
                frag_count: Some(FragCount(NonNegativeInteger::U64(0))),
                nack: None,
                other_headers: Vec::new(),
                fragment: None,
            };
            let header_size = header.size();

            let frag_count = data.len().div_ceil(mtu - header_size);

            for i in 0..frag_count {
                let frame = LpPacket {
                    sequence: Some(Sequence(seq_num.clone().freeze())),
                    frag_index: Some(FragIndex(NonNegativeInteger::new(i as u64))),
                    frag_count: Some(FragCount(NonNegativeInteger::new(frag_count as u64))),
                    nack: None,
                    other_headers: Vec::new(),
                    fragment: Some(Fragment {
                        data: data.split_to(data.len().min(mtu - header_size)),
                    }),
                };
                add_bytes(&mut seq_num, 1);
                writer.write_all(&frame.encode()).await?;
            }
        } else {
            writer.write_all(&data).await?;
        }
        writer.flush().await?;
    }
    Err(Error::ConnectionClosed)
}

/// Reads packets off the connection and broadcasts them to every
/// subscriber (the main dispatch loop, and any in-flight
/// `express_interest` calls waiting on a specific Data or NACK).
///
/// A broadcast channel, rather than a plain mpsc queue, is used because
/// more than one place needs to see every incoming packet: the main
/// loop for routing Interests, and potentially several concurrent
/// `express_interest` calls each watching for their own Data.
async fn read_thread(
    mut reader: impl AsyncRead + Unpin,
    sender: broadcast::Sender<Packet>,
    shutdown_token: CancellationToken,
) -> Result<()> {
    let _shutdown_guard = shutdown_token.drop_guard();
    while let Some(packet) = Packet::from_async_reader(&mut reader).await {
        sender.send(packet).map_err(|_| Error::ConnectionClosed)?;
    }
    Err(Error::ConnectionClosed)
}

/// Registers a single route prefix with NFD's RIB by sending a signed
/// management Interest and waiting for its response.
///
/// This is a one-shot operation, not a background task: [`App::start`]
/// awaits it once per route (with its own timeout and retry loop) before
/// entering the main event loop, so a route is guaranteed to be
/// registered with the forwarder before the app starts accepting
/// application-level Interests.
async fn register_route(
    signer: Arc<RwLock<impl SignMethod>>,
    mut receiver: broadcast::Receiver<Packet>,
    sender: mpsc::Sender<Packet>,
    route: Name,
) -> Result<()> {
    info!("Registering route {}", route.to_uri());
    let control_parameters = ControlParameters::new().set_name(route.clone());
    let mut interest = make_command("rib", "register", control_parameters).unwrap();

    {
        let mut signer = signer.write().await;
        interest.sign(&mut *signer, SignSettings::default());
    }

    sender
        .send(Packet::Interest(
            interest.clone().encode_application_parameters(),
        ))
        .await
        .map_err(|_| Error::ConnectionClosed)?;

    loop {
        match receiver.recv().await {
            Ok(Packet::Data(packet)) => {
                if packet.name().has_prefix(&interest.name()) {
                    let data = packet.decode_content::<ControlResponse<ControlParameters>>();
                    if let Some(content) = data.content() {
                        if content.status_code().as_usize() != 200 {
                            error!("Registering {route} failed with status code {status_code}: {status_text}",
                                  route = route.to_uri(),
                                  status_code = content.status_code(),
                                  status_text = String::from_utf8_lossy(&content.status_text()));
                        } else {
                            info!("Registered route {route}", route = route.to_uri());
                        }
                        return Ok(());
                    }
                }
            }
            Ok(Packet::Interest(_)) => {}
            Ok(Packet::LpPacket(packet)) => {
                println!("{:#?}", packet)
            }
            Err(broadcast::error::RecvError::Closed) => return Err(Error::ConnectionClosed),
            Err(broadcast::error::RecvError::Lagged(_)) => {}
        }
    }
}
