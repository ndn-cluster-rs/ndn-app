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

pub struct RouteHandler<Context> {
    callback: Box<dyn InterestCallbackErased<Context> + Send + Sync>,
    verifier: Box<dyn InterestVerifier + Send + Sync>,
}

type InitialisedApp<Signer, Context, Verifiers> =
    App<Signer, Context, Verifiers, Arc<RwLock<BTreeMap<Name, RouteHandler<Context>>>>>;

type UninitialisedApp<Signer, Context, Verifiers> =
    App<Signer, Context, Verifiers, BTreeMap<Name, RouteHandler<Context>>>;

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

#[derive(Clone)]
pub struct AppHandler {
    interest_sender: mpsc::Sender<InterestToSend<Bytes>>,
    in_handler: broadcast::Sender<Packet>,
    verifier_context: Arc<RwLock<TypeMap>>,
    known_verifiers: Arc<dyn ToVerifier + Send + Sync + 'static>,
    shutdown_token: CancellationToken,
}

impl AppHandler {
    pub fn shutdown(&self) {
        self.shutdown_token.cancel();
    }

    pub async fn express_interest<T>(
        &mut self,
        interest: impl std::borrow::Borrow<Interest<T>>,
        verifier: impl DataVerifier,
    ) -> Result<Data<Bytes>>
    where
        T: TlvEncode + TlvDecode + Clone,
    {
        self.express_interest_impl(interest, verifier, true).await
    }

    pub async fn express_interest_unsigned<T>(
        &mut self,
        interest: impl std::borrow::Borrow<Interest<T>>,
        verifier: impl DataVerifier,
    ) -> Result<Data<Bytes>>
    where
        T: TlvEncode + TlvDecode + Clone,
    {
        self.express_interest_impl(interest, verifier, false).await
    }

    async fn express_interest_impl<T>(
        &mut self,
        interest: impl std::borrow::Borrow<Interest<T>>,
        verifier: impl DataVerifier,
        sign: bool,
    ) -> Result<Data<Bytes>>
    where
        T: TlvEncode + TlvDecode + Clone,
    {
        let interest = interest.borrow().clone().encode_application_parameters();
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

    #[allow(private_bounds)]
    pub fn on_start<F>(mut self, on_start: F) -> Self
    where
        F: OnStartFn<Context> + 'static,
    {
        self.on_start = Some(Box::new(on_start));
        self
    }

    pub fn mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

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
                    continue;
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

        tokio::spawn(write_thread(writer, out_receiver, self.mtu));
        tokio::spawn(read_thread(reader, in_sender.clone()));

        for (route, _) in self.routes.read().await.iter() {
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
                Ok(Ok(())) => (),
                Ok(Err(x)) => {
                    error!("Route registration had an error: {}", x);
                    return Err(x);
                }
                Err(_) => {
                    error!("Route registration timed out");
                    return Err(Error::Timeout);
                }
            }
        }

        let (interest_sender, interest_receiver) = mpsc::channel(128);

        tokio::spawn(interest_thread(
            out_sender.clone(),
            interest_receiver,
            Arc::clone(&self.signer),
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

/// Processes incoming interests
async fn receive_interests_thread(receiver: broadcast::Receiver<Packet>) {
    //
}

/// Processes interest send requests
async fn interest_thread(
    sender: mpsc::Sender<Packet>,
    mut interest_receiver: mpsc::Receiver<InterestToSend<Bytes>>,
    signer: Arc<RwLock<impl SignMethod>>,
) -> Result<()> {
    while let Some(mut interest_to_send) = interest_receiver.recv().await {
        if interest_to_send.sign {
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

/// Sends packets out onto the network
async fn write_thread(
    mut writer: impl AsyncWrite + Unpin,
    mut receiver: mpsc::Receiver<Packet>,
    mtu: usize,
) -> Result<()> {
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

/// Reads packets from the network
async fn read_thread(
    mut reader: impl AsyncRead + Unpin,
    sender: broadcast::Sender<Packet>,
) -> Result<()> {
    while let Some(packet) = Packet::from_async_reader(&mut reader).await {
        sender.send(packet).map_err(|_| Error::ConnectionClosed)?;
    }
    Err(Error::ConnectionClosed)
}

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
