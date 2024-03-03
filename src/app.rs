use std::{
    collections::BTreeMap, future::Future, marker::PhantomData, pin::Pin, sync::Arc, time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use log::{debug, error, info, trace, warn};
use ndn_ndnlp::Packet;
use ndn_nfd_mgmt::{make_command, ControlParameters, ControlResponse};
use ndn_protocol::{signature::SignMethod, Data, Interest, Name, SignSettings};
use ndn_tlv::{TlvDecode, TlvEncode};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter},
    net::UnixStream,
    sync::{self, broadcast, mpsc, RwLock},
    task::JoinSet,
};
use type_map::concurrent::TypeMap;

use crate::{error::Error, verifier::InterestVerifier, DataExt, Result, ToName};

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
    ) -> Option<Data<Bytes>>;
}

#[async_trait]
impl<Context, Params, Output, T> InterestCallbackErased<Context> for T
where
    Self: Sync,
    T: InterestCallback<Context, Params = Params, Output = Output>,
    Context: Send + 'static,
    Params: TlvDecode,
    Output: TlvEncode,
{
    async fn run(
        &self,
        handler: AppHandler,
        interest: Interest<Bytes>,
        context: Context,
    ) -> Option<Data<Bytes>> {
        InterestCallback::run(
            self,
            handler,
            interest.application_parameters_decode(),
            context,
        )
        .await
        .map(|x| x.content_encode())
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
    ) -> Pin<Box<dyn Future<Output = ()> + Send + Sync>>;
}

impl<F, G, Context> OnStartFn<Context> for F
where
    F: Send + Sync,
    F: Fn(AppHandler, Context) -> G,
    G: Future<Output = ()> + 'static + Send + Sync,
{
    fn run(
        &self,
        handler: AppHandler,
        context: Context,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + Sync>> {
        Box::pin(self(handler, context))
    }
}

pub struct RouteHandler<Context> {
    callback: Box<dyn InterestCallbackErased<Context> + Send + Sync>,
    verifier: Box<dyn InterestVerifier + Send + Sync>,
}

type InitialisedRoutes<Context> = Arc<RwLock<BTreeMap<Name, RouteHandler<Context>>>>;
#[doc(hidden)]
pub type UninitialisedRoutes<Context> = BTreeMap<Name, RouteHandler<Context>>;

pub struct App<Signer, Context, Routes> {
    routes: Routes,
    on_start: Option<Box<dyn OnStartFn<Context>>>,
    connector: Connector,
    signer: Arc<RwLock<Signer>>,
    verifier_context: Arc<RwLock<TypeMap>>,
    context: Context,
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
}

impl AppHandler {
    pub async fn express_interest(
        &mut self,
        interest: impl std::borrow::Borrow<Interest<Bytes>>,
    ) -> Result<Data<Bytes>> {
        let interest = interest.borrow();
        let (notifier_sender, notifier_receiver) = sync::oneshot::channel();
        self.interest_sender
            .send(InterestToSend {
                interest: interest.clone(),
                sign: true,
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
                            return Ok(packet);
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
                                return Err(Error::NackReceived);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(Error::ConnectionClosed)
        };
        tokio::time::timeout(Duration::from_millis(lifetime), wait_for_data).await?
    }
}

impl<Signer, Context> App<Signer, Context, UninitialisedRoutes<Context>>
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
        }
    }

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
        Params: TlvDecode + 'static,
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

    pub async fn start(self) -> Result<()> {
        self.initialise().start().await
    }

    fn initialise(self) -> App<Signer, Context, InitialisedRoutes<Context>> {
        App {
            routes: Arc::new(RwLock::new(self.routes)),
            on_start: self.on_start,
            connector: self.connector,
            signer: self.signer,
            verifier_context: self.verifier_context,
            context: self.context,
        }
    }
}

impl<Signer, Context> App<Signer, Context, InitialisedRoutes<Context>>
where
    Signer: SignMethod + Send + Sync + 'static,
    Context: Clone + Send + 'static,
{
    async fn handle_interest(
        interest: Interest<Bytes>,
        routes: Arc<RwLock<BTreeMap<Name, RouteHandler<Context>>>>,
        verifier_context: Arc<RwLock<TypeMap>>,
        app_handler: AppHandler,
        signer: Arc<RwLock<Signer>>,
        out_sender: mpsc::Sender<Packet>,
        context: Context,
    ) -> Result<()> {
        let routes = routes.read().await;
        let interest_uri = interest.name().to_uri();
        info!("Received interest for {interest_uri}");
        let mut matching_route_found = false;
        for (route, route_handler) in routes.iter().rev() {
            trace!("Checking against route {}", route.to_uri());
            if interest.name().has_prefix(route) {
                matching_route_found = true;
                if !route_handler
                    .verifier
                    .verify(&interest, Arc::clone(&verifier_context))
                    .await
                {
                    info!("Verification failed for request for {interest_uri}");
                    continue;
                }
                if let Some(mut ret) = route_handler
                    .callback
                    .run(app_handler.clone(), interest.clone(), context.clone()) // TODO
                    .await
                {
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

        // Outgoing data sync
        let (out_sender, out_receiver) = mpsc::channel(128);
        // Incoming data distribution
        let (in_sender, mut in_receiver) = broadcast::channel(128);

        tokio::spawn(write_thread(writer, out_receiver));
        tokio::spawn(read_thread(reader, in_sender.clone()));

        let mut tasks = JoinSet::new();
        {
            let routes = self.routes.read().await;
            routes.iter().for_each(|(route, _)| {
                tasks.spawn(tokio::time::timeout(
                    Duration::from_secs(3),
                    register_route(
                        Arc::clone(&self.signer),
                        in_sender.subscribe(),
                        out_sender.clone(),
                        route.clone(),
                    ),
                ));
            });
        }
        while let Some(res) = tasks.join_next().await {
            match res {
                Ok(Ok(Ok(()))) => (),
                Ok(Ok(Err(x))) => return Err(x),
                Ok(Err(_)) => {
                    error!("Route registration timed out");
                    return Err(Error::Timeout);
                }
                Err(x) => {
                    error!("Route registration panicked: {:?}", x.into_panic());
                    return Err(Error::Other("panic".to_string()));
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
        };

        if let Some(on_start) = self.on_start.take() {
            tokio::spawn(on_start.run(app_handler.clone(), self.context.clone()));
        }

        loop {
            match in_receiver.recv().await {
                Ok(packet) => {
                    if let Packet::Interest(interest) = packet {
                        tokio::spawn(Self::handle_interest(
                            interest.clone(),
                            Arc::clone(&self.routes),
                            Arc::clone(&self.verifier_context),
                            app_handler.clone(),
                            Arc::clone(&self.signer),
                            out_sender.clone(),
                            self.context.clone(),
                        ));
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return Err(Error::ConnectionClosed),
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("Dropped {n} packets in routing handler");
                }
            }
        }
    }
}

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

async fn write_thread(
    mut writer: impl AsyncWrite + Unpin,
    mut receiver: mpsc::Receiver<Packet>,
) -> Result<()> {
    while let Some(packet) = receiver.recv().await {
        writer.write_all(&packet.encode()).await?;
        writer.flush().await?;
    }
    Err(Error::ConnectionClosed)
}

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
    eprintln!("Registering route {route:?}");
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
                    let data = packet.content_decode::<ControlResponse<ControlParameters>>();
                    if let Some(content) = data.content() {
                        if content.status_code().as_usize() != 200 {
                            error!("Registering {route} failed with status code {status_code}: {status_text}",
                                  route = route.to_uri(),
                                  status_code = content.status_code(),
                                  status_text = String::from_utf8_lossy(&content.status_text()));
                        } else {
                            info!("Registered route {route}", route = route.to_uri());
                        }
                    }
                    return Ok(());
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
