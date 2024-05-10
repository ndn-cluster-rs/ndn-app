# NDN App

## Example Usage

```rust
use ndn_app::{
    app::{App, AppHandler},
    verifier::ForbidUnsigned,
};
use ndn_protocol::{Data, DigestSha256, Interest};

async fn test_route(handler: AppHandler, interest: Interest<()>, context: ()) -> Option<Data<()>> {
    // AppHandler allows expressing interests, and shutting down the system gracefully
    // Possible future features include adding routes at runtime, changing the signer, etc.
    //
    // interest is the Interest that matched this route. The generic argument is the type of the
    // application parameters, which can be any type that implements TlvDecode
    //
    // The context is provided to App::new and cloned for every route handler.
    // You may place global state in there, for example using Arc<RwLock<_>>
    //
    // If the return value is None, a NACK is sent.
    // If the return value is Some, the contained Data object is sent as a response. It is the
    // responsibility of the route handler to set the name correctly.
    // The generic argument is the type of the content, which may be any type implementing
    // TlvEncode
    Some(Data::new(interest.name().clone(), ()))
}

async fn on_start(handler: AppHandler, context: ()) {
    // Executed after routes are registered and everything is up and running
}

// tokio is required
#[tokio::main]
async fn main() {
    // The verifier can be as simple or complicated as necessary, being composable with .or and .and methods.
    let verifier = ForbidUnsigned;

    App::new(DigestSha256::new(), ())
        .on_start(on_start)
        .route("test/route", verifier, test_route)
        .start()
        .await
        .unwrap();
}
```
