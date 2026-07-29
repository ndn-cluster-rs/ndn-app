# ndn-app

[![docs.rs](https://img.shields.io/docsrs/ndn-app)](https://docs.rs/ndn-app)
[![crates.io](https://img.shields.io/crates/v/ndn-app)](https://crates.io/crates/ndn-app)
[![license](https://img.shields.io/crates/l/ndn-app)](https://github.com/ndn-cluster-rs/ndn-app/blob/master/LICENSE)

An application framework for building Named Data Networking (NDN) applications in Rust, on top of [tokio](https://tokio.rs).

It handles the boilerplate of registering routes, matching incoming Interests, verifying them, and sending back Data or NACKs, so you can focus on writing handlers.

## Getting Started

### Prerequisites

`ndn-app` needs a running local [NFD](https://docs.named-data.net/NFD/current/) instance to connect to -- it talks to the forwarder over a Unix socket, and the socket path isn't configurable, so a standard local NFD setup is assumed.

### Installation

```
cargo add ndn-app
```

### Producing and consuming

`ndn-app` supports both sides of the NDN model: producing, i.e. registering routes and answering Interests, and consuming, i.e. expressing Interests and handling the resulting Data or NACK. Both are done through `AppHandler`, which is passed into every route and lifecycle callback.

The example below does both: it runs a small stateful producer, then uses the same app to consume from itself.

### Example: a signed counter service

```rust
use std::sync::Arc;

use ndn_app::{
    app::{App, AppHandler},
    verifier::{ForbidUnsigned, simple_signed},
};
use ndn_protocol::{Data, DigestSha256, Interest, Name};
use tokio::sync::RwLock;

// Context is cloned into every route and lifecycle callback -- this is the
// natural place for shared, mutable application state.
type Context = Arc<RwLock<u64>>;

// Each call increments the counter and returns its new value. The Interest's
// application parameters are decoded as `u64` -- a step to add to the counter --
// showing how request payloads flow into a handler.
async fn increment(_handler: AppHandler, interest: Interest<u64>, context: Context) -> Option<Data<u64>> {
    let step = interest.application_parameters().copied().unwrap_or(1);

    let mut counter = context.write().await;
    *counter += step;

    // Returning `Some` sends this Data as the response; the handler is
    // responsible for echoing the Interest's name onto it.
    Some(Data::new(interest.name().clone(), *counter))
}

// on_start runs once routes are registered and the app is connected to NFD.
// Here it acts as a consumer, calling the route above through the same
// AppHandler used by producers.
async fn on_start(mut handler: AppHandler, _context: Context) {
    for _ in 0..3 {
        let name = Name::from_str("counter/increment").unwrap();
        let interest = Interest::<u64>::new(name);

        match handler.express_interest(interest, ForbidUnsigned).await {
            Ok(data) => {
                let value = data.decode_content::<u64>().content().copied();
                println!("counter is now {value:?}");
            }
            Err(err) => eprintln!("increment failed: {err}"),
        }
    }
}

#[tokio::main]
async fn main() {
    let context: Context = Arc::new(RwLock::new(0));

    // simple_signed() requires a signature and accepts either a valid
    // DigestSha256 digest or a signature from a trusted key -- composed from
    // ForbidUnsigned.and(ForbidDigestSignature.or(RequireValidSignature)).
    // Verifiers compose with `.and` / `.or`, so arbitrarily complex policies
    // can be built from the same small set of primitives.
    let verifier = simple_signed();

    App::new(DigestSha256::new(), context)
        .on_start(on_start)
        .route("counter/increment", verifier, increment)
        .start()
        .await
        .unwrap();
}
```

A few things this example is showing on purpose:

- **State**: `context` is shared, typed application state, cloned into every callback -- here an `Arc<RwLock<u64>>`, but it can be anything `Clone + Send`.
- **Typed payloads**: `Interest<u64>` and `Data<u64>` decode/encode their application parameters as a concrete type via `TlvDecode`/`TlvEncode`, rather than forcing handlers to work with raw bytes.
- **Producing and consuming in one app**: the same `AppHandler` that's passed into `increment` is used from `on_start` to express an Interest and await its Data -- the "two sides" of NDN aren't two different APIs.
- **Verifier composition**: `simple_signed()` is a preset built from smaller composable verifiers; you can build your own the same way.
- **Error handling**: `express_interest` returns a `Result`, surfacing `NackReceived`, `Timeout`, `VerificationFailed`, and connection errors as an [`ndn_app::Error`](https://docs.rs/ndn-app/latest/ndn_app/error/enum.Error.html) so callers can react to each case explicitly rather than guessing from a bare `None`.

## How it works

- **Routes** are registered with a name prefix, a verifier, and an async handler. Incoming Interests are matched against registered prefixes and dispatched to the corresponding handler.
- **Signers** sign outgoing Data. `App::new` takes a signer -- `DigestSha256::new()` above -- that's used for all Data produced by the app.
- **Verifiers** decide whether an Interest (or, on the consumer side, a Data packet) is acceptable before it reaches your code. Built-in verifiers cover signature presence and validity (`ForbidUnsigned`, `RequireValidSignature`, `ForbidDigestSignature`), replay protection (`RequireValidNonce`, `RequireValidTime`, `RequireValidSeqNum`), and the unconditional `AllowAll`/`ForbidAll`. `RequireValidSignature` walks the certificate chain up to a trust anchor. Combine any of them with `.and` and `.or`, or use the `simple_verifier()` / `simple_signed()` presets, to build up more complex checks.
- **AppHandler** is passed into every route and lifecycle callback. It lets you express Interests from within a handler and shut the app down gracefully.
- **Context** is arbitrary state you provide to `App::new`, cloned into every handler -- a common place for shared, mutable state.
- **The builder is typestate-checked**: `App::new()` returns a builder that only exposes `.route()`, `.on_start()`, and `.mtu()`; calling `.start()` consumes it and moves into a runtime type that no longer exposes those methods. Registering a route after the app has started isn't a runtime error you can hit -- it's a state the type system doesn't let you construct.

## Related crates

- [`ndn-tlv`](https://crates.io/crates/ndn-tlv) encodes and decodes the TLV wire format NDN packets are built from.
- [`ndn-tlv-derive`](https://crates.io/crates/ndn-tlv-derive) provides the derive macros `ndn-tlv` uses to generate TLV encoding/decoding for structs and enums.
- [`ndn-protocol`](https://crates.io/crates/ndn-protocol) implements the core NDN packet types (Interest, Data, Names, signatures) on top of `ndn-tlv`.
- [`ndn-ndnlp`](https://crates.io/crates/ndn-ndnlp) implements NDNLPv2, the link-layer protocol used to send NDN packets over a transport.
- [`ndn-nfd-mgmt`](https://crates.io/crates/ndn-nfd-mgmt) implements the NFD management protocol, used e.g. to register routes with a local forwarder.

Each crate corresponds to one layer of the NDN stack (TLV encoding, packet types, link protocol, forwarder management) and is published separately so it can be used on its own, without pulling in the rest of the stack. `ndn-app` ties them together into an application framework.

`ndn-ndnlp` and `ndn-nfd-mgmt` only implement as much of their respective protocols as `ndn-app` needs -- they are not complete implementations of NDNLPv2 or the NFD management protocol.

## License

MIT

---

Produced as part of a Master's thesis in Computer Science.
