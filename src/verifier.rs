//! Composable acceptance policies for Interests and Data packets.
//!
//! A verifier is anything that can say yes or no to a packet before it
//! reaches application code: [`InterestVerifier`] gates producer route
//! handlers (see [`crate::app::App::route`]), and [`DataVerifier`] gates
//! responses received by [`crate::app::AppHandler::express_interest`].
//! Both traits are deliberately minimal (one `verify` method each) so
//! that policy is built by composing small, independently testable
//! pieces with [`VerifierEx::and`] and [`VerifierEx::or`], rather than by
//! writing one large verifier per use case.
//!
//! ```rust,no_run
//! use ndn_app::verifier::{ForbidUnsigned, ForbidDigestSignature, VerifierEx};
//!
//! // Require a signature, but don't accept a bare digest as proof of
//! // authenticity.
//! let verifier = ForbidUnsigned.and(ForbidDigestSignature);
//! ```
//!
//! [`simple_verifier`] and [`simple_signed`] package up the combination
//! most applications want as a starting point.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use derive_more::Constructor;
use futures::{future::BoxFuture, FutureExt};
use ndn_protocol::{
    signature::{KeyLocatorData, SignMethodType as _, ToVerifier},
    Certificate, Data, DigestSha256, Interest,
};
use tokio::sync::RwLock;
use type_map::concurrent::TypeMap;

use crate::app::AppHandler;

/// Accepts unsigned packets and packets with a valid signature, but
/// rejects a `DigestSha256` signature whose digest doesn't actually
/// match the packet.
///
/// A bare digest only proves the packet wasn't corrupted in transit, not
/// who sent it, so this is a baseline integrity check rather than
/// authentication. Reach for [`simple_signed`] when a real signature
/// should be required.
pub fn simple_verifier() -> OrVerifier<ForbidDigestSignature, RequireValidSignature> {
    OrVerifier(
        ForbidDigestSignature,
        RequireValidSignature(DigestSha256::certificate()),
    )
}

/// Same as [`simple_verifier`], but also rejects unsigned packets, so
/// every accepted packet carries a real signature.
pub fn simple_signed(
) -> AndVerifier<ForbidUnsigned, OrVerifier<ForbidDigestSignature, RequireValidSignature>> {
    AndVerifier(ForbidUnsigned, simple_verifier())
}

/// Decides whether an incoming Interest should reach a route handler.
///
/// Implementations receive the same [`AppHandler`] passed to route
/// handlers, so a verifier can itself express Interests, e.g. to fetch a
/// certificate needed to validate a signature (see
/// [`RequireValidSignature`]). `context` is a per-app [`TypeMap`] shared
/// across all verifier invocations, letting stateful verifiers (like
/// replay-protection ones) keep data between calls without threading
/// their own storage through `App`.
#[async_trait]
pub trait InterestVerifier {
    async fn verify(
        &self,
        interest: &Interest<Bytes>,
        context: Arc<RwLock<TypeMap>>,
        app_handler: AppHandler,
        signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool;
}

/// Decides whether a Data packet received in response to an expressed
/// Interest should be handed back to the caller of
/// [`AppHandler::express_interest`], mirroring [`InterestVerifier`] for
/// the consumer side.
#[async_trait]
pub trait DataVerifier {
    async fn verify(
        &self,
        data: &Data<Bytes>,
        context: Arc<RwLock<TypeMap>>,
        mut app_handler: AppHandler,
        signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool;
}

/// Adds `.and` / `.or` combinators to any verifier, so policies can be
/// built up from smaller pieces instead of writing one verifier that
/// checks everything.
pub trait VerifierEx: Sized {
    /// Accepts a packet if either `self` or `other` accepts it.
    fn or<T: Sized>(self, other: T) -> OrVerifier<Self, T> {
        OrVerifier(self, other)
    }

    /// Accepts a packet only if both `self` and `other` accept it.
    fn and<T: Sized>(self, other: T) -> AndVerifier<Self, T> {
        AndVerifier(self, other)
    }
}

/// Accepts every packet unconditionally. Useful as a placeholder while a
/// route is being developed, or as one side of an [`OrVerifier`] where
/// the other side is expected to do the real work.
#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct AllowAll;

impl VerifierEx for AllowAll {}

#[async_trait]
impl DataVerifier for AllowAll {
    async fn verify(
        &self,
        _data: &Data<Bytes>,
        _context: Arc<RwLock<TypeMap>>,
        _app_handler: AppHandler,
        _signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        true
    }
}

#[async_trait]
impl InterestVerifier for AllowAll {
    async fn verify(
        &self,
        _data: &Interest<Bytes>,
        _context: Arc<RwLock<TypeMap>>,
        _app_handler: AppHandler,
        _signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        true
    }
}

/// Rejects every packet unconditionally. The identity element for
/// [`AndVerifier`]: `AndVerifier(ForbidAll, x)` always rejects,
/// regardless of `x`, which is occasionally useful for disabling a route
/// without removing it.
#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct ForbidAll;

#[async_trait]
impl DataVerifier for ForbidAll {
    async fn verify(
        &self,
        _data: &Data<Bytes>,
        _context: Arc<RwLock<TypeMap>>,
        _app_handler: AppHandler,
        _signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        false
    }
}

#[async_trait]
impl InterestVerifier for ForbidAll {
    async fn verify(
        &self,
        _data: &Interest<Bytes>,
        _context: Arc<RwLock<TypeMap>>,
        _app_handler: AppHandler,
        _signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        false
    }
}

impl VerifierEx for ForbidAll {}

/// Accepts a packet if either wrapped verifier accepts it. Built by
/// [`VerifierEx::or`] rather than constructed directly.
///
/// Both branches always run, even once one has already accepted the
/// packet, since a verifier's side effects (e.g. recording a nonce in
/// [`RequireValidNonce`]) may matter even when its boolean result
/// doesn't end up deciding the outcome.
#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct OrVerifier<T, U>(T, U);

#[async_trait]
impl<T, U> DataVerifier for OrVerifier<T, U>
where
    T: DataVerifier + Sync,
    U: DataVerifier + Sync,
{
    async fn verify(
        &self,
        data: &Data<Bytes>,
        context: Arc<RwLock<TypeMap>>,
        app_handler: AppHandler,
        signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        let res1 = self
            .0
            .verify(
                data,
                Arc::clone(&context),
                app_handler.clone(),
                signature_verifiers,
            )
            .await;
        let res2 = self
            .1
            .verify(data, context, app_handler.clone(), signature_verifiers)
            .await;
        res1 || res2
    }
}

#[async_trait]
impl<T, U> InterestVerifier for OrVerifier<T, U>
where
    T: InterestVerifier + Sync,
    U: InterestVerifier + Sync,
{
    async fn verify(
        &self,
        interest: &Interest<Bytes>,
        context: Arc<RwLock<TypeMap>>,
        app_handler: AppHandler,
        signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        let res1 = self
            .0
            .verify(
                interest,
                Arc::clone(&context),
                app_handler.clone(),
                signature_verifiers,
            )
            .await;
        let res2 = self
            .1
            .verify(interest, context, app_handler, signature_verifiers)
            .await;
        res1 || res2
    }
}

impl<T, U> VerifierEx for OrVerifier<T, U> {}

/// Accepts a packet only if both wrapped verifiers accept it. Built by
/// [`VerifierEx::and`] rather than constructed directly.
///
/// Like [`OrVerifier`], both branches always run rather than
/// short-circuiting, so stateful verifiers on either side still observe
/// every packet regardless of the other branch's result.
#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct AndVerifier<T, U>(T, U);

#[async_trait]
impl<T, U> DataVerifier for AndVerifier<T, U>
where
    T: DataVerifier + Sync,
    U: DataVerifier + Sync,
{
    async fn verify(
        &self,
        data: &Data<Bytes>,
        context: Arc<RwLock<TypeMap>>,
        app_handler: AppHandler,
        signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        let res1 = self
            .0
            .verify(
                data,
                Arc::clone(&context),
                app_handler.clone(),
                signature_verifiers,
            )
            .await;
        let res2 = self
            .1
            .verify(data, context, app_handler.clone(), signature_verifiers)
            .await;
        res1 && res2
    }
}

#[async_trait]
impl<T, U> InterestVerifier for AndVerifier<T, U>
where
    T: InterestVerifier + Sync,
    U: InterestVerifier + Sync,
{
    async fn verify(
        &self,
        interest: &Interest<Bytes>,
        context: Arc<RwLock<TypeMap>>,
        app_handler: AppHandler,
        signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        let res1 = self
            .0
            .verify(
                interest,
                Arc::clone(&context),
                app_handler.clone(),
                signature_verifiers,
            )
            .await;
        let res2 = self
            .1
            .verify(interest, context, app_handler, signature_verifiers)
            .await;
        res1 && res2
    }
}

impl<T, U> VerifierEx for AndVerifier<T, U> {}

/// Requires a valid cryptographic signature, chaining up through
/// certificates to the trust anchor held in the tuple field.
///
/// A packet's signature is checked directly against the anchor first;
/// if the signing key isn't the anchor itself, the verifier fetches the
/// signer's certificate (by expressing an Interest for it through
/// [`AppHandler`]) and recurses, up to a fixed depth, until it either
/// reaches the anchor or gives up. This lets an application trust one
/// root key while still accepting packets signed by keys the root has
/// certified, rather than needing every valid signer's key listed
/// up front.
#[derive(Debug, Clone, Hash)]
pub struct RequireValidSignature(pub Certificate);

impl RequireValidSignature {
    fn verify_signature<'a>(
        &'a self,
        cert: &'a Certificate,
        mut app_handler: AppHandler,
        signature_verifiers: &'a (dyn ToVerifier + Sync),
        max_depth: usize,
    ) -> BoxFuture<'a, bool> {
        async move {
            if max_depth == 0 {
                return false;
            }

            let Some(info) = cert.signature_info() else {
                return false;
            };

            let Some(KeyLocatorData::Name(locator)) = info.key_locator() else {
                return false;
            };

            if self.0.name().has_prefix(locator) {
                // Signed by anchor
                let Some(verifier) = signature_verifiers.from_data(self.0 .0.clone()) else {
                    return false;
                };
                return cert.as_data().verify(&*verifier).is_ok();
            }

            let Ok(signer) = app_handler
                .express_interest_unsigned(
                    Interest::<()>::new(locator.clone()),
                    AllowAll, // SECURITY: We do custom verification
                )
                .await
            else {
                return false;
            };
            println!("{:#?}", signer);

            let signer_cert = Certificate(signer);

            if !self
                .verify_signature(
                    &signer_cert,
                    app_handler.clone(),
                    signature_verifiers,
                    max_depth - 1,
                )
                .await
            {
                return false;
            }

            let Some(verifier) = signature_verifiers.from_data(signer_cert.0) else {
                return false;
            };

            cert.as_data().verify(&*verifier).is_ok()
        }
        .boxed()
    }
}

#[async_trait]
impl InterestVerifier for RequireValidSignature {
    async fn verify(
        &self,
        interest: &Interest<Bytes>,
        _context: Arc<RwLock<TypeMap>>,
        mut app_handler: AppHandler,
        signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        const CERT_CHAIN_MAX_DEPTH: usize = 16;

        if let Some(verifier) = signature_verifiers.from_data(self.0 .0.clone()) {
            if interest.verify(&*verifier).is_ok() {
                return true;
            }
        }

        let Some(info) = interest.signature_info() else {
            return false;
        };
        let Some(locator) = info.key_locator() else {
            return false;
        };

        let Some(locator_name) = locator.as_name() else {
            return false;
        };
        let Ok(signed_by) = app_handler
            .express_interest_unsigned(
                Interest::<()>::new(locator_name.clone()),
                AllowAll, // SECURITY: We do custom verification
            )
            .await
        else {
            return false;
        };
        return self
            .verify_signature(
                &Certificate(signed_by),
                app_handler.clone(),
                signature_verifiers,
                CERT_CHAIN_MAX_DEPTH,
            )
            .await;
    }
}

#[async_trait]
impl DataVerifier for RequireValidSignature {
    async fn verify(
        &self,
        data: &Data<Bytes>,
        _context: Arc<RwLock<TypeMap>>,
        mut app_handler: AppHandler,
        signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        const CERT_CHAIN_MAX_DEPTH: usize = 16;

        if let Some(verifier) = signature_verifiers.from_data(self.0 .0.clone()) {
            if data.verify(&*verifier).is_ok() {
                return true;
            }
        }

        let Some(info) = data.signature_info() else {
            return false;
        };
        let Some(locator) = info.key_locator() else {
            return false;
        };

        let Some(locator_name) = locator.as_name() else {
            return false;
        };

        let Ok(signed_by) = app_handler
            .express_interest_unsigned(
                Interest::<()>::new(locator_name.clone()),
                AllowAll, // SECURITY: We do custom verification
            )
            .await
        else {
            return false;
        };

        return self
            .verify_signature(
                &Certificate(signed_by),
                app_handler.clone(),
                signature_verifiers,
                CERT_CHAIN_MAX_DEPTH,
            )
            .await;
    }
}

impl VerifierEx for RequireValidSignature {}

/// Rejects packets signed with a bare `DigestSha256` signature, while
/// still allowing unsigned packets and packets signed with other
/// signature types through.
///
/// A `DigestSha256` signature only proves the packet's bytes weren't
/// altered; it doesn't identify a signer, since anyone can compute a
/// digest. This verifier exists to be combined with a real signature
/// check (see [`simple_verifier`]) so digest-only packets don't
/// masquerade as authenticated ones.
#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct ForbidDigestSignature;

#[async_trait]
impl InterestVerifier for ForbidDigestSignature {
    async fn verify(
        &self,
        interest: &Interest<Bytes>,
        _context: Arc<RwLock<TypeMap>>,
        _app_handler: AppHandler,
        _signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        if let Some(info) = interest.signature_info() {
            info.signature_type().value() != ndn_protocol::DigestSha256::SIGNATURE_TYPE
        } else {
            true
        }
    }
}

#[async_trait]
impl DataVerifier for ForbidDigestSignature {
    async fn verify(
        &self,
        data: &Data<Bytes>,
        _context: Arc<RwLock<TypeMap>>,
        _app_handler: AppHandler,
        _signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        if let Some(info) = data.signature_info() {
            info.signature_type().value() != ndn_protocol::DigestSha256::SIGNATURE_TYPE
        } else {
            true
        }
    }
}

impl VerifierEx for ForbidDigestSignature {}

/// Rejects packets with no signature at all, regardless of what
/// signature type would otherwise be present.
///
/// This only checks that a `SignatureInfo` field exists; it says nothing
/// about whether the signature is valid. Combine with
/// [`RequireValidSignature`] to actually verify it.
#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct ForbidUnsigned;

#[async_trait]
impl InterestVerifier for ForbidUnsigned {
    async fn verify(
        &self,
        interest: &Interest<Bytes>,
        _context: Arc<RwLock<TypeMap>>,
        _app_handler: AppHandler,
        _signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        interest.signature_info().is_some()
    }
}

#[async_trait]
impl DataVerifier for ForbidUnsigned {
    async fn verify(
        &self,
        data: &Data<Bytes>,
        _context: Arc<RwLock<TypeMap>>,
        _app_handler: AppHandler,
        _signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        data.signature_info().is_some()
    }
}

impl VerifierEx for ForbidUnsigned {}

/// Rejects a signed Interest if its signature nonce has been seen before
/// from the same signer, and rejects signed Interests with no nonce or
/// an implausibly long one. Unsigned Interests are always accepted,
/// since there's no signer identity to track replay against.
///
/// Nonces are tracked per `(signature type, key locator)` pair in a
/// fixed-size ring buffer, so this only catches replay within a recent
/// window rather than for the lifetime of the app; a longer memory would
/// mean unbounded growth per signer.
#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct RequireValidNonce;

struct NonceList<const N: usize> {
    nonces: [Option<Bytes>; N],
    buffer_pos: usize,
}

/// Per-signer nonce history, stored in the shared verifier [`TypeMap`]
/// so it survives across calls to [`RequireValidNonce::verify`].
struct ValidNonceContext {
    used_nonces: HashMap<(u64, Option<KeyLocatorData>), NonceList<{ Self::BUFFER_SIZE }>>,
}

impl ValidNonceContext {
    const BUFFER_SIZE: usize = 16;
}

#[async_trait]
impl InterestVerifier for RequireValidNonce {
    async fn verify(
        &self,
        interest: &Interest<Bytes>,
        context: Arc<RwLock<TypeMap>>,
        _app_handler: AppHandler,
        _signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        let Some(signature_info) = interest.signature_info() else {
            // Unsigned - might be allowed
            return true;
        };

        let Some(nonce) = signature_info.nonce() else {
            // No nonce present
            return false;
        };

        if nonce.remaining() > 16 {
            // Nonce too long - limit maximimum nonce length to prevent potential out of memory
            // attacks
            return false;
        }

        let key = (
            signature_info.signature_type().value(),
            signature_info.key_locator().map(Clone::clone),
        );

        let mut context = context.write().await;
        let verifier_context = {
            if !context.contains::<ValidNonceContext>() {
                let verifier_context = ValidNonceContext {
                    used_nonces: HashMap::new(),
                };
                context.insert(verifier_context);
            }
            context.get_mut::<ValidNonceContext>().unwrap()
        };

        let used_nonces = if let Some(used_nonces) = verifier_context.used_nonces.get_mut(&key) {
            used_nonces
        } else {
            const NONE: Option<Bytes> = None;
            let used_nonces = NonceList {
                nonces: [NONE; ValidNonceContext::BUFFER_SIZE],
                buffer_pos: 0,
            };
            verifier_context
                .used_nonces
                .insert(key.clone(), used_nonces);
            verifier_context.used_nonces.get_mut(&key).unwrap()
        };

        if used_nonces.nonces.contains(&Some(nonce.clone())) {
            return false;
        }
        used_nonces.nonces[used_nonces.buffer_pos] = Some(nonce.clone());
        used_nonces.buffer_pos = (used_nonces.buffer_pos + 1) % ValidNonceContext::BUFFER_SIZE;
        true
    }
}

impl VerifierEx for RequireValidNonce {}

/// Rejects a signed Interest whose signature timestamp isn't strictly
/// greater than the last one seen from the same signer, and rejects
/// signed Interests with no timestamp. Unsigned Interests are always
/// accepted.
///
/// This is a lighter-weight alternative to [`RequireValidNonce`]: it
/// only needs one timestamp per signer rather than a window of recent
/// nonces, at the cost of requiring signers to send strictly increasing
/// timestamps (fine for a live clock, but unlike nonces it can't
/// tolerate reordering). The first Interest seen from a signer is
/// compared against `now - GRACE_PERIOD` rather than accepted
/// unconditionally, so a timestamp more than a minute old is still
/// rejected even on the first sighting.
#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct RequireValidTime;

/// Per-signer last-seen timestamp, stored in the shared verifier
/// [`TypeMap`] so it survives across calls to
/// [`RequireValidTime::verify`].
struct ValidTimeContext {
    last_seen: HashMap<(u64, Option<KeyLocatorData>), u64>,
}

impl ValidTimeContext {
    const GRACE_PERIOD: u64 = 60_000;
}

#[async_trait]
impl InterestVerifier for RequireValidTime {
    async fn verify(
        &self,
        interest: &Interest<Bytes>,
        context: Arc<RwLock<TypeMap>>,
        _app_handler: AppHandler,
        _signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        let Some(signature_info) = interest.signature_info() else {
            // Unsigned - might be allowed
            return true;
        };

        let Some(timestamp) = signature_info.time().map(|x| x.as_u64()) else {
            // No timestamp present
            return false;
        };

        let key = (
            signature_info.signature_type().value(),
            signature_info.key_locator().map(Clone::clone),
        );

        let mut context = context.write().await;
        let verifier_context = {
            if !context.contains::<ValidTimeContext>() {
                let verifier_context = ValidTimeContext {
                    last_seen: HashMap::new(),
                };
                context.insert(verifier_context);
            }
            context.get_mut::<ValidTimeContext>().unwrap()
        };

        if !verifier_context.last_seen.contains_key(&key) {
            verifier_context.last_seen.insert(
                key.clone(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64
                    - ValidTimeContext::GRACE_PERIOD,
            );
        }
        let last_seen = verifier_context.last_seen.get_mut(&key).unwrap();
        if timestamp > *last_seen {
            *last_seen = timestamp;
            return true;
        }
        false
    }
}

/// Rejects a signed Interest whose signature sequence number isn't
/// strictly greater than the last one seen from the same signer, and
/// rejects signed Interests with no sequence number. Unsigned Interests
/// are always accepted.
///
/// Unlike [`RequireValidTime`], the first Interest seen from a signer is
/// accepted unconditionally and simply establishes the baseline, since a
/// sequence number (unlike a timestamp) carries no external notion of
/// "too old" to check it against.
#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct RequireValidSeqNum;

/// Per-signer last-seen sequence number, stored in the shared verifier
/// [`TypeMap`] so it survives across calls to
/// [`RequireValidSeqNum::verify`].
struct ValidSeqNumContext {
    last_seq_num: HashMap<(u64, Option<KeyLocatorData>), u64>,
}

#[async_trait]
impl InterestVerifier for RequireValidSeqNum {
    async fn verify(
        &self,
        interest: &Interest<Bytes>,
        context: Arc<RwLock<TypeMap>>,
        _app_handler: AppHandler,
        _signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        let Some(signature_info) = interest.signature_info() else {
            // Unsigned - might be allowed
            return true;
        };

        let Some(seq_num) = signature_info.seq_num().map(|x| x.as_u64()) else {
            // No timestamp present
            return false;
        };

        let key = (
            signature_info.signature_type().value(),
            signature_info.key_locator().map(Clone::clone),
        );

        let mut context = context.write().await;
        let verifier_context = {
            if !context.contains::<ValidSeqNumContext>() {
                let verifier_context = ValidSeqNumContext {
                    last_seq_num: HashMap::new(),
                };
                context.insert(verifier_context);
            }
            context.get_mut::<ValidSeqNumContext>().unwrap()
        };

        if !verifier_context.last_seq_num.contains_key(&key) {
            verifier_context.last_seq_num.insert(key.clone(), seq_num);
            return true;
        }
        let last_seq_num = verifier_context.last_seq_num.get_mut(&key).unwrap();
        if seq_num > *last_seq_num {
            *last_seq_num = seq_num;
            return true;
        }
        false
    }
}
