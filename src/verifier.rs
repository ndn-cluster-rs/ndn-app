use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use derive_more::Constructor;
use futures::{future::BoxFuture, FutureExt};
use ndn_protocol::{
    signature::{KeyLocatorData, SignMethod, SignatureVerifier, ToVerifier},
    Certificate, Data, DigestSha256, Interest,
};
use tokio::sync::RwLock;
use type_map::concurrent::TypeMap;

use crate::app::AppHandler;

/// A simple verifier that will allow unsigned and signed interests, but will make sure a
/// DigestSha256-signed interest has a valid digest
pub const SIMPLE_VERIFIER: OrVerifier<ForbidDigestSignature, RequireValidSignature<DigestSha256>> =
    OrVerifier(
        ForbidDigestSignature,
        RequireValidSignature(DigestSha256::new()),
    );

/// Same as `SIMPLE_VERIFIER`, but does not allow unsigned interests
pub const SIMPLE_SIGNED: AndVerifier<
    ForbidUnsigned,
    OrVerifier<ForbidDigestSignature, RequireValidSignature<DigestSha256>>,
> = AndVerifier(ForbidUnsigned, SIMPLE_VERIFIER);

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

#[async_trait]
pub trait DataVerifier {
    async fn verify(&self, data: &Data<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool;
}

pub trait VerifierEx: Sized {
    fn or<T: Sized>(self, other: T) -> OrVerifier<Self, T> {
        OrVerifier(self, other)
    }

    fn and<T: Sized>(self, other: T) -> AndVerifier<Self, T> {
        AndVerifier(self, other)
    }
}

#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct AllowAll;

impl VerifierEx for AllowAll {}

#[async_trait]
impl DataVerifier for AllowAll {
    async fn verify(&self, _data: &Data<Bytes>, _context: Arc<RwLock<TypeMap>>) -> bool {
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

#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct ForbidAll;

#[async_trait]
impl DataVerifier for ForbidAll {
    async fn verify(&self, _data: &Data<Bytes>, _context: Arc<RwLock<TypeMap>>) -> bool {
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

#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct OrVerifier<T, U>(T, U);

#[async_trait]
impl<T, U> DataVerifier for OrVerifier<T, U>
where
    T: DataVerifier + Sync,
    U: DataVerifier + Sync,
{
    async fn verify(&self, data: &Data<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        let res1 = self.0.verify(data, Arc::clone(&context)).await;
        let res2 = self.1.verify(data, context).await;
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

#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct AndVerifier<T, U>(T, U);

#[async_trait]
impl<T, U> DataVerifier for AndVerifier<T, U>
where
    T: DataVerifier + Sync,
    U: DataVerifier + Sync,
{
    async fn verify(&self, data: &Data<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        let res1 = self.0.verify(data, Arc::clone(&context)).await;
        let res2 = self.1.verify(data, context).await;
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

#[derive(Debug, Clone, Copy, Hash, Default)]
pub struct RequireValidSignature<Method>(pub Method)
where
    Method: SignatureVerifier + Send + Sync;

impl<Method> RequireValidSignature<Method>
where
    Method: SignatureVerifier + Send + Sync,
{
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

            let Some(anchor_cert) = self.0.certificate() else {
                return false;
            };

            let Some(info) = cert.signature_info() else {
                return false;
            };

            let Some(KeyLocatorData::Name(locator)) = info.key_locator().map(|x| x.locator())
            else {
                return false;
            };

            if anchor_cert.name().has_prefix(locator) {
                // Signed by anchor
                return cert.as_data().verify_with_sign_method(&self.0).is_ok();
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

            cert.as_data().verify_with_sign_method(&*verifier).is_ok()
        }
        .boxed()
    }
}

#[async_trait]
impl<Method> InterestVerifier for RequireValidSignature<Method>
where
    Method: SignatureVerifier + Send + Sync,
{
    async fn verify(
        &self,
        interest: &Interest<Bytes>,
        _context: Arc<RwLock<TypeMap>>,
        mut app_handler: AppHandler,
        signature_verifiers: &(dyn ToVerifier + Sync),
    ) -> bool {
        const CERT_CHAIN_MAX_DEPTH: usize = 16;

        let verified = interest.verify_with_verifier(&self.0).is_ok();
        if verified {
            return true;
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
impl<Method> DataVerifier for RequireValidSignature<Method>
where
    Method: SignatureVerifier + Send + Sync,
{
    async fn verify(&self, data: &Data<Bytes>, _context: Arc<RwLock<TypeMap>>) -> bool {
        data.verify_with_sign_method(&self.0).is_ok()
    }
}

impl<T: SignatureVerifier + Send + Sync> VerifierEx for RequireValidSignature<T> {}

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
    async fn verify(&self, data: &Data<Bytes>, _context: Arc<RwLock<TypeMap>>) -> bool {
        if let Some(info) = data.signature_info() {
            info.signature_type().value() != ndn_protocol::DigestSha256::SIGNATURE_TYPE
        } else {
            true
        }
    }
}

impl VerifierEx for ForbidDigestSignature {}

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
    async fn verify(&self, data: &Data<Bytes>, _context: Arc<RwLock<TypeMap>>) -> bool {
        data.signature_info().is_some()
    }
}

impl VerifierEx for ForbidUnsigned {}

#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct RequireValidNonce;

struct NonceList<const N: usize> {
    nonces: [Option<Bytes>; N],
    buffer_pos: usize,
}

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
        used_nonces.buffer_pos = used_nonces.buffer_pos + 1 % ValidNonceContext::BUFFER_SIZE;
        true
    }
}

impl VerifierEx for RequireValidNonce {}

#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct RequireValidTime;

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

#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct RequireValidSeqNum;

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
