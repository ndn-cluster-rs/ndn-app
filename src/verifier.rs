use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use derive_more::Constructor;
use ndn_protocol::{
    signature::{KeyLocatorData, SignMethod},
    Data, Interest,
};
use tokio::sync::RwLock;
use type_map::concurrent::TypeMap;

#[async_trait]
pub trait InterestVerifier {
    async fn verify(&self, interest: &Interest<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool;
}

#[async_trait]
pub trait DataVerifier {
    async fn verify(&self, data: &Data<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool;
}

pub trait VerifierEx: Sized {
    fn or<T: Sized>(self, other: T) -> OrVerifier<Self, T> {
        OrVerifier {
            verifier1: self,
            verifier2: other,
        }
    }

    fn and<T: Sized>(self, other: T) -> AndVerifier<Self, T> {
        AndVerifier {
            verifier1: self,
            verifier2: other,
        }
    }
}

#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct AllowAll;

impl VerifierEx for AllowAll {}

#[async_trait]
impl DataVerifier for AllowAll {
    async fn verify(&self, _data: &Data<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        true
    }
}

#[async_trait]
impl InterestVerifier for AllowAll {
    async fn verify(&self, _data: &Interest<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        true
    }
}

#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct ForbidAll;

#[async_trait]
impl DataVerifier for ForbidAll {
    async fn verify(&self, _data: &Data<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        false
    }
}

#[async_trait]
impl InterestVerifier for ForbidAll {
    async fn verify(&self, _data: &Interest<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        false
    }
}

impl VerifierEx for ForbidAll {}

#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct OrVerifier<T, U> {
    verifier1: T,
    verifier2: U,
}

#[async_trait]
impl<T, U> DataVerifier for OrVerifier<T, U>
where
    T: DataVerifier + Sync,
    U: DataVerifier + Sync,
{
    async fn verify(&self, data: &Data<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        let res1 = self.verifier1.verify(data, Arc::clone(&context)).await;
        let res2 = self.verifier2.verify(data, context).await;
        res1 || res2
    }
}

#[async_trait]
impl<T, U> InterestVerifier for OrVerifier<T, U>
where
    T: InterestVerifier + Sync,
    U: InterestVerifier + Sync,
{
    async fn verify(&self, interest: &Interest<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        let res1 = self.verifier1.verify(interest, Arc::clone(&context)).await;
        let res2 = self.verifier2.verify(interest, context).await;
        res1 || res2
    }
}

impl<T, U> VerifierEx for OrVerifier<T, U> {}

#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct AndVerifier<T, U> {
    verifier1: T,
    verifier2: U,
}

#[async_trait]
impl<T, U> DataVerifier for AndVerifier<T, U>
where
    T: DataVerifier + Sync,
    U: DataVerifier + Sync,
{
    async fn verify(&self, data: &Data<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        let res1 = self.verifier1.verify(data, Arc::clone(&context)).await;
        let res2 = self.verifier2.verify(data, context).await;
        res1 && res2
    }
}

#[async_trait]
impl<T, U> InterestVerifier for AndVerifier<T, U>
where
    T: InterestVerifier + Sync,
    U: InterestVerifier + Sync,
{
    async fn verify(&self, interest: &Interest<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        let res1 = self.verifier1.verify(interest, Arc::clone(&context)).await;
        let res2 = self.verifier2.verify(interest, context).await;
        res1 && res2
    }
}

impl<T, U> VerifierEx for AndVerifier<T, U> {}

#[derive(Debug, Clone, Copy, Hash, Default)]
pub struct RequireValidSignature<Method: Send + Sync>(pub Method);

#[async_trait]
impl<Method> InterestVerifier for RequireValidSignature<Method>
where
    Method: SignMethod + Send + Sync,
    Method::Certificate: Clone,
{
    async fn verify(&self, interest: &Interest<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        interest
            .verify_with_sign_method(&self.0, self.0.certificate().clone())
            .is_ok()
    }
}

#[async_trait]
impl<Method> DataVerifier for RequireValidSignature<Method>
where
    Method: SignMethod + Send + Sync,
    Method::Certificate: Clone,
{
    async fn verify(&self, data: &Data<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        data.verify_with_sign_method(&self.0, self.0.certificate().clone())
            .is_ok()
    }
}

impl<T: Send + Sync> VerifierEx for RequireValidSignature<T> {}

#[derive(Debug, Clone, Copy, Hash, Constructor, Default)]
pub struct ForbidDigestSignature;

#[async_trait]
impl InterestVerifier for ForbidDigestSignature {
    async fn verify(&self, interest: &Interest<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        if let Some(info) = interest.signature_info() {
            info.signature_type().value() != ndn_protocol::DigestSha256::SIGNATURE_TYPE
        } else {
            true
        }
    }
}

#[async_trait]
impl DataVerifier for ForbidDigestSignature {
    async fn verify(&self, data: &Data<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
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
    async fn verify(&self, interest: &Interest<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        interest.signature_info().is_some()
    }
}

#[async_trait]
impl DataVerifier for ForbidUnsigned {
    async fn verify(&self, data: &Data<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
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
    async fn verify(&self, interest: &Interest<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
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
    async fn verify(&self, interest: &Interest<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
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
    async fn verify(&self, interest: &Interest<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
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
