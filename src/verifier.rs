use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
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

pub struct AllowAll;

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

pub struct OrVerifier<T, U> {
    verifier1: T,
    verifier2: U,
}

impl<T, U> OrVerifier<T, U> {
    pub fn new(verifier1: T, verifier2: U) -> Self {
        Self {
            verifier1,
            verifier2,
        }
    }
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

impl<T, U> AndVerifier<T, U> {
    pub fn new(verifier1: T, verifier2: U) -> Self {
        Self {
            verifier1,
            verifier2,
        }
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

pub struct ValidSignature<Method: Send + Sync> {
    method: Method,
}

impl<Method> ValidSignature<Method>
where
    Method: Send + Sync,
{
    pub fn new(method: Method) -> Self {
        Self { method }
    }
}

#[async_trait]
impl<Method> InterestVerifier for ValidSignature<Method>
where
    Method: SignMethod + Send + Sync,
    Method::Certificate: Clone,
{
    async fn verify(&self, interest: &Interest<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        interest
            .verify_with_sign_method(&self.method, self.method.certificate().clone())
            .is_ok()
    }
}

#[async_trait]
impl<Method> DataVerifier for ValidSignature<Method>
where
    Method: SignMethod + Send + Sync,
    Method::Certificate: Clone,
{
    async fn verify(&self, data: &Data<Bytes>, context: Arc<RwLock<TypeMap>>) -> bool {
        data.verify_with_sign_method(&self.method, self.method.certificate().clone())
            .is_ok()
    }
}

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

pub struct RequireValidNonce;

struct ValidNonceContext {
    used_nonces: HashMap<(u64, Option<KeyLocatorData>), [Option<Bytes>; Self::BUFFER_SIZE]>,
    buffer_pos: usize,
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
                    buffer_pos: 0,
                };
                context.insert(verifier_context);
            }
            context.get_mut::<ValidNonceContext>().unwrap()
        };

        let used_nonces = if let Some(used_nonces) = verifier_context.used_nonces.get_mut(&key) {
            used_nonces
        } else {
            const NONE: Option<Bytes> = None;
            let used_nonces = [NONE; ValidNonceContext::BUFFER_SIZE];
            verifier_context
                .used_nonces
                .insert(key.clone(), used_nonces);
            verifier_context.used_nonces.get_mut(&key).unwrap()
        };

        if used_nonces.contains(&Some(nonce.clone())) {
            return false;
        }
        used_nonces[verifier_context.buffer_pos] = Some(nonce.clone());
        verifier_context.buffer_pos =
            verifier_context.buffer_pos + 1 % ValidNonceContext::BUFFER_SIZE;
        true
    }
}
