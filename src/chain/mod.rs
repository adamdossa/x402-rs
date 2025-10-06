use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTimeError;

use crate::chain::evm::EvmProvider;
use crate::chain::solana::SolanaProvider;
use crate::facilitator::Facilitator;
use crate::network::Network;
use crate::types::{
    MixedAddress, Scheme, SettleRequest, SettleResponse, SupportedPaymentKindsResponse,
    VerifyRequest, VerifyResponse,
};

pub mod evm;
pub mod solana;

#[derive(Clone)]
pub enum NetworkProvider {
    Evm(EvmProvider),
    Solana(SolanaProvider),
}

#[derive(Clone)]
pub struct NetworkProviderGroup {
    providers: Arc<Vec<NetworkProvider>>,
    cursor: Arc<AtomicUsize>,
}

impl NetworkProviderGroup {
    pub fn new(providers: Vec<NetworkProvider>) -> Result<Self, &'static str> {
        if providers.is_empty() {
            return Err("provider group requires at least one provider");
        }

        Ok(Self {
            providers: Arc::new(providers),
            cursor: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn primary(&self) -> &NetworkProvider {
        &self.providers[0]
    }

    fn next_for_settlement(&self) -> NetworkProvider {
        if self.providers.len() == 1 {
            return self.providers[0].clone();
        }

        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % self.providers.len();
        self.providers[idx].clone()
    }

    pub fn providers(&self) -> &[NetworkProvider] {
        self.providers.as_ref().as_slice()
    }
}

pub trait NetworkProviderOps {
    fn signer_address(&self) -> MixedAddress;
    fn network(&self) -> Network;
}

impl NetworkProviderOps for NetworkProvider {
    fn signer_address(&self) -> MixedAddress {
        match self {
            NetworkProvider::Evm(provider) => provider.signer_address(),
            NetworkProvider::Solana(provider) => provider.signer_address(),
        }
    }

    fn network(&self) -> Network {
        match self {
            NetworkProvider::Evm(provider) => provider.network(),
            NetworkProvider::Solana(provider) => provider.network(),
        }
    }
}

impl Facilitator for NetworkProvider {
    type Error = FacilitatorLocalError;

    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
        match self {
            NetworkProvider::Evm(provider) => provider.verify(request).await,
            NetworkProvider::Solana(provider) => provider.verify(request).await,
        }
    }

    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
        match self {
            NetworkProvider::Evm(provider) => provider.settle(request).await,
            NetworkProvider::Solana(provider) => provider.settle(request).await,
        }
    }

    async fn supported(&self) -> Result<SupportedPaymentKindsResponse, Self::Error> {
        match self {
            NetworkProvider::Evm(provider) => provider.supported().await,
            NetworkProvider::Solana(provider) => provider.supported().await,
        }
    }
}

impl Facilitator for NetworkProviderGroup {
    type Error = FacilitatorLocalError;

    async fn verify(&self, request: &VerifyRequest) -> Result<VerifyResponse, Self::Error> {
        self.primary().verify(request).await
    }

    async fn settle(&self, request: &SettleRequest) -> Result<SettleResponse, Self::Error> {
        let provider = self.next_for_settlement();
        provider.settle(request).await
    }

    async fn supported(&self) -> Result<SupportedPaymentKindsResponse, Self::Error> {
        self.primary().supported().await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FacilitatorLocalError {
    /// The network is not supported by this facilitator.
    #[error("Unsupported network")]
    UnsupportedNetwork(Option<MixedAddress>),
    /// The network is not supported by this facilitator.
    #[error("Network mismatch: expected {1}, actual {2}")]
    NetworkMismatch(Option<MixedAddress>, Network, Network),
    /// Scheme mismatch.
    #[error("Scheme mismatch: expected {1}, actual {2}")]
    SchemeMismatch(Option<MixedAddress>, Scheme, Scheme),
    /// Invalid address.
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    /// The `pay_to` recipient in the requirements doesn't match the `to` address in the payload.
    #[error("Incompatible payload receivers (payload: {1}, requirements: {2})")]
    ReceiverMismatch(MixedAddress, String, String),
    /// Failed to read a system clock to check timing.
    #[error("Can not get system clock")]
    ClockError(#[source] SystemTimeError),
    /// The `validAfter`/`validBefore` fields on the authorization are not within bounds.
    #[error("Invalid timing: {1}")]
    InvalidTiming(MixedAddress, String),
    /// Low-level contract interaction failure (e.g. call failed, method not found).
    #[error("Invalid contract call: {0}")]
    ContractCall(String),
    /// EIP-712 signature is invalid or mismatched.
    #[error("Invalid signature: {1}")]
    InvalidSignature(MixedAddress, String),
    /// The payer's on-chain balance is insufficient for the payment.
    #[error("Insufficient funds")]
    InsufficientFunds(MixedAddress),
    /// The payload's `value` is not enough to meet the requirements.
    #[error("Insufficient value")]
    InsufficientValue(MixedAddress),
    /// The payload decoding failed.
    #[error("Decoding error: {0}")]
    DecodingError(String),
}
