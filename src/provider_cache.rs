//! Ethereum provider cache and initialization logic.
//!
//! This module defines a cache of configured Ethereum JSON-RPC providers with signing capabilities.
//! Providers are constructed dynamically from environment variables, including private key credentials.
//!
//! This enables interaction with multiple Ethereum-compatible networks using Alloy's `ProviderBuilder`.
//!
//! Supported signer type: `private-key`.
//!
//! Environment variables used:
//! - `SIGNER_TYPE` — currently only `"private-key"` is supported,
//! - `EVM_PRIVATE_KEYS` — optional comma-separated list of hex private keys,
//! - `EVM_PRIVATE_KEY` — fallback single private key if `EVM_PRIVATE_KEYS` is unset,
//! - `RPC_URL_BASE`, `RPC_URL_BASE_SEPOLIA` — RPC endpoints per network
//!
//! Example usage:
//! ```no_run
//! use x402_rs::network::Network;
//! use x402_rs::provider_cache::{ProviderCache, ProviderMap};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let provider_cache = ProviderCache::from_env().await?;
//! let provider = provider_cache
//!     .by_network(Network::Base)
//!     .expect("provider configured");
//! # Ok(())
//! # }
//! ```

use alloy::network::EthereumWallet;
use alloy::signers::local::PrivateKeySigner;
use serde::{Deserialize, Serialize};
use solana_sdk::signature::Keypair;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::env;

use crate::chain::evm::EvmProvider;
use crate::chain::solana::SolanaProvider;
use crate::chain::{NetworkProvider, NetworkProviderGroup, NetworkProviderOps};
use crate::network::{Network, NetworkFamily};

const ENV_SIGNER_TYPE: &str = "SIGNER_TYPE";
const ENV_EVM_PRIVATE_KEY: &str = "EVM_PRIVATE_KEY";
const ENV_EVM_PRIVATE_KEYS: &str = "EVM_PRIVATE_KEYS";
const ENV_SOLANA_PRIVATE_KEY: &str = "SOLANA_PRIVATE_KEY";
const ENV_RPC_BASE: &str = "RPC_URL_BASE";
const ENV_RPC_BASE_SEPOLIA: &str = "RPC_URL_BASE_SEPOLIA";
const ENV_RPC_XDC: &str = "RPC_URL_XDC";
const ENV_RPC_AVALANCHE_FUJI: &str = "RPC_URL_AVALANCHE_FUJI";
const ENV_RPC_AVALANCHE: &str = "RPC_URL_AVALANCHE";
const ENV_RPC_SOLANA: &str = "RPC_URL_SOLANA";
const ENV_RPC_SOLANA_DEVNET: &str = "RPC_URL_SOLANA_DEVNET";
const ENV_RPC_POLYGON_AMOY: &str = "RPC_URL_POLYGON_AMOY";
const ENV_RPC_POLYGON: &str = "RPC_URL_POLYGON";
const ENV_RPC_SEI: &str = "RPC_URL_SEI";
const ENV_RPC_SEI_TESTNET: &str = "RPC_URL_SEI_TESTNET";

/// A cache of pre-initialized [`EthereumProvider`] instances keyed by network.
///
/// This struct is responsible for lazily connecting to all configured RPC URLs
/// and wrapping them with appropriate signing and filler middleware.
///
/// Use [`ProviderCache::from_env`] to load credentials and connect using environment variables.
#[derive(Clone)]
pub struct ProviderCache {
    providers: HashMap<Network, NetworkProviderGroup>,
}

/// A generic cache of pre-initialized Ethereum provider instances [`ProviderMap::Value`] keyed by network.
///
/// This allows querying configured providers by network, and checking whether the network
/// supports EIP-1559 fee mechanics.
pub trait ProviderMap {
    type Value;

    /// Returns the Ethereum provider for the specified network, if configured.
    fn by_network<N: Borrow<Network>>(&self, network: N) -> Option<&Self::Value>;
}

impl<'a> IntoIterator for &'a ProviderCache {
    type Item = (&'a Network, &'a NetworkProviderGroup);
    type IntoIter = std::collections::hash_map::Iter<'a, Network, NetworkProviderGroup>;

    fn into_iter(self) -> Self::IntoIter {
        self.providers.iter()
    }
}

impl ProviderCache {
    /// Constructs a new [`ProviderCache`] from environment variables.
    ///
    /// Expects the following to be set:
    /// - `SIGNER_TYPE` — currently only `"private-key"` is supported
    /// - `EVM_PRIVATE_KEYS`/`EVM_PRIVATE_KEY` — private keys used to sign transactions
    /// - `RPC_URL_BASE`, `RPC_URL_BASE_SEPOLIA` — RPC endpoints per network
    ///
    /// Fails if required env vars are missing or if the provider cannot connect.
    pub async fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let mut providers = HashMap::new();
        for network in Network::variants() {
            let env_var = match network {
                Network::BaseSepolia => ENV_RPC_BASE_SEPOLIA,
                Network::Base => ENV_RPC_BASE,
                Network::XdcMainnet => ENV_RPC_XDC,
                Network::AvalancheFuji => ENV_RPC_AVALANCHE_FUJI,
                Network::Avalanche => ENV_RPC_AVALANCHE,
                Network::Solana => ENV_RPC_SOLANA,
                Network::SolanaDevnet => ENV_RPC_SOLANA_DEVNET,
                Network::PolygonAmoy => ENV_RPC_POLYGON_AMOY,
                Network::Polygon => ENV_RPC_POLYGON,
                Network::Sei => ENV_RPC_SEI,
                Network::SeiTestnet => ENV_RPC_SEI_TESTNET,
            };
            let is_eip1559 = match network {
                Network::BaseSepolia => true,
                Network::Base => true,
                Network::XdcMainnet => false,
                Network::AvalancheFuji => true,
                Network::Avalanche => true,
                Network::Solana => false,
                Network::SolanaDevnet => false,
                Network::PolygonAmoy => true,
                Network::Polygon => true,
                Network::Sei => true,
                Network::SeiTestnet => true,
            };

            let rpc_url = env::var(env_var);
            if let Ok(rpc_url) = rpc_url {
                let family: NetworkFamily = (*network).into();
                match family {
                    NetworkFamily::Evm => {
                        let wallets = SignerType::from_env()?.make_evm_wallets()?;
                        let mut network_providers = Vec::new();
                        for (index, wallet) in wallets.into_iter().enumerate() {
                            let provider =
                                EvmProvider::try_new(wallet, &rpc_url, is_eip1559, *network)
                                    .await?;
                            let provider = NetworkProvider::Evm(provider);
                            let signer_address = provider.signer_address();
                            tracing::info!(
                                "Initialized provider for {} at {} using {} (key #{})",
                                network,
                                rpc_url,
                                signer_address,
                                index
                            );
                            network_providers.push(provider);
                        }
                        let group = NetworkProviderGroup::new(network_providers)
                            .map_err(|e| format!("{e} for network {network}"))?;
                        providers.insert(*network, group);
                    }
                    NetworkFamily::Solana => {
                        let keypair = SignerType::from_env()?.make_solana_wallet()?;
                        let provider = SolanaProvider::try_new(keypair, rpc_url.clone(), *network)?;
                        let provider = NetworkProvider::Solana(provider);
                        let signer_address = provider.signer_address();
                        let group = NetworkProviderGroup::new(vec![provider])
                            .map_err(|e| format!("{e} for network {network}"))?;
                        providers.insert(*network, group);
                        tracing::info!(
                            "Initialized provider for {} at {} using {}",
                            network,
                            rpc_url,
                            signer_address
                        );
                    }
                }
            } else {
                tracing::warn!("No RPC URL configured for {} (skipped)", network);
            }
        }

        Ok(Self { providers })
    }
}

impl ProviderMap for ProviderCache {
    type Value = NetworkProviderGroup;
    fn by_network<N: Borrow<Network>>(&self, network: N) -> Option<&NetworkProviderGroup> {
        self.providers.get(network.borrow())
    }
}

/// Supported methods for constructing an Ethereum wallet from environment variables.
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerType {
    /// A local private key stored in the `PRIVATE_KEY` environment variable.
    #[serde(rename = "private-key")]
    PrivateKey,
}

impl SignerType {
    /// Parse the signer type from the `SIGNER_TYPE` environment variable.
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let signer_type_string =
            env::var(ENV_SIGNER_TYPE).map_err(|_| format!("env {ENV_SIGNER_TYPE} not set"))?;
        match signer_type_string.as_str() {
            "private-key" => Ok(SignerType::PrivateKey),
            _ => Err(format!("Unknown signer type {signer_type_string}").into()),
        }
    }

    /// Constructs one or more [`EthereumWallet`] instances based on environment variables.
    ///
    /// Supports two formats:
    /// - `EVM_PRIVATE_KEYS`: a comma-separated list of hex-encoded private keys.
    /// - `EVM_PRIVATE_KEY`: a single hex-encoded private key (legacy).
    pub fn make_evm_wallets(&self) -> Result<Vec<EthereumWallet>, Box<dyn std::error::Error>> {
        match self {
            SignerType::PrivateKey => {
                let keys = if let Ok(multi_keys) = env::var(ENV_EVM_PRIVATE_KEYS) {
                    multi_keys
                        .split(',')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(|value| value.to_string())
                        .collect::<Vec<_>>()
                } else {
                    vec![
                        env::var(ENV_EVM_PRIVATE_KEY)
                            .map_err(|_| format!("env {ENV_EVM_PRIVATE_KEY} not set"))?,
                    ]
                };

                if keys.is_empty() {
                    return Err("no private keys configured".into());
                }

                let wallets = keys
                    .into_iter()
                    .map(|private_key| {
                        let pk_signer: PrivateKeySigner = private_key.parse()?;
                        Ok(EthereumWallet::new(pk_signer))
                    })
                    .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;

                Ok(wallets)
            }
        }
    }

    pub fn make_solana_wallet(&self) -> Result<Keypair, Box<dyn std::error::Error>> {
        match self {
            SignerType::PrivateKey => {
                let private_key = env::var(ENV_SOLANA_PRIVATE_KEY)
                    .map_err(|_| format!("env {ENV_SOLANA_PRIVATE_KEY} not set"))?;
                let keypair = Keypair::from_base58_string(private_key.as_str());
                Ok(keypair)
            }
        }
    }
}
