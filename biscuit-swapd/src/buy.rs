//! Buying XMR with BTC: one swap per process, started (`buy`) or resumed
//! (`resume`) by Biscuit.
//!
//! The Bitcoin side is Biscuit's own wallet: Biscuit sends the BIP39 seed
//! (64 bytes, hex) on stdin and the helper derives the same BIP84 account
//! (m/84'/0'/0'). The lock transaction is paid from it, any refund comes back
//! to it, and the XMR goes to the Biscuit address given by the caller.
//! The seed never appears in the arguments or the environment.
//!
//! Progress is written to stdout as JSON lines, like discovery.
use anyhow::{Context, Result, bail};
use bitcoin_wallet::BitcoinWalletSeed;
use libp2p::{Multiaddr, PeerId, identity};
use serde::Deserialize;
use serde_json::json;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

use swap::database::{AccessMode, open_db};
use swap::monero::{self, LabeledMoneroAddress, MoneroAddressPool};
use swap::protocol::Database;
use swap::protocol::bob::{self, BobState};
use swap_env::env::{GetConfig, Mainnet};
use swap_p2p::protocols::rendezvous::XmrBtcNamespace;

use crate::emit;

/// Biscuit's BIP39 seed (the 64 bytes after PBKDF2, not the words).
struct BiscuitSeed(Zeroizing<Vec<u8>>);

impl BitcoinWalletSeed for BiscuitSeed {
    fn derive_extended_private_key(&self, network: bitcoin::Network) -> Result<bitcoin::bip32::Xpriv> {
        // The wallet applies the BIP84 template to this master key.
        Ok(bitcoin::bip32::Xpriv::new_master(network, &self.0)?)
    }

    fn derive_extended_private_key_legacy(
        &self,
        _network: bdk::bitcoin::Network,
    ) -> Result<bdk::bitcoin::util::bip32::ExtendedPrivKey> {
        // Only used to migrate eigenwallet wallets older than bdk 1.0.
        bail!("No legacy wallet to migrate")
    }
}

impl BiscuitSeed {
    /// First receive address of the BIP84 account (m/84'/0'/0'/0/0), as
    /// Biscuit shows it: proves both sides derived the same wallet.
    fn first_address(&self, network: bitcoin::Network) -> Result<bitcoin::Address> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let coin = if network == bitcoin::Network::Bitcoin { 0 } else { 1 };
        let path = bitcoin::bip32::DerivationPath::from_str(&format!("m/84'/{coin}'/0'/0/0"))?;
        let key = self.derive_extended_private_key(network)?.derive_priv(&secp, &path)?;
        let public_key = bitcoin::CompressedPublicKey(key.private_key.public_key(&secp));
        Ok(bitcoin::Address::p2wpkh(&public_key, network))
    }
}

impl Clone for BiscuitSeed {
    fn clone(&self) -> Self {
        BiscuitSeed(self.0.clone())
    }
}

/// What `buy` reads on stdin (one JSON line).
#[derive(Deserialize)]
struct BuyRequest {
    seed_hex: Zeroizing<String>,
    expected_first_address: String,
    /// Chosen by Biscuit, so it can track the swap from the very start.
    swap_id: Uuid,
    maker_peer_id: String,
    maker_address: String,
    btc_amount_sat: u64,
    /// Where the XMR goes: a Biscuit (sub)address.
    xmr_address: String,
    /// Change of the lock transaction: a Biscuit address.
    change_address: String,
}

/// What `resume` reads on stdin.
#[derive(Deserialize)]
struct ResumeRequest {
    seed_hex: Zeroizing<String>,
    expected_first_address: String,
}

pub struct SwapArgs {
    pub tor: bool,
    pub data_dir: PathBuf,
    pub electrum: Vec<String>,
    pub electrum_socks5: Option<String>,
    /// Some(id) to resume, None to start a new swap.
    pub resume: Option<Uuid>,
}

fn read_stdin_line() -> Result<Zeroizing<String>> {
    let mut input = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut input).context("Failed to read the request on stdin")?;
    Ok(input)
}

fn parse_seed(seed_hex: &str) -> Result<BiscuitSeed> {
    let bytes = Zeroizing::new(hex::decode(seed_hex.trim()).context("Seed is not hex")?);
    if bytes.len() != 64 {
        bail!("Expected a 64-byte BIP39 seed, got {} bytes", bytes.len());
    }
    Ok(BiscuitSeed(bytes))
}

/// The libp2p identity of a swap: random, kept for the swap's lifetime so the
/// maker recognises us when we resume, and never reused by another swap.
fn swap_identity(data_dir: &Path, swap_id: Uuid, create: bool) -> Result<identity::Keypair> {
    let dir = data_dir.join("identities");
    let path = dir.join(swap_id.to_string());
    if path.exists() {
        let bytes = Zeroizing::new(std::fs::read(&path).context("Failed to read swap identity")?);
        return identity::Keypair::from_protobuf_encoding(&bytes).context("Invalid swap identity");
    }
    if !create {
        bail!("No identity saved for swap {swap_id}");
    }
    std::fs::create_dir_all(&dir)?;
    let keypair = identity::Keypair::generate_ed25519();
    let bytes = Zeroizing::new(keypair.to_protobuf_encoding()?);
    write_private(&path, &bytes)?;
    Ok(keypair)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)?;
    Ok(())
}

/// Coarse step of a swap, for Biscuit's progress screen.
fn stage(state: &BobState) -> &'static str {
    match state {
        BobState::Started { .. } | BobState::SwapSetupCompleted { .. } => "setup",
        BobState::BtcLockReadyToPublish { .. } | BobState::BtcLocked { .. } => "btc_locked",
        BobState::XmrLockTransactionCandidate { .. } | BobState::XmrLockTransactionSeen { .. } => "xmr_lock_seen",
        BobState::XmrLocked { .. } | BobState::EncSigReadyToBeSent { .. } | BobState::EncSigSent { .. } => "xmr_locked",
        BobState::BtcRedeemed { .. } | BobState::XmrRedeemConstructed { .. } | BobState::XmrRedeemPublished { .. } => {
            "redeeming"
        }
        BobState::XmrRedeemed { .. } => "done",
        BobState::BtcRefunded { .. } | BobState::BtcEarlyRefunded { .. } | BobState::BtcPartiallyRefunded { .. } => {
            "refunded"
        }
        BobState::BtcPunished { .. } => "punished",
        _ => "refunding",
    }
}

fn emit_state(swap_id: Uuid, state: &BobState) {
    emit(json!({
        "type": "swap_state",
        "swap_id": swap_id.to_string(),
        "stage": stage(state),
        "state": state.to_string(),
    }));
}

pub async fn run(args: SwapArgs) -> Result<()> {
    let input = read_stdin_line()?;
    let (seed, expected_first_address, new_swap) = match args.resume {
        None => {
            let request: BuyRequest = serde_json::from_str(&input).context("Invalid buy request")?;
            (parse_seed(&request.seed_hex)?, request.expected_first_address.clone(), Some(request))
        }
        Some(_) => {
            let request: ResumeRequest = serde_json::from_str(&input).context("Invalid resume request")?;
            (parse_seed(&request.seed_hex)?, request.expected_first_address.clone(), None)
        }
    };
    drop(input);

    // Before anything else: this must be the very wallet Biscuit shows.
    let env_config = Mainnet::get_config();
    let first_address = seed.first_address(env_config.bitcoin_network)?;
    if first_address.to_string() != expected_first_address {
        bail!("The Bitcoin key does not match the Biscuit wallet (first address {first_address}): nothing was done");
    }

    if args.electrum.is_empty() {
        bail!("At least one --electrum server is required");
    }
    // The caller decides: Biscuit passes its own SOCKS proxy (Tor) whenever
    // its Bitcoin wallet uses one, so both reach Electrum the same way.
    if let Some(proxy) = args.electrum_socks5.clone() {
        electrum_pool::set_socks5_proxy(proxy);
    }

    std::fs::create_dir_all(&args.data_dir)?;

    let tor_client = if args.tor {
        emit(json!({ "type": "tor", "status": "bootstrapping" }));
        let client = swap::common::tor::create_tor_client(&args.data_dir)
            .await
            .context("Failed to create Tor client")?;
        swap::common::tor::bootstrap_tor_client(client.clone(), None)
            .await
            .context("Failed to bootstrap Tor")?;
        emit(json!({ "type": "tor", "status": "ready" }));
        Some(client)
    } else {
        None
    };

    // Monero: public nodes through the RPC pool (through Tor in Tor mode).
    let (server_info, _pool_status, _pool_handle) = monero_rpc_pool::start_server_with_random_port(
        monero_rpc_pool::config::Config::new_random_port_with_tor_client(
            args.data_dir.join("monero-rpc-pool"),
            tor_client.clone(),
            monero::Network::Mainnet,
        ),
    )
    .await
    .context("Failed to start the Monero node pool")?;
    let daemon = monero::Daemon::try_from(String::from(server_info))?;
    let monero_wallets = Arc::new(
        monero::Wallets::new(
            args.data_dir.join("monero"),
            "helper".to_string(),
            daemon,
            monero::Network::Mainnet,
            false,
            None,
            None,
            env_config.monero_lock_construction_cooldown,
        )
        .await
        .context("Failed to open the Monero helper wallet")?,
    );

    // Bitcoin: Biscuit's own keys. One wallet cache per seed.
    let fingerprint = seed
        .derive_extended_private_key(env_config.bitcoin_network)?
        .fingerprint(&bitcoin::secp256k1::Secp256k1::new());
    emit(json!({ "type": "bitcoin", "status": "syncing" }));
    let bitcoin_wallet = Arc::new(
        bitcoin_wallet::WalletBuilder::<BiscuitSeed>::default()
            .seed(seed)
            .network(env_config.bitcoin_network)
            .electrum_rpc_urls(args.electrum.clone())
            .persister(bitcoin_wallet::PersisterConfig::SqliteFile {
                data_dir: args.data_dir.join("bitcoin").join(fingerprint.to_string()),
            })
            .finality_confirmations(env_config.bitcoin_finality_confirmations)
            .target_block(1u32)
            .sync_interval(env_config.bitcoin_sync_interval())
            // Fee estimates from the Electrum servers only: no request to
            // mempool.space outside the chosen network path.
            .use_mempool_space_fee_estimation(false)
            .build()
            .await
            .context("Failed to open the Bitcoin wallet")?,
    );
    bitcoin_wallet.sync().await.context("Failed to sync the Bitcoin wallet")?;
    emit(json!({
        "type": "bitcoin",
        "status": "ready",
        "balance_sat": bitcoin_wallet.balance().await?.to_sat(),
    }));

    let db = open_db(args.data_dir.join("sqlite"), AccessMode::ReadWrite, None).await?;

    let swap_id = match (&new_swap, args.resume) {
        (Some(request), _) => request.swap_id,
        (None, Some(id)) => id,
        (None, None) => bail!("Nothing to resume"),
    };
    let identity = swap_identity(&args.data_dir, swap_id, new_swap.is_some())?;

    let (maker_peer_id, maker_addresses) = match &new_swap {
        Some(request) => {
            let peer_id = PeerId::from_str(&request.maker_peer_id).context("Invalid maker peer ID")?;
            let address = Multiaddr::from_str(&request.maker_address).context("Invalid maker address")?;
            (peer_id, vec![address])
        }
        None => {
            let peer_id = db.get_peer_id(swap_id).await?;
            (peer_id, db.get_addresses(peer_id).await?)
        }
    };

    let (mut swarm, tor_priority) = swap::network::swarm::cli(identity.clone(), tor_client, |relay| {
        swap::cli::Behaviour::new(
            env_config,
            bitcoin_wallet.clone(),
            identity.clone(),
            relay,
            XmrBtcNamespace::Mainnet,
            // No rendezvous point: we already know the maker.
            Vec::new(),
            db.clone(),
        )
    })
    .await
    .context("Failed to build the network stack")?;
    if let Some(tor_priority) = &tor_priority {
        tor_priority.mark_high_priority(maker_peer_id);
    }
    for address in &maker_addresses {
        swarm.add_peer_address(maker_peer_id, address.clone());
    }

    let (event_loop, mut event_loop_handle) = swap::cli::EventLoop::new(swarm, db.clone(), None, tor_priority)?;
    let _event_loop = tokio::spawn(event_loop.run());

    let swap = match new_swap {
        Some(request) => {
            let btc_amount = bitcoin::Amount::from_sat(request.btc_amount_sat);
            let xmr_address = monero::Address::from_str(monero::Network::Mainnet, &request.xmr_address)
                .map_err(|e| anyhow::anyhow!("Invalid Monero mainnet address: {e}"))?;
            let change_address = bitcoin::Address::from_str(&request.change_address)
                .context("Invalid change address")?
                .require_network(env_config.bitcoin_network)
                .context("Change address is not on the right network")?;

            let tx_lock_fee = lock_fee(&bitcoin_wallet, btc_amount, env_config.bitcoin_network).await?;
            let balance = bitcoin_wallet.balance().await?;
            if btc_amount + tx_lock_fee > balance {
                bail!(
                    "Not enough BTC: {} + {} network fee needed, {} available",
                    btc_amount,
                    tx_lock_fee,
                    balance
                );
            }

            let pool = MoneroAddressPool::new(vec![LabeledMoneroAddress::with_address(
                xmr_address,
                rust_decimal::Decimal::ONE,
                "Biscuit".to_string(),
            )?]);

            db.insert_peer_id(swap_id, maker_peer_id).await?;
            for address in &maker_addresses {
                db.insert_address(maker_peer_id, address.clone()).await?;
            }
            db.insert_monero_address_pool(swap_id, pool.clone()).await?;

            emit(json!({
                "type": "swap_started",
                "swap_id": swap_id.to_string(),
                "btc_amount_sat": btc_amount.to_sat(),
                "lock_fee_sat": tx_lock_fee.to_sat(),
            }));

            let handle = event_loop_handle.swap_handle(maker_peer_id, swap_id).await?;
            bob::Swap::new(
                db.clone(),
                swap_id,
                bitcoin_wallet.clone(),
                monero_wallets,
                env_config,
                handle,
                pool,
                change_address,
                btc_amount,
                tx_lock_fee,
            )
        }
        None => {
            for address in &maker_addresses {
                event_loop_handle.queue_peer_address(maker_peer_id, address.clone()).await?;
            }
            let pool = db.get_monero_address_pool(swap_id).await?;
            let handle = event_loop_handle.swap_handle(maker_peer_id, swap_id).await?;
            emit(json!({ "type": "swap_resumed", "swap_id": swap_id.to_string() }));
            bob::Swap::from_db(
                db.clone(),
                swap_id,
                bitcoin_wallet.clone(),
                monero_wallets,
                env_config,
                handle,
                pool,
            )
            .await?
        }
    };

    emit_state(swap_id, &swap.state);

    // The state machine saves every step in the database: report each change.
    let watcher_db = db.clone();
    let _watcher = tokio::spawn(async move {
        let mut last = String::new();
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let Ok(state) = watcher_db.get_state(swap_id).await else { continue };
            let swap::protocol::State::Bob(state) = state else { continue };
            let name = state.to_string();
            if name != last {
                emit_state(swap_id, &state);
                last = name;
            }
        }
    });

    let final_state = bob::run(swap).await.context("Swap failed")?;
    emit_state(swap_id, &final_state);
    emit(json!({
        "type": "swap_finished",
        "swap_id": swap_id.to_string(),
        "stage": stage(&final_state),
    }));
    Ok(())
}

/// Network fee of a lock transaction of `amount` from this wallet, at the
/// current fee rate: the same shape as the real one (a P2WSH output plus
/// change). Nothing is signed or broadcast.
async fn lock_fee(
    wallet: &bitcoin_wallet::Wallet,
    amount: bitcoin::Amount,
    network: bitcoin::Network,
) -> Result<bitcoin::Amount> {
    let placeholder = bitcoin::Address::p2wsh(&bitcoin::ScriptBuf::from(vec![0u8; 71]), network);
    let psbt = wallet
        .send_to_address_dynamic_fee(placeholder, amount, None)
        .await
        .context("Not enough BTC for this amount and its network fee")?;
    psbt.fee().context("Failed to compute the lock transaction fee")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP84 test vector: "abandon abandon ... about", no passphrase.
    const SEED_HEX: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    #[test]
    fn first_address_matches_bip84_vector() {
        let seed = parse_seed(SEED_HEX).unwrap();
        let address = seed.first_address(bitcoin::Network::Bitcoin).unwrap();
        assert_eq!(address.to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }

    #[test]
    fn rejects_wrong_seed_length() {
        assert!(parse_seed("abcd").is_err());
    }
}
