//! biscuit-swapd: helper process that Biscuit launches for XMR/BTC atomic swaps.
//!
//! Prototype: only discovers makers through the public rendezvous points and
//! fetches their quotes. No wallet, no funds involved. Every event is written
//! to stdout as one JSON object per line, for Biscuit to read.
use anyhow::{Context, Result, bail};
use futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, PeerId, identify, identity, multiaddr::Protocol, ping, relay};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use swap_p2p::observe;
use swap_p2p::protocols::quotes_cached::{self, QuoteStatus};
use swap_p2p::protocols::rendezvous::{XmrBtcNamespace, discovery};

/// Same protocol and agent strings as the eigenwallet CLI, so that makers and
/// rendezvous points cannot tell Biscuit users apart from eigenwallet users.
const PROTOCOL_VERSION: &str = "/comit/xmr/btc/1.0.0";
const AGENT_VERSION: &str = "cli/4.15.0 (xmr-btc-swap-mainnet)";

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "OutEvent")]
struct Behaviour {
    relay: relay::client::Behaviour,
    quotes: quotes_cached::Behaviour,
    discovery: discovery::Behaviour,
    observe: observe::Behaviour,
    ping: ping::Behaviour,
}

#[derive(Debug)]
enum OutEvent {
    Quotes(quotes_cached::Event),
    Discovery(discovery::Event),
    Observe(observe::Event),
    Other,
}

impl From<quotes_cached::Event> for OutEvent {
    fn from(event: quotes_cached::Event) -> Self {
        OutEvent::Quotes(event)
    }
}

impl From<discovery::Event> for OutEvent {
    fn from(event: discovery::Event) -> Self {
        OutEvent::Discovery(event)
    }
}

impl From<observe::Event> for OutEvent {
    fn from(event: observe::Event) -> Self {
        OutEvent::Observe(event)
    }
}

impl From<relay::client::Event> for OutEvent {
    fn from(_: relay::client::Event) -> Self {
        OutEvent::Other
    }
}

impl From<ping::Event> for OutEvent {
    fn from(_: ping::Event) -> Self {
        OutEvent::Other
    }
}

struct Args {
    tor: bool,
    data_dir: PathBuf,
}

fn parse_args() -> Result<Args> {
    let mut tor = None;
    let mut data_dir = None;
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--tor" => tor = Some(true),
            "--clearnet" => tor = Some(false),
            "--data-dir" => data_dir = Some(PathBuf::from(args.next().context("--data-dir needs a path")?)),
            other => bail!("Unknown argument: {other}"),
        }
    }

    // No default on purpose: connecting without Tor reveals the IP address to
    // rendezvous points and makers, so the caller must choose explicitly.
    let Some(tor) = tor else {
        bail!("Choose --tor or --clearnet (--clearnet reveals your IP to rendezvous points and makers)");
    };
    let data_dir = data_dir.context("--data-dir is required")?;

    Ok(Args { tor, data_dir })
}

fn emit(value: serde_json::Value) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{value}");
    let _ = stdout.flush();
}

fn quote_status_name(status: QuoteStatus) -> &'static str {
    match status {
        QuoteStatus::Received => "received",
        QuoteStatus::NotSupported => "not_supported",
        QuoteStatus::Inflight => "inflight",
        QuoteStatus::Failed => "failed",
        QuoteStatus::Nothing => "nothing",
    }
}

fn connection_status_name(status: observe::ConnectionStatus) -> &'static str {
    match status {
        observe::ConnectionStatus::Connected => "connected",
        observe::ConnectionStatus::Disconnected => "disconnected",
        observe::ConnectionStatus::Dialing => "dialing",
    }
}

fn is_onion(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::Onion3(_)))
}

/// Compact counters for the "Dialing peers / Connected to N peers" bar.
/// Only makers are counted, not rendezvous points.
#[derive(Default)]
struct Summary {
    connections: HashMap<PeerId, observe::ConnectionStatus>,
    quote_statuses: HashMap<PeerId, QuoteStatus>,
    offers: usize,
    last: Option<serde_json::Value>,
}

impl Summary {
    fn emit_if_changed(&mut self) {
        let count = |status| self.connections.values().filter(|s| **s == status).count();
        let value = json!({
            "type": "summary",
            "makers_known": self.quote_statuses.len().max(self.connections.len()),
            "dialing": count(observe::ConnectionStatus::Dialing),
            "connected": count(observe::ConnectionStatus::Connected),
            "quotes_inflight": self.quote_statuses.values().filter(|s| **s == QuoteStatus::Inflight).count(),
            "offers": self.offers,
        });

        if self.last.as_ref() != Some(&value) {
            emit(value.clone());
            self.last = Some(value);
        }
    }
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("no other rustls provider to be installed yet");

    // Logs go to stderr so that stdout only carries JSON events.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_string()))
        .init();

    if let Err(error) = run().await {
        emit(json!({ "type": "error", "message": format!("{error:#}") }));
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args = parse_args()?;

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

    // A fresh identity per run: makers cannot link two sessions together.
    let identity = identity::Keypair::generate_ed25519();

    let rendezvous_points: Vec<(PeerId, Multiaddr)> = swap_env::defaults::default_rendezvous_points()
        .into_iter()
        .filter(|addr| args.tor || !is_onion(addr))
        .map(|addr| {
            let peer_id = addr
                .iter()
                .find_map(|p| match p {
                    Protocol::P2p(peer_id) => Some(peer_id),
                    _ => None,
                })
                .context("Rendezvous point address must contain a peer ID")?;
            Ok((peer_id, addr))
        })
        .collect::<Result<_>>()?;
    let rendezvous_ids: HashSet<PeerId> = rendezvous_points.iter().map(|(id, _)| *id).collect();

    let (mut swarm, tor_priority) = swap::network::swarm::cli(identity.clone(), tor_client, |relay| {
        let identify_config = identify::Config::new(PROTOCOL_VERSION.to_string(), identity.public())
            .with_agent_version(AGENT_VERSION.to_string());

        Behaviour {
            relay,
            quotes: quotes_cached::Behaviour::new(identify_config),
            discovery: discovery::Behaviour::new(
                identity.clone(),
                rendezvous_ids.iter().copied().collect(),
                XmrBtcNamespace::Mainnet.into(),
            ),
            observe: observe::Behaviour::new(),
            ping: ping::Behaviour::new(ping::Config::new().with_timeout(Duration::from_secs(60))),
        }
    })
    .await
    .context("Failed to build the network stack")?;

    for (peer_id, addr) in rendezvous_points {
        // Same as eigenwallet: rendezvous points get the largest Tor dial budget.
        if let Some(tor_priority) = &tor_priority {
            tor_priority.mark_high_priority(peer_id);
        }
        swarm.add_peer_address(peer_id, addr);
    }

    let mut summary = Summary::default();

    emit(json!({
        "type": "started",
        "tor": args.tor,
        "rendezvous_points": rendezvous_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
    }));

    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                let SwarmEvent::Behaviour(event) = event else { continue };

                match event {
                    OutEvent::Observe(observe::Event { peer_id, update }) => match update {
                        observe::ConnectionChange::Connection(status) => {
                            emit(json!({
                                "type": "peer",
                                "peer_id": peer_id.to_string(),
                                "rendezvous": rendezvous_ids.contains(&peer_id),
                                "status": connection_status_name(status),
                            }));
                            if !rendezvous_ids.contains(&peer_id) {
                                summary.connections.insert(peer_id, status);
                            }
                        }
                        observe::ConnectionChange::LastAddress(address) => emit(json!({
                            "type": "peer_address",
                            "peer_id": peer_id.to_string(),
                            "address": address.to_string(),
                        })),
                    },
                    OutEvent::Discovery(discovery::Event::DiscoveredPeer { peer_id }) => emit(json!({
                        "type": "discovered",
                        "peer_id": peer_id.to_string(),
                    })),
                    OutEvent::Quotes(quotes_cached::Event::Progress { peers }) => {
                        summary.quote_statuses = peers
                            .iter()
                            .filter(|(peer_id, _)| !rendezvous_ids.contains(peer_id))
                            .map(|(peer_id, status)| (*peer_id, *status))
                            .collect();
                        emit(json!({
                        "type": "quotes_progress",
                        "peers": peers.iter().map(|(peer_id, status)| json!({
                            "peer_id": peer_id.to_string(),
                            "status": quote_status_name(*status),
                        })).collect::<Vec<_>>(),
                    }));
                    }
                    OutEvent::Quotes(quotes_cached::Event::CachedQuotes { quotes }) => {
                        summary.offers = quotes.len();
                        emit(json!({
                        "type": "quotes",
                        "quotes": quotes.iter().map(|(peer_id, address, quote, version)| json!({
                            "peer_id": peer_id.to_string(),
                            "address": address.to_string(),
                            "version": version.as_ref().map(|v| v.to_string()),
                            "price_sat_per_xmr": quote.price.to_sat(),
                            "min_sat": quote.min_quantity.to_sat(),
                            "max_sat": quote.max_quantity.to_sat(),
                            "refund_policy": quote.refund_policy,
                        })).collect::<Vec<_>>(),
                    }));
                    }
                    OutEvent::Other => {}
                }

                summary.emit_if_changed();
            }
            _ = tokio::signal::ctrl_c() => {
                emit(json!({ "type": "stopped" }));
                return Ok(());
            }
        }
    }
}
