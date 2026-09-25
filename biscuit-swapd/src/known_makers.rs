//! Makers that answered with an offer in earlier runs, so the next run can dial
//! them right away instead of waiting for rendezvous discovery.
//!
//! Stored as JSON in the data directory. It is a cache: a missing or corrupt
//! file only means starting from rendezvous discovery again.
use anyhow::{Context, Result};
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const FILE_NAME: &str = "known-makers.json";
/// Makers not seen for this long are forgotten.
const MAX_AGE_SECS: u64 = 30 * 24 * 3600;
const MAX_ENTRIES: usize = 100;

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    address: String,
    last_seen: u64,
}

pub struct KnownMakers {
    path: PathBuf,
    entries: HashMap<String, Entry>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl KnownMakers {
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join(FILE_NAME);
        let entries = std::fs::read(&path)
            .ok()
            .and_then(|bytes| match serde_json::from_slice::<HashMap<String, Entry>>(&bytes) {
                Ok(entries) => Some(entries),
                Err(error) => {
                    tracing::warn!(%error, "Ignoring unreadable known makers file");
                    None
                }
            })
            .unwrap_or_default();

        let mut known = Self { path, entries };
        known.prune();
        known
    }

    /// Makers to dial at startup.
    pub fn addresses(&self) -> Vec<(PeerId, Multiaddr)> {
        self.entries
            .iter()
            .filter_map(|(peer_id, entry)| Some((peer_id.parse().ok()?, entry.address.parse().ok()?)))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Records the makers that just answered with an offer.
    pub fn record(&mut self, answered: impl IntoIterator<Item = (PeerId, Multiaddr)>) -> Result<()> {
        let now = now();
        for (peer_id, address) in answered {
            self.entries.insert(
                peer_id.to_string(),
                Entry { address: address.to_string(), last_seen: now },
            );
        }
        self.prune();
        self.save()
    }

    fn prune(&mut self) {
        let cutoff = now().saturating_sub(MAX_AGE_SECS);
        self.entries.retain(|_, entry| entry.last_seen >= cutoff);

        if self.entries.len() > MAX_ENTRIES {
            let mut by_age: Vec<_> = self.entries.iter().map(|(id, e)| (e.last_seen, id.clone())).collect();
            by_age.sort();
            for (_, id) in by_age.into_iter().take(self.entries.len() - MAX_ENTRIES) {
                self.entries.remove(&id);
            }
        }
    }

    fn save(&self) -> Result<()> {
        // Write then rename, so a crash never leaves a half-written file.
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.entries)?)
            .with_context(|| format!("Failed to write {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("Failed to replace {}", self.path.display()))?;
        Ok(())
    }
}
