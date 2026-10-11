use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    pub manifest: String,
    pub device: String,
    pub nonce: String,
    pub time: String,
    pub client: String,
    pub results: BTreeMap<String, String>,
}
