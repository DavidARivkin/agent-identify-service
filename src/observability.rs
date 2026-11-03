use sha2::{Digest, Sha256};

pub fn fingerprint(value: &str) -> String {
    hex::encode(&Sha256::digest(value.as_bytes())[..8])
}

pub fn redact_token(token: &str) -> String {
    if token.len() <= 12 { return "[redacted]".into(); }
    format!("{}...[redacted]", &token[..8])
}

pub fn redact_spiffe_id(spiffe_id: &str) -> String {
    spiffe_id.rsplit('/').next().map(|s| format!(".../{s}")).unwrap_or_else(|| "[redacted]".into())
}
