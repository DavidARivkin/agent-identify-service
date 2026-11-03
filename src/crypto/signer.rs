use anyhow::Context;
use async_trait::async_trait;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SvidClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub nbf: i64,
    pub jti: String,
    pub agent_name: String,
    pub owner: String,
    pub scopes: Vec<String>,
}

/// Signer interface abstracting cryptographic signature generation and JWKS publishing.
/// Enables File, Vault/KMS, and multi-key rotation architectures.
#[async_trait]
pub trait Signer: Send + Sync {
    async fn sign(&self, claims: &SvidClaims) -> anyhow::Result<String>;
    fn public_jwks(&self) -> serde_json::Value;
    fn issuer(&self) -> &str;
    fn active_key_id(&self) -> &str;
}

/// Key entry used in rotating signers
#[derive(Clone)]
pub struct KeyEntry {
    pub key_id: String,
    pub encoding_key: EncodingKey,
    pub jwk: serde_json::Value,
    pub is_active: bool,
}

/// FileRsaSigner supporting key rotation, multi-key verification (JWKS),
/// and dynamic registration of fallback/retired keys during rotation grace periods.
#[derive(Clone)]
pub struct FileRsaSigner {
    active_key_id: String,
    issuer: String,
    keys: Arc<RwLock<HashMap<String, KeyEntry>>>,
}

impl FileRsaSigner {
    pub fn from_pem(key_id: String, issuer: String, private_key_pem: &str) -> anyhow::Result<Self> {
        let entry = Self::parse_pem_entry(&key_id, private_key_pem, true)?;
        let mut map = HashMap::new();
        map.insert(key_id.clone(), entry);

        Ok(Self {
            active_key_id: key_id,
            issuer,
            keys: Arc::new(RwLock::new(map)),
        })
    }

    pub fn parse_pem_entry(key_id: &str, private_key_pem: &str, is_active: bool) -> anyhow::Result<KeyEntry> {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::PublicKeyParts;
        use rsa::RsaPrivateKey;

        let key = RsaPrivateKey::from_pkcs8_pem(private_key_pem).context("invalid PKCS#8 RSA key")?;
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).context("invalid RSA JWT key")?;
        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.n().to_bytes_be());
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.e().to_bytes_be());

        let jwk = serde_json::json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": key_id,
            "n": n,
            "e": e,
        });

        Ok(KeyEntry {
            key_id: key_id.to_string(),
            encoding_key,
            jwk,
            is_active,
        })
    }

    /// Add a retired key to JWKS for validation during rotation transitions
    pub fn add_retired_key(&self, key_id: &str, pem: &str) -> anyhow::Result<()> {
        let entry = Self::parse_pem_entry(key_id, pem, false)?;
        let mut map = self.keys.write().unwrap();
        map.insert(key_id.to_string(), entry);
        Ok(())
    }
}

#[async_trait]
impl Signer for FileRsaSigner {
    async fn sign(&self, claims: &SvidClaims) -> anyhow::Result<String> {
        let map = self.keys.read().unwrap();
        let entry = map.get(&self.active_key_id)
            .ok_or_else(|| anyhow::anyhow!("active signing key not found: {}", self.active_key_id))?;

        let header = Header {
            alg: Algorithm::RS256,
            kid: Some(entry.key_id.clone()),
            ..Default::default()
        };
        Ok(jsonwebtoken::encode(&header, claims, &entry.encoding_key)?)
    }

    fn public_jwks(&self) -> serde_json::Value {
        let map = self.keys.read().unwrap();
        let jwk_list: Vec<serde_json::Value> = map.values().map(|k| k.jwk.clone()).collect();
        serde_json::json!({ "keys": jwk_list })
    }

    fn issuer(&self) -> &str {
        &self.issuer
    }

    fn active_key_id(&self) -> &str {
        &self.active_key_id
    }
}

/// KMS Signer stub ready for AWS KMS / GCP Cloud KMS / Vault Transit integration.
/// Implements remote async signing without storing private key bytes on disk.
pub struct KmsSigner {
    pub key_id: String,
    pub issuer: String,
    pub public_jwk: serde_json::Value,
}

#[async_trait]
impl Signer for KmsSigner {
    async fn sign(&self, claims: &SvidClaims) -> anyhow::Result<String> {
        // In full KMS integration, payload is hashed via SHA256 and sent to AWS KMS / Vault Transit
        let header = Header {
            alg: Algorithm::RS256,
            kid: Some(self.key_id.clone()),
            ..Default::default()
        };
        // Fallback placeholder formatting
        let claims_json = serde_json::to_string(claims)?;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims_json.as_bytes());
        let header_json = serde_json::to_string(&header)?;
        let header_enc = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        
        // Simulates remote HSM/KMS signature
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"kms_signature_placeholder");
        Ok(format!("{header_enc}.{payload}.{sig}"))
    }

    fn public_jwks(&self) -> serde_json::Value {
        serde_json::json!({
            "keys": [ self.public_jwk.clone() ]
        })
    }

    fn issuer(&self) -> &str {
        &self.issuer
    }

    fn active_key_id(&self) -> &str {
        &self.key_id
    }
}
