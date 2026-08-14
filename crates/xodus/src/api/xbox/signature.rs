//! Xbox Live request signing.
//!
//! `device.auth`, `title.auth` and `sisu` will not talk to a caller that cannot
//! prove it holds a private key: each request carries a `Signature` header, and
//! the matching public key is handed over in the body as a JWK ("ProofKey").
//! The signature covers the request itself, so it cannot be replayed against a
//! different method, path or body.
//!
//! The layout below is the version-1 signature policy, which is what
//! `title.mgt.xboxlive.com/titles/default/endpoints` advertises for these hosts
//! (`SupportedAlgorithms: ["ES256"]`).

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde::{Deserialize, Serialize};

/// Seconds between the Windows FILETIME epoch (1601-01-01) and the Unix epoch.
const FILETIME_EPOCH_DELTA: i64 = 11_644_473_600;

const SIGNATURE_VERSION: u32 = 1;

/// The public half, as Xbox Live wants to see it in a request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofKeyJwk {
    pub crv: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub kty: String,
    pub x: String,
    pub y: String,
}

/// A device's ECDSA P-256 key pair.
///
/// This is the device identity: once a device token has been issued against it,
/// the same key has to sign every later request, so it is persisted in the
/// keyring rather than regenerated per run.
#[derive(Clone)]
pub struct ProofKey {
    signing_key: SigningKey,
}

impl ProofKey {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::random(&mut rand::rng()),
        }
    }

    /// The private scalar, 32 bytes big-endian.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        SigningKey::from_slice(bytes)
            .ok()
            .map(|signing_key| Self { signing_key })
    }

    pub fn jwk(&self) -> ProofKeyJwk {
        let point = self.signing_key.verifying_key().to_sec1_point(false);

        ProofKeyJwk {
            crv: "P-256".to_string(),
            alg: "ES256".to_string(),
            key_use: "sig".to_string(),
            kty: "EC".to_string(),
            // Uncompressed SEC1 is 0x04 || X || Y; the JWK wants the halves
            // separately, base64url with no padding.
            x: URL_SAFE_NO_PAD.encode(point.x().expect("P-256 point has an x")),
            y: URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point has a y")),
        }
    }

    /// Build the `Signature` header for one request.
    ///
    /// `path_and_query` is the URL from the path onwards ("/device/authenticate"),
    /// `authorization` is the Authorization header being sent or "" if none, and
    /// `body` is the exact bytes that will go on the wire.
    pub fn sign_request(
        &self,
        method: &str,
        path_and_query: &str,
        authorization: &str,
        body: &[u8],
    ) -> String {
        let filetime =
            ((chrono::Utc::now().timestamp() + FILETIME_EPOCH_DELTA) as u64) * 10_000_000;
        let version = SIGNATURE_VERSION.to_be_bytes();
        let timestamp = filetime.to_be_bytes();

        // Every field is NUL-terminated, including the last one.
        let mut payload = Vec::with_capacity(body.len() + 128);
        payload.extend_from_slice(&version);
        payload.push(0);
        payload.extend_from_slice(&timestamp);
        payload.push(0);
        payload.extend_from_slice(method.as_bytes());
        payload.push(0);
        payload.extend_from_slice(path_and_query.as_bytes());
        payload.push(0);
        payload.extend_from_slice(authorization.as_bytes());
        payload.push(0);
        payload.extend_from_slice(body);
        payload.push(0);

        let signature: Signature = self.signing_key.sign(&payload);

        // The header repeats the version and timestamp in the clear so the
        // server can rebuild the same payload before verifying.
        let mut header = Vec::with_capacity(4 + 8 + 64);
        header.extend_from_slice(&version);
        header.extend_from_slice(&timestamp);
        header.extend_from_slice(&signature.to_bytes());

        STANDARD.encode(header)
    }
}


/// Xbox Live reports auth failures in headers, not the body: a bare 401 with an
/// empty body still carries `WWW-Authenticate` and an `X-Err` code.
pub(crate) fn describe_failure(what: &str, status: reqwest::StatusCode, headers: &reqwest::header::HeaderMap, body: &str) -> String {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };

    format!(
        "{what} failed ({status}); x-err {:?}, www-authenticate {:?}, body {:?}",
        header("x-err"),
        header("www-authenticate"),
        body
    )
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn proof_key_round_trips_through_bytes() {
        let key = ProofKey::generate();
        let restored = ProofKey::from_bytes(&key.to_bytes()).expect("valid scalar");

        assert_eq!(key.jwk().x, restored.jwk().x);
        assert_eq!(key.jwk().y, restored.jwk().y);
    }

    #[test]
    fn jwk_halves_are_32_bytes_each() {
        let jwk = ProofKey::generate().jwk();

        assert_eq!(URL_SAFE_NO_PAD.decode(&jwk.x).unwrap().len(), 32);
        assert_eq!(URL_SAFE_NO_PAD.decode(&jwk.y).unwrap().len(), 32);
        assert_eq!(jwk.crv, "P-256");
    }

    #[test]
    fn signature_header_is_version_timestamp_and_raw_signature() {
        let key = ProofKey::generate();
        let header = key.sign_request("POST", "/device/authenticate", "", b"{}");
        let raw = STANDARD.decode(header).expect("base64");

        assert_eq!(raw.len(), 4 + 8 + 64);
        assert_eq!(u32::from_be_bytes(raw[0..4].try_into().unwrap()), 1);
    }
}
