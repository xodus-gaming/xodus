//! Xbox Live HTTP request signatures (the `Signature` header).
//!
//! The signature covers the signing policy version, a FILETIME timestamp, the HTTP method,
//! path + query, the `Authorization` header and the first `max_body_bytes` of the body, hashed
//! with SHA-256 and signed with ES256 using the proof key that was registered with the device
//! token. The header value is `base64(version_be32 || filetime_be64 || r || s)`.
//!
//! The hashing layout is shared with xal's [`RequestSigner`]; this module only exists so a
//! signature can be produced for a request the service never sends itself (the game does).

use base64::Engine;
use chrono::{DateTime, Utc};
use p256::SecretKey;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use xal::RequestSigner;

/// Seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01.
const FILETIME_UNIX_EPOCH_DIFF: i64 = 11_644_473_600;

/// Windows FILETIME (100 ns ticks since 1601) of `timestamp`, big-endian as used in the signature.
fn filetime_be(timestamp: DateTime<Utc>) -> [u8; 8] {
    let ticks = (timestamp.timestamp() + FILETIME_UNIX_EPOCH_DIFF) as u64 * 10_000_000
        + u64::from(timestamp.timestamp_subsec_nanos() / 100);
    ticks.to_be_bytes()
}

/// `path?query` of a URL, the form the signature expects.
pub fn path_and_query(url: &reqwest::Url) -> String {
    match url.query() {
        Some(q) => format!("{}?{}", url.path(), q),
        None => url.path().to_string(),
    }
}

/// Compute the `Signature` header value for a request.
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    keypair: &SecretKey,
    policy_version: i32,
    max_body_bytes: usize,
    timestamp: DateTime<Utc>,
    method: &str,
    path_and_query: &str,
    authorization: &str,
    body: &[u8],
) -> Result<String, p256::ecdsa::Error> {
    let version = policy_version.to_be_bytes();
    let filetime = filetime_be(timestamp);
    let prehash = RequestSigner::prehash_message_data(
        &version,
        &filetime,
        method,
        path_and_query,
        authorization,
        body,
        max_body_bytes,
    );
    let signing_key: SigningKey = keypair.clone().into();
    let signature: Signature = signing_key.sign_prehash(&prehash)?;

    let mut bytes = Vec::with_capacity(4 + 8 + 64);
    bytes.extend_from_slice(&version);
    bytes.extend_from_slice(&filetime);
    bytes.extend_from_slice(&signature.to_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::TimeZone;
    use xal::response::TitleEndpointsResponse;
    use xal::{RequestSigning, SignaturePolicyCache};

    #[test]
    fn filetime_matches_known_value() {
        // 2020-01-01T00:00:00Z == 132223104000000000 (verified against .NET DateTime.ToFileTimeUtc)
        let ts = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        assert_eq!(u64::from_be_bytes(filetime_be(ts)), 132_223_104_000_000_000);
    }

    #[test]
    fn path_and_query_formatting() {
        let u = reqwest::Url::parse("https://host.xboxlive.com/a/b?x=1&y=2").unwrap();
        assert_eq!(path_and_query(&u), "/a/b?x=1&y=2");
        let u = reqwest::Url::parse("https://host.xboxlive.com/a").unwrap();
        assert_eq!(path_and_query(&u), "/a");
    }

    /// Same key, policy, timestamp and request must give the same header as xal's signer.
    #[tokio::test]
    async fn signature_matches_xal() {
        let endpoints: TitleEndpointsResponse =
            serde_json::from_str(include_str!("../../../testdata/title_endpoints.json")).unwrap();
        let mut signer = RequestSigner {
            keypair: SecretKey::random(&mut rand_core_compat::Rng),
            signature_policy_cache: SignaturePolicyCache::new(endpoints),
        };
        let ts = Utc.with_ymd_and_hms(2026, 10, 9, 12, 0, 0).unwrap();
        let url = "https://achievements.xboxlive.com/users/xuid(1)/achievements?titleId=5";
        let authorization = "XBL3.0 x=123;token";
        let body = b"{\"hello\":\"world\"}".to_vec();

        // xal's http::Request path drops every header (it `replace`s an Option<&mut HeaderMap>),
        // so compare through its reqwest path instead.
        let request = reqwest011::Client::new()
            .post(url)
            .header("Authorization", authorization)
            .body(body.clone())
            .build()
            .unwrap();
        let signed = signer.sign_request(request, Some(ts)).await.unwrap();
        let expected = signed
            .headers()
            .get("Signature")
            .expect("xal added a Signature header")
            .to_str()
            .unwrap()
            .to_owned();

        let got = sign_request(
            &signer.keypair,
            1,
            8192,
            ts,
            "POST",
            &path_and_query(&reqwest::Url::parse(url).unwrap()),
            authorization,
            &body,
        )
        .unwrap();
        assert_eq!(got, expected);
    }

    /// p256 0.13 wants a rand_core 0.6 RNG; adapt the workspace's rand without adding a dep.
    mod rand_core_compat {
        pub struct Rng;
        impl p256::elliptic_curve::rand_core::CryptoRng for Rng {}
        impl p256::elliptic_curve::rand_core::RngCore for Rng {
            fn next_u32(&mut self) -> u32 {
                let mut b = [0u8; 4];
                self.fill_bytes(&mut b);
                u32::from_le_bytes(b)
            }
            fn next_u64(&mut self) -> u64 {
                let mut b = [0u8; 8];
                self.fill_bytes(&mut b);
                u64::from_le_bytes(b)
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                getrandom_fill(dest);
            }
            fn try_fill_bytes(
                &mut self,
                dest: &mut [u8],
            ) -> Result<(), p256::elliptic_curve::rand_core::Error> {
                getrandom_fill(dest);
                Ok(())
            }
        }
        fn getrandom_fill(dest: &mut [u8]) {
            use std::io::Read;
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(dest))
                .expect("urandom");
        }
    }
}
