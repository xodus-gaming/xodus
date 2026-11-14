use std::collections::HashMap;

use base64::prelude::*;

use crate::api::live::utils;
use crate::models::soap;

pub struct RSTRequest<'a> {
    pub signed_xml: String,
    pub signature: Option<super::RSTSignature<'a>>,
}

impl<'a> RSTRequest<'a> {
    /// Makes a POST request with `reqwest::Client` and decrypts the envelope if applicable
    pub async fn request(
        self,
        client: &reqwest::Client,
        timeout: Option<std::time::Duration>,
    ) -> Result<soap::Envelope, super::RSTError> {
        tracing::trace!("Making RST2.srf request");
        let response_text = post_rst(client, RST_URL, self.signed_xml, timeout).await?;
        let envelope = parse_rst_response(&response_text)?;

        verify_and_decrypt_envelope(self.signature, response_text, envelope)
    }

    /// Like `request`, but a SOAP Fault is returned together with its verified and decrypted
    /// envelope, so the caller can read the fault's encrypted `psf:pp` (e.g. `inlineauthurl`).
    /// If the Fault envelope cannot be parsed or decrypted, the typed `RSTError::Fault` is returned.
    pub async fn request_allow_fault(
        self,
        client: &reqwest::Client,
        timeout: Option<std::time::Duration>,
    ) -> Result<(soap::Envelope, Option<super::fault::SoapFault>), super::RSTError> {
        let response_text = post_rst(client, RST_URL, self.signed_xml, timeout).await?;
        let fault = match parse_rst_response(&response_text) {
            Ok(envelope) => {
                let envelope = verify_and_decrypt_envelope(self.signature, response_text, envelope)?;
                return Ok((envelope, None));
            }
            Err(super::RSTError::Fault(fault)) => fault,
            Err(e) => return Err(e),
        };
        let decrypted = quick_xml::de::from_str::<soap::Envelope>(&response_text)
            .map_err(super::RSTError::from)
            .and_then(|envelope| verify_and_decrypt_envelope(self.signature, response_text, envelope));
        match decrypted {
            Ok(envelope) => Ok((envelope, Some(fault))),
            Err(e) => {
                tracing::warn!("Unable to decrypt RST2 Fault envelope: {e}");
                Err(super::RSTError::Fault(fault))
            }
        }
    }
}

const RST_URL: &str = "https://login.live.com/RST2.srf";

async fn post_rst(
    client: &reqwest::Client,
    url: &str,
    body: String,
    timeout: Option<std::time::Duration>,
) -> Result<String, super::RSTError> {
    let mut builder = client
        .post(url)
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(body);
    if let Some(d) = timeout {
        builder = builder.timeout(d);
    }
    Ok(builder.send().await?.text().await?)
}

/// Detects a SOAP Fault before envelope deserialization and returns it as a typed error.
fn parse_rst_response(text: &str) -> Result<soap::Envelope, super::RSTError> {
    if text.contains("<S:Fault") || text.contains(":Fault>") {
        tracing::warn!("RST2 returned a Fault: {text}");
        return match super::fault::SoapFault::parse(text) {
            Ok(fault) => Err(super::RSTError::Fault(fault)),
            Err(e) => Err(super::RSTError::Deserialization(
                <quick_xml::DeError as serde::de::Error>::custom(format!(
                    "unparseable RST2 Fault: {e}"
                )),
            )),
        };
    }
    Ok(quick_xml::de::from_str(text)?)
}

fn verify_and_decrypt_envelope<'a>(
    signature: Option<super::RSTSignature<'a>>,
    xml_text: String,
    mut envelope: soap::Envelope,
) -> Result<soap::Envelope, super::RSTError> {
    let Some(signature) = signature else {
        tracing::debug!("No signature, returning raw envelope");
        return Ok(envelope);
    };
    tracing::trace!("Decrypting soap::Envelope");
    let nonces: HashMap<String, String> = envelope
        .header
        .security
        .derived_key_tokens
        .iter()
        .map(|token| (token.id.clone(), token.nonce.clone()))
        .collect();

    if let Some(security_signature) = &envelope.header.security.signature
        && let Some(key_info) = &security_signature.key_info
    {
        let id = &key_info.security_token_reference.reference.uri;
        let nonce = id.get(1..).and_then(|k| nonces.get(k)).ok_or(super::RSTError::MissingNonce)?;
        let nonce = BASE64_STANDARD.decode(nonce)?;
        let key = signature.signing_key(&nonce)?;
        let mut kmgr = bergshamra::KeysManager::new();
        kmgr.add_key(bergshamra::Key::new(key, bergshamra::KeyUsage::Verify));
        let ctx = bergshamra::DsigContext::new(kmgr).with_strict_verification(false);
        let result = bergshamra::verify(&ctx, &xml_text)?;
        match result {
            bergshamra::VerifyResult::Invalid { reason } => {
                return Err(super::RSTError::InvalidResponseSignature(reason));
            }
            bergshamra::VerifyResult::Valid { .. } => tracing::debug!("Verification successful"),
        }
    }

    if envelope.header.pp.is_none()
        && let Some(enc_pp) = envelope.header.encrypted_pp.take()
    {
        tracing::trace!("Decrypting soap::PP");
        let pp = utils::decrypt_soap_encrypted_data(
            Box::new(enc_pp.encrypted_data),
            &signature,
            &nonces,
        )?;
        envelope.header.pp = pp;
    }

    if let soap::BodyContent::EncryptedData(enc_data) = envelope.body.body {
        tracing::trace!("Decrypting soap::Body");
        envelope.body.body = utils::decrypt_soap_encrypted_data(enc_data, &signature, &nonces)?;
    }

    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("testdata/rst-fault.xml");

    #[test]
    fn rst_response_fault_fixture() {
        match parse_rst_response(FIXTURE) {
            Err(crate::api::live::rst::RSTError::Fault(f)) => assert!(f.is_sign_in_required()),
            other => panic!("expected Fault, got {other:?}"),
        }
    }

    #[test]
    fn fault_fixture_parses_as_envelope_with_encrypted_pp() {
        let envelope: soap::Envelope = quick_xml::de::from_str(FIXTURE).unwrap();
        assert!(envelope.header.encrypted_pp.is_some());
        assert!(matches!(envelope.body.body, soap::BodyContent::Fault(_)));
    }

    #[test]
    fn rst_response_truncated_fault_is_deserialization() {
        let cut = &FIXTURE[..FIXTURE.find("<S:Detail").unwrap()];
        assert!(matches!(
            parse_rst_response(cut),
            Err(crate::api::live::rst::RSTError::Deserialization(_))
        ));
    }

    #[tokio::test]
    async fn rst_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _held = listener.accept().await;
            std::future::pending::<()>().await;
        });
        let client = reqwest::Client::new();
        let start = std::time::Instant::now();
        let r = post_rst(
            &client,
            &format!("http://{addr}/"),
            String::new(),
            Some(std::time::Duration::from_millis(200)),
        )
        .await;
        assert!(r.is_err());
        let e = start.elapsed();
        assert!(e >= std::time::Duration::from_millis(200) && e < std::time::Duration::from_secs(2));
    }
}
