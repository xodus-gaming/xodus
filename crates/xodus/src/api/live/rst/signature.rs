use base64::prelude::*;

use crate::api::live::utils;
use crate::models::soap::{self, XML_SIGNATURE_METHOD_HMAC, XML_SIGNATURE_METHOD_RSA};

pub enum RSTSignature<'a> {
    Rsa(Box<rsa::RsaPrivateKey>),
    Hmac {
        clep_secret: &'a [u8],
        /// Used only if TPMInfo public key was sent.
        /// Right now it's not needed, but the builder is capable of signing with it
        tpm_secret: &'a [u8],
    },
}

impl<'a> RSTSignature<'a> {
    pub fn method(&self) -> &'static str {
        match self {
            RSTSignature::Hmac { .. } => XML_SIGNATURE_METHOD_HMAC,
            RSTSignature::Rsa(_) => XML_SIGNATURE_METHOD_RSA,
        }
    }

    pub fn key_info(&self) -> Option<soap::SignatureKeyInfo> {
        match self {
            RSTSignature::Hmac { .. } => Some(soap::SignatureKeyInfo {
                security_token_reference: soap::SecurityTokenReference {
                    reference: soap::ReferenceUri {
                        uri: "#SignKey".to_string(),
                    },
                },
            }),
            RSTSignature::Rsa(_) => None,
        }
    }

    pub fn derived_key_token(
        &self,
        nonce: &[u8],
        reference_uri: &str,
    ) -> Option<soap::DerivedKeyToken> {
        match self {
            RSTSignature::Hmac { .. } => Some(soap::DerivedKeyToken {
                nonce: BASE64_STANDARD.encode(nonce),
                id: "SignKey".to_string(),
                algorithm: "urn:liveid:SP800108_CTR_HMAC_SHA256_DOUBLEDERIVED".to_string(),
                token_reference: None,
                requested_token_reference: Some(soap::RequestedTokenReference {
                    key_identifier: soap::KeyIdentifier {
                        value_type: "http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID".to_string(),
                        value: None,
                    },
                    reference: soap::ReferenceUri { uri: reference_uri.to_string() },
                }),
            }),
            RSTSignature::Rsa(_) => None,
        }
    }

    pub fn hmac_key(&self, nonce: &[u8]) -> Option<[u8; 32]> {
        if let Self::Hmac {
            clep_secret,
            tpm_secret,
        } = self
        {
            let clep_key = utils::generate_shared_key(32, clep_secret, soap::HMAC_KEY_USAGE, nonce);
            let hmac_key = if !tpm_secret.is_empty() {
                utils::generate_shared_key(32, tpm_secret, soap::HMAC_KEY_USAGE, &clep_key)
            } else {
                clep_key
            };

            Some(hmac_key)
        } else {
            None
        }
    }

    pub fn signing_key(&self, nonce: &[u8]) -> Result<bergshamra::KeyData, bergshamra::Error> {
        match self {
            RSTSignature::Hmac {
                clep_secret,
                tpm_secret,
            } => {
                let clep =
                    utils::generate_shared_key(32, clep_secret, soap::HMAC_KEY_USAGE, nonce);

                let hmac = if tpm_secret.is_empty() {
                    clep
                } else {
                    utils::generate_shared_key(
                        32,
                        tpm_secret,
                        soap::HMAC_KEY_USAGE,
                        &clep,
                    )
                };

                bergshamra::KeyData::from_symmetric_bytes(
                    kryptering::KeyAlgorithm::Hmac,
                    &hmac,
                )
            }
            RSTSignature::Rsa(private_key) => {
                use rsa::pkcs8::EncodePrivateKey;

                let der = private_key
                    .to_pkcs8_der()
                    .map_err(|e| bergshamra::Error::Key(e.to_string()))?;

                bergshamra::KeyData::from_pkcs8_der(
                    kryptering::KeyAlgorithm::Rsa,
                    der.as_bytes(),
                )
            }
        }
    }
}
