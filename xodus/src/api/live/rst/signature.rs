use crate::{
    api::live::utils,
    models::soap::{self, XML_SIGNATURE_METHOD_HMAC, XML_SIGNATURE_METHOD_RSA},
};
use base64::prelude::*;

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

    pub fn signing_key(&self, nonce: &[u8]) -> bergshamra::KeyData {
        match self {
            RSTSignature::Hmac {
                clep_secret,
                tpm_secret,
            } => {
                let clep_key =
                    utils::generate_shared_key(32, clep_secret, soap::HMAC_KEY_USAGE, nonce);
                let hmac_key = if !tpm_secret.is_empty() {
                    utils::generate_shared_key(32, tpm_secret, soap::HMAC_KEY_USAGE, &clep_key)
                } else {
                    clep_key
                };

                bergshamra::KeyData::Hmac(hmac_key.to_vec())
            }
            RSTSignature::Rsa(private_key) => {
                let public_key = rsa::RsaPublicKey::from(private_key.as_ref());
                bergshamra::KeyData::Rsa {
                    private: Some(private_key.as_ref().clone()),
                    public: public_key,
                }
            }
        }
    }
}
