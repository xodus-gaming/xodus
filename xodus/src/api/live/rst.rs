use crate::{
    api::live::utils,
    models::{
        secrets::Token,
        soap::{
            self, XML_SIGNATURE_DIGEST_SHA256, XML_SIGNATURE_METHOD_HMAC, XML_SIGNATURE_METHOD_RSA,
            XML_SIGNATURE_TRANSFORM_EXCLUSIVE,
        },
    },
};
use base64::prelude::*;

pub enum RSTSignature<'a> {
    RSA(rsa::RsaPrivateKey),
    HMAC {
        clep_secret: &'a [u8],
        tpm_secret: &'a [u8],
    },
}

impl<'a> RSTSignature<'a> {
    fn method(&self) -> &'static str {
        match self {
            RSTSignature::HMAC { .. } => XML_SIGNATURE_METHOD_HMAC,
            RSTSignature::RSA(_) => XML_SIGNATURE_METHOD_RSA,
        }
    }

    fn key_info(&self) -> Option<soap::SignatureKeyInfo> {
        match self {
            RSTSignature::HMAC { .. } => Some(soap::SignatureKeyInfo {
                security_token_reference: soap::SecurityTokenReference {
                    reference: soap::ReferenceUri {
                        uri: "#SignKey".to_string(),
                    },
                },
            }),
            RSTSignature::RSA(_) => None,
        }
    }

    fn derived_key_token(&self, nonce: &[u8]) -> Option<soap::DerivedKeyToken> {
        match self {
            RSTSignature::HMAC { .. } => Some(soap::DerivedKeyToken {
                nonce: BASE64_STANDARD.encode(nonce),
                id: "SignKey".to_string(),
                algorithm: "urn:liveid:SP800108_CTR_HMAC_SHA256_DOUBLEDERIVED".to_string(),
                token_reference: None,
                requested_token_reference: Some(soap::RequestedTokenReference {
                    key_identifier: soap::KeyIdentifier {
                        value_type: "http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID".to_string(),
                        value: None,
                    },
                    reference: soap::ReferenceUri { uri: "".to_string() },
                }),
            }),
            RSTSignature::RSA(_) => None,
        }
    }

    fn signing_key(&self, nonce: &[u8]) -> bergshamra::Key {
        match self {
            RSTSignature::HMAC {
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

                bergshamra::Key::new(
                    bergshamra::KeyData::Hmac(hmac_key.to_vec()),
                    bergshamra::KeyUsage::Sign,
                )
            }
            RSTSignature::RSA(private_key) => {
                let public_key = rsa::RsaPublicKey::from(private_key);
                bergshamra::Key::new(
                    bergshamra::KeyData::Rsa {
                        private: Some(private_key.clone()),
                        public: public_key,
                    },
                    bergshamra::KeyUsage::Sign,
                )
            }
        }
    }
}

pub struct RSTRequest<'a> {
    pub signature: Option<RSTSignature<'a>>,
}

pub struct RSTRequestBuilder<'a> {
    header: soap::Header,
    signature: Option<RSTSignature<'a>>,
    scope_policies: Vec<(&'a str, Option<soap::PolicyReference>)>,
    device_token: Option<Token>,
    user_token: Option<Token>,
    nonce: [u8; 32],
}

impl<'a> RSTRequestBuilder<'a> {
    pub fn new() -> Self {
        Self {
            header: soap::Header::new(),
            signature: None,
            scope_policies: Vec::new(),
            device_token: None,
            user_token: None,
            nonce: utils::generate_nonce(),
        }
    }

    pub fn user_token(mut self, token: Token) -> Self {
        self.user_token = Some(token);
        self
    }

    pub fn device_token(mut self, token: Token) -> Self {
        self.device_token = Some(token);
        self
    }

    pub fn inline_ux(mut self, inline_ux: &'a str) -> Self {
        self.header
            .auth_info
            .as_mut()
            .map(|a| a.inline_ux = inline_ux.to_string());
        self
    }

    pub fn inline_ft(mut self, inline_ft: &'a str) -> Self {
        self.header
            .auth_info
            .as_mut()
            .map(|a| a.inline_ft = Some(inline_ft.to_string()));
        self
    }

    pub fn hosting_app(mut self, hosting_app: &'a str) -> Self {
        self.header
            .auth_info
            .as_mut()
            .map(|a| a.hosting_app = hosting_app.to_string());
        self
    }

    #[must_use]
    pub fn scope_policy(
        mut self,
        scope: &'a str,
        reference: Option<soap::PolicyReference>,
    ) -> Self {
        self.scope_policies.push((scope, reference));
        self
    }

    pub fn username_token(mut self, username_token: soap::UsernameToken) -> Self {
        self.header.security.username_token = Some(username_token);
        self
    }

    pub fn signature(mut self, signature: RSTSignature<'a>) -> Self {
        self.signature = Some(signature);
        self
    }

    #[must_use]
    pub fn build(mut self) -> (String, RSTRequest<'a>) {
        let mut security_tokens = self.build_request_security_tokens();
        let signature_template = self.build_request_signature_template();

        self.header.security.signature = signature_template;

        let body = soap::Body {
            body: if security_tokens.len() > 1 {
                soap::BodyContent::RequestMultipleSecurityTokens(
                    soap::RequestMultipleSecurityTokens {
                        id: "RSTS".to_string(),
                        ps: "http://schemas.microsoft.com/Passport/SoapServices/PPCRL".to_string(),
                        security_tokens,
                    },
                )
            } else {
                soap::BodyContent::RequestSecurityToken(security_tokens.remove(0))
            },
        };

        let envelope = soap::Envelope::new(self.header, body);
        let xml = quick_xml::se::to_string(&envelope).unwrap();
        let signed_xml = sign_xml(self.signature.as_ref(), &self.nonce, xml);

        (
            signed_xml,
            RSTRequest {
                signature: self.signature,
            },
        )
    }

    fn build_request_security_tokens(&self) -> Vec<soap::RequestSecurityToken> {
        self.scope_policies
            .iter()
            .enumerate()
            .map(|(i, scope)| soap::RequestSecurityToken {
                id: format!("RST{i}"),
                request_type: "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue".to_string(),
                applies_to: soap::AppliesTo {
                    endpoint_reference: soap::EndpointReference {
                        address: scope.0.to_string(),
                    },
                },
                policy_reference: scope.1.clone(),
            })
            .collect()
    }

    fn build_request_signature_template(&mut self) -> Option<soap::Signature> {
        let signature = self.signature.as_ref()?;
        let references = &[
            if self.scope_policies.len() > 1 {
                "#RSTS"
            } else {
                "#RST0"
            },
            "#Timestamp",
            "#PPAuthInfo",
        ];

        let reference = references
            .iter()
            .map(|id| soap::SignatureReference {
                uri: id.to_string(),
                digest_method: soap::AlgorithmNode {
                    algorithm: XML_SIGNATURE_DIGEST_SHA256.to_string(),
                },
                digest_value: "".to_string(),
                transforms: soap::SignatureTransforms {
                    transform: vec![soap::AlgorithmNode {
                        algorithm: XML_SIGNATURE_TRANSFORM_EXCLUSIVE.to_string(),
                    }],
                },
            })
            .collect();

        let key_info = signature.key_info();

        if let Some(derived_key_token) = signature.derived_key_token(&self.nonce) {
            self.header.security.derived_key_tokens = vec![derived_key_token];
        }

        let signed_info = soap::SignedInfo {
            signature_method: soap::AlgorithmNode {
                algorithm: signature.method().to_string(),
            },
            canonicalization_method: soap::AlgorithmNode {
                algorithm: XML_SIGNATURE_TRANSFORM_EXCLUSIVE.to_string(),
            },
            reference,
        };

        Some(soap::Signature {
            xmlns: soap::XML_SIGNATURE_NS.to_string(),
            signed_info,
            key_info: key_info,
            signature_value: String::default(),
        })
    }
}

fn sign_xml(signature: Option<&RSTSignature>, nonce: &[u8], xml_text: String) -> String {
    let Some(signature) = signature else {
        return xml_text;
    };
    let min_xml = bergshamra::c14n::canonicalize(
        &xml_text,
        bergshamra_c14n::C14nMode::Exclusive,
        None,
        &[] as &[&str],
    )
    .unwrap();

    let mut kmgr = bergshamra::KeysManager::new();
    kmgr.add_key(signature.signing_key(nonce));
    let ctx = bergshamra::DsigContext::new(kmgr).with_strict_verification(false);
    bergshamra::sign(&ctx, std::str::from_utf8(&min_xml).unwrap()).unwrap()
}
