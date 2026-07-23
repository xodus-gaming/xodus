use super::RSTRequest;
use super::error::RSTBuilderError;
use super::signature::RSTSignature;
use crate::{
    api::live::utils,
    models::{
        secrets::{LegacyToken, Token},
        soap::{self, XML_SIGNATURE_DIGEST_SHA256, XML_SIGNATURE_TRANSFORM_EXCLUSIVE},
    },
};

pub struct RSTRequestBuilder<'a> {
    header: soap::Header,
    signature: Option<RSTSignature<'a>>,
    scope_policies: Vec<(&'a str, Option<soap::PolicyReference>)>,
    device_token: Option<LegacyToken>,
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

    pub fn device_token(mut self, token: LegacyToken) -> Self {
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

    pub fn sso_flags(mut self, sso_flags: &'a str) -> Self {
        self.header
            .auth_info
            .as_mut()
            .map(|a| a.sso_flags = sso_flags.to_string());
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

    pub fn username(mut self, username_token: soap::UsernameToken) -> Self {
        self.header.security.username_token = Some(username_token);
        self
    }

    pub fn signature(mut self, signature: RSTSignature<'a>) -> Self {
        self.signature = Some(signature);
        self
    }

    #[must_use]
    pub fn build(mut self) -> Result<RSTRequest<'a>, RSTBuilderError> {
        let mut security_tokens = self.build_request_security_tokens();
        let signature_template = self.build_request_signature_template();

        match (self.device_token, self.user_token) {
            (Some(dev_token), Some(Token::Legacy(user_token))) => {
                let encrypted_data = quick_xml::de::from_str(&user_token.token)?;
                self.header.security.binary_security_token = vec![soap::BinarySecurityTokenReq {
                    id: "DeviceDAToken".to_string(),
                    value_type: "urn:liveid:device".to_owned(),
                    value: dev_token.token,
                }];

                self.header.security.encrypted_data = Some(encrypted_data);
            }
            (Some(dev_token), None) => {
                let encrypted_data = quick_xml::de::from_str(&dev_token.token)?;
                self.header.security.encrypted_data = Some(encrypted_data);
            }
            (None, None) => (),
            _ => return Err(RSTBuilderError::UnsupportedTokenCombination),
        }

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
        let xml = quick_xml::se::to_string(&envelope)?;
        let signed_xml = utils::sign_xml(self.signature.as_ref(), &self.nonce, xml)?;

        Ok(RSTRequest {
            signed_xml,
            signature: self.signature,
        })
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
