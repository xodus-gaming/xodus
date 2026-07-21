use serde::{Deserialize, Serialize};

use crate::models::soap::{FromStrRef, StringStorage};

use super::base::ReferenceUri;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMethod {
    #[serde(rename = "@Algorithm")]
    pub algorithm: String,
    #[serde(rename = "$value", default)]
    pub val: Option<String>,
}

impl Default for EncryptionMethod {
    fn default() -> Self {
        Self {
            algorithm: "http://www.w3.org/2001/04/xmlenc#tripledes-cbc".to_string(),
            val: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CipherData {
    pub cipher_value: String,
}

impl CipherData {
    pub fn new(key: &str) -> Self {
        Self { cipher_value: key.to_owned() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTokenReference {
    #[serde(rename = "wsse:Reference", alias = "Reference")]
    pub reference: ReferenceUri,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureKeyInfo {
    #[serde(
        rename = "wsse:SecurityTokenReference",
        alias = "SecurityTokenReference"
    )]
    pub security_token_reference: SecurityTokenReference,
}

impl SignatureKeyInfo {
    pub fn sign_key() -> Self {
        Self {
            security_token_reference: SecurityTokenReference {
                reference: ReferenceUri {
                    uri: "#SignKey".to_string(),
                },
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmNode<Str: StringStorage> {
    #[serde(rename = "@Algorithm")]
    pub algorithm: Str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureTransforms<Str: StringStorage> {
    #[serde(rename = "Transform")]
    pub transform: Vec<AlgorithmNode<Str>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureReference<Str: StringStorage> {
    #[serde(rename = "@URI")]
    pub uri: Str,
    #[serde(rename = "Transforms")]
    pub transforms: SignatureTransforms<Str>,
    #[serde(rename = "DigestMethod")]
    pub digest_method: AlgorithmNode<Str>,
    #[serde(rename = "DigestValue")]
    pub digest_value: Str,
}

impl<Str: StringStorage> SignatureReference<Str> {
    pub fn exclusive<'t>(uri: &'t str) -> Self
    where
        Str: FromStrRef<'t>,
    {
        Self {
            uri: Str::st(uri),
            transforms: SignatureTransforms {
                transform: vec![AlgorithmNode {
                    algorithm: Str::st("http://www.w3.org/2001/10/xml-exc-c14n#"),
                }],
            },
            digest_method: AlgorithmNode {
                algorithm: Str::st("http://www.w3.org/2001/04/xmlenc#sha256"),
            },
            digest_value: Str::st(""),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInfo<Str: StringStorage> {
    #[serde(rename = "CanonicalizationMethod")]
    pub canonicalization_method: AlgorithmNode<Str>,
    #[serde(rename = "SignatureMethod")]
    pub signature_method: AlgorithmNode<Str>,
    #[serde(rename = "Reference")]
    pub reference: Vec<SignatureReference<Str>>,
}

impl<Str: FromStrRef<'static>> Default for SignedInfo<Str> {
    fn default() -> Self {
        Self {
            canonicalization_method: AlgorithmNode {
                algorithm: Str::st("http://www.w3.org/2001/10/xml-exc-c14n#"),
            },
            signature_method: AlgorithmNode {
                algorithm: Str::st("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"),
            },
            reference: vec![
                SignatureReference::exclusive("#RST0"),
                SignatureReference::exclusive("#Timestamp"),
                SignatureReference::exclusive("#PPAuthInfo"),
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature<Str: StringStorage> {
    #[serde(rename = "@xmlns")]
    pub xmlns: Str,
    #[serde(rename = "SignedInfo")]
    pub signed_info: SignedInfo<Str>,
    #[serde(rename = "SignatureValue")]
    pub signature_value: Str,
    #[serde(rename = "KeyInfo", skip_serializing_if = "Option::is_none")]
    pub key_info: Option<SignatureKeyInfo>,
}

impl<Str: FromStrRef<'static>> Signature<Str> {
    pub fn empty_hmac() -> Self {
        Self {
            xmlns: Str::st("http://www.w3.org/2000/09/xmldsig#"),
            signed_info: SignedInfo::default(),
            signature_value: Str::st(""),
            key_info: Some(SignatureKeyInfo::sign_key()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfoWrap {
    #[serde(
        rename = "@xmlns:ds",
        alias = "@xmlns",
        skip_serializing_if = "Option::is_none"
    )]
    pub ds: Option<String>,
    #[serde(
        rename = "ds:KeyName",
        alias = "KeyName",
        skip_serializing_if = "Option::is_none"
    )]
    pub key_name: Option<String>,
    #[serde(
        rename = "wsse:SecurityTokenReference",
        alias = "SecurityTokenReference",
        skip_serializing_if = "Option::is_none"
    )]
    pub security_token_reference: Option<SecurityTokenReference>,
}

impl KeyInfoWrap {
    pub fn sts() -> Self {
        Self {
            ds: Some("http://www.w3.org/2000/09/xmldsig#".to_string()),
            key_name: Some("http://Passport.NET/STS".to_string()),
            security_token_reference: None,
        }
    }

    pub fn as_signature(self) -> SignatureKeyInfo {
        let Self {
            security_token_reference: Some(reference),
            ..
        } = self
        else {
            panic!("Key is not named");
        };

        SignatureKeyInfo {
            security_token_reference: reference,
        }
    }

    pub fn as_named(self) -> NamedKeyInfo {
        let Self {
            ds,
            key_name,
            security_token_reference: _,
        } = self;

        NamedKeyInfo {
            ds: ds.unwrap_or_else(|| "http://www.w3.org/2000/09/xmldsig#".to_string()),
            key_name: key_name.expect("Key is not named"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedKeyInfo {
    #[serde(rename = "@xmlns:ds")]
    pub ds: String,
    #[serde(rename = "ds:KeyName", alias = "KeyName")]
    pub key_name: String,
}

impl NamedKeyInfo {
    pub fn sts() -> Self {
        Self {
            ds: "http://www.w3.org/2000/09/xmldsig#".to_string(),
            key_name: "http://Passport.NET/STS".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptedData<Str: StringStorage> {
    #[serde(rename = "@Id")]
    pub id: Str,
    #[serde(rename = "@xmlns")]
    pub xmlns: Str,
    #[serde(rename = "@Type")]
    pub el_type: Str,

    pub encryption_method: EncryptionMethod,
    #[serde(rename = "ds:KeyInfo", alias = "KeyInfo")]
    pub key_info: KeyInfoWrap,
    pub cipher_data: CipherData,
}

impl<Str: StringStorage> EncryptedData<Str> {
    pub fn devicesoftware<'t>(key: &'t str) -> Self
    where Str: FromStrRef<'t>
    {
        Self {
            id: Str::st("devicesoftware"),
            xmlns: Str::st("http://www.w3.org/2001/04/xmlenc#"),
            el_type: Str::st("http://www.w3.org/2001/04/xmlenc#Element"),
            encryption_method: EncryptionMethod::default(),
            key_info: KeyInfoWrap::sts(),
            cipher_data: CipherData::new(key),
        }
    }

    pub fn binary_da_token<'t>(key: &'t str) -> Self
    where Str: FromStrRef<'t> {
        Self {
            id: Str::st("BinaryDAToken0"),
            xmlns: Str::st("http://www.w3.org/2001/04/xmlenc#"),
            el_type: Str::st("http://www.w3.org/2001/04/xmlenc#Element"),
            encryption_method: EncryptionMethod::default(),
            key_info: KeyInfoWrap::sts(),
            cipher_data: CipherData::new(key),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptedPP<Str: StringStorage> {
    pub encrypted_data: EncryptedData<Str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_info_wrap_deserializes_ds_key_info_key_name() {
        let xml = r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                        <ds:KeyName>http://Passport.NET/STS</ds:KeyName>
                    </ds:KeyInfo>"#;

        let key_info: KeyInfoWrap =
            quick_xml::de::from_str(xml).expect("failed to deserialize key info");

        let named = key_info.as_named();
        assert_eq!(named.ds, "http://www.w3.org/2000/09/xmldsig#");
        assert_eq!(named.key_name, "http://Passport.NET/STS");
    }

    #[test]
    fn key_info_wrap_deserializes_wsse_security_token_reference() {
        let xml = r##"<KeyInfo xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                        <wsse:SecurityTokenReference>
                            <wsse:Reference URI="#SignKey"></wsse:Reference>
                        </wsse:SecurityTokenReference>
                    </KeyInfo>"##;

        let key_info: KeyInfoWrap =
            quick_xml::de::from_str(xml).expect("failed to deserialize key info");

        let signature = key_info.as_signature();
        assert_eq!(signature.security_token_reference.reference.uri, "#SignKey");
    }
}
