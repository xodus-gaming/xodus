use serde::Deserialize;

const E_FAIL: &str = "0x80004005";
const SIGN_IN_CODES: [&str; 2] = ["0x8004100c", "0x800488e5"];

/// A typed RST2 SOAP Fault (the `Envelope/Body/Fault` of a failed token request).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SoapFault {
    pub code: Option<String>,
    pub subcode: Option<String>,
    pub value: Option<String>,
    pub internal_code: Option<String>,
    pub internal_text: Option<String>,
}

#[derive(Deserialize)]
struct RawEnvelope {
    #[serde(rename = "Body")]
    body: RawBody,
}

#[derive(Deserialize)]
struct RawBody {
    #[serde(rename = "Fault")]
    fault: RawFault,
}

#[derive(Deserialize)]
struct RawFault {
    #[serde(rename = "Code", default)]
    code: Option<RawCode>,
    #[serde(rename = "Detail", default)]
    detail: Option<RawDetail>,
}

#[derive(Deserialize)]
struct RawCode {
    #[serde(rename = "Value", default)]
    value: Option<String>,
    #[serde(rename = "Subcode", default)]
    subcode: Option<RawSubcode>,
}

#[derive(Deserialize)]
struct RawSubcode {
    #[serde(rename = "Value", default)]
    value: Option<String>,
}

#[derive(Deserialize)]
struct RawDetail {
    #[serde(rename = "error", default)]
    error: Option<RawError>,
}

#[derive(Deserialize)]
struct RawError {
    #[serde(rename = "value", default)]
    value: Option<String>,
    #[serde(rename = "internalerror", default)]
    internalerror: Option<RawInternal>,
}

#[derive(Deserialize)]
struct RawInternal {
    #[serde(rename = "code", default)]
    code: Option<String>,
    #[serde(rename = "text", default)]
    text: Option<String>,
}

fn is_hex_code(s: &str) -> bool {
    let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) else {
        return false;
    };
    (1..=8).contains(&h.len()) && h.chars().all(|c| c.is_ascii_hexdigit())
}

impl SoapFault {
    pub fn parse(xml: &str) -> Result<SoapFault, quick_xml::DeError> {
        let env: RawEnvelope = quick_xml::de::from_str(xml)?;
        let f = env.body.fault;
        let (code, subcode) = match f.code {
            Some(c) => (c.value, c.subcode.and_then(|s| s.value)),
            None => (None, None),
        };
        let (value, internal) = match f.detail.and_then(|d| d.error) {
            Some(e) => (e.value, e.internalerror),
            None => (None, None),
        };
        let (internal_code, internal_text) = match internal {
            Some(i) => (i.code, i.text.map(|t| t.trim().to_string())),
            None => (None, None),
        };
        Ok(SoapFault { code, subcode, value, internal_code, internal_text })
    }

    pub fn is_sign_in_required(&self) -> bool {
        [&self.internal_code, &self.value]
            .into_iter()
            .flatten()
            .any(|c| SIGN_IN_CODES.iter().any(|s| c.trim().eq_ignore_ascii_case(s)))
    }

    pub fn error_code(&self) -> String {
        [&self.internal_code, &self.value]
            .into_iter()
            .flatten()
            .map(|c| c.trim())
            .find(|c| is_hex_code(c))
            .map(|c| format!("0x{}", c[2..].to_ascii_lowercase()))
            .unwrap_or_else(|| E_FAIL.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("testdata/rst-fault.xml");

    fn fault(inner: &str) -> String {
        format!(
            r#"<S:Envelope xmlns:S="s" xmlns:psf="p"><S:Body><S:Fault><S:Detail><psf:error>{inner}</psf:error></S:Detail></S:Fault></S:Body></S:Envelope>"#
        )
    }

    #[test]
    fn fault_fixture() {
        let f = SoapFault::parse(FIXTURE).unwrap();
        assert_eq!(f.value.as_deref(), Some("0x800488e5"));
        assert_eq!(f.internal_code.as_deref(), Some("0x8004100c"));
        assert_eq!(f.code.as_deref(), Some("S:Sender"));
        assert_eq!(f.subcode.as_deref(), Some("wst:FailedAuthentication"));
        let t = f.internal_text.unwrap();
        assert!(t.starts_with("The client is required") && t.ends_with("forced-sign in."));
        assert!(SoapFault::parse(FIXTURE).unwrap().is_sign_in_required());
    }

    #[test]
    fn fault_other_code_not_sign_in() {
        let f = SoapFault::parse(&fault(
            "<psf:value>0x80048831</psf:value><psf:internalerror><psf:code>0x80048831</psf:code></psf:internalerror>",
        ))
        .unwrap();
        assert!(!f.is_sign_in_required());
        assert_eq!(f.error_code(), "0x80048831");
    }

    #[test]
    fn fault_missing_internalerror() {
        let f = SoapFault::parse(&fault("<psf:value>0x800488e5</psf:value>")).unwrap();
        assert_eq!(f.internal_code, None);
        assert!(f.is_sign_in_required());
    }

    #[test]
    fn fault_error_code_normalizes_and_falls_back() {
        let f = SoapFault { value: Some("0X80048831".into()), ..Default::default() };
        assert_eq!(f.error_code(), "0x80048831");
        let f = SoapFault { value: Some("<bad>".into()), ..Default::default() };
        assert_eq!(f.error_code(), "0x80004005");
        let f = SoapFault { value: Some("0X8004100C".into()), ..Default::default() };
        assert_eq!(f.error_code(), "0x8004100c");
        assert!(f.is_sign_in_required());
        let f = SoapFault { value: Some("0x123456789".into()), ..Default::default() };
        assert_eq!(f.error_code(), "0x80004005");
    }

    #[test]
    fn fault_internal_code_preferred() {
        let f = SoapFault {
            value: Some("0x800488e5".into()),
            internal_code: Some("0x8004100c".into()),
            ..Default::default()
        };
        assert_eq!(f.error_code(), "0x8004100c");
        let f = SoapFault {
            value: Some("0x80048831".into()),
            internal_code: Some("junk".into()),
            ..Default::default()
        };
        assert_eq!(f.error_code(), "0x80048831");
    }

    #[test]
    fn fault_garbage_is_err() {
        assert!(SoapFault::parse("garbage").is_err());
        assert!(SoapFault::parse("").is_err());
        assert!(SoapFault::parse("<a><b/></a>").is_err());
    }
}
