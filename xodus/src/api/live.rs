use crate::models::devicecredential::{DeviceAddRequest, DeviceAddResponse};
use crate::models::soap::{self, AppliesTo, EndpointReference, UsernameToken};

pub async fn login_device_credential(
    client: &reqwest::Client,
    data: DeviceAddRequest,
) -> reqwest::Result<DeviceAddResponse> {
    let data = quick_xml::se::to_string(&data).unwrap();

    let response = client
        .post(format!(
            "https://login.live.com/ppsecure/deviceaddcredential.srf"
        ))
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(data)
        .send()
        .await?;
    let text = response.text().await?;
    let resp: DeviceAddResponse = quick_xml::de::from_str(&text).expect("Failed to de xml");
    Ok(resp)
}

pub async fn authenticate_device(
    client: &reqwest::Client,
    username: String,
    password: String,
) -> reqwest::Result<soap::Envelope> {
    let mut header = soap::Header::new();
    header.security.username_token = Some(UsernameToken::new(username, password));
    let body = soap::Body {
        body: soap::BodyContent::RequestSecurityToken(soap::RequestSecurityToken {
            id: "RST0".to_string(),
            request_type: "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue".to_string(),
            applies_to: AppliesTo {
                endpoint_reference: EndpointReference {
                    address: "http://Passport.NET/tb".to_string(),
                },
            },
            policy_reference: None,
        }),
    };
    let envelope = soap::Envelope::new(header, body);
    let xml = quick_xml::se::to_string(&envelope).unwrap();
    let header = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    let xml = format!("{header}\n{xml}");
    let response = client
        .post(format!(
            "https://login.live.com/RST2.srf"
        ))
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(xml)
        .send()
        .await?;

    let text = response.text().await?;

    let res_envelope: soap::Envelope = quick_xml::de::from_str(&text).expect("Failed to de xml");

    Ok(res_envelope)
}
