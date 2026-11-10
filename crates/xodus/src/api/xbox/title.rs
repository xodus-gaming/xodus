use crate::models::xbox::{TitleMgtEndPoint, TitleMgtResponse, TitleMgtSignaturePolicy};

pub async fn get_title_management(client: &reqwest::Client) -> reqwest::Result<TitleMgtResponse> {
    let response = client
        .get("https://title.mgt.xboxlive.com/titles/default/endpoints?type=1")
        .send()
        .await?;
    response.json().await
}

pub fn get_endpoint<'a>(url: &str, response: &'a TitleMgtResponse) -> Option<&'a TitleMgtEndPoint> {
    let parsed_url = reqwest::Url::parse(url).ok()?;
    let filtered: Vec<&TitleMgtEndPoint> = response
        .end_points
        .iter()
        .filter(|e| e.protocol == parsed_url.scheme())
        .collect();
    let hosts: Vec<globset::Glob> = filtered
        .iter()
        .map(|e| globset::Glob::new(&e.host).expect("Unsupported glob"))
        .collect();
    let set = globset::GlobSet::new(hosts).ok()?;
    let matched = set.matches(parsed_url.host_str().unwrap());
    let matched: Vec<&TitleMgtEndPoint> = matched.into_iter().map(|m| filtered[m]).collect();

    matched
        .iter()
        .max_by_key(|&&pat| pat.host.chars().filter(|&c| c != '*').count())
        .copied()
}

/// Relying party used when no endpoint matches (same default as the Xbox runtime).
pub const DEFAULT_RELYING_PARTY: &str = "http://xboxlive.com";

/// What a service request needs to know about its target endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedEndpoint {
    pub relying_party: String,
    /// Signature policy to sign the request with, `None` when the endpoint is not signed.
    pub signature_policy: Option<TitleMgtSignaturePolicy>,
}

/// Resolve the relying party and signature policy for a request URL, the way
/// `XUserGetTokenAndSignature` does: match protocol, host (fqdn or `*.` wildcard) and, when
/// the endpoint declares one, the exact path; the most specific match wins (a path-specific
/// entry beats a host-only one, a longer host beats a shorter one).
pub fn resolve_relying_party(url: &str, table: &TitleMgtResponse) -> Option<ResolvedEndpoint> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let scheme = match parsed.scheme() {
        "wss" => "https",
        "ws" => "http",
        other => other,
    };
    let host = parsed.host_str()?;

    let best = table
        .end_points
        .iter()
        .filter(|e| e.protocol.eq_ignore_ascii_case(scheme))
        .filter(|e| match e.host_type.as_deref() {
            Some("wildcard") => {
                let suffix = e.host.trim_start_matches('*');
                host.ends_with(suffix) && host.len() > suffix.len()
            }
            _ => host.eq_ignore_ascii_case(&e.host),
        })
        .filter(|e| e.path.as_deref().is_none_or(|p| p == parsed.path()))
        .max_by_key(|e| {
            (
                e.path.is_some(),
                e.host.chars().filter(|&c| c != '*').count(),
            )
        });

    let (relying_party, policy_index) = match best {
        Some(e) => (
            e.relying_party
                .clone()
                .unwrap_or_else(|| DEFAULT_RELYING_PARTY.to_string()),
            e.signature_policy_index,
        ),
        None => (DEFAULT_RELYING_PARTY.to_string(), None),
    };
    let signature_policy =
        policy_index.and_then(|i| table.signature_policies.get(i as usize).cloned());

    Some(ResolvedEndpoint {
        relying_party,
        signature_policy,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    const ENDPOINTS_JSON: &str = include_str!("../../../testdata/title_endpoints.json");

    #[test]
    fn test_endpoint_cases() {
        let response =
            serde_json::from_str::<TitleMgtResponse>(ENDPOINTS_JSON).expect("Failed to parse");

        let live = get_endpoint("https://xboxlive.com", &response).expect("No xboxlive endpoint");
        assert_eq!(live.host, "xboxlive.com");
        assert_eq!(live.relying_party.as_deref(), Some("http://xboxlive.com"));
        let playfab =
            get_endpoint("https://playfabapi.com", &response).expect("No playfab endpoint found");
        assert_eq!(playfab.host, "playfabapi.com");
        assert_eq!(
            playfab.relying_party.as_deref(),
            Some("http://playfab.xboxlive.com/")
        );
        let updates =
            get_endpoint("https://update.xboxlive.com", &response).expect("No updates endpoint");

        assert_eq!(updates.host, "update.xboxlive.com");
        assert_eq!(
            updates.relying_party.as_deref(),
            Some("http://update.xboxlive.com")
        );
    }

    #[test]
    fn test_resolve_relying_party() {
        let table = serde_json::from_str::<TitleMgtResponse>(ENDPOINTS_JSON).expect("parse");

        // exact host
        let r = resolve_relying_party(
            "https://achievements.xboxlive.com/users/xuid(1)/achievements?titleId=5",
            &table,
        )
        .unwrap();
        assert_eq!(r.relying_party, "http://xboxlive.com");
        assert_eq!(r.signature_policy.as_ref().map(|p| p.version), Some(1));
        assert_eq!(
            r.signature_policy.as_ref().map(|p| p.max_body_bytes),
            Some(8192)
        );

        // specific host beats the *.xboxlive.com wildcard
        let r = resolve_relying_party("https://packagespc.xboxlive.com/GetBasePackage/x", &table)
            .unwrap();
        assert_eq!(r.relying_party, "http://update.xboxlive.com");

        // wildcard with a different policy index
        let r = resolve_relying_party("https://a.experimentation.xboxlive.com/", &table).unwrap();
        assert_eq!(r.relying_party, "http://experimentation.xboxlive.com/");
        assert_eq!(
            r.signature_policy.as_ref().map(|p| p.max_body_bytes),
            Some(2147483647)
        );

        // path-specific entry beats the host-only one for the same host
        let r = resolve_relying_party(
            "https://device.mgt.xboxlive.com/devices/current/unlock",
            &table,
        )
        .unwrap();
        assert_eq!(r.relying_party, "http://unlock.device.mgt.xboxlive.com");
        let r =
            resolve_relying_party("https://device.mgt.xboxlive.com/registrations", &table).unwrap();
        assert_eq!(r.relying_party, "http://device.mgt.xboxlive.com");

        // unsigned endpoint (no SignaturePolicyIndex) and unknown host -> default RP, no policy
        let r = resolve_relying_party("https://playfabapi.com/Client/Login", &table).unwrap();
        assert_eq!(r.relying_party, "http://playfab.xboxlive.com/");
        assert!(r.signature_policy.is_none());
        let r = resolve_relying_party("https://example.com/", &table).unwrap();
        assert_eq!(r.relying_party, DEFAULT_RELYING_PARTY);
        assert!(r.signature_policy.is_none());

        // ws(s) is treated as http(s); bad URLs are rejected
        assert!(resolve_relying_party("wss://xboxlive.com/", &table).is_some());
        assert!(resolve_relying_party("not a url", &table).is_none());
    }
}
