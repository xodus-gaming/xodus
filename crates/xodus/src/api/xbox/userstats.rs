use crate::models::xbox::userstats::{TitleName, UserstatsBatchRequest, UserstatsBatchResponse};

pub async fn get_userstats(
    client: &reqwest::Client,
    auth_header: &str,
    xuid: &str,
    title_ids: &[u32],
) -> reqwest::Result<UserstatsBatchResponse> {
    let body = UserstatsBatchRequest {
        groups: title_ids
            .iter()
            .map(|&title_id| TitleName {
                name: "Hero".to_string(),
                title_id: title_id.to_string(),
            })
            .collect(),
        arrange_by_field: "xuid".to_string(),
        xuids: vec![xuid.to_string()],
        stats: title_ids
            .iter()
            .map(|&title_id| TitleName {
                name: "MinutesPlayed".to_string(),
                title_id: title_id.to_string(),
            })
            .collect(),
    };

    let response = client
        .post("https://userstats.xboxlive.com/batch")
        .header("x-xbl-contract-version", "2")
        .header("Authorization", auth_header)
        .json(&body)
        .send()
        .await?;

    response.error_for_status()?.json().await
}
