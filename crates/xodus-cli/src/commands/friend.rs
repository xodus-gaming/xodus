use std::process::ExitCode;
use reqwest::{RequestBuilder, Response};
use reqwest::header::AUTHORIZATION;
use reqwest::StatusCode;
use xodus::api::xbox;
use xodus::api::xbox::auth::get_xsts_auth_header;
use xodus::models::secrets::Token;
use xodus::models::xbox::social::{AddFriendResponse, RemoveFriendResponse};
use xodus::tokens::TokenManager;

const SOCIAL_XBOXLIVE: &str = "https://social.xboxlive.com/users/me/people";

async fn authorize_and_send(
    client: &reqwest::Client,
    tokens: &TokenManager,
    request: RequestBuilder,
) -> reqwest::Result<Response> {
    let Token::Legacy(device_token) = tokens.get_device_sts_token().unwrap() else { panic!("unsupported device token") };
    let Token::Legacy(user_token) = tokens.get_user_sts_token().unwrap() else { panic!("unsupported user token") };

    let xsts_token = xbox::run(
        client,
        device_token,
        user_token,
        "http://xboxlive.com",
    ).await;

    let auth_header = get_xsts_auth_header(xsts_token);
    request
        .header("x-xbl-contract-version", "3")
        .header(AUTHORIZATION, auth_header)
        .send().await?
        .error_for_status()
}

pub async fn add(client: &reqwest::Client, tokens: &TokenManager, xuid: String) -> ExitCode {
    let request = client.put(format!("{SOCIAL_XBOXLIVE}/friends/v2/xuid({})", xuid));
    let response = authorize_and_send(client, tokens, request).await.unwrap();
    let response: AddFriendResponse = response.json().await.expect("Failed to parse response.");
    println!("{:?}", response);
    ExitCode::SUCCESS
}

pub async fn remove(client: &reqwest::Client, tokens: &TokenManager, xuid: String) -> ExitCode {
    let request = client.delete(format!("{SOCIAL_XBOXLIVE}/friends/v2/xuid({})?deleteRelationships=friends", xuid));
    let response = authorize_and_send(client, tokens, request).await.unwrap();
    let response: RemoveFriendResponse = response.json().await.expect("Failed to parse response.");
    println!("{:?}", response);
    ExitCode::SUCCESS
}

pub async fn follow(client: &reqwest::Client, tokens: &TokenManager, xuid: String) -> ExitCode {
    let request = client.put(format!("{SOCIAL_XBOXLIVE}/xuid({})", xuid));
    let response = authorize_and_send(client, tokens, request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    ExitCode::SUCCESS
}

pub async fn unfollow(client: &reqwest::Client, tokens: &TokenManager, xuid: String) -> ExitCode {
    let request = client.delete(format!("{SOCIAL_XBOXLIVE}/friends/v2/xuid({})?deleteRelationships=follows", xuid));
    let response = authorize_and_send(client, tokens, request).await.unwrap();
    let response: RemoveFriendResponse = response.json().await.expect("Failed to parse response.");
    println!("{:?}", response);
    ExitCode::SUCCESS
}

pub async fn remove_follower(client: &reqwest::Client, tokens: &TokenManager, xuid: String) -> ExitCode {
    let request = client.delete(format!("{SOCIAL_XBOXLIVE}/follower/xuid({})", xuid));
    let response = authorize_and_send(client, tokens, request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    ExitCode::SUCCESS
}


