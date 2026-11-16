use std::process::ExitCode;
use std::vec::Vec;
use xodus::api::social::peoplehub;
use xodus::api::xbox;
use xodus::tokens::TokenManager;
use xodus::models::secrets::Token;
use xodus::models::xbox::peoplehub::{DecorationType, People, SearchOptions, Users};

async fn get_authorization_header(
    client: &reqwest::Client,
    tokens: &TokenManager,
) -> (String, String) {
    let Token::Legacy(device_token) = tokens.get_device_sts_token().unwrap() else { panic!("unsupported device token") };
    let Token::Legacy(user_token) = tokens.get_user_sts_token().unwrap() else { panic!("unsupported user token") };

    let xsts_response = xbox::run(
        client,
        device_token,
        user_token,
        "http://xboxlive.com",
    ).await;

    let xuid = xsts_response.xuid().expect("This user's xuid is unknown.").to_string();
    let auth_header = xbox::get_xsts_auth_header(xsts_response);

    (xuid, auth_header)
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    user: Option<String>,
    friends: bool,
    followers: bool,
    recent_players: bool,
    recommendations: bool,
    social: bool,
    sent_requests: bool,
    recieved_requests: bool,
    xuids: Vec<String>,
    played_title: Option<u32>,
    search: Option<String>,
    max_results: u32,
    detail: bool,
    preferred_color: bool,
    presence_detail: bool,
    multiplayer_summary: bool,
    all: bool,
) -> ExitCode {
    let (our_xuid, authorization) = get_authorization_header(client, tokens).await;
    let user: Users = match user {
        Some(user_xuid) => {
            let private_info = recent_players || recommendations || sent_requests || recieved_requests;
            if private_info && user_xuid != our_xuid {
                eprintln!(
                    "You may not view the recent players or friend recommendations of other users."
                );
                return ExitCode::FAILURE;
            }
            Users::Xuid(user_xuid)
        },
        None => Users::Me,
    };
    let mut details = Vec::new();
    if detail || all { details.push(DecorationType::Detail) };
    if preferred_color || all { details.push(DecorationType::PreferredColor) };
    if presence_detail || all { details.push(DecorationType::PresenceDetail) };
    if multiplayer_summary || all {
        details.push(DecorationType::MultiplayerSummary);
    }

    if !(1..1000).contains(&max_results) {
        eprintln!("max_results must be between 1 and 1000");
    }
    let options = SearchOptions {
        search_term: search.clone(),
        max_items: Some(max_results as u16),
    };

    if friends {
        let result = peoplehub::run(client, &authorization, &user, People::Friends, &details, &options);
        println!("Friends: {:?}", result.await);
    }
    if followers {
        let result = peoplehub::run(client, &authorization, &user, People::Friends, &details, &options);
        println!("Followers: {:?}", result.await);
    }
    if recent_players {
        let result = peoplehub::run(client, &authorization, &user, People::RecentPlayers, &details, &options);
        println!("Recent players: {:?}", result.await);
    }
    if recommendations {
        let result = peoplehub::run(client, &authorization, &user, People::Friends, &details, &options);
        println!("Friend recommendations: {:?}", result.await);
    }
    if social {
        let result = peoplehub::run(client, &authorization, &user, People::Social, &details, &options);
        println!("Following: {:?}", result.await);
    }
    if sent_requests {
        let result = peoplehub::run(
            client,
            &authorization,
            &user,
            People::FriendRequestsSent,
            &details,
            &options
        ).await;
        println!("Sent friend requests: {:?}", result);
    }
    if recieved_requests {
        let result = peoplehub::run(
            client,
            &authorization,
            &user,
            People::FriendRequestsRecieved,
            &details,
            &options
        ).await;
        println!("Recieved friend requests: {:?}", result);
    }
    match xuids.len() {
        0 => (),
        1 => {
            let result = peoplehub::run(client, &authorization, &user, People::Xuids(&xuids[0]), &details, &options);
            println!("User {}: {:?}", xuids[0], result.await);
        }
        _ => {
            let result = peoplehub::run(client, &authorization, &user, People::Batch(&xuids), &details, &options);
            println!("XUIDs: {:?}", result.await);
        }
    }
    if let Some(title_id) = played_title {
        let result = peoplehub::run(
            client,
            &authorization,
            &user,
            People::PlayedTitle(title_id),
            &details,
            &options
        ).await;
        println!("Played title {}: {:?}", title_id, result);
    }

    if friends || followers || recent_players || recommendations || social
        || sent_requests || recieved_requests || !xuids.is_empty() || played_title.is_some() {
        return ExitCode::SUCCESS;
    }

    if search.is_some() {
        let result = peoplehub::run(client, &authorization, &user, People::Search, &details, &options);
        println!("Search results: {:?}", result.await);
    } else {
        let result = peoplehub::run(client, &authorization, &user, People::Xuids(&our_xuid), &details, &options);
        println!("You: {:?}", result.await);
    }

    ExitCode::SUCCESS
}

