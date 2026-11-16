use crate::models::xbox::peoplehub::*;
use reqwest::header::{ACCEPT, ACCEPT_LANGUAGE, AUTHORIZATION};
use std::ops::AddAssign;

pub async fn run (
    client: &reqwest::Client,
    authorization_header: &str,
    users: &Users,
    people: People<'_>,
    decoration: &Decoration,
    options: &SearchOptions,
) -> reqwest::Result<PeopleResponse> {
    let mut url = "https://peoplehub.xboxlive.com".to_string();
    match users {
        Users::Me => url.add_assign("/users/me"),
        Users::Xuid(xuid) => {
            url.add_assign("/users/xuid(");
            url.add_assign(xuid);
            url.add_assign(")");
        }
    }
    match people {
        People::Friends => url.add_assign("/people/friends"),
        People::Followers => url.add_assign("/people/followers"),
        People::RecentPlayers => url.add_assign("/people/recentplayers"),
        People::Recommendations => url.add_assign("/people/recommendations"),
        People::Search => url.add_assign("/people/search"),
        People::Social => url.add_assign("/people/social"),
        People::Xuids(xuid) => {
            url.add_assign("/people/xuids(");
            url.add_assign(xuid);
            url.add_assign(")");
        },
        People::Batch(_) => url.add_assign("/people/batch"),
        People::FriendRequestsRecieved => url.add_assign("/people/friendrequests(recieved)"),
        People::FriendRequestsSent => url.add_assign("/people/friendrequests(sent)"),
        People::PlayedTitle(title_id) => {
            url.add_assign("/people/playedTitle(");
            url.add_assign(&title_id.to_string());
            url.push(')');
        }
    }
    if !decoration.is_empty() {
        url.add_assign("/decoration/");
        for decoration_type in decoration {
            url.add_assign(match decoration_type {
                DecorationType::Detail => "detail,",
                DecorationType::PreferredColor => "preferredColor,",
                DecorationType::PresenceDetail => "presenceDetail,",
                DecorationType::MultiplayerSummary => "multiplayerSummary,",
                DecorationType::TitleHistory => "titleHistory,",
            });
        }
        url.pop();
    }

    let query = match (options.search_term.as_ref(), options.max_items.as_ref()) {
        (Some(s), Some(m)) => format!("?q={s}&maxItems={m}"),
        (Some(s), None   ) => format!("?q={s}"),
        (None,    Some(m)) => format!("?maxItems={m}"),
        (None,    None   ) => "".to_string(),
    };

    url.add_assign(&query);

    let request = {
        if let People::Batch(xuids) = people {
            let body = BatchRequest { xuids: xuids.to_vec() };
            client.post(url).json(&body)
        } else {
            client.get(url)
        }
    };
    request
        .header(AUTHORIZATION, authorization_header)
        .header(ACCEPT, "application/json")
        .header(ACCEPT_LANGUAGE, "en-US")
        .header("x-xbl-contract-version", "7")
        .send().await?
        .error_for_status()?
        .json().await
}
