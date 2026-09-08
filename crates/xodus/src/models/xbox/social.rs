use chrono::DateTime;
use serde::{Deserialize, Serialize};
use super::Xuid;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AddFriendResponse {
    pub xuid: Xuid,
    pub added_date_time_utc: DateTime<chrono::Utc>,
    pub friend_request_sent: bool,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RemoveFriendResponse {
    pub xuid: Xuid,
}

