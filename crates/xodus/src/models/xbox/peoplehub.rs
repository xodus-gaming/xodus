use chrono::{DateTime, NaiveDateTime};
use serde::{Deserialize, Serialize};
use std::vec::Vec;
use super::profile::ColorTheme;
use reqwest::Url;
use uuid::Uuid;

type Xuid = String;

/* Requests */
#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Users {
    Me,
    Xuid(Xuid),
}

#[derive(Debug)]
pub enum People<'a> {
    Friends,
    Followers,
    RecentPlayers,
    Recommendations,
    Search,
    Social, // a.k.a. following
    Xuids(&'a Xuid),
    Batch(&'a Vec<Xuid>),
    FriendRequestsSent,
    FriendRequestsRecieved,
    PlayedTitle(u32),
}

#[derive(Debug)]
pub enum DecorationType {
    Detail,
    PreferredColor,
    PresenceDetail,
    MultiplayerSummary,
    // Causes 500 Internal Server Error unless people/playedTitle
    TitleHistory, 
}

pub type Decoration = Vec<DecorationType>;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchOptions {
    #[serde(rename="q")]
    pub search_term: Option<String>,
    pub max_items: Option<u16>, // Must be in (0, 1000)
}

#[derive(Debug, Serialize)]
pub struct BatchRequest {
    pub xuids: Vec<Xuid>,
}

/* Responses */

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Badge {
    pub id: String,
    pub name: String,
    pub description: String,
    pub is_showcase: bool,
    pub is_public: bool,
    pub awarded_at: Option<DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
pub enum AccountTier {
    Silver,
}

#[derive(Debug, Deserialize)]
pub enum Reputation {
    GoodPlayer,
}

#[derive(Debug, Deserialize)]
pub enum PresenceState {
    Online,
    Offline,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activity {

}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartyDetails {

}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MultiplayerSummary {
    pub joinable_activities: Vec<Activity>,
    pub party_details: Vec<PartyDetails>,
    pub in_party: u32
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlatformType {
    PC,
    Console,
    Mobile,
}

/*#[derive(Debug, Deserialize)]
pub struct Rgb(String);

pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

struct RgbVisitor;

impl Visitor for RgbVisitor {
    type Value = Rgb;
    fn expecting(&self, formatter: &mut fmt::Formater) -> fmt::Result {
        write!(formater, "an object with r,g,b properties or a hexcode string")
    }
    fn visit_str<E + Error>(&self, v: &str) -> Result<Self::Value, E> {
        let v = v.trim_start_matches('#');
        if v.len() != 6 return E::invalid_length(v.len(), 6);
        value: u32 = match u32::from_str_radix(v, 16) {
            Ok(value) => value,
            Err(_) => return E::unexpected_value(
        Rbg {
            r: value & 0xFF,
            g: (value >> 8) & 0xFF,
            b: (value >> 8) & 0xFF,
        }
    }
    fn visit_map<A + MapAccess>(&self, map: A) -> Result<Self::Value, A::Error> {
        loop {
            map.next_entry<String, u8>
        }
    }
}


impl Deserialize for Rgb {
    deserialize<D + Deserializer>(deserializer: D) {
        deserializer.deserialize_str(
}*/
/* RGB color code */
type Rgb = String;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ColorPreference {
    pub primary_color: Rgb,
    pub secondary_color: Rgb,
    pub tertiary_color: Rgb,
    pub color_uri: Url
}

#[derive(Debug, Deserialize)]
pub enum DeviceType {
    WindowsOneCore,
    Android,
}

#[derive(Debug, Deserialize)]
pub enum PresenceDetailsState {
    LastSeen,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct PresenceDetail {
    pub is_broadcasting: bool,
    pub device: DeviceType,
    pub device_sub_type: Option<serde_json::Value>,
    pub gameplay_type: Option<serde_json::Value>,
    pub presence_text: String,
    pub state: PresenceDetailsState,
    pub title_id: String,
    pub title_type: Option<serde_json::Value>,
    pub is_primary: bool,
    pub is_game: bool,
    pub rich_presence_text: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PersonDetail {
    pub can_be_friended: bool,
    pub can_be_followed: bool,
    pub is_friend: bool,
    pub friend_count: u32,
    pub is_friend_request_received: bool,
    pub is_friend_request_sent: bool,
    pub is_friend_list_shared: bool,
    pub is_following_caller: bool,
    pub is_followed_by_caller: bool,
    pub is_favorite: bool,
    pub badges: Vec<Badge>,
    pub account_tier: AccountTier,
    pub bio: String,
    pub is_verified: bool,
    pub location: String,
    pub tenure: String,
    pub watermarks: Vec<Uuid>,
    pub blocked: bool,
    pub mute: bool,
    pub follower_count: u32,
    pub following_count: u32,
    pub has_game_pass: bool,
}


#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FollowerInfo {
    pub followed_date_time_utc: DateTime<chrono::Utc>,
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub enum RecommendationType {
    CommunitySuggestion,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct RecommendationInfo {
    pub r#type: RecommendationType,
    pub reasons: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub enum SearchType {
    None,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct SearchInfo {
    pub r#type: SearchType,
    pub reasons: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Person {
    pub detail: Option<PersonDetail>,
    pub follower: Option<FollowerInfo>,
    pub recommendation: Option<RecommendationInfo>,
    pub is_friend: bool,
    pub friended_date_time_utc: Option<DateTime<chrono::Utc>>,
    pub is_friend_request_received: bool,
    pub is_friend_request_sent: bool,
    pub xuid: Xuid,
    pub app_xuid: Option<serde_json::Value>,
    pub is_favorite: bool,
    pub is_following_caller: bool,
    pub is_followed_by_caller: bool,
    pub is_identity_shared: bool,
    pub added_date_time_utc: Option<DateTime<chrono::Utc>>,
    pub display_name: Option<String>,
    pub real_name: String,
    pub display_pic_raw: reqwest::Url,
    pub show_user_as_avatar: String,
    pub gamertag: String,
    pub gamer_score: String,
    pub modern_gamertag: String,
    pub modern_gamertag_suffix: String,
    pub unique_modern_gamertag: String,
    pub xbox_one_rep: Reputation,
    pub presence_state: Option<PresenceState>,
    pub presence_text: Option<String>,
    pub presence_devices: Option<serde_json::Value>,
    pub is_broadcasting: bool,
    pub is_cloaked: Option<bool>,
    pub is_quarantined: bool,
    pub is_xbox360_gamerpic: bool,
    pub last_seen_date_time_utc: Option<NaiveDateTime>,
    pub suggestion: Option<serde_json::Value>,
    pub search: Option<SearchInfo>,
    pub title_history: Option<serde_json::Value>,
    pub multiplayer_summary: Option<MultiplayerSummary>,
    pub recent_player: Option<serde_json::Value>,
    pub preferred_color: Option<ColorPreference>,
    pub presence_details: Option<Vec<PresenceDetail>>,
    pub title_presence: Option<serde_json::Value>,
    pub title_summaries: Option<serde_json::Value>,
    pub presence_title_ids: Option<serde_json::Value>,
    pub community_manager_titles: Option<serde_json::Value>,
    pub social_manager: Option<serde_json::Value>,
    pub broadcast: Option<serde_json::Value>,
    pub avatar: Option<serde_json::Value>,
    pub linked_accounts: Option<Vec<serde_json::Value>>,
    pub color_theme: ColorTheme,
    pub preferred_flag: String,
    pub preferred_platforms: Vec<PlatformType>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecommendationSummary {
    pub steam_friend: u32,
    pub community_suggestion: u32,
    pub promote_suggestions: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FriendFinderState {
    pub facebook_opt_in_status: OptInStatus,
    pub facebook_token_status: TokenStatus,
    pub phone_opt_in_status: OptInStatus,
    pub phone_token_status: TokenStatus,
    pub steam_opt_in_status: OptInStatus,
    pub steam_token_status: TokenStatus,
    pub discord_opt_in_status: OptInStatus,
    pub discord_token_status: TokenStatus,
    pub instagram_opt_in_status: OptInStatus,
    pub instagram_token_status: TokenStatus,
    pub mixer_opt_in_status: OptInStatus,
    pub mixer_token_status: TokenStatus,
    pub reddit_opt_in_status: OptInStatus,
    pub reddit_token_status: TokenStatus,
    pub tfl_opt_in_status: OptInStatus,
    pub tfl_token_status: TokenStatus,
    pub twitch_opt_in_status: OptInStatus,
    pub twitch_token_status: TokenStatus,
    pub twitter_opt_in_status: OptInStatus,
    pub twitter_token_status: TokenStatus,
    pub you_tube_opt_in_status: OptInStatus,
    pub you_tube_token_status: TokenStatus,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountLinkDetails {

}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FriendRequestSummary {
    pub friend_requests_received_count: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeopleResponse {
    pub people: Vec<Person>,
    pub recommendation_summary: Option<RecommendationSummary>,
    pub friend_finder_state: Option<FriendFinderState>,
    pub account_link_details: Option<AccountLinkDetails>,
    pub friend_request_summary: Option<FriendRequestSummary>,
}

#[derive(Debug, Deserialize)]
pub enum OptInStatus {
    Excluded,
    ShowPrompt,
    Unknown,
}

#[derive(Debug, Deserialize)]
pub enum TokenStatus {
    Unknown,
    NotRequired,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedAccount {
    pub network_name: super::profile::SupportedNetwork,
    pub opt_in_status: OptInStatus,
    pub token_status: TokenStatus,
    pub show_on_profile: bool,
    pub deeplink: Option<Url>,
}

pub type AccountLinkResponse = Vec<LinkedAccount>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response() {
        let data = r#"
{
 "people": [
    {
     "detail": null,
     "follower": null,
     "recommendation": null,
     "isFriend": false,
     "friendedDateTimeUtc": null,
     "isFriendRequestReceived": false,
     "isFriendRequestSent": false,
     "xuid": "2535412854559864",
     "appXuid": null,
     "isFavorite": false,
     "isFollowingCaller": false,
     "isFollowedByCaller": false,
     "isIdentityShared": false,
     "addedDateTimeUtc": null,
     "displayName": "BF5258",
     "realName": "",
     "displayPicRaw": "https://images-eds-ssl.xboxlive.com/image?url=8Oaj9Ryq1G1_p3lLnXlsaZgGzAie6Mnu24_PawYuDYIoH77pJ.X5Z.MqQPibUVTcS9jr0n8i7LY1tL3U7Aiaffk8VUakeanjxD5Yw0TfDwCSfJyGJe21_9jyMeqwWrc0&format=png",
     "showUserAsAvatar": "2",
     "gamertag": "BF5258",
     "gamerScore": "385",
     "modernGamertag": "BF5258",
     "modernGamertagSuffix": "",
     "uniqueModernGamertag": "BF5258",
     "xboxOneRep": "GoodPlayer",
     "presenceState": "Offline",
     "presenceText": "Last seen 8d ago: Xbox App",
     "presenceDevices": null,
     "isBroadcasting": false,
     "isCloaked": true,
     "isQuarantined": false,
     "isXbox360Gamerpic": false,
     "lastSeenDateTimeUtc": "2026-09-27T03:59:24.6447351",
     "suggestion": null,
     "search": null,
     "titleHistory": null,
     "multiplayerSummary": null,
     "recentPlayer": null,
     "preferredColor": null,
     "presenceDetails": null,
     "titlePresence": null,
     "titleSummaries": null,
     "presenceTitleIds": null,
     "communityManagerTitles": null,
     "socialManager": null,
     "broadcast": null,
     "avatar": null,
     "linkedAccounts": [],
     "colorTheme": "basic",
     "preferredFlag": "",
     "preferredPlatforms": ["pc"]
    }
  ],
 "recommendationSummary": null,
 "friendFinderState": null,
 "accountLinkDetails": null,
 "friendRequestSummary": null
}
        "#;
        let _result: PeopleResponse = serde_json::from_str(data).expect("Failed to deserialize test response:");
    }
}
