use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Gamerpic(String);
#[derive(Debug, Serialize, Deserialize)]
pub struct PreferredPlatforms(String);

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ColorTheme {
    Moondust, Ultraviolet, Dejagoo, Midnight, Fullthrottle, Flow, Midsummer, Elastic, Loungsinger,
    Nebula, Basic, Gamerpicblur, Aoretold, Avowed, Blackops6, Blackops7, Mw2, Mw3, Warzone2,
    Cyberpunk2077, Destiny2beyondlight, Diablo4loh, Doomdarkages, Madden27, Forzahorizon4,
    Forahorizon6, Forzamotorsport, Gears, Grounded2, Halo, Haloce, Haloinfinite, Highonlife2,
    Indianajones, Kiln, Liesofp, Minecraft, Outerworlds2, Palwold, Paryanimals, Readfall,
    Seaofthieves, Senua2, Southofmidnight, Starfield, Subnautica2, Titytinaswonderlands, Thps,
    Wearexbox, Weare360, Weareone, Wearex, Ms50, Bayou, Kingdom, Apihm24, Louder, Bloomingdesert,
    Rainforest, Ribbons, Rainbow, Unity, Divinerenaissance, Cybersunset, Savpoint, Wildgarden, Tile,
    Stickers, Truecolors, Rainbowburst, Movingmountains, Seriesx, Seriess, Gamepass, Alienplanet,
    Desert, Dreamcity, Forest, Northsea, Outerspace, Possiblity, Original, Haloinfinitemasterpiece,
    Thecrown, Leafygreen, Shoreline, Yourstorey1, Yourstory2, Wigboss, Wigdeveloper, Wigheroine,
    Wigprogamer, Wigstreamer,
    #[serde(rename = "360")]
    X360,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "id", content = "value")]
pub enum UserSetting {
    Bio(String),
    Location(String),
    PreferredPlatforms(PreferredPlatforms),
    PublicGamerpic(Gamerpic),
    WebColorTheme(ColorTheme),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ProfileSetting {
    UserSetting,
}

#[derive(Debug, Serialize)]
pub struct ModifyProfileSettings {
    pub setting: Vec<ProfileSetting>
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SupportedNetwork {
    Discord,
    Facebook,
    Instagram,
    Mixer,
    Phone,
    Reddit,
    Steam,
    Twitch,
    Twitter,
    YouTube,
    TFL,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LinkedAccounts {
    pub network: SupportedNetwork,
    pub show_linked_account: Option<bool>,
}

