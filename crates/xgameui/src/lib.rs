use std::collections::HashMap;

use eframe::{CreationContext, egui};
use egui::{Id, Sense};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Default)]
pub struct PlayerPicker {
    users: HashMap<String, ProfileUser>,
}

impl PlayerPicker {
    pub fn new(cc: &CreationContext<'_>, users: HashMap<String, ProfileUser>) -> Self {
        egui_extras::install_image_loaders(&cc.egui_ctx);

        Self { users }
    }
}

impl eframe::App for PlayerPicker {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for user in self.users.values_mut() {
                        ui.horizontal(|ui| {
                            let (_, rect) = ui.allocate_space(egui::vec2(50.0, 50.0));
                            let mut r2 = rect;
                            r2.max.x += ui.available_width();

                            let response =
                                ui.interact(r2, Id::new(user.id.clone()), Sense::click());
                            if response.clicked() {
                                user.selected = !user.selected;
                            }
                            let painter = ui.painter();
                            painter.rect_filled(
                                r2,
                                5.0,
                                if user.selected {
                                    egui::Color32::LIGHT_BLUE
                                } else {
                                    egui::Color32::LIGHT_GRAY
                                },
                            );
                            if let Some(base_url) = user.picture.as_ref() {
                                egui::Image::from_uri(base_url)
                                    .fit_to_exact_size(rect.shrink(5.0).size())
                                    .paint_at(ui, rect.shrink(5.0));
                            }
                            ui.label(&user.description);
                        });
                    }
                });
        });
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserProfileBatch<'t> {
    user_ids: &'t [&'t str],
    settings: &'t [&'t str],
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserProfileSettings {
    id: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserProfileEntry {
    id: String,
    settings: Vec<UserProfileSettings>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserProfileBatchResponse {
    profile_users: Vec<UserProfileEntry>,
}

pub struct ProfileUser {
    pub id: String,
    pub settings: std::collections::HashMap<String, String>,
    pub selected: bool,
    pub presense: String,
    pub picture: Option<String>,
    pub gamer_tag: String,
    pub description: String,
}

pub async fn fetch_user_profiles(
    client: &Client,
    token: &str,
    user_ids: &[&str],
) -> Result<HashMap<String, ProfileUser>, Box<dyn std::error::Error>> {
    let r = client
        .post("https://profile.xboxlive.com/users/batch/profile/settings")
        .header("x-xbl-contract-version", "2")
        .header("Authorization", token)
        .json(&UserProfileBatch {
            user_ids,
            settings: &[
                "AppDisplayName",
                "AppDisplayPicRaw",
                "GameDisplayName",
                "GameDisplayPicRaw",
                "Gamerscore",
                "Gamertag",
                "ModernGamertag",
                "ModernGamertagSuffix",
                "UniqueModernGamertag",
            ],
        })
        .send()
        .await?
        .json::<UserProfileBatchResponse>()
        .await?;

    let users = r
        .profile_users
        .into_iter()
        .map(|user| {
            let mut settings_map = std::collections::HashMap::new();
            for setting in user.settings {
                settings_map.insert(setting.id, setting.value);
            }
            let gt = settings_map
                .get("Gamertag")
                .map_or_else(|| String::new(), |f| f.clone());
            (
                user.id.clone(),
                ProfileUser {
                    id: user.id,
                    selected: false,
                    presense: String::new(),
                    picture: settings_map
                        .get("GameDisplayPicRaw")
                        .map(|f| format!("{}&w=128&h=128", f)),
                    gamer_tag: settings_map
                        .get("Gamertag")
                        .map_or_else(|| String::new(), |f| f.clone()),
                    settings: settings_map,
                    description: gt,
                },
            )
        })
        .collect::<std::collections::HashMap<_, _>>();

    Ok(users)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PeopleHubResponseEntry {
    pub is_friend: bool,
    pub xuid: String,
    pub gamertag: String,
    pub modern_gamertag: String,
    pub modern_gamertag_suffix: String,
    pub unique_modern_gamertag: String,
    pub presence_state: String,
    pub display_pic_raw: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PeopleHubResponse {
    people: Vec<PeopleHubResponseEntry>,
}

pub async fn fetch_friends(
    client: &Client,
    token: &str,
    xuid: &str,
) -> Result<HashMap<String, ProfileUser>, Box<dyn std::error::Error>> {
    let r = client
        .get(&format!(
            "https://peoplehub.xboxlive.com/users/xuid({})/people/friends/decoration/presenceDetail,preferredcolor",
            xuid
        ))
        .header("x-xbl-contract-version", "7")
        .header("Authorization", token)
        .header("Accept-Language", "en-US")// Required for no http 400
        .send()
        .await?;

    println!("Friends response: {} {:?}", r.status(), r.content_length());

    let t: PeopleHubResponse = r.json().await?;

    println!("Friends response text: {:?}", t);

    let mut out = HashMap::new();
    for entry in t.people {
        out.insert(
            entry.xuid.clone(),
            ProfileUser {
                id: entry.xuid,
                selected: false,
                description: format!("{} {}", entry.gamertag, entry.presence_state),
                presense: entry.presence_state,
                picture: Some(entry.display_pic_raw),
                gamer_tag: entry.gamertag,
                settings: HashMap::new(),
            },
        );
    }

    Ok(out)
}
