use std::collections::HashMap;

use eframe::{CreationContext, egui};
use egui::{Id, Sense};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

pub struct SearchFeature {
    search: String,
    search_results: HashMap<String, ProfileUser>,
    access_token: String,
    tokio_runtime: tokio::runtime::Runtime,
    result: mpsc::Receiver<HashMap<String, ProfileUser>>,
    sender: mpsc::Sender<HashMap<String, ProfileUser>>,
}

#[derive(Default)]
pub struct PlayerPicker {
    users: HashMap<String, ProfileUser>,
    submit: String,
    search: Option<SearchFeature>,
}

impl PlayerPicker {
    pub fn new(
        cc: &CreationContext<'_>,
        users: HashMap<String, ProfileUser>,
        access_token: Option<String>,
    ) -> Self {
        egui_extras::install_image_loaders(&cc.egui_ctx);
        let (tx, rx) = mpsc::channel(1);
        let mut s = Self {
            users,
            submit: String::new(),
            search: access_token.map(|token| SearchFeature {
                search: String::new(),
                search_results: HashMap::new(),
                access_token: token,
                tokio_runtime: tokio::runtime::Runtime::new().unwrap(),
                result: rx,
                sender: tx,
            }),
        };

        s.submit = s.get_submit_text();

        s
    }
}

impl PlayerPicker {
    fn get_submit_text(&self) -> String {
        format!(
            "Selected {} Player",
            self.users.iter().filter(|f| f.1.selected).count()
        )
    }
}

impl eframe::App for PlayerPicker {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if let Some(search) = &mut self.search {
            if let Ok(users) = search.result.try_recv() {
                search.search_results = users;
            }
            egui::Panel::top("top_bar")
                .min_size(60.0)
                .max_size(100.0)
                .show(ui, |ui| {
                    egui::Panel::right("search_pane")
                        .show_separator_line(false)
                        .max_size(100.0)
                        .show(ui, |ui| {
                            ui.centered_and_justified(|ui| ui.button("Search"));
                        });
                    ui.centered_and_justified(|ui| {
                        if ui.text_edit_singleline(&mut search.search).changed() {
                            if search.search.is_empty() {
                                search.search_results.clear();
                                return;
                            }
                            let query = search.search.clone();
                            let token = search.access_token.clone();
                            let sender = search.sender.clone();
                            search.tokio_runtime.spawn(async move {
                                let client = reqwest::Client::new();
                                sender
                                    .send(
                                        fetch_gt_tokio(&client, &token, &query)
                                            .await
                                            .unwrap_or_default(),
                                    )
                                    .await
                                    .expect("Failed to send search results");
                            });
                        }
                    });
                });
        }
        egui::Panel::bottom("bottom_bar")
            .show_separator_line(false)
            .show(ui, |ui| {
                ui.centered_and_justified(|ui| if ui.button(&self.submit).clicked() {});
            });

        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let mut changed = false;
                    let default = &mut self.users;
                    let it_org = self
                        .search
                        .as_mut()
                        .and_then(|t| {
                            if t.search_results.is_empty() {
                                None
                            } else {
                                Some(t)
                            }
                        })
                        .map(|s| &mut s.search_results);
                    let was_search = it_org.is_some();
                    let it = it_org.unwrap_or(default).values_mut();
                    for user in it {
                        ui.horizontal(|ui| {
                            let (_, rect) = ui.allocate_space(egui::vec2(50.0, 50.0));
                            let mut r2 = rect;
                            r2.max.x += ui.available_width();

                            let response =
                                ui.interact(r2, Id::new(user.id.clone()), Sense::click());
                            if response.clicked() {
                                user.selected = !user.selected;
                                changed = true;
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
                    if changed {
                        self.submit = self.get_submit_text();
                        if was_search {
                            for u in self.search.as_ref().unwrap().search_results.values() {
                                if u.selected {
                                    self.users.insert(
                                        u.id.clone(),
                                        ProfileUser {
                                            id: u.id.clone(),
                                            settings: u.settings.clone(),
                                            selected: true,
                                            presense: u.presense.clone(),
                                            picture: u.picture.clone(),
                                            gamer_tag: u.gamer_tag.clone(),
                                            description: u.description.clone(),
                                        },
                                    );
                                }
                            }
                            self.search.as_mut().unwrap().search_results.clear();
                        }
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

async fn parse_user_profile_response(r: &UserProfileBatchResponse) -> HashMap<String, ProfileUser> {
    let users = r
        .profile_users
        .iter()
        .map(|user| {
            let mut settings_map = std::collections::HashMap::new();
            for setting in &user.settings {
                settings_map.insert(setting.id.clone(), setting.value.clone());
            }
            let gt = settings_map
                .get("Gamertag")
                .map_or_else(|| String::new(), |f| f.clone());
            (
                user.id.clone(),
                ProfileUser {
                    id: user.id.clone(),
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

    users
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

    Ok(parse_user_profile_response(&r).await)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PeopleHubResponseEntry {
    pub xuid: String,
    pub gamertag: String,
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
) -> Result<HashMap<String, ProfileUser>, Box<dyn std::error::Error>> {
    let r = client
        .get(
            "https://peoplehub.xboxlive.com/users/me/people/friends/decoration/presenceDetail,preferredcolor",
        )
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

pub async fn fetch_gt(
    client: &Client,
    token: &str,
    gamer_tag: &str,
) -> Result<HashMap<String, ProfileUser>, Box<dyn std::error::Error>> {
    let r = client
        .get(
            format!(
                "https://profile.xboxlive.com/users/gt({})/profile/settings?settings=GameDisplayPicRaw,Gamertag",
                gamer_tag
            ),
        )
        .header("x-xbl-contract-version", "2")
        .header("Authorization", token)
        .send()
        .await?
        .json::<UserProfileBatchResponse>()
        .await?;

    Ok(parse_user_profile_response(&r).await)
}

pub async fn fetch_gt_tokio(
    client: &Client,
    token: &str,
    gamer_tag: &str,
) -> Option<HashMap<String, ProfileUser>> {
    match fetch_gt(client, token, gamer_tag).await {
        Ok(users) => Some(users),
        Err(e) => {
            eprintln!("Error fetching user profiles: {}", e);
            None
        }
    }
}
