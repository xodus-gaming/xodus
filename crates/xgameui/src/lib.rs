use std::collections::HashMap;

use eframe::{CreationContext, egui};
use egui::{Id, Pos2, Sense};
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
                            let (_, rect) = ui.allocate_space(egui::vec2(200.0, 150.0));
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

#[derive(Default)]
pub struct ShowAchievments {
    achievements: Vec<AchievementEntry>,
    search: String,
    status_filter: String,
}

impl ShowAchievments {
    pub fn new(cc: &CreationContext<'_>, achievements: Vec<AchievementEntry>) -> Self {
        egui_extras::install_image_loaders(&cc.egui_ctx);
        let s = Self {
            achievements,
            search: String::new(),
            status_filter: "All".to_string(),
        };
        s
    }
}

impl eframe::App for ShowAchievments {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("top_bar")
            .min_size(60.0)
            .max_size(100.0)
            .show(ui, |ui| {
                egui::Panel::right("my_filter_panel")
                    .show_separator_line(false)
                    .min_size(100.0)
                    .show(ui, |ui| {
                        ui.centered_and_justified(|ui| {
                            egui::ComboBox::from_label("Status")
                                .selected_text(&self.status_filter)
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut self.status_filter,
                                        "All".to_string(),
                                        "All",
                                    );
                                    ui.selectable_value(
                                        &mut self.status_filter,
                                        "Achieved".to_string(),
                                        "Achieved",
                                    );
                                    ui.selectable_value(
                                        &mut self.status_filter,
                                        "NotStarted".to_string(),
                                        "NotStarted",
                                    );
                                    ui.selectable_value(
                                        &mut self.status_filter,
                                        "InProgress".to_string(),
                                        "InProgress",
                                    );
                                })
                        });
                    });
                ui.centered_and_justified(|ui| {
                    ui.text_edit_singleline(&mut self.search);
                });
            });
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for achievement in &self.achievements {
                        if !self.search.is_empty()
                            && achievement
                                .name
                                .to_lowercase()
                                .contains(&self.search.to_lowercase())
                                == false
                            && achievement
                                .description
                                .to_lowercase()
                                .contains(&self.search.to_lowercase())
                                == false
                        {
                            continue;
                        }
                        if !self.status_filter.is_empty()
                            && self.status_filter != "All"
                            && achievement.progress_state != self.status_filter
                        {
                            continue;
                        }
                        ui.horizontal(|ui| {
                            let (_, rect) = ui.allocate_space(egui::vec2(200.0, 150.0));
                            let mut r2 = rect;
                            r2.max.x += ui.available_width();

                            let painter = ui.painter();
                            painter.rect_filled(
                                r2,
                                5.0,
                                if achievement.progress_state == "Achieved" {
                                    egui::Color32::LIGHT_GREEN
                                } else {
                                    egui::Color32::LIGHT_GRAY
                                },
                            );
                            if let Some(base_url) = achievement.media_assets.get(0).map(|f| &f.url)
                            {
                                egui::Image::from_uri(base_url)
                                    .fit_to_exact_size(rect.shrink(5.0).size())
                                    .paint_at(ui, rect.shrink(5.0));
                            }
                            // TODO new struct for holding the string without realloc
                            ui.label(format!(
                                "{}\nStatus {}\nReward {}G\n{}",
                                achievement.name,
                                achievement.progress_state,
                                achievement
                                    .rewards
                                    .iter()
                                    .find(|p| p.type_ == "Gamerscore")
                                    .map(|p| p.value.clone())
                                    .unwrap_or_else(|| "".to_string()),
                                achievement.description
                            ));
                            let mut i = 0 as f32;
                            let size = achievement.rewards.len() as f32;
                            for rew in &achievement.rewards {
                                if let Some(media) = &rew.media_asset {
                                    let draw = egui::Rect {
                                        min: Pos2 {
                                            x: r2.right()
                                                - (size - i) * (r2.bottom() - r2.top()) * 3.0 / 2.0,
                                            y: r2.top(),
                                        },
                                        max: Pos2 {
                                            x: r2.right()
                                                - (size - i - 1.0) * (r2.bottom() - r2.top()) * 3.0
                                                    / 2.0,
                                            y: r2.bottom(),
                                        },
                                    };
                                    ui.horizontal(|ui| {
                                        egui::Image::from_uri(&media.url)
                                            .fit_to_exact_size(draw.shrink(5.0).size())
                                            .paint_at(ui, draw.shrink(5.0));
                                    });
                                }
                                i += 1.0;
                                // ui.label(format!("Reward {}: {} ({})", rew.type_, rew.value, rew.value_type));
                            }
                            achievement
                                .progression
                                .requirements
                                .iter()
                                .map(|f| {
                                    if let Some(c) = &f.current {
                                        if c == &f.target {
                                            return 1.0;
                                        }
                                        return (c.parse::<f32>().unwrap_or(0.0)
                                            / f.target.parse::<f32>().unwrap_or(1.0))
                                        .min(1.0);
                                    }
                                    0.0
                                })
                                .map(|f| (f, 1.0))
                                .reduce(|l, r| (l.0 + r.0, l.1 + r.1))
                                .map(|f| {
                                    println!("{}: {} {}", f.0, f.1, f.0 / f.1);
                                    let progress = f.0 / f.1;
                                    let draw = egui::Rect {
                                        min: Pos2 {
                                            x: r2.left(),
                                            y: r2.bottom() - 10.0,
                                        },
                                        max: Pos2 {
                                            x: r2.left() + (r2.right() - r2.left()) * progress,
                                            y: r2.bottom(),
                                        },
                                    };
                                    ui.horizontal(|ui| {
                                        let painter = ui.painter();
                                        painter.rect_filled(
                                            draw,
                                            5.0,
                                            if progress >= 1.0 {
                                                egui::Color32::DARK_GREEN
                                            } else {
                                                egui::Color32::DARK_GRAY
                                            },
                                        );
                                    });
                                });
                            // achievement.progression.requirements.iter().for_each(|p| {
                            //     ui.label(format!("Requirement {}: {}/{}", p.id, p.current.as_ref().map(|f| f.to_string()).unwrap_or_else(||"0".to_string()), p.target));
                            // });
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
        .error_for_status()?
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
        .await?
        .error_for_status()?;

    let t: PeopleHubResponse = r.json().await?;

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
        .error_for_status()?
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AchievementReward {
    value: String,
    #[serde(rename = "type")]
    type_: String,
    value_type: String,
    media_asset: Option<AchievementMediaAsset>,
    name: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AchievementMediaAsset {
    url: String,
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Progression {
    requirements: Vec<ProgressionRequirement>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressionRequirement {
    id: String,
    current: Option<String>,
    target: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AchievementEntry {
    id: String,
    name: String,
    progress_state: String,
    progression: Progression,
    media_assets: Vec<AchievementMediaAsset>,
    description: String,
    rewards: Vec<AchievementReward>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PagingInfo {
    continuation_token: Option<String>,
    total_records: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AchievementsResponse {
    achievements: Vec<AchievementEntry>,
    paging_info: PagingInfo,
}

pub async fn fetch_achivements(
    client: &Client,
    token: &str,
    xuid: &str,
    title_id: i64,
) -> Result<HashMap<String, ProfileUser>, Box<dyn std::error::Error>> {
    let r = client
        .get(
            format!("https://achievements.xboxlive.com/users/xuid({xuid})/achievements?titleId={title_id}&maxItems=1000&includeHidden=true"),
        )
        .header("x-xbl-contract-version", "2")
        .header("Authorization", token)
        .header("Accept-Language", "de-DE")// Required for no http 400
        .send()
        .await?
        .error_for_status()?;

    let t = r.json::<AchievementsResponse>().await?;

    let mut out = HashMap::new();
    for entry in t.achievements {
        out.insert(
            entry.id.clone(),
            ProfileUser {
                id: entry.id,
                selected: false,
                description: format!(
                    "{}\nStatus {}\nReward {}G\n{}",
                    entry.name,
                    entry.progress_state,
                    entry
                        .rewards
                        .iter()
                        .find(|p| p.type_ == "Gamerscore")
                        .map(|p| p.value.clone())
                        .unwrap_or_else(|| "".to_string()),
                    entry.description
                ),
                presense: String::new(),
                picture: entry.media_assets.get(0).map(|f| format!("{}", f.url)),
                gamer_tag: String::new(),
                settings: HashMap::new(),
            },
        );
    }
    Ok(out)
}

pub async fn fetch_achivements_2(
    client: &Client,
    token: &str,
    xuid: &str,
    title_id: i64,
) -> Result<Vec<AchievementEntry>, Box<dyn std::error::Error>> {
    let r = client
        .get(
            format!("https://achievements.xboxlive.com/users/xuid({xuid})/achievements?titleId={title_id}&maxItems=1000&includeHidden=true"),
        )
        .header("x-xbl-contract-version", "2")
        .header("Authorization", token)
        .header("Accept-Language", "en-US")// Required for no http 400
        .send()
        .await?
        .error_for_status()?;

    let t: AchievementsResponse = r.json::<AchievementsResponse>().await?;

    println!(
        "Fetched {} achievements of {}",
        t.achievements.len(),
        t.paging_info.total_records
    );

    Ok(t.achievements)
}
