use std::collections::BTreeMap;
use std::error::Error;

use tokio::sync::OnceCell;

use xodus_peer::proto::xodus::userstats::*;

use xodus::api::xbox::title::{get_endpoint, get_title_management};
use xodus::api::xbox::userstats::get_userstats;
use xodus::api::xbox::{get_xsts_auth_header, run};
use xodus::models::secrets::Token;
use xodus::models::xbox::userstats::UserstatsBatchResponse;
use xodus::tokens::TokenManager;
use xodus::tokens::store::TokenStoreError;

pub struct Userstats {
    client: reqwest::Client,
    tokens: TokenManager,
    relying_party: OnceCell<String>,
}

impl Userstats {
    pub fn new(client: &reqwest::Client, tokens: &TokenManager) -> Self {
        Self {
            client: client.clone(),
            tokens: tokens.clone(),
            relying_party: OnceCell::new(),
        }
    }

    async fn get_relying_party(&self) -> Result<&str, Box<dyn Error + Send + Sync>> {
        let url = self
            .relying_party
            .get_or_try_init(|| async {
                let title_mgt_response = get_title_management(&self.client).await?;
                let relying_party =
                    get_endpoint("https://userstats.xboxlive.com", &title_mgt_response)
                        .and_then(|e| e.relying_party.clone())
                        .ok_or("no relying party for host")?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(relying_party)
            })
            .await?;
        Ok(url)
    }
}

impl UserstatsService for Userstats {
    async fn get_userstats(
        &self,
        req: GetUserstatsRequest,
    ) -> Result<GetUserstatsResponse, Box<dyn Error + Send + Sync>> {
        if req.xuid == 0 {
            return Ok(GetUserstatsResponse {
                titles: Vec::new(),
                error: UserstatsError::NotSignedIn as i32,
            });
        }

        if req.title_ids.is_empty() {
            return Ok(GetUserstatsResponse {
                titles: Vec::new(),
                error: UserstatsError::EmptyList as i32,
            });
        }

        let relying_party = self.get_relying_party().await?;

        let xsts_token = match self.tokens.get_cached_xsts(relying_party) {
            Some(tok) => tok,
            None => {
                let dev_token = self.tokens.get_device_sts_token()?;
                let Token::Legacy(dev_token) = dev_token else {
                    return Err("device STS token is not a legacy token".into());
                };

                let user_token = match self.tokens.get_user_sts_token() {
                    Ok(tok) => tok,
                    Err(TokenStoreError::NotFound) => {
                        return Ok(GetUserstatsResponse {
                            titles: Vec::new(),
                            error: UserstatsError::NotSignedIn as i32,
                        });
                    }
                    Err(e) => return Err(e.into()),
                };
                let Token::Legacy(legacy) = user_token else {
                    return Err("user STS token is not a legacy token".into());
                };

                let tok = run(&self.client, dev_token, legacy, relying_party).await;
                self.tokens.cache_xsts(relying_party, &tok);
                tok
            }
        };

        let parsed = get_userstats(
            &self.client,
            &get_xsts_auth_header(xsts_token),
            &req.xuid.to_string(),
            &req.title_ids,
        )
        .await?;

        let titles = to_title_stats(parsed, &req.title_ids);

        Ok(GetUserstatsResponse {
            titles,
            error: UserstatsError::Ok as i32,
        })
    }
}

fn to_title_stats(parsed: UserstatsBatchResponse, title_ids: &[u32]) -> Vec<TitleStats> {
    // Move stats to tuples
    let title_groups = parsed.groups.into_iter().flat_map(|group| {
        let title_id = group.title_id;
        group
            .statlistscollection
            .into_iter()
            .flat_map(|list| list.stats)
            .map(move |s| (title_id.clone(), s))
    });

    let outside_title_groups = parsed
        .statlistscollection
        .into_iter()
        .flat_map(|list| list.stats)
        .filter_map(|s| Some((s.title_id.clone()?, s)));

    // Remove any duplicate stats. Every requested title gets an entry, even with no stats.
    let mut no_duplicates: BTreeMap<u32, Vec<Stat>> =
        title_ids.iter().map(|&id| (id, Vec::new())).collect();
    for (id, stat) in title_groups.chain(outside_title_groups) {
        // Use tuple ids to check validity
        let Ok(id) = id.parse::<u32>() else { continue };

        // Use tuple stat names to check for duplicates.
        let stats = no_duplicates.entry(id).or_default();
        if stats.iter().any(|x| x.name == stat.name) {
            continue;
        }

        // Generate a stat body for the client to receive
        stats.push(Stat {
            display_name: stat
                .properties
                .and_then(|p| p.display_name)
                .or(stat.group_properties.and_then(|p| p.display_name))
                .unwrap_or_else(|| stat.name.clone()),
            name: stat.name,
            value: stat.value.unwrap_or_default(),
            stat_type: stat.kind,
        })
    }

    no_duplicates
        .into_iter()
        .map(|(title_id, stats)| TitleStats { title_id, stats })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_not_signed_in() {
        let client = reqwest::Client::new();
        let tokens = TokenManager::with_memory();

        let svc = Userstats::new(&client, &tokens);
        let resp = svc
            .get_userstats(GetUserstatsRequest {
                xuid: 0,
                title_ids: vec![1705097731],
            })
            .await
            .unwrap();
        assert_eq!(resp.error, UserstatsError::NotSignedIn as i32);
        assert!(resp.titles.is_empty());
    }

    #[ignore]
    #[tokio::test]
    async fn test_get_userstats() {
        let client = reqwest::Client::new();
        xodus::secrets::init_secrets().expect("Unable to initialize credentials");
        let tokens = TokenManager::with_keychain_and_memory();
        xodus::tokens::device::ensure_device_credentials(&client, &tokens).await;

        let svc = Userstats::new(&client, &tokens);
        let xuid = std::env::var("XUID").expect("set XUID").parse().unwrap();
        let resp = svc
            .get_userstats(GetUserstatsRequest {
                xuid,
                title_ids: vec![1705097731, 1810111157],
            })
            .await
            .unwrap();
        println!("{resp:?}");
    }

    #[ignore]
    #[tokio::test]
    async fn test_cache_token() {
        let client = reqwest::Client::new();
        xodus::secrets::init_secrets().expect("Unable to initialize credentials");
        let tokens = TokenManager::with_keychain_and_memory();
        xodus::tokens::device::ensure_device_credentials(&client, &tokens).await;
        let svc = Userstats::new(&client, &tokens);
        let rp = svc.get_relying_party().await.unwrap();
        assert!(tokens.get_cached_xsts(rp).is_none());
        let xuid = std::env::var("XUID").expect("set XUID").parse().unwrap();
        let resp = svc
            .get_userstats(GetUserstatsRequest {
                xuid,
                title_ids: vec![1705097731],
            })
            .await
            .unwrap();
        assert!(tokens.get_cached_xsts(rp).is_some());
        println!("{resp:?}");
        let resp = svc
            .get_userstats(GetUserstatsRequest {
                xuid,
                title_ids: vec![1810111157],
            })
            .await
            .unwrap();
        assert_eq!(resp.error, UserstatsError::Ok as i32);
        println!("{resp:?}");
    }

    #[test]
    fn test_to_title_stats() {
        let json = r##"{ "groups": [
            {
                "name": "Hero",
                "titleid": "896928775",
                "statlistscollection": [
                    {
                        "arrangebyfield": "xuid",
                        "arrangebyfieldid": "0",
                        "stats": [
                            {
                                "name": "BlockBrokenTotal",
                                "type": "Integer",
                                "value": "5",
                                "properties": { "DisplayName": "Blocks Broken" },
                                "groupproperties": { "DisplayName": "Group Blocks Broken" }
                            },
                            {
                                "name": "MobKilled",
                                "type": "Integer",
                                "value": "3",
                                "properties": null,
                                "groupproperties": { "DisplayName": "Monsters Killed" }
                            },
                            {
                                "name": "DistanceTravelled",
                                "value": "1.5",
                                "properties": { "DisplayName": "Distance Travelled" },
                                "groupproperties": {}
                            },
                            {
                                "name": "MinutesPlayed",
                                "type": "Integer",
                                "value": "10",
                                "properties": {},
                                "groupproperties": {}
                            }
                        ]
                    }
                ]
            }
        ],
        "statlistscollection": [
            {
                "arrangebyfield": "xuid",
                "arrangebyfieldid": "0",
                "stats": [
                    {
                        "titleid": "896928775",
                        "name": "MinutesPlayed",
                        "type": "Integer",
                        "value": "99",
                        "properties": {},
                        "groupproperties": {}
                    },
                    {
                        "titleid": "not-a-number",
                        "name": "MinutesPlayed",
                        "type": "Integer",
                        "value": "7",
                        "properties": {},
                        "groupproperties": {}
                    }
                ]
            }
        ] }"##;
        let parsed = serde_json::from_str(json).unwrap();
        let titles = to_title_stats(parsed, &[896928775, 999999999]);

        let names: Vec<_> = titles[0].stats.iter().map(|s| s.name.as_str()).collect();
        let stats = &titles[0].stats;
        // Correct names
        assert_eq!(
            names,
            [
                "BlockBrokenTotal",
                "MobKilled",
                "DistanceTravelled",
                "MinutesPlayed"
            ]
        );
        // Use .properties name instead of .group_properties when available
        assert_eq!(stats[0].display_name, "Blocks Broken");
        // null .properties uses .group_properties
        assert_eq!(stats[1].display_name, "Monsters Killed");
        // default value is String
        assert_eq!(stats[2].stat_type, "String");
        // fallback value correct
        assert_eq!(stats[3].display_name, "MinutesPlayed");
        // Should use group's value rather than duplicate
        assert_eq!(stats[3].value, "10");
        // Requested title with no stats still gets an entry (999999999)
        assert_eq!(titles.len(), 2);
        assert!(titles[1].stats.is_empty());
    }
}
