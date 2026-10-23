use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserstatsBatchRequest {
    pub groups: Vec<TitleName>,
    #[serde(rename = "arrangebyfield")]
    pub arrange_by_field: String,
    pub xuids: Vec<String>,
    pub stats: Vec<TitleName>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TitleName {
    pub name: String,
    pub title_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UserstatsBatchResponse {
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub statlistscollection: Vec<StatlistCollection>,
}

#[derive(Debug, Deserialize)]
pub struct Group {
    #[serde(default)]
    pub statlistscollection: Vec<StatlistCollection>,
    #[serde(rename = "titleid")]
    pub title_id: String,
}

#[derive(Debug, Deserialize)]
pub struct StatlistCollection {
    #[serde(default)]
    pub stats: Vec<StatsBody>,
}

#[derive(Debug, Deserialize)]
pub struct StatsBody {
    #[serde(rename = "titleid")]
    pub title_id: Option<String>,
    pub name: String,
    pub value: Option<String>,
    #[serde(rename = "type")]
    #[serde(default = "default_format")]
    pub kind: String,
    pub properties: Option<StatProperties>,
    #[serde(rename = "groupproperties")]
    pub group_properties: Option<StatProperties>,
}

#[derive(Debug, Deserialize)]
pub struct StatProperties {
    #[serde(rename = "DisplayName")]
    pub display_name: Option<String>,
}

fn default_format() -> String {
    "String".to_string()
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_deserialize_batch_response() {
        let json = r##"{
            "groups": [
                {
                "name": "Hero",
                "titleid": "896928775",
                "statlistscollection": [
                    {
                    "arrangebyfield": "xuid",
                    "arrangebyfieldid": "0",
                    "stats": [
                        {
                        "groupproperties": {
                            "Ordinal": "1",
                            "SortOrder": "Descending",
                            "DisplayName": "Blocks Broken",
                            "DisplayFormat": "Integer",
                            "DisplaySemantic": "Cumulative"
                        },
                        "xuid": "",
                        "scid": "4fc10100-5f7a-4470-899b-280835760c07",
                        "name": "BlockBrokenTotal",
                        "type": "Integer",
                        "value": "0",
                        "properties": {
                            "DisplayName": "Blocks Broken"
                        }
                        },
                        {
                        "groupproperties": {
                            "Ordinal": "2",
                            "SortOrder": "Descending",
                            "DisplayName": "Monsters Killed",
                            "DisplayFormat": "Integer",
                            "DisplaySemantic": "Cumulative"
                        },
                        "xuid": "",
                        "scid": "4fc10100-5f7a-4470-899b-280835760c07",
                        "name": "MobKilled.IsMonster.1",
                        "type": "Integer",
                        "value": "0",
                        "properties": {
                            "DisplayName": "Monsters Killed"
                        }
                        },
                        {
                        "groupproperties": {
                            "Ordinal": "3",
                            "SortOrder": "Descending",
                            "DisplayName": "Distance Travelled",
                            "DisplayFormat": "Integer",
                            "DisplaySemantic": "Cumulative"
                        },
                        "xuid": "",
                        "scid": "4fc10100-5f7a-4470-899b-280835760c07",
                        "name": "DistanceTravelled",
                        "type": "Double",
                        "value": "0.0",
                        "properties": {
                            "DisplayName": "Distance Travelled"
                        }
                        }
                    ]
                    }
                ]
                }
            ],
            "statlistscollection": [
                {
                "arrangebyfield":"xuid",
                "arrangebyfieldid":"0",
                "stats": [
                    {
                    "groupproperties": {},
                    "xuid": "",
                    "scid": "4fc10100-5f7a-4470-899b-280835760c07",
                    "titleid": "896928775",
                    "name": "MinutesPlayed",
                    "type": "Integer",
                    "value": "0",
                    "properties": {}
                    }
                ]
                }
            ]
        }"##;

        let parsed: UserstatsBatchResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.groups.len(), 1);
        assert_eq!(parsed.groups[0].title_id, "896928775");
        assert_eq!(parsed.groups[0].statlistscollection[0].stats.len(), 3);
        assert_eq!(parsed.statlistscollection[0].stats[0].name, "MinutesPlayed");
        assert_eq!(
            parsed.statlistscollection[0].stats[0]
                .properties
                .as_ref()
                .unwrap()
                .display_name,
            None
        );
        assert_eq!(
            parsed.statlistscollection[0].stats[0].title_id.as_deref(),
            Some("896928775")
        );
        let hero = &parsed.groups[0].statlistscollection[0].stats;
        assert_eq!(hero[0].kind, "Integer");
        assert_eq!(hero[0].title_id, None);
        assert_eq!(
            hero[0].properties.as_ref().unwrap().display_name.as_deref(),
            Some("Blocks Broken")
        );
        assert_eq!(
            hero[0]
                .group_properties
                .as_ref()
                .unwrap()
                .display_name
                .as_deref(),
            Some("Blocks Broken")
        );
        assert_eq!(hero[2].kind, "Double");
        assert_eq!(hero[2].value.as_deref(), Some("0.0"));
    }

    #[test]
    fn test_deserialize_empty_response() {
        let parsed: UserstatsBatchResponse = serde_json::from_str("{}").unwrap();
        assert!(parsed.groups.is_empty());
        assert!(parsed.statlistscollection.is_empty());
    }
}
