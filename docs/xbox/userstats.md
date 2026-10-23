# Userstats

Used by `get_userstats` to fetch a user's featured ("Hero") stats and `MinutesPlayed` for each title.

### Endpoint
```
POST https://userstats.xboxlive.com/batch
```

### Headers
```
x-xbl-contract-version: 2
Authorization: XBL3.0 x=<uhs>;<xsts>
```

### Request
`groups` requests every stat in a named group. `stats` requests single stats by name.
There is no way to list every stat a title has; stats can only be requested by group or by name.
```
{
  "arrangebyfield": "xuid",
  "xuids": ["<xuid>", ...],
  "groups": [{ "name": "Hero", "titleId": "<title_id>" }, ...],
  "stats": [{ "name": "MinutesPlayed", "titleId": "<title_id>" }, ...]
}
```

### Response
Group stats are returned under `groups`, stats requested by name under the top-level `statlistscollection`.
```
{
  "groups": [
    {
      "name": "Hero",
      "titleid": "<title_id>",
      "statlistscollection": [
        {
          "arrangebyfield": "xuid",
          "arrangebyfieldid": "",
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
              "scid": "<scid>",
              "name": "BlockBrokenTotal",
              "type": "Integer",
              "value": "0",
              "properties": { "DisplayName": "Blocks Broken" }
            },
            ...
          ]
        }
      ]
    }
  ],
  "statlistscollection": [
    {
      "arrangebyfield": "xuid",
      "arrangebyfieldid": "<xuid>",
      "stats": [
        {
          "groupproperties": {},
          "xuid": "",
          "scid": "<scid>",
          "titleid": "<title_id>",
          "name": "MinutesPlayed",
          "type": "Integer",
          "value": "<minutes>",
          "properties": {}
        }
      ]
    }
  ]
}
```

Notes:
- Stats inside a group have no `titleid`; the title is on the group. Top-level stats carry their own `titleid`.
- `value` is always a string. `type` gives its type (`Integer`, `Double`, ...).
- `DisplayName` can be in `properties`, `groupproperties` or neither. `MinutesPlayed` has neither.

### References
- [Featured stats overview](https://learn.microsoft.com/en-us/gaming/gdk/docs/services/player-data/stats-leaderboards/featured-stats/live-featuredstats-overview?view=gdk-2604)
- [userstats REST reference](https://learn.microsoft.com/en-us/gaming/gdk/docs/reference/live/rest/uri/userstats/atoc-reference-userstats?view=gdk-2604)
