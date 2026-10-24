# Game Pass endpoints

All verified September 2026 with `market=US` unless noted.

| Endpoint | Auth | Use |
|---|---|---|
| [`/subscriptions`](#catalog-lists) | none | Product IDs per catalog list |
| [`/sigls/v3`](#sigl-lists) | none | Games per subscription and platform |
| [`/misc/pc-pfns-list`](#pc-packagefamilynames) | none | PackageFamilyNames of PC games |
| [`/pcsubscriptions`](#subscription-metadata) | none | Per-product tier metadata |
| [`beige.xboxservices.com/.../subscriptions`](#subscription-entitlements) | MSA ticket | User's active subscriptions |

## Subscription IDs

| ID | Subscription |
|---|---|
| `CFQ7TTC0K5DJ` | Xbox Game Pass Essential (formerly Core) |
| `CFQ7TTC0P85B` | Xbox Game Pass Premium (formerly Standard) |
| `CFQ7TTC0KHS0` | Xbox Game Pass Ultimate |
| `CFQ7TTC0KGQ8` | PC Game Pass |
| `CFQ7TTC0K6L8` | Xbox Game Pass for Console (retired) |
| `CFQ7TTC10QFD` | Xbox Game Pass (Starter Edition) |
| `CFQ7TTC0HXBN` | Unknown, returned with entitlements |

## Catalog lists

```
GET https://catalog.gamepass.com/subscriptions?market={MARKET}
```

- `MARKET` must be uppercase, `market=us` returns `404 {"reason":"InvalidSubscriptionType"}`
- Returns store product IDs (displaycatalog `bigIds`) grouped by list name
- Lists include add-ons, displaycatalog `ProductKind` is `Game`, `Durable` or `Consumable`
- Supports `ETag`, `cache-control: public, max-age=` varies (115-250 seen)

```json
{"pc":["9MSMN2PJ6HQN","9MSVBF0KZFVW", ...],"console":[...], ...}
```

List names don't reference subscription IDs. Mapping inferred from list overlap and [SIGL](#sigl-lists) results:

| List | Subscription | Notes |
|---|---|---|
| `xgpp` | Essential | Games catalog only |
| `gamepasscore` | Essential | `xgpp` + 44 free-to-play games with member perks |
| `gamepassstandard` | Premium | Superset of `gamepasscore` |
| `pc` | PC Game Pass | Also has EA Play and day-one titles missing from `gamepassstandard` |
| `ultimate` | Ultimate | Free-to-play perk games (Fortnite, Genshin Impact, Warzone), not the Ultimate catalog |
| `nakupc` | Ultimate | Ubisoft+ Classics for PC |

`console`, `eaaccess`, `ubisoftplus`, `nakuconsole`, `gtaplus` are unverified.

Titles for many products at once (~700 IDs per request worked):
```
GET https://displaycatalog.mp.microsoft.com/v7.0/products?bigIds={ID1},{ID2}&market={MARKET}&languages={LANGUAGES}
```

## SIGL lists

```
GET https://catalog.gamepass.com/sigls/v3/?language={LANGUAGE}&market={MARKET}&id={SIGL_ID}&platformContext=pc&subscriptionContext={SUBSCRIPTION_ID}
```

Returns games only (no add-ons), filtered by subscription and platform. First element is list metadata (`siglId`, `title`, `description`, `requiresShuffling`, `imageUrl`), the rest are `{"id": "<product id>"}`.

- `platformContext` and `subscriptionContext` are required, `400` otherwise
- Unknown `subscriptionContext` returns `400 Invalid subscription`
- `pc` is the only known `platformContext`, `console`, `xbox`, `cloud`, `windows` and numbers are rejected

| SIGL ID | Title |
|---|---|
| `fdd9e2a7-0fee-49f6-ad69-4354098401ff` | All PC Games |
| `f6f1f99f-9b49-4ccd-b3bf-4d9767a77f5e` | All Console Games |
| `29a81209-df6f-41fd-a528-2ae6b91f719c` | All games |

Game count per subscription (`platformContext=pc`):

| Subscription | All PC Games | All games | All Console Games |
|---|---|---|---|
| Essential | 0 | 56 | 0 |
| Premium | 0 | 278 | 0 |
| PC Game Pass | 476 | 319 | 0 |
| Ultimate | 518 | 319 | 323 |

Each result is a subset of its [catalog list](#catalog-lists):
- Essential: all in `gamepasscore`, 35 from `xgpp` + 21 free-to-play perk games
- Premium: all in `gamepassstandard`
- PC Game Pass: all in `pc`
- Ultimate: all 476 PC Game Pass games + 41 Ubisoft+ Classics from `nakupc` + Fortnite

Other versions:
- `sigls/v2` ignores `subscriptionContext` (a bogus ID returns the same full list), can't filter per subscription
- `sigls/v1` and `sigls/v4` return `409 PublicAccessNotPermitted`

## PC PackageFamilyNames

```
GET https://catalog.gamepass.com/misc/pc-pfns-list
```

- Supports `ETag`, sending it back in `If-None-Match` returns `304 Not Modified`
- Matches displaycatalog `Properties.PackageFamilyName`, every `pc` game with one is in the list
- Takes no market and has more than the `pc` list:
  - free-to-play perk games from other lists (Fortnite, Rocket League, Genshin Impact)
  - region-specific titles, e.g. Japanese "Z Version" Resident Evil editions only in `pc` for `market=JP`
  - unreleased titles, e.g. Fable

Use `/subscriptions` for what's currently available.

```json
{"PackageFamilyNames":[
"10192RubberBandGames.WobblyLife_cy31b6rjjkmkj",
"11443ChasingCarrotsGmbHCo.HallsofTorment_xfxtxadz31m7r",
...
]}
```

## Subscription metadata

```
GET https://catalog.gamepass.com/pcsubscriptions?market={MARKET}&language={LANGUAGE}
```

Keyed by product ID. Per product: `XCloudEnabled`, `RecursiveChildren` (bundle contents) and `*SubMetadata` per list (`PCSubMetadata`, `StandardSubMetadata`, ...) with `Included` and `EntranceDate`.

## Subscription entitlements

Used by the Xbox PC app to check the user's Game Pass subscriptions.

```
POST https://beige.xboxservices.com/PCGAFD/entitlements/subscriptions?market={MARKET}&language={LANGUAGE}
x-ms-api-version: 1.1
authorization: {MSA_TICKET}
ms-cv: {CORRELATION_VECTOR}
Content-Type: application/json

{"productIds":["CFQ7TTC0K6L8","CFQ7TTC0K5DJ","CFQ7TTC0KGQ8","CFQ7TTC0P85B","CFQ7TTC0KHS0","CFQ7TTC10QFD", "CFQ7TTC0HXBN"]}
```

- `authorization` is a compact MSA user ticket for `www.microsoft.com` with `MBI_SSL` policy, same as for `licensing.mp.microsoft.com`.
- `ms-cv` is required. Without it: `400 {"MissingHeader":["Header MS-CV is missing"]}`
- The Xbox app also sends `x-ms-authorization-social: XBL3.0 x=...`, `usersegments` and `appVersion={APP_VERSION}`, none are required
- `productIds` are [subscription IDs](#subscription-ids)
- Note: `CFQ7TTC0HXBN` returns here, but is not a valid subscriptionContext per the SIGL lists. Returns with `"Invalid subscription 'CFQ7TTC0HXBN' in SubscriptionContextParameter."`

Without an active subscription:
```json
{"entitlements":{}}
```

With an active subscription, keyed by subscription ID:
```json
{"entitlements":{
  "CFQ7TTC0KHS0":{"autoRenew":<bool>,"endDate":"<ISO 8601 UTC>","isTrial":<bool>,"recurrenceSkuId":"<account-specific>","status":"Active","sharingSource":"None"},
  ...
}}
```

- Ultimate returns entries for Ultimate, PC Game Pass, Premium, Essential and Game Pass for Console (`CFQ7TTC0KHS0`, `CFQ7TTC0KGQ8`, `CFQ7TTC0P85B`, `CFQ7TTC0K5DJ`, `CFQ7TTC0K6L8`)
- All entries share the same `endDate` and `recurrenceSkuId`, so they come from one subscription
- `CFQ7TTC10QFD` and `CFQ7TTC0HXBN` are not returned for Ultimate

## Affirmations

```
GET https://displaycatalog.mp.microsoft.com/v7.0/products?bigIds={ID1},{ID2}&market={MARKET}&languages={LANGUAGES}
```

Each product lists the subscriptions that include it in `LocalizedProperties[].EligibilityProperties.Affirmations`:

```json
"Affirmations":[
  {"AffirmationId":"9WNZS2ZC9L74","AffirmationProductId":"CFQ7TTC0K6L8","Description":"with your Xbox Game Pass membership"},
  {"AffirmationId":"B1FFW2F7JKV0","AffirmationProductId":"CFQ7TTC0KGQ8","Description":"with your Game Pass membership"}
]
```

- `AffirmationProductId` is a [subscription ID](#subscription-ids), same value as `subscriptionContext`
- `AffirmationId` is not unique per subscription, so probably only want to match AffirmationProductId's.
- Ultimate is not listed. An Ultimate account also holds the PC Game Pass, Premium and Game Pass for Console [entitlements](#subscription-entitlements), so affirmations are checked against every entitlement the user has
- Game Pass for Console (`CFQ7TTC0K6L8`) still appears although retired

| Product | Kind | Affirmations |
|---|---|---|
| `9MSVBF0KZFVW` Blood Dungeon | Game | Game Pass for Console, PC Game Pass |
| `9MSMN2PJ6HQN` AoE III: DE - Mexico Civilization | Durable | Premium, PC Game Pass |
| `9NWQ686JB33G` Wartales | Game | Premium, Game Pass for Console, PC Game Pass |
