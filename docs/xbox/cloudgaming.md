# XBOX Cloud Gaming

> [!NOTE]
> The specific endpoint does not use XBL tokens, but otherwise, needs a Bearer token, that you need to get via the original authentification board.
> 
> It needs to have these scopes in order to be authorized by the Cloud Gaming platform : service::http://passport.net/purpose::PURPOSE_XBOX_CLOUD_CONSOLE_TRANSFER_TOKEN openid profile offline_access
>
> Make sure it replies properly.


## Login to the Cloud Gaming server

> [!NOTE]
> I cannot confirm nor deny the headers are the same in an XBOX environment. These are valid for a browser connection (play.xbox.com) [Belleza]

```
POST https://cloudgaming.gssv-play-prod.xboxlive.com/v2/login/user
```

Headers :
```
accept: */*
accept-encoding: gzip, deflate, br, zstd
accept-language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7
authorization:
cache-control: no-cache
connection: keep-alive
content-type: application/json; charset=utf-8
host: cloudgaming.gssv-play-prod.xboxlive.com
ms-cv: <cv>
origin: https://play.xbox.com
pragma: no-cache
sec-ch-ua: "Chromium";v="158", "Not.A/Brand";v="24", "Brave";v="158"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
sec-fetch-dest: empty
sec-fetch-mode: cors
sec-fetch-site: cross-site
sec-gpc: 1
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36
x-gssv-client: XboxComBrowser
x-gssv-routing: AFD
```

Body :
```
{"token":"XBL3.0 x=<token>","offeringId":"CLOUDGAMING"}
```

Answer : 
```
{
    "offeringSettings": {
        "allowRegionSelection": false,
        "regions": [
            {
                "name": "AUSTRALIAEAST",
                "baseUri": "https://eau.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "eau.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "AUSTRALIASOUTHEAST",
                "baseUri": "https://seau.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "seau.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "BRAZILSOUTH",
                "baseUri": "https://brs.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "brs.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "CENTRALINDIA",
                "baseUri": "https://CIA.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "CIA.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "CHILECENTRAL",
                "baseUri": "https://clc.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "clc.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "EASTUS",
                "baseUri": "https://eus.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "eus.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "EASTUS2",
                "baseUri": "https://eus2.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "eus2.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "JAPANEAST",
                "baseUri": "https://ejp.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "ejp.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "KOREACENTRAL",
                "baseUri": "https://ckr.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "ckr.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "MEXICOCENTRAL",
                "baseUri": "https://mxc.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "mxc.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "NORTHCENTRALUS",
                "baseUri": "https://ncus.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "ncus.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "SOUTHINDIA",
                "baseUri": "https://sia.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "sia.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "SOUTHCENTRALUS",
                "baseUri": "https://scus.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "scus.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "SWEDENCENTRAL",
                "baseUri": "https://cse.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "cse.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "UKSOUTH",
                "baseUri": "https://uks.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "uks.gssv-fastlane-prod.xboxlive.com",
                "isDefault": true,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "WESTEUROPE",
                "baseUri": "https://weu.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "weu.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "WESTUS",
                "baseUri": "https://wus.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "wus.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "WESTUS2",
                "baseUri": "https://wus2.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "wus2.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            },
            {
                "name": "WESTUS3",
                "baseUri": "https://wus3.core.gssv-play-prod.xboxlive.com",
                "networkTestHostname": "wus3.gssv-fastlane-prod.xboxlive.com",
                "isDefault": false,
                "systemUpdateGroups": [],
                "fallbackPriority": -1
            }
        ],
        "selectableServerTypes": [],
        "clientCloudSettings": {
            "Environments": [
                {
                    "Name": "Prod",
                    "AuthBaseUri": null
                }
            ]
        }
    },
    "market": "<userMarket>",
    "gsToken": "<token>",
    "tokenType": "bearer",
    "durationInSeconds": 14400
}
```

> [!NOTE]
> Based on this URL, you can change the rest of the host URLs to the one closest to your country.
>
> Or, refer to this little JS shenanigan

```
[[e.Albania, [p.NorthEurope, p.WestEurope]], [e.Algeria, [p.SouthAfricaNorth]], [e.Argentina, [p.BrazilSouth]], [e.Australia, [p.AustraliaEast, p.AustraliaSoutheast]], [e.Austria, [p.NorthEurope, p.WestEurope]], [e.Bahrain, [p.SouthAfricaNorth, p.WestEurope]], [e.Belgium, [p.NorthEurope, p.WestEurope]], [e.Bolivia, [p.BrazilSouth]], [e.BosniaAndHerzegovina, [p.NorthEurope, p.WestEurope]], [e.Brazil, [p.BrazilSouth]], [e.Bulgaria, [p.NorthEurope, p.WestEurope]], [e.Canada, [p.NorthCentralUS, p.EastUS, p.EastUS2, p.WestUS]], [e.Chile, [p.BrazilSouth]], [e.China, [p.EastAsia, p.SoutheastAsia]], [e.Colombia, [p.BrazilSouth]], [e.CostaRica, [p.BrazilSouth, p.SouthCentralUS]], [e.Croatia, [p.NorthEurope, p.WestEurope]], [e.Cyprus, [p.NorthEurope, p.WestEurope]], [e.CzechRepublic, [p.NorthEurope, p.WestEurope]], [e.Denmark, [p.NorthEurope, p.WestEurope]], [e.Ecuador, [p.BrazilSouth]], [e.Egypt, [p.SouthAfricaNorth]], [e.ElSalvador, [p.BrazilSouth, p.SouthCentralUS]], [e.Estonia, [p.NorthEurope, p.WestEurope]], [e.Finland, [p.NorthEurope, p.WestEurope]], [e.France, [p.NorthEurope, p.WestEurope]], [e.Georgia, [p.NorthEurope, p.WestEurope]], [e.Germany, [p.NorthEurope, p.WestEurope]], [e.Greece, [p.NorthEurope, p.WestEurope]], [e.Guatemala, [p.BrazilSouth, p.SouthCentralUS]], [e.Honduras, [p.BrazilSouth, p.SouthCentralUS]], [e.HongKong, [p.EastAsia, p.SoutheastAsia]], [e.Hungary, [p.NorthEurope, p.WestEurope]], [e.Iceland, [p.NorthEurope, p.WestEurope]], [e.India, [p.EastAsia, p.SoutheastAsia]], [e.Indonesia, [p.EastAsia, p.SoutheastAsia]], [e.Ireland, [p.NorthEurope, p.WestEurope]], [e.Israel, [p.SouthAfricaNorth, p.WestEurope]], [e.Italy, [p.NorthEurope, p.WestEurope]], [e.Japan, [p.JapanEast, p.JapanWest]], [e.Kuwait, [p.SouthAfricaNorth, p.WestEurope]], [e.Latvia, [p.NorthEurope, p.WestEurope]], [e.Libya, [p.SouthAfricaNorth, p.WestEurope]], [e.Liechtenstein, [p.NorthEurope, p.WestEurope]], [e.Lithuania, [p.NorthEurope, p.WestEurope]], [e.Luxembourg, [p.NorthEurope, p.WestEurope]], [e.Malaysia, [p.EastAsia, p.SoutheastAsia]], [e.Malta, [p.NorthEurope, p.WestEurope]], [e.Mexico, [p.CentralUS, p.SouthCentralUS]], [e.Moldova, [p.NorthEurope, p.WestEurope]], [e.Montenegro, [p.NorthEurope, p.WestEurope]], [e.Morocco, [p.SouthAfricaNorth, p.WestEurope]], [e.Netherlands, [p.NorthEurope, p.WestEurope]], [e.NewZealand, [p.AustraliaEast, p.AustraliaSoutheast]], [e.Nicaragua, [p.SouthCentralUS, p.BrazilSouth]], [e.NorthMacedonia, [p.NorthEurope, p.WestEurope]], [e.Norway, [p.NorthEurope, p.WestEurope]], [e.Oman, [p.SouthAfricaNorth, p.WestEurope]], [e.Panama, [p.BrazilSouth, p.SouthCentralUS]], [e.Paraguay, [p.BrazilSouth]], [e.Peru, [p.BrazilSouth]], [e.Philippines, [p.EastAsia, p.SoutheastAsia]], [e.Poland, [p.NorthEurope, p.WestEurope]], [e.Portugal, [p.NorthEurope, p.WestEurope]], [e.Qatar, [p.SouthAfricaNorth, p.WestEurope]], [e.Romania, [p.NorthEurope, p.WestEurope]], [e.Russia, [p.NorthEurope, p.WestEurope, p.EastAsia]], [e.SaudiArabia, [p.SouthAfricaNorth, p.WestEurope]], [e.Serbia, [p.NorthEurope, p.WestEurope]], [e.Singapore, [p.EastAsia, p.SoutheastAsia]], [e.Slovakia, [p.NorthEurope, p.WestEurope]], [e.Slovenia, [p.NorthEurope, p.WestEurope]], [e.SouthAfrica, [p.SouthAfricaNorth]], [e.SouthKorea, [p.JapanEast, p.JapanWest]], [e.Spain, [p.NorthEurope, p.WestEurope]], [e.Sweden, [p.NorthEurope, p.WestEurope]], [e.Switzerland, [p.NorthEurope, p.WestEurope]], [e.Taiwan, [p.EastAsia, p.SoutheastAsia]], [e.Thailand, [p.EastAsia, p.SoutheastAsia]], [e.Tunisia, [p.SouthAfricaNorth, p.WestEurope]], [e.Turkiye, [p.NorthEurope, p.WestEurope]], [e.Ukraine, [p.NorthEurope, p.WestEurope]], [e.UnitedArabEmirates, [p.SouthAfricaNorth, p.WestEurope]], [e.UnitedKingdom, [p.NorthEurope, p.WestEurope]], [e.UnitedStates, [p.CentralUS, p.NorthCentralUS, p.SouthCentralUS, p.EastUS, p.EastUS2, p.WestUS]], [e.Uruguay, [p.BrazilSouth]], [e.Vietnam, [p.EastAsia, p.SoutheastAsia]]])
```
where e = country & p = corresponding Azure server.

## Search for a title inside the Cloud Gaming platform 

```
POST https://weu.core.gssv-play-prod.xboxlive.com/v2/titles
```

Headers : 
```
Accept: */*
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7
Cache-Control: no-cache
Connection: keep-alive
Content-Length: 63
Host: weu.core.gssv-play-prod.xboxlive.com
Origin: https://play.xbox.com
Pragma: no-cache
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Sec-GPC: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36
authorization: Bearer <token>
content-type: application/json; charset=utf-8
ms-cv: <CV>
sec-ch-ua: "Not:A-Brand";v="8", "Chromium";v="156", "Brave";v="156"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
```
Body (example) : 
```JSON
{"alternateIds":["FORZAHORIZON6"],"alternateIdType":"sourceId"}
```
Result :
```JSON
{
    "results": [
        {
            "titleId": "FORZAHORIZON6",
            "details": {
                "productId": "9NR1R1XWLCNB",
                "xboxTitleId": 2079757188,
                "hasEntitlement": false,
                "supportsInAppPurchases": true,
                "supportedTabs": [
                    {
                        "id": "ee0c7785-80a6-4074-9ef7-7ced14bb8559",
                        "tabVersion": "1.1.0.0",
                        "layoutVersion": "3.1",
                        "manifestVersion": "2.0"
                    }
                ],
                "supportedInputTypes": [
                    "Controller",
                    "CustomTouchOverlay",
                    "Caccsg"
                ],
                "programs": [
                    "CALLISTO",
                    "DIA",
                    "EUROPA",
                    "TRITON"
                ],
                "userPrograms": [],
                "userSubscriptions": [
                    "XGPSTARTER"
                ],
                "earlyAccessProductIds": [
                    "9NDBXSJFP7DH",
                    "9N4XW3N02MNJ",
                    "9P88R7QT123M",
                    "9NZFTFQFKJJP"
                ],
                "isFreeInStore": false,
                "maxSessionLengthInSeconds": 0
            }
        }
    ]
}
```

## Authorize a cloud gaming session

> [!WARNING]
> Make sure that the response is 202 Accepted.

> [!NOTE]
> The client session ID can be found in the token you've recieved from the previous authorization.
>
> You may read the id_token JWT & find the "sid" inside the payload.

```
POST https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/play
```
Headers :
```
Accept: */*
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7
Cache-Control: no-cache
Connection: keep-alive
Content-Length: 365
Host: weu.core.gssv-play-prod.xboxlive.com
Origin: https://play.xbox.com
Pragma: no-cache
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Sec-GPC: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36
authorization: Bearer <token>
content-type: application/json; charset=utf-8
ms-cv: <cv>
sec-ch-ua: "Not:A-Brand";v="8", "Chromium";v="156", "Brave";v="156"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
x-ms-device-info: {"appInfo":{"env":{"clientAppId":"play.xbox.com","clientAppType":"browser","clientSdkVersion":"placeholder","httpEnvironment":"prod","sdkInstallId":""}},"dev":{"displayInfo":{"dimensions":{"heightInPixels":1184,"widthInPixels":1904},"pixelDensity":{"dpiX":1,"dpiY":1}},"browser":{"browserName":"chrome","browserVersion":"156.0.0.0"},"hw":{"make":"unknown","model":"unknown","platformType":"desktop","sdkType":"web"},"os":{"name":"windows","ver":"19.0.0","platform":"desktop"}}}
```
Body :
```JSON
{
  "titleId":"ASTRONEER",
  "systemUpdateGroup":"",
  "settings":{"nanoVersion":"V3;WebrtcTransport.dll",
              "enableTextToSpeech":false,
              "highContrast":0,
              "locale":"fr-FR",
              "useIceConnection":false,
              "timezoneOffsetMinutes":60,
              "sdkType":"web",
              "osName":"windows",
              "enableOptionalDataCollection":false
              },
    "serverId":"",
    "fallbackRegionNames":[],
    "clientSessionId":"<client_session_id>"
}
```
Answer (if 202 Accepted) :
```JSON
{
    "sessionPath": "v5/sessions/cloud/<uuid>",
    "queueConfig": "<sha1 looking string>"
}
```

## Get cloud gaming wait time for the concerned title

```
GET https://weu.core.gssv-play-prod.xboxlive.com/v1/waittime/<game>
```

Headers :
```
Accept: */*
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7
Cache-Control: no-cache
Connection: keep-alive
Host: weu.core.gssv-play-prod.xboxlive.com
Origin: https://play.xbox.com
Pragma: no-cache
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Sec-GPC: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36
authorization: Bearer <token>
content-type: application/json; charset=utf-8
ms-cv: <cv>
sec-ch-ua: "Not:A-Brand";v="8", "Chromium";v="156", "Brave";v="156"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
```
Result (example) :
```JSON
{
    "estimatedProvisioningTimeInSeconds": 10,
    "estimatedAllocationTimeInSeconds": 0,
    "estimatedTotalWaitTimeInSeconds": 10
}
```

## Connect to cloud gaming session

```
POST https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/<uuid>/connect
```

> [!WARNING]
> Make sure that the response is 202 Accepted.
> The UUID must match the one recieved in the creation request.

Headers :
```
Accept: */*
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7
Cache-Control: no-cache
Connection: keep-alive
Content-Length: 668
Host: weu.core.gssv-play-prod.xboxlive.com
Origin: https://play.xbox.com
Pragma: no-cache
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Sec-GPC: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36
authorization: Bearer <token>
content-type: application/json; charset=utf-8
ms-cv: <cv>
sec-ch-ua: "Not:A-Brand";v="8", "Chromium";v="156", "Brave";v="156"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
```
Body :
```JSON
{"userToken":"<access_token from previous cloud login session>","userTokenIssuer":"MSA"}
```
No answer for this endpoint is expected.

## Get current state of cloud session

```
GET https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/<uuid>/state
```

Headers :
```
Accept: */*
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7
Cache-Control: no-cache
Connection: keep-alive
Host: weu.core.gssv-play-prod.xboxlive.com
Origin: https://play.xbox.com
Pragma: no-cache
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Sec-GPC: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36
authorization: Bearer <token>
content-type: application/json; charset=utf-8
ms-cv: <cv>
sec-ch-ua: "Not:A-Brand";v="8", "Chromium";v="156", "Brave";v="156"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
```
Answer (OK example) :
```JSON
{"state":"Provisioning","serverPlatform":"XBOX","errorDetails":null}
```

## Get current cloud gaming configuration (Controllers, XBOX settings)

```
GET https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/<uuid>/configuration
```

Headers :
```
Accept: */*
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7
Cache-Control: no-cache
Connection: keep-alive
Host: weu.core.gssv-play-prod.xboxlive.com
Origin: https://play.xbox.com
Pragma: no-cache
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Sec-GPC: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36
authorization: Bearer <token>
content-type: application/json; charset=utf-8
ms-cv: <cv>
sec-ch-ua: "Not:A-Brand";v="8", "Chromium";v="156", "Brave";v="156"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
```
Answer (OK example):
```JSON
{
    "keepAlivePulseInSeconds": 60,
    "timeoutForNoConnectionSeconds": 300,
    "serverDetails": {
        "ipAddress": "13.104.102.28",
        "port": 1050,
        "ipV4Address": "13.104.102.28",
        "ipV4Port": 1050,
        "ipV6Address": "[2603:1020:204:F0::C0A8:1C]",
        "ipV6Port": 9002,
        "srtp": {
            "key": "<specific_key>"
        },
        "ipV4List": [
            {
                "address": "13.104.102.28",
                "port": 1050,
                "rigPort": 1314,
                "routingPreference": "AZURE"
            }
        ]
    },
    "clientStreamingConfigOverrides": "{\"inputConfiguration\":{\"useGamepadEventListenerForInput\":false,\"useUnreliableInput\":true},\"nqiConfiguration\":{\"consecutiveBadIntervalsForTrigger\":10,\"pingMsBadThreshold\":100},\"statisticsConfiguration\":{\"useQosChannel\":true},\"videoConfiguration\":{\"preferMainH264Profile\":true}}"
}
```

## Get WebRTC connection data

```
GET https://uks.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/<UUID>/sdp
```

Headers :
```
Accept: */*
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7
Cache-Control: no-cache
Connection: keep-alive
Host: uks.core.gssv-play-prod.xboxlive.com
Origin: https://play.xbox.com
Pragma: no-cache
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Sec-GPC: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36
authorization: Bearer <token from previous Cloud Gaming auth>
content-type: application/json; charset=utf-8
ms-cv: <cv>
sec-ch-ua: "Chromium";v="158", "Not.A/Brand";v="24", "Brave";v="158"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
```

Answer :
```
{
    "exchangeResponse": "{\"chatStream\":1,\"control\":3,\"message\":1,\"messageType\":\"answer\",\"qos\":1,\"reliableinput\":10,\"sdp\":\"v=0\\r\\no=- <int> 2 IN IP4 127.0.0.1\\r\\ns=-\\r\\nt=0 0\\r\\na=group:BUNDLE 0 1 2\\r\\na=extmap-allow-mixed\\r\\na=msid-semantic: WMS 0 1\\r\\nm=audio 9 UDP/TLS/RTP/SAVPF 111 63 110\\r\\nc=IN IP4 0.0.0.0\\r\\na=rtcp:9 IN IP4 0.0.0.0\\r\\na=ice-ufrag:d7CX\\r\\na=ice-pwd:<ice-pwdsrv1>\\r\\na=ice-options:trickle renomination\\r\\na=fingerprint:sha-256 <srv-fingerprint>\\r\\na=setup:passive\\r\\na=mid:0\\r\\na=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\\r\\na=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\\r\\na=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\\r\\na=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\\r\\na=sendrecv\\r\\na=msid:0 <microsoftID>\\r\\na=rtcp-mux\\r\\na=rtcp-rsize\\r\\na=rtpmap:111 opus/48000/2\\r\\na=fmtp:111 minptime=10;useinbandfec=1\\r\\na=rtpmap:63 red/48000/2\\r\\na=fmtp:63 111/111\\r\\na=rtpmap:110 telephone-event/48000\\r\\na=ssrc:<ssrc> cname:<srvCNAME>\\r\\nm=video 9 UDP/TLS/RTP/SAVPF 116 39 102 103 104 107 108 109 114 115 117 40 122 123 124 53\\r\\nc=IN IP4 0.0.0.0\\r\\na=rtcp:9 IN IP4 0.0.0.0\\r\\na=ice-ufrag:d7CX\\r\\na=ice-pwd:<ice-pwdsrv2>\\r\\na=ice-options:trickle renomination\\r\\na=fingerprint:sha-256 <srv-fingerprint>\\r\\na=setup:passive\\r\\na=mid:1\\r\\na=extmap:14 urn:ietf:params:rtp-hdrext:toffset\\r\\na=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\\r\\na=extmap:13 urn:3gpp:video-orientation\\r\\na=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\\r\\na=extmap:5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay\\r\\na=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/video-content-type\\r\\na=extmap:7 http://www.webrtc.org/experiments/rtp-hdrext/video-timing\\r\\na=extmap:8 http://www.webrtc.org/experiments/rtp-hdrext/color-space\\r\\na=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid\\r\\na=extmap:10 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\\r\\na=extmap:11 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id\\r\\na=sendonly\\r\\na=msid:1 <microsoftID>\\r\\na=rtcp-mux\\r\\na=rtcp-rsize\\r\\na=rtpmap:116 H264/90000\\r\\na=rtcp-fb:116 goog-remb\\r\\na=rtcp-fb:116 transport-cc\\r\\na=rtcp-fb:116 ccm fir\\r\\na=rtcp-fb:116 nack\\r\\na=rtcp-fb:116 nack pli\\r\\na=fmtp:116 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=4d002a\\r\\na=rtpmap:39 H264/90000\\r\\na=rtcp-fb:39 goog-remb\\r\\na=rtcp-fb:39 transport-cc\\r\\na=rtcp-fb:39 ccm fir\\r\\na=rtcp-fb:39 nack\\r\\na=rtcp-fb:39 nack pli\\r\\na=fmtp:39 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=4d002a\\r\\na=rtpmap:102 H264/90000\\r\\na=rtcp-fb:102 goog-remb\\r\\na=rtcp-fb:102 transport-cc\\r\\na=rtcp-fb:102 ccm fir\\r\\na=rtcp-fb:102 nack\\r\\na=rtcp-fb:102 nack pli\\r\\na=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42002a\\r\\na=rtpmap:103 rtx/90000\\r\\na=fmtp:103 apt=102\\r\\na=rtpmap:104 H264/90000\\r\\na=rtcp-fb:104 goog-remb\\r\\na=rtcp-fb:104 transport-cc\\r\\na=rtcp-fb:104 ccm fir\\r\\na=rtcp-fb:104 nack\\r\\na=rtcp-fb:104 nack pli\\r\\na=fmtp:104 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42002a\\r\\na=rtpmap:107 rtx/90000\\r\\na=fmtp:107 apt=104\\r\\na=rtpmap:108 H264/90000\\r\\na=rtcp-fb:108 goog-remb\\r\\na=rtcp-fb:108 transport-cc\\r\\na=rtcp-fb:108 ccm fir\\r\\na=rtcp-fb:108 nack\\r\\na=rtcp-fb:108 nack pli\\r\\na=fmtp:108 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e02a\\r\\na=rtpmap:109 rtx/90000\\r\\na=fmtp:109 apt=108\\r\\na=rtpmap:114 H264/90000\\r\\na=rtcp-fb:114 goog-remb\\r\\na=rtcp-fb:114 transport-cc\\r\\na=rtcp-fb:114 ccm fir\\r\\na=rtcp-fb:114 nack\\r\\na=rtcp-fb:114 nack pli\\r\\na=fmtp:114 level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e02a\\r\\na=rtpmap:115 rtx/90000\\r\\na=fmtp:115 apt=114\\r\\na=rtpmap:117 rtx/90000\\r\\na=fmtp:117 apt=116\\r\\na=rtpmap:40 rtx/90000\\r\\na=fmtp:40 apt=39\\r\\na=rtpmap:122 red/90000\\r\\na=rtpmap:123 rtx/90000\\r\\na=fmtp:123 apt=122\\r\\na=rtpmap:124 ulpfec/90000\\r\\na=rtpmap:53 flexfec-03/90000\\r\\na=rtcp-fb:53 goog-remb\\r\\na=rtcp-fb:53 transport-cc\\r\\na=fmtp:53 repair-window=10000000\\r\\na=ssrc-group:FID <ssrcgrp>\\r\\na=ssrc-group:FEC-FR <ssrcgrp>\\r\\na=ssrc:<ssrc> cname:<srvCNAME>\\r\\na=ssrc:<ssrc> cname:<srvCNAME>\\r\\na=ssrc:<ssrc> cname:<srvCNAME>\\r\\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\\r\\nc=IN IP4 0.0.0.0\\r\\na=ice-ufrag:d7CX\\r\\na=ice-pwd:<ice-pwdsrv3>\\r\\na=ice-options:trickle renomination\\r\\na=fingerprint:sha-256 <srv-fingerprint>\\r\\na=setup:passive\\r\\na=mid:2\\r\\na=sctp-port:5000\\r\\na=max-message-size:262144\\r\\n\",\"sdpType\":\"answer\",\"status\":\"success\",\"unreliableinput\":10}",
    "errorDetails": null
}
```

**yes, definitely WebRTC data feed**

## Terminate a cloud session

```
DELETE https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/<uuid>
```

Headers :
```
Accept: */*
Accept-Encoding: gzip, deflate, br, zstd
Accept-Language: fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7
Cache-Control: no-cache
Connection: keep-alive
Host: weu.core.gssv-play-prod.xboxlive.com
Origin: https://play.xbox.com
Pragma: no-cache
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Sec-GPC: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36
authorization: Bearer <token>
content-type: application/json; charset=utf-8
ms-cv: <cv>
sec-ch-ua: "Not:A-Brand";v="8", "Chromium";v="156", "Brave";v="156"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
```

## Other linkups not in this writeup

```
https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/<uuid>/ice | ?
https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/<uuid>/keepalive | Keeps the connection alive.
```
