# XBOX Cloud Gaming

> [!NOTE]
> The specific endpoint does not use XBL tokens, but otherwise, needs a Bearer token, that you need to get via the original authentification board.
> 
> It needs to have these scopes in order to be authorized by the Cloud Gaming platform : service::http://passport.net/purpose::PURPOSE_XBOX_CLOUD_CONSOLE_TRANSFER_TOKEN openid profile offline_access
>
> Make sure it replies properly.

## Search for a title inside the Cloud Gaming platform 

POST https://weu.core.gssv-play-prod.xboxlive.com/v2/titles

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

POST https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/play

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

GET https://weu.core.gssv-play-prod.xboxlive.com/v1/waittime/\<game\>

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

POST https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/\<uuid\>/connect

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

GET https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/\<uuid\>/state

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

GET https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/\<uuid\>/configuration

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

## Terminate a cloud session

DELETE https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/\<uuid\>

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

https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/\<uuid\>/sdp | Get the necessary info for WebRTC connection.
https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/\<uuid\>/ice | ?
https://weu.core.gssv-play-prod.xboxlive.com/v5/sessions/cloud/\<uuid\>/keepalive | Keeps the connection alive.
