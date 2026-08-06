
### Endpoint
`titlestorage.xboxlive.com/connectedstorage/users/xuid(<XUID>)/scids/<SCID>`

### Headers
The folling headers are on all requests to titlestorage.xboxlive.com:
```
Connection: Keep Alive
Authorization: XBL3.0 x=<base64>
MS-CV: <base 64>.0
x-xbl-pfn: <Package Family Name>
x-xbl-lock-ext: <base 64>
```

### Lock
Locks prevent multiple devices from writing save-files at the same time.
The lock is enabled for the duration of the game and when uploading saves.

Enable:
```
PUT /lock?friendlyName=<Device name>
-H "x-xbl-lock-ver: 1"
```
Sent after upload completed:
```
PUT /lock?uploadProcess=80
```
Disable:
```
DELETE /lock?newSavesUploaded=false
```

Response:
```
{ "ownerChangedId":<GUID>, "quotaBytes":<Quota> }
```

### Container index
List containers:
```
GET /
```
```
{
    blobs: [
        // For each container
        {
            "clientFileTime": <lastModifiedTime>
            "displayName": <containerDisplayName>
            "etag": <not exposed to the API but saved in containers.index>
            "fileName": <containerName>,savedGame
            "size": <totalSize>
        }
    ],
    pagingInfo: {
        "contaiuationToken": null,
        "totalItems" <number of containers>
    }
}
```

### Containers
Get blob names in a container:
```
GET /savedgames/<containerName>
```
```{
    "atoms": [ 
        // For each blob in the container
        {
            "atom": <atom GUID>
            "name": <blobName>
            "size": <byteCount>
        }
    ]
}
```
Update or create a container:
```
PUT /savedgames/<containerName>?currentFileTime=<time>&displayName=<containerDisplayName>
-H "context-type: application/json"
```
```
{
    "atoms": [
        {
            "atom": <atom GUID>
            "name": <blobName>
        }
    ]
}
```
Delete a container:
```
DELETE /savedgames/<containerName>
```

### Blobs
Blobs are uploaded as atoms. Each time a blob is written to a new atom GUID is created.
To delete a blob exclude it from the next container update.

```
GET /<current atom GUID>,binary
-H "Accept-Encoding: gzip"
```
When submitting an update do 1 for each blob first, then 2 for each blob, then 3.

1
```
POST /atoms/<new atom GUID>
-H "Content-Type: application/json"
-H "Accept: application/json"
-H "Content-Length: <length of JSON body>
-d "{size: <blobSize>}"
```
```
{ blobUri: <URI to put blob> }
```

2
```
PUT <URI to put blob>
-H "Connection: Keep Alive"
-H "MS-CV: <base 64>.0"
-H "Content-Length: <blobSize>"
-d@<blobData>
```

3
```
POST /atoms/<new atom GUID>?commit=true
-H "Content-Type: application/json"
-H "Accept: application/json"
-H "Content-Length: <length of JSON body>
-d '{ "blockIds":<can be found in the URI the server gave us>, "size": <blobSize> }'
```

### Glossary
#### AUMID
Application User Model ID
Equal to `<package family name>!Game` for games.

#### Package Full Name
Equal to `<package name>_<version>_<architecture>__<publisher id>`

#### Package Family Name
Equal to `<package name>_<publisher id>`

#### Publisher ID
The first four bytes of the sha256 of the LE UTF-16 encoded publisher name, written in Crockford's base 32.

Example: (https://discord.com/channels/1123890623586504714/1123953698440220672/1532205122430570537

#### SCID
Service Configuration ID
An ID provided by Microsoft that allows games to access various cloud services.

MicrosoftGame.config contains the package name, publisher, version, and SCID.
