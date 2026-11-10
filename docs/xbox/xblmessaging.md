# Xbox Live Messaging
### Authorization
Only user token is required. Device and title claims are not needed.
```
authorizationHeader="XBL3.0 x=${uhs};${xsts}"
```
### One to one
Read messages from a user:
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/conversations/users/xuid(${xuid})?maxItems=100' \
  -H 'Accept: application/json' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'content-type: application/json' \
  -H 'x-xbl-contract-version: 1' \
  -H "authorization: ${authorizationHeader}"
```
Send message to user: <br />
This will start a new conversation if not already present.
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/conversations/users/xuid(${xuid})' \
  -X POST \
  -H 'Accept: application/json' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Content-Type: application/json' \
  -H 'x-xbl-contract-version: 1' \
  -H "authorization: ${authorizationHeader}" \
  --data-raw '{"parts":[{"contentType":"text","version":0,"text":"<message contents>"}]}'
```
### All conversations
Read messages:
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/inbox' \
  -H 'Accept: application/json' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'content-type: application/json' \
  -H 'x-xbl-contract-version: 1' \
  -H "authorization: ${authorizationHeader}" 
```
Delete a message:
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/conversations/${conversationId}/messages/${messageId}' \
  -X DELETE \
  -H 'Accept: application/json' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Referer: https://www.xbox.com/' \
  -H 'content-type: application/json' \
  -H 'x-xbl-contract-version: 1' \
  -H "authorization: ${authorizationHeader}" \
```
Mark a message as read:
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/conversations/horizon' \
  -X PUT \
  -H 'Accept: application/json' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Content-Type: application/json' \
  -H 'x-xbl-contract-version: 2' \
  -H "authorization: ${authorizationHeader}" \
  -H 'Connection: keep-alive' \
  --data-raw '{"conversations":[{"conversationId":"${conversationId}","conversationType":"OneToOne","horizonType":"Read","horizon":"${messageId}"}]}'
```
Upload a jpg:
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/upload/jpg' \
  -H 'Accept: application/json' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'content-type: application/json' \
  -H 'x-xbl-contract-version: 1' \
  -H "authorization: ${authorizationHeader}" \
  -H 'Connection: keep-alive'
```
```
curl "${uploadURI}" \
  -X PUT \
  -H 'Accept: application/json' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Content-Type: application/octet-stream' \
  -H 'x-ms-blob-type: BlockBlob' \
  -H 'x-xbl-contract-version: 3' \
  -H 'Sec-GPC: 1' \
  -d@fileToUpload.jpg
```
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/conversations/users/xuid(${xuid})' \
  -X POST \
  -H 'Accept: application/json' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Content-Type: application/json' \
  -H 'x-xbl-clientseqnum: 0' \
  -H 'x-xbl-contract-version: 1' \
  -H "authorization: ${authorizationHeader}" \
  --data-raw "{\"parts\":[{\"contentType\":\"image\",\"version\":0,\"attachmentId\":\"${attachmentId}\",\"filetype\":\"jpg\",\"sizeInBytes\":${size},\"hash\":\"${hash}\",\"height\":${height},\"width\":${width}}]}"
```
Move conversation <br />
The target folder may be `Primary` or `Secondary`.
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/conversations/move' /
-H 'x-xbl-contract-version: 1' /
-H 'accept: application/json' /
-H "authorization: ${authorizationHeader}" /
-H 'Content-Type: application/json' /
-d "{\"conversations\":[{\"conversationId\":\"${conversationId}\",\"targetFolder\":\"Primary\"}]}'
```
Delete conversation:
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/conversations/horizon' \
  -X PUT \
  -H 'Accept: application/json' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Accept-Encoding: gzip, deflate, br, zstd' \
  -H 'Content-Type: application/json' \
  -H 'x-xbl-contract-version: 2' \
  -H "authorization: $authorizationHeader" \
  --data-raw "{"conversations":[{\"conversationId\":\"${conversationId}\",\"conversationType\":\"OneToOne\",\"horizonType\":\"Delete\",\"horizon\":\"$horizon\"}]}"
```

### Group chats
Start a group chat
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/groups' \
  -H 'x-xbl-contract-version: 1' \
  -H "authorization: $authorizationHeader" \
  --data-raw '{"participants":["${xuid}"]}'
```
List groups
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/groups' \
  -H 'Accept: application/json' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'content-type: application/json' \
  -H 'x-xbl-contract-version: 1' \
  -H "authorization: $authorizationHeader" \
````
Get summary
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/groups/${groupId}/summary' \
  -H 'x-xbl-contract-version: 1' \
  -H "authorization: $authorizationHeader" \
```
Read group chat
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/groups/${groupId}/channels/${channelNumber}/messages?maxItems=100&formatted=true' \
  -H 'x-xbl-contract-version: 1' \
  -H "authorization: $authorizationHeader" \
```
Rename the chat
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/groups/${groupId}/name' \
  --compressed \
  -X POST \
  -H 'x-xbl-contract-version: 1' \
  -H "authorization: $authorizationHeader" \
  --data-raw '{"name":"${newName}"}'
```
read recipt for group chat
```
{
	"conversations": [
		{
			"channel": {
				"channelId": "0",
				"groupId": "${groupId}"
			},
			"conversationType": "Group",
			"horizon": "${messageId}",
			"horizonType": "Read"
		}
	]
}
```
Invite user
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/groups/${groupId}/participants' \
  -H 'x-xbl-contract-version: 1' \
  -H "authorization: $authorizationHeader" \
  --data-raw '{"participants":["${xuid}"]}'
```
Leave group chat
```
curl 'https://xblmessaging.xboxlive.com/network/xbox/users/me/groups/${groupId}/participants/xuid(${xuid})' \
  -X DELETE \
  -H "authorization: $authorizationHeader" \
  -H 'x-xbl-contract-version: 1' \
```

### safety settings
```
curl "https://xblmessaging.xboxlive.com/network/xbox/users/xuid($xuid)/safetySettings" \
  -H 'Accept: application/json' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'content-type: application/json' \
  -H 'x-xbl-contract-version: 2' \
  -H "authorization: ${auth}"
```

