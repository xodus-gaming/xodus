# Chat
## xboxlive messaging
See [xblmessaging](./xblmessaging.md).

## Party chat
Party chat is sent over peer to peer connections using WebRTC.

## Websocket
The chat websocket provides notifications about new messages, invites, and achievements.
```
curl "https://chat.xboxlive.com/users/xuid($xuid)/chat/auth" \
-H "authorization: XBL3.0 x=${uhs};${xsts}"
```
```
wscat -p 13 -s chat --connect "wss://chat.xboxlive.com/users/xuid($xuid)/chat/connect?AuthKey=${authKey}"
```
The first message sent by the client is always:
```
{"clientSeqNum":0,"channel":{"type":"System"},"messageType":"WhoAmI"}
```
The the response provides the chat nonce and chat connection id to provide
to `notificationinbox.xboxlive.com`.

The following is sent after recieving a response from WhoAmI:<br />
```{"clientSeqNum":1,"channel":{"type":"XboxMessage","id":"<xuid>"},"messageType":"JoinChannel"}```

The following is sent before opening the party menu:<br />
```{"clientSeqNum":2,"channel":{"type":"Party","id":"<xuid>"},"messageType":"JoinChannel"}```


If a message from the server was sent in response to a message from the client,
`flagServerOriginated` is missing and `clientSeqNum` matches that from the client.
Otherwise flagServerOriginated is `true` and `clientSeqNum` is zero.

## Notification inbox
To subscribe to notifications a request is sent to `notificationinbox.xboxlive.com`:
```
curl 'https://notificationinbox.xboxlive.com/users/this user's xuid/inbox/push?subscriptionCategory=Microsoft.Xbox.Multiplayer,Microsoft.Xbox.Achievements,Microsoft.Xbox.People&subscriptionType=GameInvites,GamePartyInvites,MultiplayerActivityGameInvites,PartyInvites,AchievementUnlock,Followers,IncomingFriendRequests,AcceptedFriendRequests' \
  -H 'Accept: */*' \
  -H 'Accept-Language: en-US,en;q=0.9' \
  -H 'Content-Type: application/json' \
  -H 'x-xbl-contract-version: 1' \
  -H "authorization: $auth" \
  -d "{\"ChatNonce\":\"$chatNonce\",\"ChatConnectionId\":\"$chatConnection\"}"
```

### Needs testing
What is the difference between
- Microsoft.Xbox.People&subscriptionType=GameInvites,
- MultiplayerActivityGameInvites,
- GamePartyInvites,
- PartyInvites

What is the difference between `Microsoft.Xbox.Achievements` and
`AchievementUnlock`? Is one our achievements and the other our friend's?

What is `Microsoft.Xbox.Multiplayer`?

## Example messages from server
```
{
  "clientSeqNum": 0,
  "messageTime": "2026-10-24T00:00:00Z",
  "messageType": "WhoAmI",
  "messageId": "A unique number for each message",
  "senderXuid": "this user's xuid",
  "senderGamertag": "This User's Gamertag",
  "channel": {
    "type": "System"
  },
  "connectionId": "e0e32405-75a8-4d0d-97d7-2c229d879da4",
  "serverNonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
}
{
  "clientSeqNum": 0,
  "messageTime": "2016-01-01T00:00:00Z",
  "messageType": "NoOp",
  "messageId": "0",
  "senderXuid": "0",
  "senderGamertag": "",
  "channel": {
    "type": "System"
  },
  "flagServerOriginated": true
}
{
  "clientSeqNum": 0,
  "messageTime": "2026-10-24T00:00:00Z",
  "messageType": "UserInfo",
  "messageId": "0",
  "senderXuid": "this user's xuid",
  "senderGamertag": "This User's Gamertag",
  "channel": {
    "type": "Party",
    "id": "this user's xuid"
  },
  "flagServerOriginated": true,
  "permissions": {
    "canRead": true,
    "canWrite": false,
    "canModerate": false,
    "canSetMotd": false
  },
  "connectionId": "e0e32405-75a8-4d0d-97d7-2c229d879da4"
}
{
  "clientSeqNum": 0,
  "messageTime": "2026-10-24T00:00:00Z",
  "messageType": "UserInfo",
  "messageId": "0",
  "senderXuid": "this user's xuid",
  "senderGamertag": "This User's Gamertag",
  "channel": {
    "type": "XboxMessage",
    "id": "this user's xuid"
  },
  "flagServerOriginated": true,
  "permissions": {
    "canRead": true,
    "canWrite": false,
    "canModerate": false,
    "canSetMotd": false
  },
  "connectionId": "14480a32-1b47-4539-be35-417921afee02"
}
{
  "clientSeqNum": 0,
  "messageTime": "2026-10-24T00:00:00Z",
  "messageType": "XboxMessage",
  "messageId": "A unique number for each message",
  "senderXuid": "other user's xuid",
  "senderGamertag": "",
  "channel": {
    "type": "XboxMessage",
    "id": "this user's xuid"
  }
  "flagServerOriginated": true,
  "payload": {
    "contentPayload": {
      "content": {
        "parts": [
          {
            "contentType": "text",
            "version": 0,
            "text": "This is the content of the message that was sent.",
            "unsuitableFor": []
          }
        ]
      }
    },
    "timestamp": "2026-10-24T00:00:00.0000000Z",
    "lastUpdateTimestamp": "2026-10-24T00:00:00.0000000Z",
    "type": "ContentMessage",
    "networkId": "Xbox",
    "conversationType": "OneToOne",
    "conversationId": "3bf7c8dc-c520-44af-bec7-1e6a804c8092",
    "owner": this user's xuid,
    "sender": "other user's xuid",
    "messageId": "00000000000000000",
    "clock": "00000000000000000",
    "isDeleted": false,
    "isServerUpdated": false,
    "notifyPayload": {
      "shouldToast": true,
      "folder": "Primary",
      "muted": false,
      "conversationName": "",
      "isOffensive": false
    }
    "notificationPayload": {
      "shouldToast": true,
      "folder": "Primary",
      "muted": false,
      "conversationName": "",
      "isOffensive": false
    }
  }
}
{
  "clientSeqNum": 0,
  "messageTime": "2026-10-24T00:00:00Z",
  "messageType": "NotificationInbox",
  "messageId": "A unique number for each message",
  "senderXuid": "0",
  "senderGamertag": "",
  "channel": {
    "type": "NotificationInbox",
    "id": "a238fb1b-a11e-43b6-b71b-04b4386123fb"
  },
  "flagServerOriginated": true,
  "PushNotificationType": "NewAction",
  "PushNotification": {
    "Action": {
      "Actor": {
        "ClassicGamertag": "Other User's Gamertag",
        "ModernGamertag": "Other User's Gamertag",
        "ModernGamertagSuffix": "",
        "UniqueModernGamertag": "Other User's Gamertag",
        "Name": "Other User's Gamertag",
        "Id": "other user's xuid",
        "Type": 1
      },
      "ActionId": "fe29df85-8238-47a0-96f7-a4c7310f0bf5",
      "ActionTime": "2026-10-24T00:00:00.0000000Z",
      "LaunchInfo": {
        "mpsdHandleId": "b9b5578d-6f8e-4094-97c2-45e9a71af1e4",
        "expirationTime": "2026-10-24T00:00:00.0000000Z"
      },
      "SubscriptionCategory": "Microsoft.Xbox.Multiplayer",
      "SubscriptionType": "PartyInvites",
      "SubscriptionId": "this user's xuid_0_other user's xuid"
    },
    "NotificationOptions": {
      "Location": {
        "ClassicGamertag": "Other User's Gamertag",
        "ModernGamertag": "Other User's Gamertag",
        "ModernGamertagSuffix": "",
        "UniqueModernGamertag": "Other User's Gamertag",
        "Name": "Other User's Gamertag",
        "Id": "other user's xuid",
        "Type": 1
      },
      "LocalizationInfo": {
        "xuid": "other user's xuid",
        "titleId": null
      },
      "LaunchInfo": {
        "mpsdHandleId": "f316f602-8f05-4da2-bce4-1bda42445edc",
        "expirationTime": "2026-10-24T00:00:00.0000000Z"
      },
    },
    "Image": "https://images-eds-ssl.xboxlive.com/image?url=8Oaj9Ryq1G1_p3lLnXlsaZgGzAie6Mnu24_PawYuDYIoH77pJ.X5Z.MqQPibUVTcS9jr0n8i7LY1tL3U7AiafVwZf9hucyjgkDmhrunAiEm18xd.hm6GkriV1tRzbwNyb0UuOgqh9GapMk18TggSUg--&format=png",
    "ImageType": 1,
    "InboxOptions": {
      "CountOptions": {
        "InboxProvidesCount": true,
        "ResetCountOnRead": true
      },
      "ImageOptions": {
        "UseActorImage": true
      },
      "ExpiresAfterMinutes": 1440
    },
    "SubscriptionCategory": "Microsoft.Xbox.Multiplayer",
    "SubscriptionType": "PartyInvites",
    "SubscriptionId": "this user's xuid_0_other user's xuid"
  }
}
{
  "clientSeqNum": 0,
  "messageTime": "2026-10-24T00:00:00Z",
  "messageType": "NotificationInbox",
  "messageId": "A unique number for each message",
  "senderXuid": "0",
  "senderGamertag": "",
  "channel": {
    "type": "NotificationInbox",
    "id": "2677a4f4-cfa9-46c9-89c9-bfae7f496788"
  },
  "flagServerOriginated": true,
  "PushNotificationType": "SubscriptionUpdate",
  "PushNotification": {
    "Timestamp": "2026-10-24T00:00:00.0000000Z",
    "UpdateType": 5,
    "SubscriptionCategory": "Microsoft.Xbox.People",
    "SubscriptionType": "AcceptedFriendRequests",
    "SubscriptionId": "this user's xuid"
  }
}
{
  "clientSeqNum": 1,
  "messageTime": "2026-10-24T00:00:00Z",
  "messageType": "JoinChannel",
  "messageId": "A unique number for each message",
  "senderXuid": "this user's xuid",
  "senderGamertag": "This User's Gamertag",
  "channel": {
    "type": "XboxMessage",
    "id": "this user's xuid"
  },
  "connectionId": "e0e32405-75a8-4d0d-97d7-2c229d879da4"
}
{
  "clientSeqNum": 2,
  "messageTime": "2026-10-24T00:00:00Z",
  "messageType": "JoinChannel",
  "messageId": "A unique number for each message",
  "senderXuid": "this user's xuid",
  "senderGamertag": "This User's Gamertag",
  "channel": {
    "type": "Party",
    "id": "this user's xuid"
  },
  "connectionId": "e0e32405-75a8-4d0d-97d7-2c229d879da4"
}
```

