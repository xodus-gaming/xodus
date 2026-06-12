## OfflinePC

> [!NOTE]
> Endpoint needs authorization  
> The Authorization header is a t= token
> x-ms-authorization-social contains Xbox style token - XBL3.0 x={hash};{token}

## Status

```
GET https://beige.xboxservices.com/pcgafd/config/offlinepc
```

```json
{
  "offlinePermissions": {
    "enabled": false,
    "requestData": {
      "success": true,
      "maxTogglesPerPeriod": 3,
      "remainingTogglesForPeriod": 3,
      "periodLengthDays": 365,
      "nextTimeToAdd": "1601-01-01T00:00:00+00:00"
    }
  }
}
```

## MyGames

```
GET https://beige.xboxservices.com/pcgafd/mygames?market={MARKET}&language={LANGUAGE}&appVersion=2605.1001.14.0
```

Endpoint returns list of IDs and summaries for games

