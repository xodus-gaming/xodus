## Subscriptions

```
GET https://catalog.gamepass.com/pcsubscriptions?market={MARKET}&language={LANGUAGE}
```
Tons of IDs relations and capabilities, like whether XCloud is included in the offer

## PC PackageFamilyNames

```
GET https://catalog.gamepass.com/misc/pc-pfns-list
```

this one supports `If-None-Match` with Etag - update checking

It seems to corelate what games are available on PC from the catalog? Unsure how to corelate those values yet with anything meaningful.  
Sample:
```json
"10192RubberBandGames.WobblyLife_cy31b6rjjkmkj",
"1047Games.Splitgate2_04wnr0yq4se82",
"11443ChasingCarrotsGmbHCo.HallsofTorment_xfxtxadz31m7r",
"11bitstudios.20925BA3921E0_gwy9gn5q9j1y6",
"16902PlaydeadAPS.PlaydeadsLIMBO_2m6wzp0cmt084",
"181CBCCD.8e9b6fe9-66b3-4704-815d-44ada631592c_9y3t8zad226mc",
```

## 