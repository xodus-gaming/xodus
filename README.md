<p align="center"><img width="128" src="assets/Icon/Icon.ico" /></p>
<h1 align="center">Xodus</h1>
<p align="center">The great gaming migration to Linux</p>
<p align="center">
    <a href="https://discord.gg/ZG774FK4tq">
        <img src="https://img.shields.io/discord/1123890623586504714?logo=discord&style=for-the-badge&color=red&label=Game+Launchers+Reverse+Engineering" alt="Discord" />
    </a>
</p>

> [!CAUTION]
> This project is not endorsed by Microsoft. Use at your own risk

## Current state of the project

The project can now login, download packages and obtain licenses for games.

These parts are still quite scattered arround.

- [x] Device registration
- [x] Device token exchange
- [x] License parsing
- [x] Device key deriviation
- [x] User TokenBroker auth
- [x] User token exchange
- [x] Licensing flow
- [x] Xbox auth and MSIXVC downloads
- [x] MSIXVC parsing support
- [x] Decryption
- [ ] On-demand .exe decryption
- [ ] MSIXVC2 support

## FAQ

**Q: What is Xodus**  
Xodus aims to bring Xbox PC games to Linux and possibly Mac devices.

**Q: When can I play my Minecraft Bedrock?**  
While Xodus is quickly maturing, there is still a lot of work to support it from Wine standpoint to provide necessary Xbox Services to games.  
*TL;DR* soon<sup>tm</sup>

**Q: How to get involved?**  
Start by joining our Discord or review any open GitHub issues .

**Q: What games will be supported?**  
We hope to manage to support most of the catalog, the limitation is the game has to be GDK and in MSIXVC format.  
So far `Gears of War 4` is a prominent unsupported title for the time being.

## Special Thanks

- [XvdTool.Streaming](https://github.com/LukeFZ/XvdTool.Streaming) and [CikExtractor](https://github.com/LukeFZ/CikExtractor) by LukeFZ
