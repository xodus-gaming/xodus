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
- [ ] On-demand .exe decryption [#50](https://github.com/xodus-gaming/xodus/issues/50)
- [ ] MSIXVC2 support [#53](https://github.com/xodus-gaming/xodus/issues/53)

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

## Building

The project structure is as follows.

```
.
├── msixvc - [rlib] common rlib crate for utilities for parsing MSIXVC and XSP files
├── xodus - [rlib] common rlib crate that contains core xodus functionality, API calls abstractions and utilities
├── xodus-cli - [bin] CLI currently used for iterating over new xodus features 
└── xodus-service - [bin] service process exposing a xodus.sock for IPC communication, it takes care of and xgameruntime.dll integration.
```

> [!NOTE]
> xodus-service aims to become a main point of integration. All xodus clients will connect to it to interact with games and Xbox services.

### Prerequisites

- Rust version supporting `edition = "2024"`
- Right now CLI relies on wry and tao to show a login page. Consult https://docs.rs/wry/latest/wry/#platform-considerations
- xodus-service relies on `protoc` to compile `proto/` definitions make sure to install it for your platform

### Running

Building all crates in release mode
```bash
cargo build --release --workspace
```

Running cli in debug
```
cargo run -- --help
```

Running xodus-service in debug
```
cargo run --bin xodus-service
```

### CLI Usage

```
Usage: xodus-cli <COMMAND>

Commands:
  download   Download msixvc or xsp files fo given game
  license    Dump CIKs for use with XvdTool
  extract    Extract locally stored msixvc file
  login      
  streaming  Download and extract the game through streaming algorithm
  help       Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```


## Special Thanks

- [XvdTool.Streaming](https://github.com/LukeFZ/XvdTool.Streaming) and [CikExtractor](https://github.com/LukeFZ/CikExtractor) by LukeFZ
