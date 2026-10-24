# Xodus Docs

## Components

![Xodus architecture diagram](/assets/Docs/architecture_diagram.png)

At a high level, the design of the Xodus project consists of three main components:

- [Xodus](https://github.com/xodus-gaming/xodus) - Process ran in the Linux host environment that communicates with xgameruntime via IPC, handling the processing of complex runtime API calls that involve communication with the XBOX Servers or host-side UI. This Wiki focuses on the documentation of this project.
- [xgamertuntime](https://github.com/xodus-gaming/xgameruntime) - Open source implementation of `xgameruntime.dll`, a Windows component required to execute XBOX PC games. 
- [Wine](https://github.com/xodus-gaming/wine) - Xodus fork of Wine that is patched to include the open source `xgameruntime.dll`.


## Xodus Project Structure

The Xodus project divides responsibilities into Rust crates. The crates are as follows,

- `msixvc` - common rlib crate for utilities for parsing MSIXVC and XSP files.
- `xodus-cli` - basic CLI utilities for interacting with Xodus.
- `xodus-gui` - GUI intended to use peer and services for communication.
- `xodus-peer` - protobuf definitions and IPC transport utilities.
- `xodus-service` - service process exposing a xodus.sock for IPC communication, it takes care of xgameruntime.dll integration.
- `xodus` - common rlib crate that contains core xodus functionality, API calls abstractions and utilities.

## Contents

- For high-level information on the architecture and requirements, see [Architecture](./architecture/architecture.md)
- For API documentation generated from source code (xodus-peer, xodus-service, etc.), see [Crates](./crates/crates.md)
