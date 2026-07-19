# Login flow implemented in Xodus

Xodus uses `InlineLogin.srf`, the same hosted login page Windows loads inside `CloudExperienceHost` (the native shell that embeds sign-in webviews for TokenBroker). It's similar to `InlineConnect.srf` known from mobile devices, but the page talks to its host over a JS IPC bridge instead of redirect URLs.

The end goal is the same - get the STS token, allowing to get tokens for any supported Microsoft service.

Flow looks as follows

- Open `InlineLogin.srf` in a webview, presenting as `CloudExperienceHost`
- The page calls back over IPC as it loads, and again once `post.srf` finishes loading, handing over the signed-in user's tokens (`DAProperty`)
- use RST2.srf to exchange it for real Xbox Live tokens (`exchange_user_token`)
- On SSO failure - open the URL returned in the fault for auth approval
- Call RST2.srf again once that second session completes

## Webview / JS IPC

On Windows, `CloudExperienceHost` hosts the login page and exposes itself to it as `window.external`, plus a `CloudExperienceHost.Bridge.dispatchMessage` bridge the page can call into and get answers from. Xodus doesn't have a real `CloudExperienceHost` - `xodus-cli/src/webview.rs` re-implements just enough of it inside its own embedded webview (tao/wry) for the page to behave as if it were signing in through Windows.

What that involves:

- **Identifying as the host.** The initial request to `InlineLogin.srf` carries a set of `cxh-*` headers (capabilities, correlation id, MSA/identity client binary versions, OS version, platform, protocol) that a real `CloudExperienceHost` would send. Without these the page can behave differently or refuse to proceed.
- **Aliasing the IPC channel.** wry only exposes `window.ipc.postMessage`; an injected init script aliases `window.external.notify` to it so the page's existing calls reach Xodus unmodified.
- **Two kinds of IPC message.** Everything the page posts over IPC lands in `with_ipc_handler` and is tried as two different shapes:
  - A `DAProperty` payload - the actual sign-in result (DA token, DA session key, STS inline flow token, sign-in name, PUID). This is what `SessionHandler::on_token` receives.
  - A `HostBridgeMessage` invoking `CloudExperienceHost.getContext` - the page asking its host for context about itself. Xodus answers by evaluating a script that calls `dispatchMessage` back into the page with a canned context payload, mirroring what the real host would return.
- **Forcing the final handoff.** The page only pushes its `ServerData` (containing the `DAProperty`) over IPC on its own if a real host asked for it earlier in a way Xodus doesn't replicate. Instead, once the page finishes loading `https://login.live.com/ppsecure/post.srf`, Xodus evaluates `window.ipc.postMessage(JSON.stringify(ServerData))` itself to pull the tokens out.

The webview runtime itself is generic: a `SessionHandler` trait (`bootstrap` / `on_token` / `on_closed`) describes what to do at each step, and a `RuntimeCommands` action queue lets a handler open or close webview sessions without owning the event loop directly. `xodus-cli/src/commands/login.rs`'s `LoginHandler` is the only implementation today - its `on_token` calls `exchange_user_token` (see [RST2.srf](#rst2srf)), and if that comes back as a SOAP fault with an inline auth URL, it closes the current session and opens a second one at that URL instead of failing outright. Once that second session also produces a `DAProperty`, the exchange is retried with an extra `http://Passport.NET/tb` scope added, which is what actually finalizes the token.

## RST2.srf

If you know about Xbox services, this is similar to XSTS endpoint. It applies to both user and device STS tokens.

You can see a sample RST2.srf request when we used it in [device](./device.md) STS flow.

Device token always revolves arround user token - its binary secret is used for signing XML payloads as well as decrypting responses.

