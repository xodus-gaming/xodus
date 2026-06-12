# Login flow implemented in Xodus

Xodus uses the InlineFlow.srf used on Windows. It's similar to InlineConnect.srf known from mobile devices, but involves JS IPC.

The end goal is the same - get the STS token, allowing to get tokens for any supported Microsoft service.

Flow looks as follows

- InlineFlow.srf
- on post.srf get final STS token
- use RST2.srf to exchange it
- On SSO failure - open requested URL for auth approval
- InlineClientAuth
- Call RST2.srf again 

## RST2.srf

If you know about Xbox services, this is similar to XSTS endpoint. It applies to both user and device STS tokens.

You can see a sample RST2.srf request when we used it in [device](./device.md) STS flow.

Device token always revolves arround user token - its binary secret is used for signing XML payloads as well as decrypting responses.

