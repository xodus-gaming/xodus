A rsa secured device cannot directly request a clientid specific user token. (Caution We can not easily decrypt responses, windows could but does not have to get same errors)

Windows continues here
```xml
<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wssc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
    <wsa:To s:mustUnderstand="1">https://login.live.com:443/RST2.srf</wsa:To>
    <wsa:MessageID>1782977821</wsa:MessageID>
    <ps:AuthInfo xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" Id="PPAuthInfo">
      <ps:HostingApp>0000000040159362</ps:HostingApp>
      <ps:BinaryVersion>45</ps:BinaryVersion>
      <ps:UIVersion>1</ps:UIVersion>
      <ps:InlineUX>TokenBroker</ps:InlineUX>
      <ps:IsAdmin>1</ps:IsAdmin>
      <ps:Cookies/>
      <ps:RequestParams>xxxx</ps:RequestParams>
      <ps:WindowsClientString>xxxx</ps:WindowsClientString>
      <ps:ClientCapabilities>1</ps:ClientCapabilities>
    </ps:AuthInfo>
    <wsse:Security>
      <wsse:UsernameToken wsu:Id="user">
        <wsse:Username>somerealmail@live.com</wsse:Username>
        <wsse:LoginOption>6</wsse:LoginOption>
      </wsse:UsernameToken>
      <wsse:SecurityTokenReference>
        <wsse:KeyIdentifier ValueType="ps:LoginKeyToken" EncodingType="#Base64Binary">NGCNonce</wsse:KeyIdentifier>
      </wsse:SecurityTokenReference>
      <wsu:Timestamp wsu:Id="Timestamp">
        <wsu:Created>2026-07-02T07:36:59Z</wsu:Created>
        <wsu:Expires>2026-07-02T07:41:59Z</wsu:Expires>
      </wsu:Timestamp>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <ps:RequestMultipleSecurityTokens xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" Id="RSTS">
      <wst:RequestSecurityToken Id="RST0">
        <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
        <wsp:AppliesTo>
          <wsa:EndpointReference>
            <wsa:Address>scope=service::user.auth.xboxlive.com::MBI_SSL&amp;api-version=2.0&amp;uaid=7a93ccc0-b191-474b-be0f-05d7664a3f7b&amp;clientid=0000000040159362</wsa:Address>
          </wsa:EndpointReference>
        </wsp:AppliesTo>
        <wsp:PolicyReference URI="TOKEN_BROKER"/>
      </wst:RequestSecurityToken>
      <wst:RequestSecurityToken Id="RST1">
        <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
        <wsp:AppliesTo>
          <wsa:EndpointReference>
            <wsa:Address>http://Passport.NET/tb</wsa:Address>
          </wsa:EndpointReference>
        </wsp:AppliesTo>
      </wst:RequestSecurityToken>
    </ps:RequestMultipleSecurityTokens>
  </s:Body>
</s:Envelope>
```

this returns

```
<?xml version="1.0" encoding="utf-8"?>
<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust" xmlns:psf="http://schemas.microsoft.com/Passport/SoapServices/SOAPFault">
  <S:Header>
    <psf:pp xmlns:psf="http://schemas.microsoft.com/Passport/SoapServices/SOAPFault">
      <psf:serverVersion>1</psf:serverVersion>
      <psf:authstate>0x80048800</psf:authstate>
      <psf:reqstatus>0x800488aa</psf:reqstatus>
      <psf:signChallenge>CHALLENGESTRINGFORJWT</psf:signChallenge>
      <psf:serverInfo LocVersion="0" ServerTime="2026-07-02T07:37:00Z" BuildVersion="16.0.31112.12">BL02EPF0001D973 16.0.31112.12</psf:serverInfo>
      <psf:cookies/>
      <psf:response/>
      <psf:UserSessionKey>0</psf:UserSessionKey>
    </psf:pp>
  </S:Header>
  <S:Body>
    <S:Fault>
      <S:Code>
        <S:Value>S:Sender</S:Value>
        <S:Subcode>
          <S:Value>wst:FailedAuthentication</S:Value>
        </S:Subcode>
      </S:Code>
      <S:Reason>
        <S:Text xml:lang="en-US">Authentication Failure</S:Text>
      </S:Reason>
      <S:Detail>
        <psf:error>
          <psf:value>0x800488aa</psf:value>
          <psf:internalerror>
            <psf:code>0x80045c39</psf:code>
            <psf:text>The credential requires the use of a nonce
</psf:text>
          </psf:internalerror>
        </psf:error>
      </S:Detail>
    </S:Fault>
  </S:Body>
</S:Envelope>
```

then we appearently need to sign a jwt with an currently unknown rsa

```js
{'typ': 'JWT', 'alg': 'RS256', 'kid': '5Ade6S7gX6UsI3gokpjoFIxUyDjR2_v45BDNI76q7Z8'}
```
```js
{'aud': 'http://login.live.com', 'cnf': {'jwk': {'kty': 'RSA', 'n': 'xxxxxxxxxxxx', 'e': 'AQAB', 'alg': 'RSA-OAEP', 'use': 'enc'}}, 'request_nonce': 'CHALLENGESTRINGFORJWT'}
```

Then RST2

```xml
<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wssc="http://schemas.xmlsoap.org/ws/2005/02/sc" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust">
  <s:Header>
    <wsa:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
    <wsa:To s:mustUnderstand="1">https://login.live.com:443/RST2.srf</wsa:To>
    <wsa:MessageID>1782977821</wsa:MessageID>
    <ps:AuthInfo xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" Id="PPAuthInfo">
      <ps:HostingApp>0000000040159362</ps:HostingApp>
      <ps:BinaryVersion>45</ps:BinaryVersion>
      <ps:UIVersion>1</ps:UIVersion>
      <ps:InlineUX>TokenBroker</ps:InlineUX>
      <ps:IsAdmin>1</ps:IsAdmin>
      <ps:Cookies/>
      <ps:RequestParams>xxx</ps:RequestParams>
      <ps:WindowsClientString>xxx</ps:WindowsClientString>
      <ps:ClientCapabilities>1</ps:ClientCapabilities>
    </ps:AuthInfo>
    <wsse:Security>
      <wsse:UsernameToken wsu:Id="user">
        <wsse:Username>somerealmail@live.com</wsse:Username>
        <wsse:LoginOption>6</wsse:LoginOption>
      </wsse:UsernameToken>
      <wsse:BinarySecurityToken EncodingType="ps:JWT" ValueType="ps:LoginKeyToken" Id="LoginKeyToken">JWT</wsse:BinarySecurityToken>
      <wsse:BinarySecurityToken ValueType="urn:liveid:device" id="DeviceDAToken">&lt;EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Id="devicesoftware" Type="http://www.w3.org/2001/04/xmlenc#Element"&gt;&lt;EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"&gt;&lt;/EncryptionMethod&gt;&lt;ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"&gt;&lt;ds:KeyName&gt;http://Passport.NET/STS&lt;/ds:KeyName&gt;&lt;/ds:KeyInfo&gt;&lt;CipherData&gt;&lt;CipherValue&gt;M.C532_BAY.0.D.MsaArtifacts.xxx&lt;/CipherValue&gt;&lt;/CipherData&gt;&lt;/EncryptedData&gt;</wsse:BinarySecurityToken>
      <EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Id="BinaryDAToken1" Type="http://www.w3.org/2001/04/xmlenc#Element">
        <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
          <ds:KeyName>http://Passport.NET/STS</ds:KeyName>
        </ds:KeyInfo>
        <CipherData>
          <CipherValue>M.C547_BAY.0.U.MsaArtifacts.xxxxx</CipherValue>
        </CipherData>
      </EncryptedData>
      <wssc:DerivedKeyToken wsu:Id="SignKey" Algorithm="urn:liveid:SP800108_CTR_HMAC_SHA256_DOUBLEDERIVED">
        <wsse:RequestedTokenReference>
          <wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID"/>
          <wsse:Reference URI="#DeviceDAToken"/>
        </wsse:RequestedTokenReference>
        <wssc:Nonce>4NwLzXgjn/tNzZmrV5D11Y+mqr4qxG83</wssc:Nonce>
      </wssc:DerivedKeyToken>
      <wsu:Timestamp wsu:Id="Timestamp">
        <wsu:Created>2026-07-02T07:37:07Z</wsu:Created>
        <wsu:Expires>2026-07-02T07:42:07Z</wsu:Expires>
      </wsu:Timestamp>
      <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
          <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"/>
          <Reference URI="#RSTS">
            <Transforms>
              <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </Transforms>
            <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <DigestValue>eP3gt9kTtoSKjKVv69OaKEoumitN6iT3IjCxAAdMM1I=</DigestValue>
          </Reference>
          <Reference URI="#Timestamp">
            <Transforms>
              <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </Transforms>
            <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <DigestValue>QrNazUs+cyAHNjnmQPEcuncJB+sOt13b+smqXYmObuA=</DigestValue>
          </Reference>
          <Reference URI="#PPAuthInfo">
            <Transforms>
              <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            </Transforms>
            <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <DigestValue>sKKYQf/QuZnoVQKj+6Bp7xCabtoB30EAXqmaac+8Utg=</DigestValue>
          </Reference>
        </SignedInfo>
        <SignatureValue></SignatureValue>
        <KeyInfo>
          <wsse:SecurityTokenReference>
            <wsse:Reference URI="#SignKey"/>
          </wsse:SecurityTokenReference>
        </KeyInfo>
      </Signature>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <ps:RequestMultipleSecurityTokens xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" Id="RSTS">
      <wst:RequestSecurityToken Id="RST0">
        <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
        <wsp:AppliesTo>
          <wsa:EndpointReference>
            <wsa:Address>scope=service::user.auth.xboxlive.com::MBI_SSL&amp;api-version=2.0&amp;uaid=7a93ccc0-b191-474b-be0f-05d7664a3f7b&amp;clientid=0000000040159362</wsa:Address>
          </wsa:EndpointReference>
        </wsp:AppliesTo>
        <wsp:PolicyReference URI="TOKEN_BROKER"/>
      </wst:RequestSecurityToken>
      <wst:RequestSecurityToken Id="RST1">
        <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
        <wsp:AppliesTo>
          <wsa:EndpointReference>
            <wsa:Address>http://Passport.NET/tb</wsa:Address>
          </wsa:EndpointReference>
        </wsp:AppliesTo>
      </wst:RequestSecurityToken>
    </ps:RequestMultipleSecurityTokens>
  </s:Body>
</s:Envelope>
```

The next seen request seems to be the request xodus does.
