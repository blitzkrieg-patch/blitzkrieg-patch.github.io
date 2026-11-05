---
title: "Bright VPN: Is it just vpn or proxyware?"
description: "A static teardown of `net_updater32.exe`, the service component that ships with Bright VPN"
summary: "A static teardown of `net_updater32.exe`, the service component that ships with Bright VPN"
categories: ["Writeup"]
tags: ["Reverse"]
#externalUrl: ""
date: 2026-10-23
draft: false
authors:
  - blitzkrieg
cover: 	/images/reverse_kr/bright.jpg
---


# Bright VPN: Is it just vpn or proxyware?

*A static teardown of `net_updater32.exe`, the service component that ships with Bright VPN.*

**Short answer:** it's both. The file I analyzed is the Windows service/updater of the **Bright SDK**, Bright Data's peer network client. Its own consent text says the app is "free in return for allowing Bright Data to occasionally use your device's free resources and IP address to download public web data from the Internet." That is residential proxyware, not a classic VPN component and not classic malware. It is validly signed, and it is the kind of thing enterprise policy usually blocks.

> **Scope note.** This is static analysis only. I did not execute the sample, capture traffic, or fetch the live cloud config. Everything below was re-checked directly against the binary; where something is inferred, I say so.

---

## 1. The sample

| Field | Value |
|---|---|
| File | `net_updater32.exe` |
| Size | 9,495,144 bytes |
| SHA256 | `9f8f52920fcfa7efe57362822f6ddef7c311d5765f525b3f71b978c95becece7` |
| SHA1 | `40b1900e12fafc7d851799cf3f46fc9e68fe1dbf` |
| MD5 | `aefb3f650fe3800d1cddcb08dea65f87` |
| PE | 32-bit (`0x14c`), **console** subsystem, 5 sections |
| Compile timestamp (PE header) | 2026-03-11 11:58:25 UTC (headers can be forged; treat as a hint) |
| Version info | `CompanyName=BrightData Ltd.`, `ProductName=Bright SDK`, `FileVersion=1.614.174`, `InternalName=net_updater.exe` |
| Description | `BrightData service allows free use of certain features in an app you installed` |

The description string is worth reading twice. The binary describes itself as the thing that "allows free use of certain features in an app you installed", which is the trade: free app, your IP address as payment.

**Where it came from.** The sample was found in `C:\Program Files (x86)\Bright VPN\` and flagged by Trend Micro as `PUA.Win32.Luminati.A`. Those two facts come from the original incident, not from the file itself.

### The signature is valid, and that settles less than you'd think

I computed the Authenticode SHA256 of the PE myself and found it inside the embedded PKCS#7 signature:

```
computed authenticode sha256: b0de6e67f8677b413462eb8e1adc6437166615d80270986a77381b065eb1dbe3
digest present in signature:  True
```

Signing certificate:

```
subject: jurisdictionC=IL, businessCategory=Private Organization, serialNumber=514114842,
         C=IL, L=NETANYA, O=Bright Data Ltd, CN=Bright Data Ltd
issuer:  C=US, O="DigiCert, Inc.", CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1
valid:   2025-09-28 to 2027-11-07
```

The chain also includes a DigiCert timestamping CA (`DigiCert Trusted G4 TimeStamping RSA4096 SHA256 2025 CA1`). A valid signature tells you who built it and that it wasn't tampered with. It does not tell you that you want it on your endpoint.

---

## 2. A Russian doll of PE files

`net_updater32.exe` is mostly a container. About 6.9 MB of its 9.5 MB sits in the `.rsrc` section as plain, unencrypted PE files nested inside each other. I extracted each layer and hashed it:

| Layer | Where | Size | SHA256 | What it is |
|---|---|---:|---|---|
| 1 | the EXE | 9,495,144 | `9f8f5292…ecece7` | Native service/updater |
| 2 | `BINARY/100/1033` in layer 1 | 6,876,776 | `bfbea33303800d51166a8af6b636c072b0d33b44ce14e2988cd08f799982c42f` | Native SDK DLL, exports `brd_sdk_*` |
| 3 | `BINARY/100/2057` in layer 2 | 5,063,272 | `bb46a4ccee2d199be43e2c38c4ded1769505369e97248d93003ba56557735525` | Native wrapper DLL, exports `brd_api_*` |
| 4 | `BINARY/100/2057` in layer 3 | 4,962,920 | `83d959e869e31f2802051da0827226411eb4e045b5d2a961535233d0a4a99b7c` | .NET core `BrightData.Sdk.Core` |
| 5 | `BINARY/102/2057` in layer 2 | 970,912 | `86e39b5995af0e042fcdaa85fe2aefd7c9ddc7ad65e6327bd5e7058bc3ab615f` | VC++ 2013 runtime (`msvcr120.dll`) |
| 6 | `BINARY/103/2057` in layer 2 | 31,336 | `63b9b863c40206b874ff0227eedf23e0490c7ea6e41868d76046d7e85b1e23c8` | `test_wpf.exe` |

Reproduce the first hop:

```python
import pefile, hashlib
p = pefile.PE("net_updater32.exe")
for t in p.DIRECTORY_ENTRY_RESOURCE.entries:
    if t.name and t.name.decode() == "BINARY":
        for n in t.directory.entries:
            for l in n.directory.entries:
                d = l.data.struct
                data = p.get_data(d.OffsetToData, d.Size)
                print(n.id, l.id, len(data), hashlib.sha256(data).hexdigest())
```

Output: `100 1033 6876776 bfbea333…c42f`.

The native EXE also loads the SDK DLL **from memory** instead of dropping it to disk. These strings are in the native code:

```
dll_failed_loading_mem_res
dll_failed_loading_mem_mod
mem loaded sdk dll 0x%p
```

The .NET layer carries a `Dotfuscator` attribute and `SuppressIldasm`, so it is obfuscated. The layering makes casual triage harder, though nothing is encrypted.

The exported API tells you what the SDK is for. Layer 2 exports (among 148):

```
?brd_sdk_opt_in@@YGXXZ
?brd_sdk_opt_out@@YGXXZ
?brd_sdk_show_consent@@YGXXZ
?brd_sdk_get_consent_choice@@YGHXZ
?brd_sdk_start_service@@YGXXZ
?brd_sdk_stop_service@@YGXXZ
?brd_sdk_pause@@YGXXZ
?brd_sdk_resume@@YGXXZ
?brd_sdk_set_service_auto_start@@YGXH@Z
?brd_sdk_set_skip_consent_on_init@@YGXE@Z
?lum_sdk_get_bw@@YGPADH@Z
```

That is a host app's control panel: opt in, opt out, start or stop the service, pause, and set auto-start. There is also a `set_skip_consent_on_init` switch, so whether the consent dialog appears is partly the integrating app's choice.

---

## 3. What you are agreeing to

The consent strings are embedded in the .NET layer as JSON. Verbatim:

```json
"desc_main_app_name": "Your use of {placeholder:app_name/} is free in return for allowing {url}Bright Data{/url} to occasionally use your device's free resources and IP address to download public web data from the Internet. ... None of your personal information is accessed or collected except your IP address."
```

```json
"tt_approved":   "Your IP address WILL be used for cases such as:",
"tt_approved_1": "Support academic research",
"tt_approved_2": "Help brands track sites selling fake products",
"tt_approved_3": "Collect public web data like product prices and reviews",
"tt_approved_4": "Aggregate travel information like flights and hotel prices",
"tt_malicious_1": "Never to steal, encrypt, or delete sensitive data",
"tt_malicious_3": "Never to monitor users' computer activity"
```

```json
"choice_use_free_resources":      "allow Bright Data to use device's free resources",
"choice_dont_use_free_resources": "don't allow Bright Data to use device's free resources"
```

Two things stand out. First, this is an explicit, disclosed model, and Bright Data says the user can opt out any time (`"desc_opt_out": "You can opt-out anytime."`). Second, "use your IP address" means other people's web requests leave from *your* connection. Those are Bright Data's own words, not my inference.

The code also links the consent screen to the vendor's web-indexing page (`https://bright-sdk.com/users#learn-more-about-bright-sdk-web-indexing`), the EULA (`https://bright-sdk.com/EULA`) and the privacy policy (`https://bright-sdk.com/privacy-policy`).

---

## 4. The service it installs

### Command line

The native binary prints its own usage text. This is a verbatim excerpt:

```
net_updater [OPTIONS] - %s %s
  --updater appid - run init_monitor with provided appid.
  --install appid - install service with provided appid
  --install-ui appid - install service with provided appid after showing dialog and getting user permission
  --check-peer appid - validate peer
  --uninstall appid - remove service with provided appid (must match appid used during install)
  --start-service appid - starts Bright Data service
  --stop-service appid - stops Bright Data service
```

Additional flags in the binary: `--opt-in`, `--uuid`, `--set-uuid`, `--tid`, `--beta`, `--campaign`, `--tracking_id`, `--elevate`, `--fast`, `--remote`, `--no-cleanup`, `--debug`, plus a family of `--dlg-*` options for skinning the consent dialog (colors, logo, app name, button text).

Note `--check-peer`: the updater has a command whose help text is "validate peer".

### Service identity

Native strings:

```
luminati_net_updater
%s_%s
luminati_net_updater_undefined
Brightdata Service
Brightdata Service (%s)
cmd /c net start %s
--updater %s
service %s not found
can't stop service %s %m
service %s uninstalled %m
```

So the service is named `luminati_net_updater` plus an app-specific suffix, and shows up as **Brightdata Service**. The `luminati_` prefix is the vendor's former name (Luminati Networks), which is why antivirus detections still say "Luminati".

The import table includes the full service-control API from `ADVAPI32.dll`:

```
OpenSCManagerW  CreateServiceW  StartServiceW  ChangeServiceConfigW  ChangeServiceConfig2W
DeleteService  ControlService  QueryServiceStatusEx
StartServiceCtrlDispatcherW  RegisterServiceCtrlHandlerExW  SetServiceStatus
```

The .NET layer installs by launching the updater elevated. These are the relevant strings, adjacent in the .NET user-string heap:

```
--install
--no-cleanup
net_updater: install failed
service_install_uac_agree
service_install_uac_decline
runas
```

That is consistent with a `net_updater32.exe --install <appid> --no-cleanup` invocation launched via `runas` (a UAC prompt), with separate `agree` and `decline` outcomes for the prompt. I read this from the string layout; I did not trace the code.

Uninstall in the .NET layer is built from separate string pieces: `cmd.exe`, `/c`, `sc`, `delete`. That assembles to `cmd.exe /c sc delete <service>`. This is inferred from adjacency, not read as one string.

Start mode is configurable. The .NET layer calls `ChangeServiceConfig` and exposes `SetServiceAutoStart`, and the native SDK exports `brd_sdk_set_service_auto_start`. I did not run it, so I can't say what the default is; whether the service starts automatically depends on how the host app calls this API.

### Running code in your desktop session

A service runs in session 0 with no UI, so it needs a way to show the consent dialog. The native binary imports `WTSQueryUserToken` and `CreateProcessAsUserW`, and contains the wide string `winsta0\default`. The .NET layer contains the matching logic (source file `proc.cs`):

```
explorer
failed opening token of pid {0} {1}
failed duplicating token of pid {0} {1}
winsta0\default
```

(Correction to a common claim: the native EXE does not import `DuplicateTokenEx`; token duplication is in the .NET layer.)

### Cleanup command

Self-removal strings in the native binary:

```
cmd.exe /c choice /c y /d y /n /t 1 & del /f /q "%s\msvcr120.dll" "%s\lum_sdk.dll" "%s\lum_sdk32.dll"  "%s\lum_sdk64.dll" "%s\net_updater32.exe" "%s\net_updater64.exe" "%s\lum_sdk32_clr.dll" "%s\lum_sdk64_clr.dll"
```

A one-second `choice` delay, then delete the binaries after the process has exited.

---

## 5. The peer machinery

The .NET layer's compiled-in source paths are unusually informative. They survive in the binary as strings:

```
c:\cygwin64\home\bat\bat\checkout\zon\pkg\win\sdk\Peer\Peer.cs
c:\cygwin64\home\bat\bat\checkout\zon\pkg\win\sdk\Peer\Conn.cs
c:\cygwin64\home\bat\bat\checkout\zon\pkg\win\sdk\Peer\BW.cs
c:\cygwin64\home\bat\bat\checkout\zon\pkg\win\sdk\Peer\Device.cs
c:\cygwin64\home\bat\bat\checkout\zon\pkg\win\sdk\Peer\DevMon.cs
```

Surrounding strings include `peer_start`, `peer_stop`, `peer_init_err`, `15_peer_start`, `16_peer_dev_init`, `17_peer_dev_testing`, `18_peer_dev_verified`, `user_chose_peer`, `user_chose_not_peer`, `invalid tunnel_init args`, and the class-like names `TunnelProxy`, `ProxyjsConn` and `ZagentConn`. The .NET layer also references `Proxy-Authorization` and `Proxy-Authenticate` headers and uses the WebSocketSharp library.

Static strings can't show the proxy protocol in action, so I'm not claiming a full traffic model. But a component named "Peer" with a connection class, bandwidth accounting (`BW.cs`, `lum_sdk_get_bw`), "tunnel" initialization and proxy-header handling is peer-to-proxy plumbing.

Two guardrails are visible as well:

```
peer_stop_high_cpu
peer_stop monitor percent {0}%
Unregistered apps are not allowed to run SDK service and users won't be qualified as SDK peers.
```

The SDK monitors CPU and stops the peer when usage is high. It also refuses to run for app IDs that aren't registered with Bright Data (the registration page `https://bright-sdk.com/cp/` is also referenced in the .NET layer).

---

## 6. Phone-home and self-update

### Embedded default configuration

The native binary stores its default config as base64 chunks. I decoded them (alignment-shifted, since the chunks split mid-quantum). The first chunk starts mid-key (`ON_VERSION`, almost certainly `CONFIG_VERSION`, which sits next to `CONFIG_MAKEFLAGS`):

```json
ON_VERSION":"1.614.174",
"CONFIG_MAKEFLAGS":"DIST=APP RELEASE=y TOKEN_SIGN=y CONFIG_WIN_SDK=y OBFUSCATE_SDK=y EARNAPP_OFW_UPDATE=y BUNDLER=y EARNAPP_BRANCH_ONLY_OFW=y CONFIG_BATREQ=y CONFIG_BAT_CYCLE=y CONFIG_BAT_PLATFORM=app_win64r_obf",
"DEFAULT_UA":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0",
"CLOUD_CONFIG_URL":"https://cdn-cloud.b-cdn.net/static/cloud_config.dat",
"CCGI_SSL_HOST":"clientsdk.luminati-china.io",
"PERR_SSL_HOST":"clientsdk.bright-sdk.com",
"SPROXY_SSL_HOST":"clientsdk.luminati-china.io",
"SC_RESTORE_REMOVED":true
```

Note the build flags mention `EARNAPP`, another Bright Data product in the passive-income-for-bandwidth category. The key name `SPROXY_SSL_HOST` is literally "S-proxy host."

Next to this config sit hard-coded fallback server lists (`zagent_sdk_ips`, `perr_domains`). The decoded IPv4 blob holds roughly 400 addresses, 389 unique. Examples:

```
8.183.57.101   167.172.37.75   152.42.138.187   64.23.221.123
209.222.21.235   139.59.189.155   88.166.107.113   159.65.107.204
45.76.148.186   128.199.123.255
```

(One of the earlier-listed addresses, `45.77.221.213`, straddles a chunk boundary, so I can only see `5.77.221.213` cleanly; I'm leaving it out.)

### Telemetry

Native format string, verbatim:

```
https://%s/perr?id=lum_sdk_win_%3.s&appid=%3.s&ver=%3.s&uuid=%3.s&old_uuid=%3.s&build=%3.s&cid=%3.s&rmt_update=%d&timestamp=%3.s&channel=%3.s
```

The .NET layer also contains `/client_cgi/perr?` and `sdk_config_win.json`. Local state files named in the native binary: `lum_sdk_install_id`, `lum_sdk_session_id`, `channel.txt`, `%s/../db/conf.json`, and `%s/perr_%s_%s.sent`. The native binary contains the user-agent prefix `BrightSDK/`, and the .NET layer references `websocket-sharp`.

### Self-update

Native strings:

```
%s/net_updater%d.exe
%s/lum_sdk%d.dll
%s.old
%s/net_updater%d.exe:Zone.Identifier
%s/lum_sdk%d.dll:Zone.Identifier
rmt_update_files_ok
rmt_update_files_revert_ok
dll_invalid_size_%s
dll_invalid_hash_%s
dll_invalid_signature_%s
no signature found on the file
WinVerifyTrust failed with error 0x%.8X
sdk certificate verified
```

The updater downloads new EXE/DLL files, keeps `.old` copies for rollback, and checks size, SHA256 and an Authenticode signature (`WinVerifyTrust`) before accepting them. It accepts three signer subjects:

```
C=IL, PostalCode=4250713, L=Netanya, STREET=3 Hamachshev st, O=Luminati Networks Ltd, CN=Luminati Networks Ltd
C=IL, S=Central, O=Bright Data Ltd., CN=Bright Data Ltd.
OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.3=IL, SERIALNUMBER=514114842, C=IL, L=Netanya, O=Bright Data Ltd, CN=Bright Data Ltd
```

The embedded layer-2 hash `bfbea333…c42f` also appears in the native binary as a plain string, which fits a check-before-load design.

Reading this as a security person: update integrity is well handled. But it is a persistent, privileged, self-updating service that takes new code from the vendor's infrastructure, so the vendor is your trust boundary. The `:Zone.Identifier` references point at the downloaded files' Mark-of-the-Web stream. I can see the strings, not the call, so I only say it is consistent with clearing that stream.

---

## 7. Things that look alarming but are not proof of malice

- **VM detection.** The .NET layer checks the registry and device names for virtualization:
  ```
  HARDWARE\ACPI\DSDT\MSFTVM    HARDWARE\ACPI\DSDT\PRLS__    HARDWARE\ACPI\DSDT\BOCHS_
  HARDWARE\ACPI\DSDT\VBOX__    HARDWARE\ACPI\DSDT\PTLTD_
  microsoft hyper-v video    parallels virtio ethernet adapter    vmware svga 3d
  ```
  It sits next to a `tunnel_init VM check exception:` message, so it looks tied to peer eligibility, which is plausible anti-fraud (a peer network doesn't want datacenter VMs). It also hinders sandbox analysis. I would not call it malware evidence by itself.
- **Obfuscation.** Dotfuscator and layered resources are annoying, but commercial software does this too.
- **A valid signature** proves origin, not intent (see section 1).

## 8. What I did not find

- No ransomware, credential theft, keylogging or document-targeting logic in the strings I examined.
- No exploit code.
- Static analysis can't rule out behavior delivered later through the cloud config or an update, and I did not fetch the live config.

I also did not analyze the 64-bit variant (`net_updater64.exe`), the Bright VPN installer, or the service's account and ACL.

---

## 9. Indicators and hunting

**Hashes**

```
9f8f52920fcfa7efe57362822f6ddef7c311d5765f525b3f71b978c95becece7  net_updater32.exe
bfbea33303800d51166a8af6b636c072b0d33b44ce14e2988cd08f799982c42f  embedded SDK DLL (layer 2)
bb46a4ccee2d199be43e2c38c4ded1769505369e97248d93003ba56557735525  embedded wrapper DLL (layer 3)
83d959e869e31f2802051da0827226411eb4e045b5d2a961535233d0a4a99b7c  BrightData.Sdk.Core (layer 4)
86e39b5995af0e042fcdaa85fe2aefd7c9ddc7ad65e6327bd5e7058bc3ab615f  msvcr120.dll (layer 5)
63b9b863c40206b874ff0227eedf23e0490c7ea6e41868d76046d7e85b1e23c8  test_wpf.exe (layer 6)
```

**Host artifacts**

| Type | Value |
|---|---|
| Service name | `luminati_net_updater*` |
| Service display name | `Brightdata Service` / `Brightdata Service (<appid>)` |
| Files | `net_updater32.exe`, `net_updater64.exe`, `lum_sdk32.dll`, `lum_sdk64.dll`, `lum_sdk32_clr.dll`, `lum_sdk64_clr.dll` |
| State | `lum_sdk_install_id`, `lum_sdk_session_id`, `channel.txt`, `conf.json` under a `luminati` directory |
| Registry | `SOFTWARE\Hola`, `SOFTWARE\Luminati`, `...\CurrentVersion\Uninstall\Hola` |
| Named pipe (prefix) | `\\.\pipe\lum_sdk_` |
| Mutex (prefix) | `luminati_sdk_` |
| Command lines | `net_updater32.exe --install`, `--install-ui`, `--updater`, `--uninstall`; `cmd /c net start luminati_net_updater_*` |

**Network**

```
cdn-cloud.b-cdn.net            (cloud config: /static/cloud_config.dat)
clientsdk.bright-sdk.com
clientsdk.luminati-china.io
bright-sdk.com                 (consent / EULA / privacy / registration pages)
brightdata.com
```

**Quick PowerShell checks**

```powershell
Get-Service -Name 'luminati_net_updater*' | Select Name, DisplayName, Status, StartType
Get-CimInstance Win32_Service | ? { $_.PathName -match 'net_updater(32|64)\.exe' } | Select Name, PathName, StartName
Get-FileHash 'C:\Program Files (x86)\Bright VPN\net_updater32.exe' -Algorithm SHA256
```

**Remove it (if unapproved)**

```powershell
Stop-Service -Name 'luminati_net_updater*' -Force
sc.exe delete <exact_service_name>
```

Uninstall the parent app (Bright VPN) first through Windows Settings; the commands above are a fallback.

---

## Verdict

Is Bright VPN "just a VPN"? Going by this binary, no. The VPN is the free product, and the Bright SDK service is how it's paid for: a persistent, self-updating, signed service whose own consent screen says it may use your IP address and free resources for Bright Data's traffic. It is disclosed and opt-out-able, so it is closer to *consentware* than to stealth malware, but it is proxyware all the same.

If you run it at home, read the consent screen as a contract. If you manage endpoints, treat it as unapproved proxyware and block or remove it, because outbound traffic from your network may be someone else's.

---

### How I checked this

Every snippet above was extracted from the sample with `pefile`, `strings`, `openssl` and a short base64 decoder, and each hash was recomputed. A few details differ from the first pass of this analysis, so they are stated here: the PE subsystem is **console** (not GUI), `DuplicateTokenEx` is **not** in the native import table, the VM checks and `explorer` token logic live in the **.NET layer** (not the outer EXE), and the `sc delete` command is assembled from separate strings.
