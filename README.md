# TunTrail

An Android VPN client with a Go engine. WireGuard, VLESS+Reality and Hysteria2
in one app, with split routing that costs a radix-trie lookup per connection.

Built to be read: the engine is ~4200 lines of Go with tests that run without a
device, and the Kotlin layer contains no networking logic at all.

## Why the build happens in CI

The Go engine is compiled into an Android shared library with `gomobile`, which
needs the Android NDK. The NDK ships x86_64 binaries for Linux, and its linker
does not run correctly under qemu on an arm64 host — compilation succeeds,
linking dies with `Illegal instruction`.

GitHub's runners are x86_64, so the build workflow lives there. You do not need
a local Android toolchain.

## Getting an APK

1. Push this repository to GitHub.
2. Open **Actions → Build APK → Run workflow**.
3. Wait ~8 minutes.
4. Download the `tuntrail-debug` artifact and install the APK.

The APK is debug-signed, so Android will ask you to allow installs from unknown
sources. That is expected for a personal build.

## Using it

1. Open the app, tap the node card, then **Settings**.
2. Paste a WireGuard config (`[Interface]` + `[Peer]`) and tap **Import**.
3. Go back and tap the dial.

Reality and Hysteria2 profiles can be added by editing a node's `configJson`, or
by extending the import screen — the engine already accepts both:

```json
{
  "mode": "global",
  "tunAddress": "172.19.0.1/30",
  "tunMtu": 1400,
  "profile": {
    "id": "r1",
    "name": "Reality node",
    "protocol": "reality",
    "reality": {
      "server": "203.0.113.10",
      "port": 443,
      "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
      "serverName": "www.microsoft.com",
      "publicKey": "<server reality public key, base64url>",
      "shortId": "0123456789abcdef",
      "fingerprint": "chrome",
      "flow": "xtls-rprx-vision"
    }
  },
  "dns": { "servers": ["1.1.1.1"], "fakeIp": false },
  "rules": { "final": "proxy" }
}
```

For Hysteria2, use `"protocol": "hysteria2"` with a `hysteria2` block carrying
`server`, `port`, `password`, `sni`, and optionally `upMbps` / `downMbps` (the
Brutal pacing targets — set them near your real link speed).

## Layout

```
engine/                  Go
  internal/route/        radix trie, longest-prefix match, 46 ns/lookup
  internal/proxy/        gVisor stack + tunnel bridging
  internal/tun/          Android tun fd, plus an in-memory twin for tests
  internal/proto/        wireguard, realis (VLESS+Reality), hysteria2, vless
  internal/engine/       connection state machine
  mobile/                the only package gomobile binds
  cmd/tuntrail-cli/      host-side verification, no device needed

app/                     Kotlin + Compose (Material 3)
  TunService.kt          VpnService scaffolding only
  AppModel.kt            state holder, never touches packets
  ConnectDial.kt         the dial and its motion
  HomeScreen.kt          main surface
  SettingsScreen.kt      import and routing
```

## Testing without a phone

```bash
cd engine
go test ./...              # unit + integration, no device
go run ./cmd/tuntrail-cli selftest
```

`selftest` builds a real gVisor stack, opens a TCP connection through it and
verifies a round trip. If that passes, the data plane is wired correctly.

## What is verified and what is not

Verified here, with output:

- Routing: 46 ns per lookup over 4000 prefixes, 36× faster than a linear scan.
- Data plane: a real SYN enters the tun twin, the gVisor stack parses it, the
  forwarder fires, the router picks `proxy` or `direct`, and the right dialer is
  called for each.
- Reality: a full TLS 1.3 handshake against a live site, with the injected
  SessionID accepted and verification correctly rejected when the peer cannot
  prove key ownership.
- VLESS header serialisation for domain, IPv4 and IPv6 targets.

Not verified, because it needs credentials or a device:

- Hysteria2 against a real server.
- Any end-to-end "connect and browse" session.
- The APK itself has never been assembled; CI will be the first attempt.

## Reality handshake notes

Two NIC flags are load-bearing in `internal/proxy`, and both were found by
reading gVisor's source after a day of wrong guesses:

- `SetPromiscuousMode` — a tun receives packets addressed to remote hosts, and
  the NIC drops them otherwise.
- `SetSpoofing` — the forwarder calls `FindRoute` with the packet's *source* as
  the local address. Client addresses are not ours, so without spoofing every
  `CreateEndpoint` fails with `no route to host`.

Also: the interface must be addressed with a subnet (`/30`), not a single host,
or peers on the link have no route.
