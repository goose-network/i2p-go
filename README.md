# i2p-go

A clean-room I2P client/router written in pure Go. It connects to the
public I2P network (netdb reseed, NTCP2 transports, ECIES-Ratchet
garlic, streaming) and exposes a local SOCKS5 proxy for `.i2p`
destinations — and, through a configured outproxy, for clearnet hosts.

Reference implementation studied for protocol compatibility:
[i2p.i2p](https://geti2p.net) (Java, 2.13.0). No Java runtime, no CGo —
the router is a single static Go binary.

## Status

Working end-to-end against the real network (verified 2026-10-16 from a
NAT'd VM whose only outbound path is an upstream SOCKS5 proxy):

```
curl -A "MYOB/6.66 (AN/ON)" --socks5-hostname 127.0.0.1:9050 http://zzz.i2p/
```

returns the real zzz.i2p homepage: HTTP 200, 32 KB, ~3.5 s steady state
(~8 s including a fresh garlic handshake). Five sequential fetches all
succeeded.

Why the odd User-Agent: zzz.i2p runs I2PTunnelHTTPServer with
`rejectUserAgents`, which answers normal browser/curl UAs with
`403 Inproxy access denied`. Java's own HTTP proxy rewrites the UA to
`MYOB/6.66 (AN/ON)` by default; a SOCKS5 pipe — Java's as much as ours —
passes the client's UA through untouched. The 403 body itself is still a
complete HTTP response delivered over our data path.

With an outproxy configured, clearnet HTTPS sites are reachable through
I2P (verified 2026-10-16 against `exit.stormycloud.i2p`):

```
./i2p-go ... -outproxy exit.stormycloud.i2p -outproxy-type connect
curl --socks5-hostname 127.0.0.1:9050 https://www.google.com/   # 200, 85 KB
curl --socks5-hostname 127.0.0.1:9050 https://duckduckgo.com/   # 200, 236 KB
```

I2P has no Tor-style exit-node pool to choose from: an outproxy is a
volunteer-run I2P destination that fetches the clearnet on your behalf,
so `-outproxy` names one (an addressbook name such as
`exit.stormycloud.i2p`, a `.b32.i2p` host, or a full base64
destination, optionally with `:port`). The two `-outproxy-type`
protocols are both spoken, matching the Java router: `connect` (HTTP
CONNECT, the default — what the default outproxies speak) and `socks`
(full SOCKS5 client). Most outproxies tunnel TLS only; stormycloud
answers `CONNECT example.com:80` with `403 Forbidden`, which we surface
to the SOCKS client as host-unreachable, just as the Java proxy does.

What works:

- Reseed (SU3 over HTTPS through the upstream proxy), netdb load/persist
- NTCP2 outbound handshakes (Alice role) with cached connections and
  keepalives
- Netdb lookups/stores to floodfills (RI and LeaseSet2)
- 1-hop inbound tunnels (IBGW → IBEP), rotating every 10 minutes with
  LeaseSet2 republish
- Garlic: ECIES-Ratchet (enc type 4) with NS/NSR/ES, retransmit-safe
  pending handshake state
- I2P streaming protocol: SYN/SYN-ACK/data/CLOSE, gzip payloads,
  retransmit with RTO backoff
- SOCKS5 CONNECT proxy with `.i2p` addressbook + b32 resolution
- Outproxy forwarding of clearnet CONNECTs (HTTP CONNECT or SOCKS5
  protocol, failure mapped to host-unreachable); localhost and LAN
  targets are never relayed

Known limitations:

- Outbound is 0-hop direct-to-gateway (no outbound tunnel hops);
  inbound is a single 1-hop tunnel. This is deliberate for a
  proxied/NAT environment and trades anonymity for reachability.
- The client destination and router identity are ephemeral: fresh keys
  every start (no persistence yet).
- NTCP2 inbound (Bob role) is not implemented; the published router
  address is deliberately undialable, so we only accept inbound traffic
  through our inbound tunnel.

## Build and run

```
go build ./cmd/i2p-go
./i2p-go -socks 127.0.0.1:9050 -upstream 127.0.0.1:7890 \
         -netdb /var/lib/i2p-go -hosts hosts.txt
```

Flags:

| Flag | Default | Meaning |
|------|---------|---------|
| `-socks` | `127.0.0.1:9050` | SOCKS5 listener (CONNECT, `.i2p` hostnames resolved via I2P) |
| `-upstream` | `127.0.0.1:7890` | upstream SOCKS5 proxy for all outbound TCP (empty = direct) |
| `-hosts` | *(none)* | addressbook file, `name=base64destination` lines |
| `-seed` | *(built-in list)* | single reseed URL override |
| `-netdb` | `netdb` | netdb directory (i2pd on-disk format); seeded once, then persisted |
| `-outproxy` | *(none)* | outproxy for non-I2P hosts: addressbook name, `.b32.i2p`, or base64 destination, optional `:port` |
| `-outproxy-type` | `connect` | protocol the outproxy speaks: `connect` (HTTP CONNECT) or `socks` (SOCKS5) |

Then point any SOCKS5-aware client at `127.0.0.1:9050`:

```
curl --socks5-hostname 127.0.0.1:9050 http://zzz.i2p/
```

The first run reseeds and builds a tunnel (a few seconds); the first
request to a new destination includes the garlic handshake.

## Architecture

```
cmd/i2p-go          router main: wiring, tunnels, client destination
internal/
  socks5            SOCKS5 CONNECT server, byte pump to streams,
                    outproxy forwarding (outproxy.go)
  streaming         I2P streaming protocol (packets, connections, RTO)
  garlic            ECIES-Ratchet garlic routing (NS/NSR/ES, cloves)
  i2np              I2NP message codec (DatabaseStore, TunnelData, ...)
  tunnel            inbound tunnel pipeline (IBGW/IBEP, short tunnels)
  ntcp2             NTCP2 transport (Noise_XK_25519_ChaChaPoly_SHA256)
  netdb             router-info/leaseset2 database, lookup/store clients,
                    floodfill selection, on-disk persistence
  reseed            SU3 fetch/verify/extract
  data              I2P data structures (RouterInfo, LeaseSet2,
                    Destination, ElGamal/DSA keys, signatures)
  i2pcrypto         ElGamal, AES256, ChaChaPoly, Ed25519, HKDF helpers
  noise             Noise protocol state machine (IK for garlic)
  proxy             upstream SOCKS5 dialer
```

Message path for `curl → zzz.i2p`:

```
curl → SOCKS5 → streaming (SYN, gzip) → garlic (ECIES-Ratchet to the
remote's LeaseSet2 key, our LeaseSet2 attached on first contact) →
TunnelGateway → remote's inbound tunnel → zzz's eepsite; the reply
rides the reverse path through our inbound tunnel (IBGW → TunnelData →
IBEP → garlic decrypt → streaming → curl).
```

## Utilities

Under `cmd/`:

- `b32check` — print a base64 destination's b32 hostname and key types
- `genkeyfile` / `dumpkeys` — write/inspect Java-I2P-format private key files
- `ls2inspect` — dump a LeaseSet2's destination, keys, and leases
- `riprobe` — print a RouterInfo file
- `samhttp` — SAM v3 client hosting a tiny HTTP responder (interop testing)

## Tests

```
go test ./...
```

Unit tests cover the codec and crypto layers (data structures,
signatures, ElGamal, Noise, NTCP2 frames, I2NP messages, streaming
packet round-trips, garlic NS/NSR/ES including the retransmit-keeps-
prior-handshake regression). Real-network behavior is verified with the
curl recipe above.
