# thinkpol-vpn — Transport design

The transports: what a link looks like on the wire, and the traffic shape each transport owns. The entry point is [DESIGN.md](../../DESIGN.md).

#### Transports

Roughly in order of how hard they are to catch:

| Transport | Shape | Notes |
|---|---|---|
| `udp` | sealed datagrams | the baseline; trivially profiled (RR30) |
| `tls` | TLS 1.3 with a browser fingerprint (uTLS), probe fallback to a real site | after the MVP, node-to-node links (TP-028) |
| `ws` | WebSocket over TLS | can sit behind a CDN, which hides the node's IP |
| `reality` | REALITY's handshake: a browser ClientHello that seals the client's id; failed auth is spliced to a real site | the disguised transport for client → entry (M2, TP-087); no certificate of our own |
| `obfs-udp` | obfuscated datagrams | direct device-to-device paths, where TCP hole punching is impractical |

Stream transports carry TCP inside TCP and degrade under loss; datagram transports are the first thing throttled under whitelists. Hence **transports are chosen per link**. How stream transports authenticate and treat replays is in [`transport`](../../internal/dataplane/transport/doc.go); what a server's own hello still tells a censor is RR31. A "bridge" node type (a VLESS ingress routed into the overlay) was considered and set aside as too complex for now.

**The map says, the engine converts, the transport decides.** Each transport's settings are its own protobuf messages: the controller encodes them, the transport's adapter decodes them, and the map and everything between carry them as opaque bytes. The engine converts the map to the transport port and checks every entry with the transport before using it. Endpoints in the map are IP literals: the controller resolves names, nodes never resolve them at dial time. Nodes' clocks must agree within five minutes.

**Transports own traffic shape.** WireGuard's fixed packet sizes and its rhythm (rekey every 2 minutes, keepalives) would show through any wrapper, and only the transport knows what traffic it's imitating. So padding, batching, timing and cover traffic are part of the transport contract (C6), and the layers above never pad; they only mark the packets that keep a link warm, so a transport can fold their rhythm into its own.

- **Per end, from the map, never negotiated:** each end shapes what *it* sends; receivers undo shaping from the wire format alone.
- **Refuse, never weaken:** an adapter refuses a link whose shaping it can't honour, and a node refuses shaping fields it doesn't know, rather than shape less than the map asks. Shaping sits inside the transport's encryption and never touches its authentication or replay protection.
- **Rollout:** refusing is safe only if the controller never asks a node for what it can't do. So it puts a shaping (or a new shaping field or value) into a link only once both ends' nodes reported supporting it, in the version and capabilities agents report when they register and update; until then the link goes unshaped or keeps its old shaping.

The lab measures how much shaping is enough per transport and tunes the defaults (none, until it says otherwise).
