# Running a space by hand (before the controller)

Until the controller exists (M4), a space's maps are built with the dev
tooling and copied to the nodes by hand. This is the runbook for that
period: rotating the map, restarting a node after a reboot, updating a
binary, and keeping the nodes' clocks in agreement. Everything the
controller will automate (SSH provisioning, map gossip, signed updates,
dashboards) is out of scope here; the design refs are PRD A4/A5 and DESIGN
"The signed map" and "Server agent".

## What lives where

A **node** (server or device) holds only:

```
/var/lib/thinkpol/          # Linux; a macOS device: /private/var/lib/thinkpol
  node.key                  # the node's id and private keys (0600)
  space.pub                 # the space's id and public keys: what every map is verified against
  map.bin                   # the latest map; the node can open only its own section
  blobs/                    # GeoIP list blobs, files named by their SHA-256
```

The **admin's build machine** holds the `keys/` directory from
`thinkpol dev keygen space` and `thinkpol dev keygen node`: `space.key`
(the signing key — private), `recovery.key` (offline, never on any machine
that runs the network; create it with `dev keygen space -recovery-out
<dir>`), `space.pub`, and per node `<name>.key` and `<name>.pub`. The spec
(`spec.yaml`) describing the space lives next to it; `thinkpol dev map
spec` prints its format.

Never copy `space.key` or `recovery.key` onto a node: the agent refuses to
start when it finds a space's private key in its state directory, and a
node that could sign maps breaks the trust model. A node needs only its own
`<name>.key` (as `node.key`), `space.pub` and `map.bin`.

The server agent is `thinkpol up`, run as root on the VPS. It serves the
space whenever it runs; its log goes to stderr and an in-memory ring
(`thinkpol logs`, root only), never to disk by the agent's own hand. There
is no service unit from us yet (that is TP-046); run it under your own
service manager, for example a unit named `thinkpol.service`:

```ini
[Unit]
Description=thinkpol node agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/thinkpol up
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

When systemd captures the agent's stderr, journald stores it on disk;
keeping the journal volatile is part of provisioning (TP-038), not of this
runbook.

## Rotating and distributing the map

The nodes follow the newest map they are given and never ask anything
else: to change the network you issue a new map version and copy it to
every node.

1. Edit `spec.yaml`.
2. Rotate the map:

   ```sh
   thinkpol dev map rotate -keys keys -out map.bin spec.yaml
   ```

   `dev map rotate` rebuilds the spec with fresh per-link credentials and a
   version past the deployed map (so nodes take it). It requires a valid
   signed map of the same space at `-out` (the file to replace); the first
   build of a space is `thinkpol dev map build` instead. `thinkpol dev map
   inspect -keys keys map.bin` shows what the new map says.

   Every `dev map build` and every rotation re-keys **all** links in the
   spec, not only the ones you changed. Nodes on different map versions
   cannot link to each other.
3. Copy the same `map.bin` to every node. **Devices have no SSH path** —
   deliver their map through whatever channel you use for device config, or
   accept that they stay cut off until they get it. **Admin access over the
   overlay** can drop mid-rollout when credentials change; reach nodes by
   their **public** addresses from the spec, push the file to all servers
   in parallel, then signal each one:

   ```sh
   staging=$(mktemp -d)
   scp map.bin root@<node>:"$staging/map.new"
   ssh root@<node> "cp \"$staging/map.new\" /var/lib/thinkpol/map.bin && chmod 644 /var/lib/thinkpol/map.bin && rm -rf \"$staging\" && systemctl kill -s HUP thinkpol"
   ```

   The dev tooling writes maps atomically (temp file in the state
   directory, then rename over `map.bin`). On the node, copy into place
   before removing the old file so a node that starts during the gap does
   not see a half-written map. The file must end up owned by root (or the
   agent's user) and not group- or world-writable.

   Deliver to **devices first**, or accept that they drop off until they
   receive the new map.
4. Each node takes the new map within its map poll (5 s by default,
   `THINKPOL_MAP_POLL`) or immediately on `SIGHUP`, and says so in `thinkpol
   status` (the map version).

Notes:

- Every node gets the same file: the envelope is signed for the whole
  space, and each node can open only its own sealed section inside it.
- A rotation re-credentials every link. A node that already has the new
  map refuses links from nodes still on the old one, and the other way
  round, so distribute the file to all nodes promptly; links come back as
  each end picks the new map up.
- A node refuses any map older than the one it holds. There is no
  rollback: fix forward with a newer version.
- `space.pub` only changes when the space's keys themselves change; nodes
  already hold it.

## After a VPS reboot

The state directory survives; everything else the node knew is in memory
on purpose (no logs, no state on disk). Recovery is starting the agent
again:

1. Start it the way you run it (for example `systemctl start thinkpol`).
2. Check `thinkpol status`: serving, its workers ready.

Nothing else to do. The agent re-derives its firewall and network setup on
start, removes what a dead predecessor left, and keeps serving the map it
has until you rotate a new one.

## Updating a binary over SSH

Signed updates distributed through the network arrive with the controller
(TP-044). Until then, updates are hand-carried:

1. Build or download the binary for the node's platform (`make build` from
   the revision you trust; verify a release's checksum with whatever
   accompanied it). Check it runs before installing:

   ```sh
   staging=$(mktemp -d)
   scp bin/thinkpol root@<node>:"$staging/thinkpol.new"
   ssh root@<node> "\"$staging/thinkpol.new\" version"
   ```

2. Swap the binary and restart the agent:

   ```sh
   ssh root@<node> "install -m 755 \"$staging/thinkpol.new\" /usr/local/bin/thinkpol && rm -rf \"$staging\" && systemctl restart thinkpol"
   ```

3. `ssh root@<node> thinkpol status`: serving again, workers ready.

The restart is the whole outage: keys and map are on disk, and the agent
refuses to start twice on one host, so a stray manual run changes nothing.

## Clocks

Transports rely on clocks: nodes' clocks must agree within five minutes,
and `udp` drops datagrams sealed further from its own clock than that
(DESIGN, "The map says, the engine converts, the transport decides"). A
node whose clock is off cannot link, and the peers that drop its datagrams
report the skew in their health once several such drops arrive in a short
window (not from a single replayed packet).

- **Linux nodes:** install and enable chrony (any NTP client will do;
  provisioning sets this up automatically from M4, TP-038):

  ```sh
  apt install chrony      # or dnf install chrony
  systemctl enable --now chrony
  chronyc tracking        # check the "System time" offset is small
  ```

- **Devices:** keep the OS's own automatic date and time on (macOS and
  Windows do this by default).

- **Reading the health:** `thinkpol status` on the receiving node names a
  clock-skew problem when it dropped several authenticated datagrams sent
  outside the five-minute agreement recently — a peer's clock is off, or
  (after the threshold) evidence of sustained skew. Fix a clock that is
  off; do not touch the map.

## When something is wrong

- `thinkpol status`: connection, health (problems from a fixed vocabulary),
  a server's workers and public listeners, a device's peers and neighbors.
- `thinkpol logs`: the agent's own log ring (root only).
- A node that its map no longer includes idles instead of failing: it
  starts, finds no section for itself, and waits. Adding it back to the
  spec and rotating brings it in at the next map. 
