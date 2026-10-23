# Running a space by hand (before the controller)

Until the controller exists (M4), a space's maps are built with the dev
tooling and copied to the nodes by hand. This is the runbook for that
period: rotating the map, restarting a node after a reboot, updating a
binary, and keeping the nodes' clocks in agreement. Everything the
controller will automate (SSH provisioning, map gossip, signed updates,
dashboards) is out of scope here; the design refs are PRD A4/A5,
[docs/design/control-plane.md](design/control-plane.md#the-signed-map) and
[docs/design/server-agent.md](design/server-agent.md#server-agent-one-worker-per-space).

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
(`thinkpol logs`, root only), never to disk by the agent's own hand. Run it
as a service: `thinkpol service install`, as root, copies the binary to
`/usr/local/bin/thinkpol`, writes the systemd unit `thinkpol.service`,
makes the `thinkpol` group (the local API's; `-user` adds someone to it)
and starts the agent. It starts at every boot, and systemd starts it again
5 s after any exit. `systemctl reload thinkpol` sends SIGHUP to the agent
alone, which re-reads the map at once; the per-space workers it runs don't
handle SIGHUP, so never signal the whole unit. `thinkpol service uninstall`
stops it, undoes what a crashed agent left, and removes the unit and the
binary; the `thinkpol` group and the state directory stay. Both refuse
while an agent you started by hand holds the host lock: stop it first. Package `agent/service` has the unit and why it is so.

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
3. Copy the same `map.bin` to every node. Whichever side of a link has
   the new map can't link to the other until both have it, so go in this
   order:

   - **Devices first.** They have no SSH path: deliver the file through
     whatever channel you use for device config. Stage it in the device's
     state directory under a temporary name and rename it over `map.bin`
     (same directory, same filesystem — no torn write), the same way as
     for servers. Each device drops off until the servers have the new map
     too, so finish the servers right after.
   - **Then every server, in parallel.** Admin access over the overlay can
     drop mid-rollout as credentials change, so reach servers by their
     **public** addresses from the spec. Per server, stage the file in a
     directory made on the node, copy it into the state directory under a
     temporary name, and rename it over `map.bin`:

     ```sh
     set -e
     staging=$(ssh root@<node> mktemp -d)
     test -n "$staging"
     scp map.bin root@<node>:"$staging/map.bin"
     ssh root@<node> "install -m 644 -o root -g root \"$staging/map.bin\" /var/lib/thinkpol/.map.new && mv -f /var/lib/thinkpol/.map.new /var/lib/thinkpol/map.bin && rm -rf \"$staging\""
     ```

     The rename is atomic (same directory, same filesystem), so an agent
     that starts or polls mid-copy sees the old map or the new one, never
     a half-written file; the dev tooling writes its own output the same
     way. The file must end up owned by root (or the agent's user) and
     not group- or world-writable.
4. Each node takes the new map within its map poll (5 s by default,
   `THINKPOL_MAP_POLL`) and says so in `thinkpol status` (the map
   version). To take it at once, `ssh root@<node> systemctl reload
   thinkpol` with the service's unit, which sends SIGHUP to the agent's main
   process only. Don't use `systemctl kill -s HUP thinkpol`: it signals
   every process in the unit's cgroup, and a per-space worker there dies
   of the SIGHUP it doesn't handle (the agent restarts it, an outage for
   that space).

Notes:

- Every node gets the same file: the envelope is signed for the whole
  space, and each node can open only its own sealed section inside it.
- A rotation re-credentials every link. A node that already has the new
  map refuses links from nodes still on the old one, and the other way
  round, so distribute the file to all nodes promptly; links come back as
  each end picks the new map up.
- A node refuses any map older than the one it holds on the normal poll
  path. A restart loads whatever `map.bin` verifies, so replacing the
  file and restarting rolls **that** node back; peers already on the newer
  map won't link to it until they roll back too or you issue a newer map
  everyone takes.
- `space.pub` only changes when the space's keys themselves change; nodes
  already hold it.

## After a VPS reboot

The state directory survives; everything else the node knew is in memory
on purpose (no logs, no state on disk). Recovery is starting the agent
again:

1. The service starts the agent at boot (with your own service manager,
   start it the way you run it).
2. Check `thinkpol status`: serving, its workers ready.

Nothing else to do. The agent re-derives its firewall and network setup on
start, removes what a dead predecessor left, and keeps serving the map it
has until you rotate a new one.

## Updating a binary over SSH

Signed updates distributed through the network arrive with the controller
(TP-044). Until then, updates are hand-carried:

1. Build or download the binary for the node's platform (`make build` from
   the revision you trust; verify a release's checksum with whatever
   accompanied it). Stage it in a directory made on the node and check it
   runs there before installing:

   ```sh
   staging=$(ssh root@<node> mktemp -d)
   scp bin/thinkpol root@<node>:"$staging/thinkpol"
   ssh root@<node> "\"$staging/thinkpol\" version"
   ```

2. Install the staged binary as the service: it copies itself over
   `/usr/local/bin/thinkpol` with a rename (an agent restarted mid-copy
   never runs a half-written file) and restarts the agent:

   ```sh
   ssh root@<node> "\"$staging/thinkpol\" service install && rm -rf \"$staging\""
   ```

3. `ssh root@<node> thinkpol status`: serving again, workers ready.

The restart is the whole outage: keys and map are on disk, and the agent
refuses to start twice on one host, so a stray manual run changes nothing.

## Clocks

Transports rely on clocks: nodes' clocks must agree within five minutes,
and `udp` drops datagrams sealed further from its own clock than that
(docs/design/transports.md, "The map says, the engine converts, the transport decides"). A
node whose clock is off by more cannot link to its peers.

- **Linux nodes:** install and enable chrony (any NTP client will do;
  provisioning sets this up automatically from M4, TP-038):

  ```sh
  apt install chrony           # Debian/Ubuntu; service unit: chrony
  # dnf install chrony         # Fedora/RHEL; service unit: chronyd
  systemctl enable --now chrony  # or chronyd on Fedora/RHEL
  chronyc tracking               # check the "System time" offset is small
  ```

- **Devices:** keep the OS's own automatic date and time on (macOS and
  Windows do this by default).

- **Spotting a clock that is off:** `thinkpol status` has no clock
  problem yet (TP-090). The symptom is links that never come up between
  nodes on the same map version. Compare the clocks of both ends
  (`date -u` on each, `chronyc tracking` on Linux), fix the one that is
  off, and leave the map alone.

## When something is wrong

- `thinkpol status`: connection, health (problems from a fixed vocabulary),
  a server's workers and public listeners, a device's peers and neighbors.
- `thinkpol logs`: the agent's own log ring (root only).
- A node that its map no longer includes idles instead of failing: it
  starts, finds no section for itself, and waits. Adding it back to the
  spec and rotating brings it in at the next map. 
