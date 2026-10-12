# The one image every lab node runs. Binaries are not baked in: they are
# cross-compiled on the host into lab/bin and mounted read-only.
# The base is pinned by digest (a multi-platform index), so a rebuild gets
# the same Debian.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
# Not org.thinkpol.lab: containers inherit image labels, and that one marks
# what tear-down may remove.
LABEL org.thinkpol.lab.image="1"
# wireguard-tools: wg, to read handshakes and keys; openssl s_server and
# nginx-light: TLS and HTTP targets; netcat: raw TCP and UDP;
# dbus-daemon and systemd-resolved: a device whose OS resolves through
# resolved (started by the tests that need it, never by the image).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iproute2 nftables iputils-ping tcpdump curl ca-certificates procps \
      wireguard-tools openssl nginx-light netcat-openbsd \
      dbus-daemon systemd-resolved \
 && rm -rf /var/lib/apt/lists/*
