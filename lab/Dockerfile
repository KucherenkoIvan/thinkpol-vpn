# The one image every lab node runs. Binaries are not baked in: they are
# cross-compiled on the host into a run's directory and mounted read-only.
# The base is pinned by digest (a multi-platform index), so a rebuild gets
# the same Debian.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
# Not org.thinkpol.lab: containers inherit image labels, and that one marks
# what tear-down may remove.
LABEL org.thinkpol.lab.image="1"
# wireguard-tools: wg, to read handshakes and keys, and to run kernel
# WireGuard as the censor matrix's reference; openvpn: the matrix's other
# reference VPN, pinned to the version lab/RESULTS.md was scored against
# (a Debian update that drops it fails the build: re-pin and re-run the
# matrix); openssl s_server and nginx-light: TLS and HTTP targets;
# netcat: raw TCP and UDP;
# dbus-daemon and systemd-resolved: a device whose OS resolves through
# resolved (started by the tests that need it, never by the image).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iproute2 nftables iputils-ping tcpdump curl ca-certificates procps \
      wireguard-tools openvpn=2.6.14-0+deb12u2 openssl nginx-light netcat-openbsd \
      dbus-daemon systemd-resolved \
 && rm -rf /var/lib/apt/lists/*
# The lab CA, made when the image is built and private to it, and the
# camouflage site's certificate it signs (lab.StartCamouflage): every node
# trusts the CA as a system root, so a reality listener's certificate
# check, and REALITY's own detection of the target's records, verify the
# lab's camouflage site as they would a real one.
RUN mkdir -p /etc/lab/ca /etc/lab/camouflage \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
      -subj "/CN=thinkpol lab CA" -keyout /etc/lab/ca/ca.key -out /etc/lab/ca/ca.crt 2>/dev/null \
 && printf 'subjectAltName=DNS:camouflage.example.net,DNS:www.example.net\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n' \
      > /etc/lab/camouflage/ext.cnf \
 && openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=camouflage.example.net" \
      -keyout /etc/lab/camouflage/key.pem -out /etc/lab/camouflage/req.pem 2>/dev/null \
 && openssl x509 -req -in /etc/lab/camouflage/req.pem -CA /etc/lab/ca/ca.crt -CAkey /etc/lab/ca/ca.key \
      -CAcreateserial -days 3650 -extfile /etc/lab/camouflage/ext.cnf -out /etc/lab/camouflage/cert.pem 2>/dev/null \
 && cp /etc/lab/ca/ca.crt /usr/local/share/ca-certificates/thinkpol-lab-ca.crt \
 && update-ca-certificates
