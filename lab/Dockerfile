# The one image every lab node runs. Binaries are not baked in: they are
# cross-compiled on the host into lab/bin and mounted read-only.
FROM debian:bookworm-slim
LABEL org.thinkpol.lab="1"
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iproute2 nftables iputils-ping tcpdump curl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*
