# thinkpol-vpn

A self-hosted virtual network for people behind a censor. Your devices and a few VPS nodes form one private network, traffic between them is disguised so no VPN fingerprint reaches the wire, and internet traffic can leave through a chain of hops. Managed like Tailscale, without depending on anyone's servers.

Work in progress: the project is being rewritten from scratch.

- [PRD.md](PRD.md): what it must do
- [DESIGN.md](DESIGN.md): how it works
- [tickets/](tickets/README.md): the board (`python3 tickets/board.py`)

## Development

Needs Go 1.25 (with `GOTOOLCHAIN=auto`, an older Go downloads it) and `make`. [go-kernel](https://github.com/KucherenkoIvan/go-kernel) is public, so no `GOPRIVATE` or SSH setup is needed.

```sh
make tools                     # one-time: golangci-lint
make lint test                 # before every commit
go run ./cmd/thinkpol version
```

Linux networking code is tested only inside the lab's containers, never on the host.

## License

[MIT](LICENSE)
