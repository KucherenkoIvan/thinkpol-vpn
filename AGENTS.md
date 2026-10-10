# Agent instructions

thinkpol-vpn is a self-hosted virtual network that survives a censor: one Go binary (`thinkpol`) for the node agent, the client service, the CLI and the admin panel. [PRD.md](PRD.md) says what it must do and [DESIGN.md](DESIGN.md) says how; they are the source of truth. Don't contradict them in code: if they're wrong, fix them in the same branch and say so in the ticket's log.

## Hard rules

1. **Privacy.** The repo is public and personal. Never reference the author's employer, work projects, internal repository or package names, or copy content from other private codebases, in code, docs, comments, commit messages or examples. Grep the staged changes before every commit and scrub any hit. When unsure whether a term is safe, don't write it.
2. **Never touch the host's network stack.** No changes to the macOS (or any host) interfaces, routes, DNS, firewall or sysctls, not even "just to test". Linux networking code (network namespaces, netlink, nftables, NFQUEUE, TUN) is tested only inside lab containers.
3. **There is no CI: you are the CI.** `make lint` and `make test` must pass before every commit, plus the lab checks a ticket names.
4. **No cgo in `internal/dataplane` and `internal/netmap`.** Android comes after the MVP, so both must stay buildable for mobile. Everything builds with `CGO_ENABLED=0` (the Makefile exports it).
5. **Dependency direction** (depguard-enforced): `dataplane` and `netmap` never import `features`; `features` never imports `dataplane`. The control plane and the data plane meet only through the signed map.
6. **Protobuf contracts live in this repo**, buf-managed, never in go-kernel's `contracts/`. A deliberate thinkpol-only exception to the kernel convention; see DESIGN.md "Kernel usage".

## Workflow

- **Tickets.** Work comes from the board in [tickets/](tickets/README.md); follow its rules for moving tickets exactly. One ticket, one branch (`<id-lowercase>-<slug>`), cut from `rewrite` and merged back into it only after review.
- **Worktrees.** Never work in the main checkout. Each branch gets its own worktree at `../.worktrees/<repo>/<branch>`.
- **Push.** Ticket branches and `rewrite` live on `origin`; push a ticket branch as soon as it exists and after every commit.
- **Commits.** Conventional commits (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`).
- **go-kernel** is the control plane's kernel and is public: no `GOPRIVATE` or SSH setup. Its own rules apply to `KRN-` tickets, which are worked in go-kernel's repo.

## Conventions

- English everywhere. Name things for what they are; the mechanism should be readable from the name.
- `cmd/thinkpol`: one file per subcommand, registered from `init`, so adding a command never touches shared code.
- Control plane features follow go-kernel's service structure; the data plane is plain ports and adapters, no DDD aggregates.
- Tests assert behavior, not call sequences. Prefer real components over mocks.
- Comments state non-obvious constraints only.

```sh
make help      # list targets
make lint      # gofmt + go vet + golangci-lint, required before commit
make test      # unit tests, required before commit
make build     # bin/thinkpol
make tools     # one-time dev tooling install
python3 tickets/board.py   # the board and what's ready to start
```
