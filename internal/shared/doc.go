// Package shared holds no code: what the control plane features share lives
// in shared/domain (value objects and events), shared/ports (interfaces
// between features) and shared/infra (reusable infrastructure, including
// the admin panel's page shell in shared/infra/webui), as in go-kernel's
// service structure. shared never imports features.
//
// # The admin panel's canvas (planned)
//
// The panel is server-rendered with go-kernel's webui (htmx) for lists,
// forms and dashboards. The canvas (nodes, links, transports, chains as
// paths, live health and traffic on top, editing by dragging) is a
// JavaScript island on its page: a graph-editor library fed by a JSON
// endpoint and a live-update stream, its shell in shared/infra/webui.
// Shared nodes appear on a guest's canvas read-only, labelled `owned by
// <space>`. Whether islands like this belong in webui itself is a kernel
// question this project answers. Provisional: the admin panel and the
// client apps get separate frontends, and both stacks are revisited in
// TP-086; who may sign in and what the canvas endpoint exposes is open
// (DESIGN.md "Open questions").
package shared
