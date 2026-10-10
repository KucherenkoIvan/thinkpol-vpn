// Package shared holds no code: what the control plane features share lives
// in shared/domain (value objects and events), shared/ports (interfaces
// between features) and shared/infra (reusable infrastructure, including
// the admin panel's page shell in shared/infra/webui), as in go-kernel's
// service structure. shared never imports features.
package shared
