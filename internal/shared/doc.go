// Package shared is code reused across the control plane features, split as
// in go-kernel's service structure: shared/domain (value objects and events
// several features use), shared/ports (interfaces between features) and
// shared/infra (reusable infrastructure). Anything the data plane also needs
// belongs in netmap or dataplane instead.
package shared
