# Migrating From meshguard-rust To AGT + MeshGuard

The Rust SDK remains supported for existing integrations. The strategic Rust investment shifts to guardian sidecar and egress enforcement components.

## Recommended Path

1. Keep current Rust SDK calls stable.
2. Move policy definitions to AGT-compatible YAML.
3. Validate parity through MeshGuard audit history.
4. Use the guardian sidecar or egress proxy for Rust workloads that need language-neutral enforcement.

