# Using AGT With meshguard-rust

MeshGuard supports direct Rust SDK governance, guardian sidecar enforcement, egress enforcement, and AGT-native governance in the same control plane. AGT is an additional policy enforcement path for teams that use Microsoft Agent Governance Toolkit in part of their fleet.

## Direct Rust SDK Pattern

```rust
let decision = client.check("agent-1", "file.read", None).await?;
```

## AGT-Compatible Path

1. Keep current Rust SDK integrations in place.
2. Use AGT-compatible policy YAML when you want policies shared across Rust SDK, AGT, sidecar, and egress paths.
3. Point AGT-instrumented agents at the same MeshGuard PDP and audit plane.
4. Use the guardian sidecar or egress proxy where language-neutral enforcement is a better fit.
5. Choose the enforcement path per agent, framework, and deployment architecture.
