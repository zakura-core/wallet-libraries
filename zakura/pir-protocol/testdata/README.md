# Previous-provider metadata

`previous_provider_metadata.json` contains the exact serialized parameter JSON
from IPIR-SP `0.1.0-rc.7` at commit
`5ea080a3281a01c5459f585e0a1bbbde50ec2bd2`. Each case preserves JSON field order
inside its string, including the served native-width overrides.

`scripts/probes/previous_provider.rs` recomputes and checks this fixture during
dependency-graph verification. Its explicit `--emit-fixtures` mode captures the
pinned provider's outputs. Ordinary unit tests compare the current private
parameter builder and served metadata to these independently checked strings.
