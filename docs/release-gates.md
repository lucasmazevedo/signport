# Publication gates
- [ ] Confirm rights holder, license grants, root file scopes, SPDX/REUSE and DCO.
- [ ] Compare bundled license reference texts against official sources; resolve third-party notices and SBOM.
  - Evidence 27/11/2026: `LICENSES/Apache-2.0.txt` and `packages/protocol/LICENSE` are byte-identical to https://www.apache.org/licenses/LICENSE-2.0.txt (SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`). AGPL-3.0, GPL-3.0 and CC-BY-4.0 texts still pending.
- [ ] Confirm name/brand, personal repository owner, registry names, reporting channel and store policies.
- [ ] Provide corresponding source per GPL/AGPL artifact, including build/install scripts and runtime source link as applicable.
- [ ] Validate Bird ID terms, BYOC, costs and publication of adapter; local functionality remains independent.
- [ ] Verify cryptographic policy, actual hardware, ITI validation evidence, privacy and threat model.
- [ ] Test clean installation, upgrade, backup/restore, build provenance and signed releases.
- [ ] Verify build-tool provenance beyond SHA-256 (e.g. GitHub artifact attestations for uv, pnpm and Actions) before any release; P1 E0–E2 accepted SHA-256 only.
- [ ] Authorization Foundation (P1.5): concurrency and replay tests for single-use consumption, revocation and expiration pass in CI.
- [ ] Validate the terms of the WiX Toolset version used for the MSI installer (Inno Setup contingency only).

## Gate separation
Public pre-alpha repository: confirm rights and actual license grants, notices, brand, private security reporting and absence of secrets. Production releases additionally require technical, provider (for cloud only), distribution and compliance gates above. Do not block local development on Bird ID.
