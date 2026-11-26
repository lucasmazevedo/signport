# Publication gates
- [ ] Confirm rights holder, license grants, root file scopes, SPDX/REUSE and DCO.
- [ ] Compare bundled license reference texts against official sources; resolve third-party notices and SBOM.
- [ ] Confirm name/brand, personal repository owner, registry names, reporting channel and store policies.
- [ ] Provide corresponding source per GPL/AGPL artifact, including build/install scripts and runtime source link as applicable.
- [ ] Validate Bird ID terms, BYOC, costs and publication of adapter; local functionality remains independent.
- [ ] Verify cryptographic policy, actual hardware, ITI validation evidence, privacy and threat model.
- [ ] Test clean installation, upgrade, backup/restore, build provenance and signed releases.

## Gate separation
Public pre-alpha repository: confirm rights and actual license grants, notices, brand, private security reporting and absence of secrets. Production releases additionally require technical, provider (for cloud only), distribution and compliance gates above. Do not block local development on Bird ID.
