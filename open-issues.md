# Open Issues

## PAT Scope Allowlist

The internal PAT issuer currently accepts arbitrary scope strings from its authorized caller, including broad scopes such as `kms:*`. This is acceptable only if the dashboard remains the fully trusted policy decision point. For defense-in-depth, we should consider adding an issuer-side allowlist for supported scopes such as `kms:create`, `kms:encrypt`, `kms:decrypt`, `kms:sign`, `kms:import`, `kms:export`, `kms:delete`, `kms:rotate`, and `kms:*`.
