# Vendored from cloudflare/security-audit-skill

`report-schema.json` is the record contract for the skill's `findings.json`, copied
unchanged from [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)
(`skills/security-audit/report-schema.json`) under the MIT license in `LICENSE`.

It is vendored so `tests/test_audit_phase.py` can check this service's export against the
contract without a network fetch. The authoritative check is the skill's own validator:

```sh
node <skill-dir>/validate-findings.cjs findings.json
```

Nothing else from the skill is vendored. The skill itself is installed separately:

```sh
npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit
```

Refresh this copy when the upstream schema changes, and run the test suite afterwards.
