# Security

Report a vulnerability privately through GitHub's "Report a vulnerability" button on this repository (Security tab). Please do not open a public issue for it.

The package reads local JSON and TOML files, makes no network calls and holds no secrets.

Things worth a private report:

- A request that gets `allow` when a control in the policy should have held or blocked it.
- A way to edit, drop or reorder an audit log entry that `verify-log` does not catch.
- Input that makes two different destinations share a fingerprint, or one destination get two.

A wrong default or an unclear finding message is a normal bug; a public issue is fine for that.
