# Security Policy

## Supported Versions

We actively support and patch security issues in the following versions of the Raffle Oracle and Smart Contracts:

| Version | Supported |
| ------- | --------- |
| 1.x.x   | Yes       |
| < 1.0.0 | No        |

## Reporting a Vulnerability

If you discover a security vulnerability, please do **not** open a public issue. Instead, report it privately:

1. Send an email to **security@cracked.studio**.
2. Include a detailed description of the vulnerability, steps to reproduce it, and the potential impact.
3. We will acknowledge receipt of your vulnerability report within 48 hours and work with you to coordinate a security fix and release.

## Oracle Private Key Hardening

The oracle service handles sensitive private key material. To protect these credentials, we implement the following runtime security practices:

### 1. Zeroizable Buffer Key Handling
Private keys are never stored as plain strings in memory. They are loaded into zeroizable `Buffer` objects. Once the key has been processed or signed, the buffers are immediately filled with zeros to scrub the private key bytes from memory.

### 2. Environment Variable Cleansing
To prevent leakages (e.g., via diagnostic logs, child processes, or memory dumps), the `EnvSecretsAdapter` immediately deletes `ORACLE_SECRET_KEY` from `process.env` once parsed during bootstrap. In production mode, environment variables are blocked entirely, requiring the use of HashiCorp Vault.

### 3. Secure Key Vault
The service supports fetching keys dynamically over HTTPS from a secure Vault instance (`VaultSecretsAdapter`). Keys retrieved via Vault are similarly scrubbed from memory immediately after use.

Run `cargo audit` and `cd oracle && npm audit --omit=dev` locally before release. Known accepted findings must be recorded in this section with rationale and review date.

| Advisory | Package | Status | Reviewed |
|----------|---------|--------|----------|
| RUSTSEC-2024-0388 | `derivative` | Accepted — informational ("unmaintained") proc-macro used at build time only via `ark-ec` (transitive of `soroban-env-host 23.x`); ignored in `.cargo/audit.toml` until the `soroban-sdk` major upgrade that replaces arkworks | 2026-08-30 |
| RUSTSEC-2024-0436 | `paste` | Accepted — informational ("unmaintained") proc-macro used at build time only via `ark-ff` (transitive of `soroban-env-host 23.x`); ignored in `.cargo/audit.toml` until the `soroban-sdk` major upgrade that replaces arkworks | 2026-08-30 |

## Secure development

- Contract changes affecting fund flows require review from a code owner.
- Randomness and draw paths are covered by invariant and budget regression tests — regressions that exceed committed baselines fail CI.
- WASM artifacts are size-checked against committed baselines on every PR.

## Supply-chain hardening

Repositories on GitHub have been targeted by campaigns that land code through
an ordinary-looking merged pull request, then execute it on a contributor's
machine with no deliberate action: a VS Code task set to run on folder open,
or an npm lifecycle script that runs on `npm install`. The payload is usually
disguised as an asset — a webfont, a build output — so the diff looks
uninteresting.

This repository defends that surface in three layers.

### 1. Nothing in this repo runs on clone, open or install

- `.vscode/settings.json` pins `"task.allowAutomaticTasks": "off"`.
- No `.vscode/tasks.json` exists, and no task may declare `"runOn": "folderOpen"`.
- No manifest declares a `preinstall`, `install`, `postinstall` or `prepare`
  script. The oracle service builds with an explicit `npm run build`.
- No font or binary files are tracked.

### 2. CI blocks them from reappearing

`scripts/check_supply_chain.py` runs on every push and every pull request via
`.github/workflows/supply-chain-guard.yml`, with no path filter. It fails the
build on:

| Finding | Why it matters |
|---------|----------------|
| `dist/setup.js`, `public/fonts/fa-solid-*` | Exact artefacts of the 2026 auto-task campaign |
| Any tracked `.woff`/`.woff2`/`.eot`/`.ttf`/`.otf`/`.llf` | The dropper ships disguised as a webfont |
| `preinstall`/`install`/`postinstall`/`prepare` in any `package.json` | npm runs these without asking |
| A locked dependency with `hasInstallScript` | A transitive package gaining the ability to run code at install time |
| `task.allowAutomaticTasks` set to anything but `"off"` | Re-opens folder-open execution |
| `"runOn": "folderOpen"` in any `tasks.json` | Executes when the repo is opened |
| A tracked symlink resolving outside the repository | Redirects reads and writes out of the tree |

Run it locally with `make supply-chain`. Two dev-only native-binding packages
(`@parcel/watcher` and `unrs-resolver`, both reached through jest) are
allowlisted by name in the script with their rationale; a *new* install-scripted
dependency fails the check and must be reviewed on its own merits.

### 3. Review is mandatory on the paths that execute

`.github/CODEOWNERS` assigns a maintainer to `.vscode/`, `.devcontainer/`,
hook configuration, every dependency manifest and lockfile, Dockerfiles,
`.env.example`, and every binary and font extension.

**CODEOWNERS only requests review — it does not require it.** For these
patterns to be enforced, branch protection on `master` must have both
*Require a pull request before merging* and *Require review from Code Owners*
enabled, under **Settings → Branches → Branch protection rules**. Verify on
the same page that no CODEOWNERS line is reported as invalid: an owner that
does not exist silently assigns no reviewer at all, and the last matching
pattern in the file wins outright rather than adding to earlier ones.

### If you suspect a compromise

Report it to **security@cracked.studio** as above. Because this class of
payload executes on the machine that opened the repository, treat any
credential that was present on that machine — npm and crates.io tokens, SSH
keys, `.env` values, Stellar secret keys — as exposed and rotate it, rather
than only cleaning the repository.

## Front-running mitigation

See the existing randomness fulfillment delay notes below.

### Attack Vector

The raffle contract's randomness fulfillment mechanism (`provide_randomness`) was vulnerable to front-running and manipulation attacks. In the original implementation, an oracle could submit randomness immediately after a raffle transitioned to `Drawing`, potentially allowing an attacker to:

1. Observe the pending raffle finalization
1. Manipulate oracle behavior to favor specific outcomes
1. Execute malicious transactions in the same block

### Mitigation Implemented

To address this vulnerability, we've implemented a minimum ledger delay between randomness request and fulfillment:

- A constant `RANDOMNESS_MIN_DELAY_LEDGERS = 10` is enforced
- When randomness is requested (during the Drawing phase transition), the current ledger sequence is stored under `DataKey::RandomnessRequestLedger`
- In `provide_randomness`, we check that the current ledger sequence is at least 10 ledgers higher than the request ledger
- If fulfillment is attempted too early, the transaction is rejected with `Error::RandomnessTooEarly`

This delay ensures there's sufficient time for:

- The market and participants to stabilize
- No same-block manipulation
- A clear window between request and fulfillment

### Other Security Considerations

- **Drawing Lock**: Exclusive lock to prevent concurrent state transitions
- **Oracle Timeout**: Fallback mechanism if oracle doesn't respond within 200 ledgers
- **Reentrancy Guard**: Prevents reentrant attacks
### 4. Alert Payload Scanning
To prevent accidental leakage of secret keys or other sensitive materials through operational alerts (e.g., webhook integrations, Discord, Slack), all alert payloads are recursively scanned before dispatch. If any string or property matches the format of a private key or loaded secret, the dispatch is aborted and a secure placeholder warning is generated.
