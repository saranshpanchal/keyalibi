# KeyAlibi

Your process has an alibi because the real key was never inside it.

KeyAlibi is a local-first phantom-secret injector and outbound network-boundary
firewall. AI coding agents, test runners, and third-party scripts receive
**phantom credentials** that satisfy client-side SDK checks. The real secret
stays in the supervisor process. An egress proxy swaps the phantom for the
real value only when the destination host is on that secret's allowlist, and
it blocks the request when a phantom (raw or base64) is headed anywhere else.

```text
child env / .env  --phantom-->  KeyAlibi proxy  --real-->  api.openai.com
                                      |
                                      +-- 451 -->  anywhere else
```

## Install

```bash
cargo build --release
./target/release/keyalibi --help
```

The crate, binary, and repository name are `keyalibi`. The proxy is
`hyper` and `hyper-util` on `tokio-rustls`. The self-test speaks to that
proxy with the same stack. `reqwest` is not a dependency: current 0.12
releases pull an HTTP/3 graph that does not build on Rust 1.83.

## Usage

```bash
# Detect providers from .env / .env.example and write allowlists.
# Secret values are not written into the policy.
keyalibi init

# Run an agent or a test suite. Put the child command after `--`.
keyalibi run -- claude
keyalibi run --policy .keyalibi.toml -- pytest

# Self-test: phantom shape, allowlisted swap, exfiltration block.
keyalibi verify

# Audit log and live dashboard.
keyalibi audit
keyalibi tui
```

`keyalibi run` reads secret values from the process environment and from the
env files named in the policy (`.env`, `.env.local`, `.env.production`, …).
It then:

1. Mints a session-scoped phantom for each secret and keeps the real value in
   supervisor memory (`secrecy` / `zeroize`, best-effort `mlock`,
   `PR_SET_DUMPABLE=0`).
2. Starts a localhost proxy.
3. On Linux, enters a user and mount namespace and bind-mounts phantom copies
   over workspace env files and common credential files, then `exec`s the
   child. The host files are not modified.
4. Injects the phantom into the child environment, points provider base URLs
   at the proxy (Topology A), and sets `HTTP_PROXY` / `HTTPS_PROXY` plus CA
   bundle variables (Topology B).

If user or mount namespaces are not available, KeyAlibi prints a warning and
continues in env + proxy mode. In that mode the child can still read the real
`.env` from disk.

### Policy

`.keyalibi.toml` lists env var names, providers, and host allowlists. It never
stores secret values.

```toml
on_exfiltration = "none" # none | sigstop | sigkill

[network]
allow_loopback = false
allow_private = false
allow_link_local = false
allow_cidrs = []

[proxy]
listen = "127.0.0.1:0"
mitm = true

[upstreams]
openai = "https://api.openai.com"
anthropic = "https://api.anthropic.com"
stripe = "https://api.stripe.com"
github = "https://api.github.com"
aws = "https://sts.amazonaws.com"

[[secrets]]
env = "OPENAI_API_KEY"
provider = "openai"
allowed_hosts = ["api.openai.com"]

[[secrets]]
env = "AWS_ACCESS_KEY_ID"
provider = "aws"
allowed_hosts = ["*.amazonaws.com"]
paired_env = "AWS_SECRET_ACCESS_KEY"
```

`on_exfiltration` controls what happens after a blocked leak is logged:
`none` (default), `sigstop`, or `sigkill` of the child process group.

Default masked paths (only when the file exists): `~/.aws/credentials`,
`~/.aws/config`, `~/.config/gh/hosts.yml`, `~/.npmrc`, `~/.pypirc`, `~/.netrc`,
`~/.docker/config.json`, `~/.kube/config`.

## Architecture

### Phantom mint

Phantoms are deterministic for a session seed and env var, and they follow the
shape each SDK checks offline:

| Provider | Shape |
| --- | --- |
| GitHub `ghp_` `gho_` `ghu_` `ghs_` `ghr_` | prefix + 30 Base62 + 6-char Base62 CRC32 (IEEE, `crc32fast`) |
| AWS | `AKIA`/`ASIA` + 16 chars from `A-Z2-7`, plus a 40-character phantom secret. The proxy re-signs `AWS4-HMAC-SHA256` because the real secret never travels. |
| Stripe | `sk_live_` / `sk_test_` / `rk_live_` / `rk_test_` + Base62 with a `KEYALIBI` marker |
| Anthropic | `sk-ant-api03-` + 93 `[A-Za-z0-9_-]` + `AA` |
| OpenAI | `sk-proj-` or `sk-` + Base62 with a `KEYALIBI` marker |
| Slack / Google | `xoxb-` `xoxp-` `xapp-` / `AIza` + 35 |
| Generic | preserve prefix, length, and charset when possible, otherwise `KEYALIBI_P_<session>_…` |

The supervisor holds `phantom -> { real_secret, env_var, allowed_hosts, mint_time }`.
Database URLs (`postgres://`, `redis://`, `mysql://`, `mongodb://`) are left
alone: this proxy cannot swap them.

### Dual-topology proxy

**Topology A (no CA).** The child receives:

- `OPENAI_BASE_URL=http://127.0.0.1:<port>/upstream/openai/v1`
- `ANTHROPIC_BASE_URL=…/upstream/anthropic`
- `STRIPE_API_BASE=…/upstream/stripe`
- `GITHUB_API_URL=…/upstream/github`
- `AWS_ENDPOINT_URL=…/upstream/aws`
- `SLACK_API_URL`, `GOOGLE_API_BASE`, `GEMINI_API_BASE`

SDKs that honor those variables talk HTTP to localhost. No custom CA is
required, which matters for Rust clients that pin `webpki-roots`.

**Topology B (CONNECT).** `HTTP_PROXY` and `HTTPS_PROXY` point at the same
listener. A per-session root from `rcgen` is written into a bundle referenced
by `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`,
`CURL_CA_BUNDLE`, `DENO_CERT`, and `CARGO_HTTP_CAINFO`, and
`NODE_USE_ENV_PROXY=1` is set. TLS is terminated only for allowlisted hosts.
Other CONNECTs are raw TCP tunnels after the ClientHello SNI is checked, so
package managers keep working.

**Tripwire.** URLs, query strings, headers, and bodies (JSON, form, multipart
bytes, plus standard and URL-safe base64 of the phantom, including decoded
blobs) are scanned with `aho-corasick`.

- Allowlisted host: swap phantom to real, or re-sign SigV4.
- Any other host: `451` with body `Exfiltration Blocked by KeyAlibi`, a
  critical audit row (child pid, command, destination, env var name), and the
  optional stop/kill action. The real secret is not forwarded.

**Response scrubber.** Real secrets are written back to their phantoms on the
way to the child, including a sliding overlap window so a value split across
chunked or SSE frames is still caught. `gzip` bodies are decoded, scrubbed,
and re-encoded. Other content encodings are refused after a swap rather than
forwarded blind.

**SSRF.** Each upstream dial resolves DNS once, rejects private, loopback,
link-local, CGNAT, and metadata addresses (including `169.254.169.254`) unless
the policy allows that class or an explicit CIDR, and connects to the pinned
address.

### Filesystem jail

On Linux the child `unshare`s `CLONE_NEWUSER|CLONE_NEWNS`, makes `/` private,
and bind-mounts tmpfs-backed phantom files over the workspace env files. `cat
.env` inside the child returns phantoms. A process outside the namespace still
sees the original bytes.

### Audit log and TUI

Events go to `./.keyalibi/audit.db` (SQLite). `keyalibi audit` prints them.
`keyalibi tui` is a `ratatui` dashboard of mint, swap, scrub, and block
counts. Rows store env var names and destinations, not secret bytes.

## Threat model

KeyAlibi assumes the supervisor is started by you and the child is less
trusted than you: an agent, a test plugin, or a script that might exfiltrate
whatever is in its environment or in `.env`.

What it prevents, when the child actually uses the proxy:

- The real secret appearing in the child's environment.
- The real secret appearing in `cat .env` (Linux namespace jail).
- A phantom, or a base64 encoding of it, being sent to a host outside the
  allowlist via the proxy.
- The upstream echoing the real secret back into the child's response stream.
- Casual ptrace or `/proc/<supervisor>/mem` reads by the same user after
  `PR_SET_DUMPABLE=0`.
- The proxy itself being steered at `169.254.169.254` or other non-public
  addresses by DNS rebinding.

What it does not pretend to prevent:

- Root, or anyone who can debug the supervisor before dumpable is cleared.
- A child that ignores `HTTP_PROXY` and the injected base URLs and opens its
  own socket. It can send the **phantom** to an attacker. The phantom is not
  the real credential, but the tripwire only sees traffic that enters the
  proxy. There is no network namespace forcing all egress through it.
- A colluding allowlisted host. If `api.openai.com` is allowlisted, a
  compromised response or a bug in that service can receive the real key.
  Keep allowlists tight.
- Secrets already resident in the child from a previous run, a prompt, or a
  file the jail did not mask.

## Known limitations

These are hard limits of the approach, not temporary omissions.

- **macOS has no mount namespaces.** The filesystem jail is Linux-only. On
  macOS, or when `CLONE_NEWUSER` is blocked (many container sandboxes,
  `kernel.unprivileged_userns_clone=0`, AppArmor), KeyAlibi warns and runs in
  env + proxy mode. Host `.env` files stay readable.
- **Postgres, Redis, MySQL, and similar credentials** travel inside their own
  wire protocols. An HTTP proxy cannot swap them. KeyAlibi skips database
  URLs. A protocol broker is out of scope.
- **Some AWS requests cannot be re-signed here.**
  - Streaming or chunked SigV4 payloads (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`
    and trailer variants) are rejected with 501.
  - SigV4A (`AWS4-ECDSA-P256-SHA256`, multi-region) is rejected. The proxy
    does not have the asymmetric key and cannot produce that signature.
  - Presigned URLs are re-signed only for the simple
    `AWS4-HMAC-SHA256` query form. Chunked uploads and SigV4A presigns are
    not.
  - Topology A sets `AWS_ENDPOINT_URL`, which only redirects SDKs that honor
    the global endpoint override. Service-specific endpoints that ignore it
    still need Topology B, and the cases above still cannot be re-signed.
- **Topology B depends on the client trusting the session CA.**
  - Rust clients built on `webpki-roots` (typical `reqwest` + rustls) ignore
    `SSL_CERT_FILE` and any private CA. Use Topology A base-URL injection for
    those.
  - Go on macOS ignores CA environment variables and uses the system trust
    store, so the session CA is not installed by setting `SSL_CERT_FILE`.
  - `SSL_CERT_FILE` replaces the OpenSSL bundle. KeyAlibi writes a bundle of
    the system CA file plus the session CA when `/etc/ssl/certs/ca-certificates.crt`
    is present. Clients that do not read these variables are unaffected, which
    is why Topology A exists.
- **Direct sockets bypass the tripwire.** `NO_PROXY` includes loopback so the
  child can reach the proxy without looping. Anything that dials a public host
  itself never hits the scanner. The real key is still absent from the child;
  the phantom can leak.
- **Unknown compressed responses.** After a swap, a body whose
  `Content-Encoding` is not `identity` or `gzip` is refused. A compressed
  echo of the real secret must not be forwarded just because the scanner
  cannot see it. `gzip` is decoded and scrubbed. Very large bodies (over
  16 MiB) are rejected.
- **Short secrets** (under 8 characters) are not used as scrubber needles, so
  a tiny value is not substituted into unrelated response bytes.
- **`mlockall(MCL_FUTURE)` is intentionally not used.** Unprivileged processes
  often have an 8 MiB `RLIMIT_MEMLOCK` and cannot raise the hard limit.
  Locking every future allocation would make the proxy fail once that cap is
  hit. KeyAlibi `mlock`s the secret byte slices it holds and sets
  `PR_SET_DUMPABLE=0`. The Aho-Corasick automaton keeps its own copy of the
  needles for the life of the process; those allocations are freed when the
  proxy exits and are not separately wiped by the automaton.
- **HTTP/1.1 only** toward upstreams. The intercept certificate advertises
  `http/1.1` so a client does not negotiate HTTP/2 inside the MITM session
  and then fail to be parsed.
- **Multipart and form bodies** are scanned as raw bytes plus base64-decoded
  blobs, not with a structured MIME parser. A token split by a custom
  encoding other than base64 can be missed. Contiguous occurrences are
  swapped or blocked.

## Development

```bash
cargo build
cargo clippy --all-targets -- -D warnings
cargo test
```

Integration tests cover GitHub CRC32 and the other phantom shapes, an
end-to-end localhost swap with response scrubbing, a 451 exfiltration block
plus audit row, and the Linux env-file overlay. The overlay test skips with a
message when user namespaces cannot be created. No test contacts a real
provider network.

## License

MIT OR Apache-2.0
