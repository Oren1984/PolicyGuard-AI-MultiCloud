# Known Local-Environment Limitations

This file documents local-development-machine limitations encountered on
this specific machine, why they happened, and what was done about each one.
Recorded here so that anyone continuing this build, reviewing it, or running
it on a different machine understands exactly what could and could not be
verified locally, and why.

## Root cause (both items below share it)

This machine runs Norton AV with its "Web/Mail Shield" HTTPS-scanning proxy,
which intercepts outbound TLS connections to real internet hosts and
re-signs them with a locally-installed Norton root certificate
(`CN=Norton Web/Mail Shield Root`, present in
`Cert:\LocalMachine\Root`). Any process that doesn't already trust that
root certificate sees a normal, legitimate-looking site as if its
certificate were untrusted.

## Docker image build — FIXED

**Symptom (as originally encountered):** Inside the Docker Desktop Linux VM,
`pip install` failed against `pypi.org` with `SSL: CERTIFICATE_VERIFY_FAILED:
unable to get local issuer certificate` — reproduced identically with a
bare, unrelated `curlimages/curl` container hitting the same URL, which
confirmed the interception happens at the Docker Desktop VM's network
layer, not in this project's `Dockerfile`.

**Fix applied:** the same pattern the sibling ChangeGuard AI MultiCloud
repository already uses for this exact situation — trust the intercepting
proxy's root certificate explicitly, rather than disabling TLS verification
(which would be a real security weakening). Concretely:

- `certs/` — a new directory, empty by default (kept via `certs/.gitkeep`;
  any real certificate dropped here is gitignored via `certs/*` +
  `!certs/.gitkeep`, so this is never committed and is a no-op for anyone
  else's checkout on a network without this interception).
- `Dockerfile`'s builder stage now does `COPY certs/
  /usr/local/share/ca-certificates/extra/` + `RUN update-ca-certificates`
  before installing Python dependencies, and sets `ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt`
  so pip uses the system CA bundle (which now includes any extra trusted
  root) instead of its own bundled `certifi` list.
- The Norton root certificate already present in this machine's own
  `Cert:\LocalMachine\Root` store was exported (a public certificate, not a
  private key or any secret) to `certs/dev-ca.crt` for local use only.

This does not weaken security: it adds one more explicitly-trusted root to
the build image's CA bundle, the same way a corporate laptop trusts its own
IT department's TLS-inspection root — it does not disable or bypass
certificate verification for anything else.

**Verified working, end to end, this session:**

```
docker build -t policyguard-app:fixtest .        # succeeds
docker compose down -v                            # clean slate
docker compose build                               # both images build
docker compose up -d                                # db → migrations → app, all healthy
curl http://localhost:8000/health                   # {"status":"ok"}
python demo/scripts/run_demo.py --base-url http://localhost:8000   # 18/18 scenarios pass
pytest tests/e2e/test_dockerized_stack.py -v         # both tests pass for real, no skip
```

A second, unrelated bug was found and fixed while verifying this:
`docker-compose.yml`'s `app` service hardcoded its host port (`"8000:8000"`),
but `tests/e2e/test_dockerized_stack.py` expects to override it via
`POLICYGUARD_HOST_PORT` so the test's own compose project doesn't collide
with a developer's already-running stack on the standard port. Fixed to
`"${POLICYGUARD_HOST_PORT:-8000}:8000"` — default behavior (port 8000)
unchanged.

The full test suite now passes with **zero skips**: 293/293.

## Terraform `validate` — still blocked, different mechanism, not fixed

**Symptom:** `terraform validate` fails for both `infrastructure/aws/` and
`infrastructure/gcp/` with `Plugin did not respond` / `x509: certificate
signed by unknown authority`, visible with `TF_LOG=trace` as a failure in
Terraform core's own internal mTLS handshake with its downloaded provider
plugin *subprocess* — a loopback connection between two local processes,
not a real network call. `terraform init -backend=false` (a real network
call to the public Terraform registry) and `terraform fmt` both succeed.

**Why the same fix doesn't apply:** the Docker/pip fix works because pip
trusts *the operating/container system's CA bundle* for a real TLS
connection to a real external host (`pypi.org`) — adding Norton's root to
that bundle is exactly the intended mechanism for trusting an intercepting
proxy. Terraform's provider-plugin transport is different in kind: it is a
mutually-authenticated TLS connection over localhost using a certificate
pair Terraform itself generates fresh for that specific subprocess
invocation, not validated against the system CA bundle at all. The Windows
certificate store already contains the Norton root (confirmed — it's the
same store the Docker fix reads from), so if this were a trust-store
problem the same way, it would already be resolved; it isn't, which
confirms this is Norton's network filter interfering with the local
loopback socket/handshake itself, not a missing trusted CA. There is no
certificate to add to a bundle that would fix this.

**Not attempted:** pausing or reconfiguring Norton's own scanning behavior
(a host security-software configuration change, outside this project's
scope and not something to change without the machine owner's own direct
action) or introducing any `-insecure`/skip-verification flag (would
weaken a real security control for no justified reason, and does not exist
as an option for this particular internal Terraform mechanism regardless).

**Expected to pass unmodified** on GitHub Actions CI (`terraform` job,
standard hosted runner, no such interception) or any other machine without
this specific local network condition.

## Scope and re-validation

Both items above are specific to this development machine's security
software, not a defect in the `Dockerfile`, `docker-compose.yml`, or the
Terraform configurations. The Docker item is now fixed and verified
end-to-end on this same machine. The Terraform item remains an honestly
documented, root-caused local limitation with no available fix at the
Terraform-invocation level.
