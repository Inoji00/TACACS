# Reproduce tests and image scans

**English** · [Tiếng Việt](TESTING.vi.md)

The [Tests and image security workflow](https://github.com/Inoji00/TACACS/actions/workflows/ci.yml) runs on pushes to `main`, pull requests and manual dispatch. Use the run for the **exact commit** under review; an old green run does not validate newer source or a new build. No deployed appliance, Slack webhook or operator database is used.

## Run from a clean checkout

Use Linux, Python 3.12+, Docker Engine with Compose v2, and Node.js 22 with npm. Internet access is required to install dependencies, pull base images and update Trivy's vulnerability database. Run Docker commands as an account with Docker access. Use a disposable machine for integration tests.

```bash
git clone https://github.com/Inoji00/TACACS.git
cd TACACS
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
python scripts/run_tests.py --report artifacts/python.json
cd tests/ui
npm ci --ignore-scripts
npm test
cd ../..
```

The first Python run includes real Linux socket/loopback and TLS tests. Database-dependent cases explicitly skip when no disposable database is configured; skips are listed separately, never counted as passes. The UI checks parse and render the **shipped console bundle**, checking English/Vietnamese Slack settings, escaping, webhook masking and Users navigation. They are not browser visual acceptance tests.

## Actual runtime images and PostgreSQL

```bash
docker build --pull -t tnac:ci .
docker build --pull -f Dockerfile.postgres -t tnac-postgres:ci .
mkdir -p artifacts/integration
chmod 0777 artifacts/integration
python scripts/test_postgres.py --linux --full --image tnac:ci \
  --postgres-image tnac-postgres:ci --report artifacts/integration/postgres.json
python scripts/test_compose.py --admin --image tnac:ci --postgres-image tnac-postgres:ci
```

Only the generated evidence directory is made writable for the non-root test container; never apply that permission to application secrets or deployment state. Tests generate random credentials and uniquely named containers/networks/volumes. The PostgreSQL runner creates its own database instance and schemas, applies all committed migrations, tests runtime database permissions, identity/lockout, session and policy/audit behavior, then removes its instance. It does not read deployment DSNs. The Compose smoke test checks one-shot initialization, TCP/49 readiness, direct TLS 1.3 Web Admin, anonymous-session denial and credential mount isolation. It does not prove physical-device interoperability, public-CA issuance, the deployed proxy path, or successful Slack delivery.

`tests/` also contains parser/framing, AUTHEN challenge/sequence, authorization allow/deny, accounting durability/redaction, CSRF/session/RBAC, migration checksums, scoped device/log permissions and alert queue/retry tests. Mock-based unit cases and real PostgreSQL integration are distinguishable by module. Software tests do not certify every vendor or firmware.

## Trivy and the security gate

CI installs Trivy **0.76.2** from its official release and checks the archive against the published SHA-256 checksums. Official Actions are pinned to commit SHAs. The workflow has read-only repository permissions and uses no deployment secrets.

With that Trivy version installed, run against the same local image IDs:

```bash
trivy image --scanners vuln --timeout 10m --format json --output artifacts/trivy-tnac.json tnac:ci
trivy image --scanners vuln --timeout 10m --format json --output artifacts/trivy-postgres.json tnac-postgres:ci
python scripts/check_trivy.py artifacts/trivy-tnac.json artifacts/trivy-postgres.json
```

The gate fails on **any HIGH or CRITICAL** finding, including findings without a fixed version. Missing/invalid reports also fail. No `--ignore-unfixed`, ignore file, or exported-filesystem substitution is used. Historical `gosu` findings in image layers therefore remain visible even when its final path is replaced. Functional tests passing does not make a failing CVE gate pass. Vulnerability results can change as the database and base images change.

Open the workflow run → **Artifacts** to download `regression-<commit>` and `images-and-security-<commit>`. They retain logs, JSON test IDs/outcomes, exact image inspection, source commit, Docker/Trivy versions and complete JSON/text vulnerability reports for 30 days. A scan/download/build failure is a failed check, not a clean report. Save evidence longer yourself when needed. The immutable `v1.1.0` release tag/ZIP predates this CI addition; clone `main` (or the exact subsequent commit) to reproduce these checks.
