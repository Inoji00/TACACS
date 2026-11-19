# Security validation

[Tiếng Việt](SECURITY-VALIDATION.vi.md)

These results apply to **v1.1.2**, commit `20936d8`.

**66/66 focused local security tests passed. CI passed 512/512 regression tests with no skips.** Trivy found **zero Critical and zero High** in both images. TNAC had **5 Medium and 1 Low** findings. Results apply to the covered tests and the images built in that CI run. [GitHub Actions evidence](https://github.com/Inoji00/TACACS/actions/runs/44460843426)

| Area | Validation scope |
|---|---|
| Web sign-in and sessions | Authentication, session controls, CSRF and rate limiting. |
| API authorization | Reject unauthenticated and unauthorized requests. Device Syslog requires administration privileges. |
| Device Syslog | Review SQLite parameter binding, filter validation, literal search and read-only queries. CI checks UDP and read-only volume access. |
| Database and credentials | Role permissions, secret file permissions and release-source privacy checks. |
| Web assets | Security headers, HTTP methods and asset path restrictions. |

## Rerun the focused tests

```bash
(
  set -euo pipefail
  git clone --branch v1.1.2 https://github.com/Inoji00/TACACS.git tnac-security-review
  cd tnac-security-review
  python3 -m venv .venv
  .venv/bin/python -m pip install -e '.[test]'
  for pattern in test_admin_api.py test_admin_login.py test_admin_sessions.py \
    test_authorization_security.py test_database_security.py 'test_rate_limit*.py' \
    test_secret_files.py test_admin_console.py test_device_syslog.py; do
    .venv/bin/python -m unittest discover -s tests -p "$pattern"
  done
  .venv/bin/python scripts/check_release_privacy.py
)
```

[Reproduce CI and Trivy scans](TESTING.md)
