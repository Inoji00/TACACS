# Kiểm chứng bảo mật

[English](SECURITY-VALIDATION.md)

Các kết quả bên dưới áp dụng cho **v1.1.2**, commit `20936d8`.

**66/66 bài kiểm tra bảo mật local đạt. CI đạt 512/512 bài hồi quy, 0 skip.** Trivy ghi nhận **0 Critical và 0 High** trên cả hai image. TNAC còn **5 Medium và 1 Low**. Các kết quả có phạm vi theo bài đã chạy và đúng image CI. [Báo cáo GitHub Actions](https://github.com/Inoji00/TACACS/actions/runs/44460843426)

| Hạng mục | Phạm vi kiểm tra |
|---|---|
| Đăng nhập và phiên Web | Xác thực, kiểm soát phiên, CSRF và giới hạn tần suất. |
| Phân quyền API | Từ chối truy cập thiếu phiên hoặc thiếu quyền. Device Syslog yêu cầu quyền quản trị. |
| Device Syslog | Rà truy vấn tham số SQLite, bộ lọc hợp lệ, tìm kiếm theo nghĩa đen và kết nối đọc. CI kiểm tra UDP và đọc volume chỉ đọc. |
| Database và bí mật | Quyền role, quyền file bí mật, kiểm tra file nhạy cảm trong source phát hành. |
| Tài nguyên Web | Security headers, phương thức HTTP và giới hạn truy cập đường dẫn. |

## Chạy lại nhóm test bảo mật

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

[Hướng dẫn chạy lại CI và Trivy](TESTING.vi.md)
