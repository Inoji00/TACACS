# Rà soát kiến trúc TNAC+

| Luồng | Liên kết trong source |
| --- | --- |
| TACACS+ | `server.py` nhận TCP/49. Registry nhận diện thiết bị từ IP kết nối. Router phân luồng authentication, authorization và accounting. Các module PostgreSQL sở hữu truy vấn và giao dịch audit. |
| Web Admin | HTTPS proxy chuyển tới Web Admin. `admin_composition.py` gắn API với dịch vụ, pool PostgreSQL và audit. API tiếp tục kiểm tra session, CSRF và quyền trước khi ghi. |
| Mật khẩu tài khoản | Tạo/sửa device user, tự đổi mật khẩu Web và bootstrap dùng `password_policy.py`. Argon2id tiếp tục xử lý hash. Mật khẩu đã lưu vẫn được xác thực theo luồng hiện hành. |
| Syslog | Collector UDP lưu SQLite và archive theo ngày. Web Admin gắn dữ liệu log chỉ đọc và lưu profile riêng. Bố cục bộ lọc độc lập với phần xử lý AAA và quyền truy cập. |

Đối chiếu cấu hình Compose, các điểm nối API và test cho thấy thay đổi này không cần migration. Tên service, cổng, mount và schema giữ nguyên. Nghiệm thu trên switch và VM vẫn là một bước riêng.

## Source React và bundle phát hành

Source React gốc nằm trong `frontend/`. GitHub Actions cài dependency từ
`frontend/package-lock.json`, kiểm tra TypeScript, chạy test source và build JavaScript
vào `artifacts/react-console/`. Lệnh tương ứng trên máy phát triển:

```bash
npm --prefix frontend ci
npm --prefix frontend run check
npm --prefix frontend test
npm --prefix frontend run build
```

Docker hiện vẫn phục vụ console đã phát hành từ `src/tacacs_appliance/console/`.
Build React có đích riêng để tránh ghi đè console đang dùng trước khi xác minh
tương đương. Các điểm cần đồng bộ trước khi chuyển đầu ra React sang bộ cài gồm
Device Syslog và quản lý profile, hướng dẫn kết nối Cisco, cấu hình webhook
Slack/Mattermost và các luồng quản trị cùng kiểm thử song ngữ. Sau khi chuyển,
CI cần kiểm thử chính bundle sinh từ source và bộ cài phải dùng đúng bundle đã kiểm thử.

Ruff kiểm tra toàn bộ `src/` và `scripts/`:

```bash
ruff check src scripts
ruff format --check src scripts
```
