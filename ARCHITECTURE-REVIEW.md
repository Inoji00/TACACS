# Rà soát kiến trúc TNAC+

| Luồng | Liên kết trong source |
| --- | --- |
| TACACS+ | `server.py` nhận TCP/49. Registry nhận diện thiết bị từ IP kết nối. Router phân luồng authentication, authorization và accounting. Các module PostgreSQL sở hữu truy vấn và giao dịch audit. |
| Web Admin | HTTPS proxy chuyển tới Web Admin. `admin_composition.py` gắn API với dịch vụ, pool PostgreSQL và audit. API tiếp tục kiểm tra session, CSRF và quyền trước khi ghi. |
| Mật khẩu tài khoản | Tạo/sửa device user, tự đổi mật khẩu Web và bootstrap dùng `password_policy.py`. Argon2id tiếp tục xử lý hash. Mật khẩu đã lưu vẫn được xác thực theo luồng hiện hành. |
| Syslog | Collector UDP lưu SQLite và archive theo ngày. Web Admin gắn dữ liệu log chỉ đọc và lưu profile riêng. Bố cục bộ lọc độc lập với phần xử lý AAA và quyền truy cập. |

Đối chiếu cấu hình Compose, các điểm nối API và test cho thấy thay đổi này không cần migration. Tên service, cổng, mount và schema giữ nguyên. Nghiệm thu trên switch và VM vẫn là một bước riêng.

## Điểm cần đồng bộ

Checkout phát hành chứa JavaScript đã đóng gói và CSS mà Docker phục vụ. Source React trong workspace Desktop thuộc một cây riêng và có khác biệt về tính năng. Khi xây dựng lại frontend, cần xác định một cây source có đầy đủ các tính năng đang phát hành và kiểm tra đầu ra CI trước khi thay bundle. Bản thay đổi này cập nhật các trường mật khẩu trong bundle hiện đang dùng.
