# Bảo mật TNAC+

[English](SECURITY.md) · **Tiếng Việt**

## Kiểm soát hiện có

- Web Admin dùng TLS 1.3, cookie `Secure`, `HttpOnly`, `SameSite=Strict`, kiểm tra Origin và CSRF, và giới hạn lượt đăng nhập. Bản cài mới bắt đầu bằng tài khoản và mật khẩu khởi tạo được sinh riêng.
- Web Admin và TACACS+ dùng role PostgreSQL riêng. File bí mật được tạo trong volume khi cài. Container ứng dụng giảm Linux capabilities và mount cấu hình dịch vụ, thông tin kết nối database cùng khóa TLS ở chế độ chỉ đọc.
- Cấu hình và hàng đợi Slack nằm trong volume ghi riêng, dành cho Web Admin và monitor host. Webhook lưu bằng file quyền 0600, không trả qua API GET và được loại trừ khỏi gói cài. Lưu cấu hình/gửi thử cần quyền admin, Origin và CSRF hợp lệ. Kết nối gửi kiểm tra HTTPS, chặn redirect và URL ngoài mẫu webhook Slack được hỗ trợ.
- PostgreSQL TCP/5432 dùng nội bộ. HTTPS/8443 và TACACS+/49 bind vào IPv4 đã chọn. Giới hạn truy cập hai cổng từ mạng quản trị và IP thiết bị tương ứng.
- TCP/49 dùng TACACS+ legacy. Cơ chế obfuscation của giao thức thiếu bảo vệ toàn vẹn và bí mật hiện đại. Triển khai trên mạng quản trị được bảo vệ. [RFC 8907 §10](https://www.rfc-editor.org/rfc/rfc8907.html#section-10)

## Trạng thái bản vá của các image ứng viên trước đây

Kết quả dưới đây thuộc các image ứng viên ở đợt trước. Chưa build và quét lại image v1.1.0 trong đợt xuất bản này; cần đánh giá đúng image sẽ triển khai.

| Thành phần | Thay đổi trong source | Kết quả kiểm thử image ứng viên |
| --- | --- | --- |
| Python và OS | Chuyển image TNAC+ sang Python 3.12 trên Debian Trixie. | Image TNAC+ r2 có 0 Critical và 47 High trong lần quét ứng viên. |
| `zlib1g` | Build nâng gói lên bản vá Debian hoặc mới hơn và kiểm tra phiên bản tối thiểu. | Trivy không còn phát hiện CVE-2026-85091 trên image TNAC+ r2. [Debian Security Tracker](https://security-tracker.debian.org/tracker/CVE-2026-85091) |
| PostgreSQL và `gosu` | Chuyển PostgreSQL lên 16.16 trên Alpine 3.23. Base image được chốt theo digest. Entrypoint chuyển quyền sang UID 70 qua `su-exec`. | Trivy vẫn báo 1 Critical và 25 High ở đường dẫn `gosu` khi quét image theo layer. Quét filesystem xuất từ image ghi nhận 0 Critical và 0 High sau khi xác nhận đích symlink là `su-exec`. [Go advisory](https://pkg.go.dev/vuln/GO-2026-4337) |

## Phạm vi kiểm thử và phần còn mở

Hai image ứng viên đã qua initdb, restart và dump/restore PostgreSQL, khởi tạo migrations, kiểm tra TCP/49 readiness, HTTPS trực tiếp tới Web Admin, đăng nhập, đăng xuất và thu hồi cookie cũ. AAA trên switch thật và đường HTTPS qua proxy chưa được nghiệm thu trong đợt này.

Các số trên thuộc về image ứng viên. Source online có thể lấy base Python và dependency khác ở lần build tiếp theo. Cần quét đúng image ID của mỗi bản build dùng để triển khai và ghi nhận các phát hiện còn lại. Báo cáo CVE có thể chứa tên image và thông tin môi trường. Khi báo lỗi, gửi riêng bản đã loại thông tin nhạy cảm cho maintainer.

## Kiểm chứng v1.1.0

Kiểm thử hồi quy local có 424 bài pass. 44 bài skip và 38 bài socket loopback được loại khỏi lượt chạy.

JavaScript đã qua kiểm tra cú pháp và render từ bundle đóng gói cho trang Slack Anh/Việt, ẩn webhook và điều hướng Users. Trình duyệt preview chưa kết nối được server local, nên đợt xuất bản này chưa bổ sung nghiệm thu trực quan trên trình duyệt.

Người vận hành đã cung cấp bằng chứng tin Slack cho xác thực PASS/FAIL, authorization allow, accounting start và khóa tài khoản, đồng thời chấp nhận các cập nhật hoạt động nhanh và khóa nhanh cuối cùng. Mốc 3–5 giây là mục tiêu, độ trễ phụ thuộc mạng, hàng đợi và Slack. PostgreSQL thật, build container mới, quét CVE mới và nghiệm thu thiết bị rộng hơn chưa được chạy lại trong đợt xuất bản local này.
