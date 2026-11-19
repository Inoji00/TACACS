# Bảo mật TNAC+

[English](SECURITY.md) · **Tiếng Việt**

[Sử dụng có trách nhiệm và miễn trừ trách nhiệm](DISCLAIMER.vi.md)

> **[Kiểm chứng bảo mật](SECURITY-VALIDATION.vi.md)** · 66 bài bảo mật local · 512 bài hồi quy CI · 0 Critical / 0 High

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

## Kiểm chứng v1.1.1

Runtime TNAC dùng Alpine 3.23. PostgreSQL dùng `su-exec` và image phát hành không chứa layer có binary Go `gosu` cũ. Xem kết quả Trivy của đúng commit trong GitHub Actions.

## Phạm vi kiểm thử và phần còn mở

Hai image ứng viên đã qua initdb, restart và dump/restore PostgreSQL, khởi tạo migrations, kiểm tra TCP/49 readiness, HTTPS trực tiếp tới Web Admin, đăng nhập, đăng xuất và thu hồi cookie cũ. AAA trên switch thật và đường HTTPS qua proxy chưa được nghiệm thu trong đợt này.

Các số trên thuộc về image ứng viên. Source online có thể lấy base Python và dependency khác ở lần build tiếp theo. Cần quét đúng image ID của mỗi bản build dùng để triển khai và ghi nhận các phát hiện còn lại. Báo cáo CVE có thể chứa tên image và thông tin môi trường. Khi báo lỗi, gửi riêng bản đã loại thông tin nhạy cảm cho maintainer.

## Kiểm chứng có thể chạy lại

[Bộ test trong repo](tests/) và [GitHub Actions](.github/workflows/ci.yml) cung cấp bằng chứng có thể chạy lại. Xem [TESTING.vi.md](TESTING.vi.md) để lấy CLI từ checkout sạch, phạm vi kiểm tra, vị trí artifact và chính sách quét. CI build cả hai image runtime, chạy socket/TLS Linux, hồi quy với PostgreSQL dùng một lần, kiểm tra console đóng gói và Compose smoke, đồng thời quét hai image đầy đủ bằng Trivy.

Đối chiếu [lần chạy đúng commit](https://github.com/Inoji00/TACACS/actions/workflows/ci.yml). JSON tách riêng pass, skip, loại khỏi lượt chạy và lỗi. Gate HIGH/CRITICAL tính cả CVE chưa có bản vá; thiếu báo cáo cũng thất bại. Số liệu ứng viên và kết quả filesystem cũ ở trên không đáp ứng gate này. Tài liệu không tuyên bố image hiện tại hết CVE.

Câu “424 tests passed” trước đây thuộc lượt local chưa đầy đủ và bản xuất bản ban đầu thiếu source test. Đây không phải kết quả CI có thể tái lập; thay bằng báo cáo workflow gắn với commit. Tag và ZIP v1.1.0 bất biến không bị ghi đè; hạ tầng test mới nằm trên main.

Bằng chứng người vận hành nhận Slack authentication/authorization/accounting/lock được tách khỏi CI. Kiểm thử phần mềm không chứng nhận tương thích thiết bị thật hay bảo đảm deadline gửi ra ngoài 3–5 giây.
