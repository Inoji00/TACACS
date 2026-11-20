# Lịch sử thay đổi

[English](CHANGELOG.md) · **Tiếng Việt**

## Chưa phát hành

- Khôi phục mật khẩu admin khởi tạo bằng `tnac reset-admin` trong terminal root riêng. Thu hồi phiên Web hiện có và giữ MFA.

- Mật khẩu mới phải có tối thiểu 12 ký tự, gồm chữ hoa, chữ thường, chữ số và ký hiệu ASCII. Mật khẩu hiện tại vẫn dùng được đến khi đổi.
- Áp dụng khi tạo hoặc đặt lại mật khẩu device user, đổi mật khẩu Web và khởi tạo admin. Giao diện hiển thị yêu cầu bằng cả hai ngôn ngữ.
- Căn đều bộ lọc Syslog theo chiều rộng màn hình, giữ mỗi bản ghi trên một dòng.
- Ghi lại ranh giới các thành phần, phạm vi triển khai và phần source frontend cần đồng bộ với bundle. Xem [biên bản rà soát kiến trúc](ARCHITECTURE-REVIEW.md).

## v1.1.3 — 20/11/2026

- Cài mới tự bật Device Syslog sau khi kiểm tra UDP/514.
- Admin quản lý profile Switch, Router hoặc Firewall theo IPv4 nguồn và lọc cả log đang lưu.
- Hiển thị mỗi bản ghi Syslog trên một dòng, cuộn ngang để đọc nội dung dài.
- Bổ sung hướng dẫn CLI Anh–Việt để kiểm tra và lọc file theo ngày.

- Xuất Device Syslog còn hạn thành file theo IPv4 nguồn và ngày nhận UTC+07. Dùng tên container ngắn, giữ đủ cột trạng thái Compose. Cài mới dùng volume `tnac-syslog`; nâng cấp giữ log hiện có.

## v1.1.2 — 19/11/2026

- Thêm Device Syslog để nhận log vận hành UDP/514, kể cả thiết bị chưa đăng ký TACACS+. Admin lọc theo IP nguồn, thời gian nhận, severity và nội dung.
- Giữ log 30 ngày trong volume riêng. Dọn bản ghi hết hạn theo lô và giới hạn mỗi trang ở 100 dòng.
- Thêm hướng dẫn kết nối Cisco Anh–Việt trong Devices, đọc offline và sao chép CLI mẫu.
- ZIP cài đặt chỉ chứa thành phần vận hành và tài liệu. Source clone giữ test và workflow để tái hiện CI.

## v1.1.1 — 19/11/2026

- Chuyển runtime TNAC sang Python 3.12 trên Alpine 3.23.
- Loại binary Go `gosu` cũ khỏi các layer PostgreSQL phát hành và giữ `su-exec` cùng UID 70.
- Thêm hồi quy PostgreSQL thật, Compose smoke, dump/restore, Trivy và kiểm tra dữ liệu nhạy cảm trong CI.
- Giữ nguyên 37 migration. Clone mặc định lấy nhánh `main`; ZIP cố định theo tag.

## v1.1.0 — 18/11/2026

- Thêm cấu hình Slack Incoming Webhook, gửi tin thử qua hàng đợi, trạng thái gửi và các nhóm sự kiện trên Web Admin.
- Chuyển tiếp xác thực thiết bị thành công, xác thực thất bại và kết quả AAA khác, lệnh được ghi nhận và thao tác Web có audit.
- Thêm worker hoạt động trên host mỗi 3 giây. Khóa/mở khóa tài khoản dùng worker nhanh và được ưu tiên trước tin hoạt động thường. Mục tiêu gửi khoảng 3–5 giây, phụ thuộc mạng, hàng đợi và giới hạn Slack.
- Giữ kiểm tra Docker, kết nối, ngưỡng tài nguyên và tổng số lần xác thực thất bại theo snapshot khoảng một phút.
- Lưu hàng đợi có giới hạn và con trỏ audit bền vững. Thử lại khi lỗi, áp dụng thời gian chờ cho toàn webhook và giữ vị trí đọc khi hàng đợi đầy.
- Liên kết audit accounting mới bằng đúng ID bản ghi trong cùng giao dịch. Lệnh được áp dụng redaction trước khi gửi.
- Khóa tài khoản thiết bị ngay lần sai mật khẩu liên tiếp thứ 4. Bộ đếm lưu xuyên các phiên SSH. Xác thực Web giữ ngưỡng hiện có và dùng chung trạng thái khóa tài khoản.
- Khai báo external cho volume cấu hình và secret do bộ cài tạo. Thêm helper sao lưu và kiểm tra Compose khi nâng cấp.
- Cho phép bấm ô Inventory, giữ danh sách Users đầy đủ cùng cột Status và căn đồng nhất thời gian cập nhật Dashboard.
- Tách luồng hoạt động nhanh khỏi dữ liệu sức khỏe để tránh báo phục hồi/mở khóa sai khi chưa thu thập dữ liệu tương ứng.
- Minify UI đóng gói, giữ tên identifier. Gói cài loại trừ ZIP vá tạm, trạng thái triển khai local, thông tin đăng nhập và dữ liệu địa điểm thử nghiệm.

### Phạm vi kiểm chứng

Kiểm thử local bao phủ phân quyền repository/API, CSRF, redaction, phục hồi hàng đợi, con trỏ khi đầy hàng đợi, cooldown, lịch worker nhanh và render UI Anh/Việt. Tổng hợp kết quả phát hành nằm trong SECURITY.vi.md.

Bằng chứng do người vận hành cung cấp xác nhận tin thử Slack, xác thực PASS/FAIL, EXEC authorization allow, accounting start và cảnh báo khóa. Người vận hành đã chấp nhận các bản cập nhật hoạt động nhanh và khóa nhanh cuối cùng. Kết quả này có phạm vi theo môi trường đã thử. Chưa quét CVE lại các image v1.1.0 trong đợt xuất bản.

## v1.0

Gói cài online ban đầu, hướng dẫn cài đặt/vận hành/bảo mật song ngữ, mở khóa tài khoản, phân quyền AAA log theo phạm vi và điều chỉnh giới hạn API quản trị.
