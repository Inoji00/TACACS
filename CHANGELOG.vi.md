# Lịch sử thay đổi

[English](CHANGELOG.md) · **Tiếng Việt**

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
