# Nâng cấp lên v1.1.2

[English](UPGRADE.md) · **Tiếng Việt**

v1.1.2 giữ nguyên 37 migration. Sao lưu PostgreSQL, thử restore vào container riêng và lưu cấu hình Compose cùng đúng image ID đang chạy để rollback. Nếu thiếu image cũ, cần bản sao toàn VM có thể khôi phục.

Build và quét hai image từ checkout v1.1.2 riêng theo [hướng dẫn kiểm thử](TESTING.vi.md). Khi bảo trì, cập nhật image của app/admin/proxy và PostgreSQL trong Compose project đang dùng. Tạo lại cả bốn service vì Web Admin và proxy phụ thuộc namespace của PostgreSQL. Giữ các volume hiện có. Kiểm tra trạng thái service, đăng nhập HTTPS và xác thực, cấp quyền, accounting trên thiết bị.

- [Triển khai và rollback Device Syslog](DEVICE-SYSLOG.md)
