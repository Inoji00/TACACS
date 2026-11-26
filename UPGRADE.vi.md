# Nâng cấp lên v1.1.8

[English](UPGRADE.md) · **Tiếng Việt**

v1.1.8 giữ nguyên 37 migration. Sao lưu PostgreSQL, thử restore vào container riêng và lưu cấu hình Compose cùng đúng image ID đang chạy để rollback. Nếu thiếu image cũ, cần bản sao toàn VM có thể khôi phục.

Build và quét hai image từ checkout v1.1.8 riêng theo [hướng dẫn kiểm thử](TESTING.vi.md). Khi bảo trì, cập nhật image của app/admin/proxy và PostgreSQL trong Compose project đang dùng. Tạo lại cả bốn service vì Web Admin và proxy phụ thuộc namespace của PostgreSQL. Giữ các volume hiện có. Kiểm tra trạng thái service, đăng nhập HTTPS và xác thực, cấp quyền, accounting trên thiết bị.

- [Triển khai và rollback Device Syslog](DEVICE-SYSLOG.md)

Nếu đã bật giám sát Slack, hãy cập nhật tiến trình trên host sau khi nâng image Web Admin. Chạy từ thư mục source v1.1.8 đã xác minh.

```bash
monitor=/usr/local/lib/tnac-monitoring
sudo test -f "$monitor/slack_monitor.py"
sudo cp -p "$monitor/slack_monitor.py" "$monitor/slack_monitor.py.v1.1.8-backup"
sudo install -m 0644 scripts/slack_monitor.py "$monitor/slack_monitor.py.new"
sudo cp -p "$monitor/alert_storage.py" "$monitor/alert_storage.py.v1.1.8-backup"
sudo install -m 0644 src/tacacs_appliance/alert_storage.py "$monitor/alert_storage.py.new"
sudo mv "$monitor/slack_monitor.py.new" "$monitor/slack_monitor.py"
sudo mv "$monitor/alert_storage.py.new" "$monitor/alert_storage.py"
sudo systemctl restart tnac-alerts.service
sudo systemctl is-active tnac-alerts.service
```
