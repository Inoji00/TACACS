# Device Syslog / Syslog thiết bị

TNAC+ receives operational Syslog from infrastructure devices over IPv4 UDP/514, including sources without a TACACS+ registration. The first acceptance target is a Cisco switch on a protected management network. / TNAC+ nhận Syslog vận hành qua IPv4 UDP/514, kể cả nguồn chưa đăng ký TACACS+. Mục tiêu nghiệm thu ban đầu là switch Cisco trong mạng quản trị.

## Deploy / Triển khai

Fresh installations from current main enable Device Syslog automatically on the selected VM server IPv4. Use the procedure below for existing installs and the original v1.1.2 installer ZIP. / Bản cài mới từ main hiện tự bật Device Syslog ở IPv4 máy chủ đã chọn. Dùng quy trình bên dưới cho hệ thống đang chạy và ZIP v1.1.2 gốc.

Install TNAC+ first. For an existing installation use a separate source checkout. Take the database/config backups and retain the currently running image IDs before upgrading. This procedure enables or upgrades the Syslog collector and Web Admin. For an upgrade of older TACACS+ or PostgreSQL images, follow the separate upgrade guide first. / Cài TNAC+ trước. Với hệ thống đang chạy, dùng checkout source riêng, sao lưu database/cấu hình và giữ image hiện tại. Quy trình dưới đây cập nhật Web và bộ thu Syslog. Nếu cần nâng image TACACS+ hoặc PostgreSQL đời cũ, thực hiện hướng dẫn nâng cấp riêng trước.

```bash
git clone --branch v1.1.2 https://github.com/Inoji00/TACACS.git tnac-syslog-src
cd tnac-syslog-src
sudo docker build -t tnac:device-syslog-v1.1.2 .
read -r -p 'Management IPv4: ' listen_ip
sudo bash scripts/enable_device_syslog.sh "$HOME/TNAC+" "$listen_ip" tnac:device-syslog-v1.1.2
```

The script prints the Compose backup path and creates or reuses the project Syslog volume. It recreates the Web services and briefly interrupts HTTPS. Keep the backup path and verify the collector, admin and proxy are healthy. Permit UDP/514 only from your intended device networks at the network boundary. UDP sources can be spoofed and UDP delivery may lose messages. / Script in đường dẫn backup Compose và tạo hoặc dùng lại volume Syslog của project. Hai dịch vụ Web được tạo lại và HTTPS gián đoạn ngắn. Giữ đường dẫn backup, kiểm tra collector, admin và proxy báo healthy. Chỉ mở UDP/514 từ mạng thiết bị cần nhận log. UDP có thể mất bản tin và địa chỉ nguồn có thể bị giả mạo.

## Cisco example / Ví dụ Cisco

```text
configure terminal
logging host 192.0.2.20
end
show logging
```

Replace the example server IP. `configure terminal` opens configuration mode. `logging host` adds the collector while keeping existing destinations. `end` returns to EXEC and `show logging` verifies the destinations, transport and severity. Syntax and defaults vary by model and firmware. Keep the existing source interface, routing/VRF and severity unless a change has been reviewed. / Thay IP ví dụ. `configure terminal` vào chế độ cấu hình. `logging host` thêm máy nhận và giữ đích cũ. `end` về EXEC, `show logging` kiểm tra đích, cổng và severity. Cú pháp và mặc định phụ thuộc model, firmware. Giữ interface nguồn, định tuyến/VRF và severity hiện tại nếu chưa đánh giá thay đổi.

Create a safe non-AAA event on a lab port. In **System Administration → Device Syslog**, search by source IP, receive time, severity or message. Confirm all configured collectors still receive events before saving with `copy running-config startup-config`. / Tạo sự kiện ngoài AAA trên cổng lab. Vào **Quản trị hệ thống → Syslog thiết bị**, lọc IP nguồn, thời điểm nhận, severity hoặc nội dung. Xác nhận các máy nhận vẫn hoạt động rồi lưu bằng `copy running-config startup-config`.

## Retention and limits / Lưu giữ và giới hạn

Logs expire after 30 days by receive time. Cleanup runs in batches. An existing database can reuse freed pages, while new stores also use incremental SQLite vacuum. Monitor disk growth during the trial. The UI loads at most 100 events at a time. The collector preserves the received message and reads facility/severity from a valid PRI, including Cisco legacy and RFC 5424 input. It does not extract every structured-data field. Treat logs as sensitive because devices may emit usernames or configuration details. / Log hết hạn sau 30 ngày tính theo lúc nhận. Dọn theo lô. Kho hiện có dùng lại trang trống, kho mới dùng thêm SQLite incremental vacuum. Theo dõi tăng trưởng ổ đĩa trong đợt thử. UI tải tối đa 100 bản ghi mỗi lần. Bộ thu giữ nội dung và đọc facility/severity từ PRI hợp lệ, gồm bản tin Cisco cũ và RFC 5424. Chưa tách hết structured data. Log có thể chứa username hoặc thông tin cấu hình do thiết bị gửi.

## Rollback / Hoàn tác

If removing the new destination, remove only that logging host on the switch. If rolling back the image, keep network settings intact. Restore the printed Compose backup and recreate the Web services. If the backup already defines Device Syslog, also recreate that service with the old image. If the backup predates Device Syslog, stop and remove only the collector container before restoring the backup. Preserve the Syslog volume. / Khi gỡ đích mới, chỉ gỡ logging host tương ứng trên switch. Khi quay lại image cũ, giữ cấu hình mạng. Khôi phục file backup đã in và tạo lại hai dịch vụ Web. Nếu backup đã có Syslog, tạo lại cả service Syslog bằng image cũ. Nếu backup chưa có Syslog, dừng và gỡ riêng container collector trước khi phục hồi. Giữ volume Syslog.

[Cisco System Message Logging](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_2_e/consolidated_guide/configuration_guide/b_1522e_consolidated_2960x_cg/m_sm_log_cg.html) · [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424.html)
