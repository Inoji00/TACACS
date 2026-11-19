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

## Daily files and status / File theo ngày và trạng thái

The collector also exports retained SQLite events to `/var/lib/tnac-syslog/archive/<SOURCE_IP>/YYYY-MM-DD.log` about once a minute. Days use UTC+07 receive time. It refreshes changed files by streaming rows into a temporary file and replacing the previous copy. This uses additional disk space per retained message. / Bộ thu xuất log còn hạn từ SQLite sang file theo IP và ngày, làm mới khoảng mỗi phút. Ngày tính theo giờ nhận UTC+07. File thay đổi được tạo lại theo luồng rồi thay thế bản cũ. Cần dự trù thêm dung lượng vì log có thêm một bản dạng text.

New deployments use the volume and container name `tnac-syslog`. Existing deployments retain their configured volume and its logs. The status command keeps all default Compose columns. / Bản cài mới dùng tên volume và container `tnac-syslog`. Hệ thống hiện hữu giữ volume và log đang có. Bảng trạng thái giữ đầy đủ cột Compose.

Run these read-only commands on the Ubuntu VM. / Chạy các lệnh chỉ đọc sau trên VM Ubuntu.

```bash
cd "$HOME/TNAC+"
project=$(sudo docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' tnac-app)
sudo docker compose -p "$project" -f data/vm-appliance/compose.json ps
sudo docker port tnac-syslog
```

`inspect` reads the active Compose project name. `compose ps` shows the full status table. `docker port` confirms the host UDP/514 to collector UDP/1514 mapping. On an older deployment without the short name, use the collector name printed by `compose ps`. / `inspect` đọc tên Compose project đang chạy. `compose ps` hiển thị đầy đủ trạng thái. `docker port` xác nhận ánh xạ UDP/514 của VM vào UDP/1514 của collector. Nếu bản cũ chưa có tên ngắn, dùng tên collector từ bảng trạng thái.

```bash
sudo docker exec tnac-admin find /var/lib/tnac-syslog/archive -maxdepth 2 -type f -name '*.log' | sort
```

`find` lists files by source IP and date. Use an IP and date returned by the command. The path is inside the container. / `find` liệt kê file theo IP nguồn và ngày. Thay IP và ngày theo kết quả vừa in. Đây là đường dẫn bên trong container.

```bash
log=/var/lib/tnac-syslog/archive/192.0.2.10/2026-11-19.log
sudo docker exec tnac-admin tail -n 30 "$log"
sudo docker exec tnac-admin grep -F 'CONFIG_I' "$log"
sudo docker exec tnac-admin grep -F '%PARSER' "$log"
sudo docker exec tnac-admin grep -E 'LINK|LINEPROTO' "$log"
```

`tail` shows the last 30 records. `grep -F` searches literal text. `CONFIG_I` shows configuration-change events and `%PARSER` selects Cisco parser messages. `grep -E` matches either link-related keyword. / `tail` xem 30 dòng cuối. `grep -F` tìm chuỗi chữ. `CONFIG_I` lọc sự kiện thay đổi cấu hình và `%PARSER` lọc bản tin parser Cisco. `grep -E` tìm một trong hai từ khóa trạng thái cổng.

If a new event is missing, generate a safe lab event while this capture runs. Replace the example source IP. / Nếu thiếu sự kiện mới, thay IP mẫu và tạo sự kiện lab an toàn trong lúc lệnh bắt gói chạy.

```bash
sudo timeout 60 tcpdump -ni any -nn -c 3 'src host 192.0.2.10 and udp dst port 514'
```

A captured packet confirms arrival at the VM. Allow about one minute for the daily archive to refresh. If no packet arrives, check the switch destination, routing and ACLs. If packets arrive but the file is still empty, inspect collector logs. / Có gói nghĩa là bản tin đã đến VM. Chờ khoảng một phút để file cập nhật. Nếu không thấy gói, kiểm tra đích Syslog trên switch, định tuyến và ACL. Nếu có gói nhưng file vẫn trống, xem log collector.

```bash
sudo docker compose -p "$project" -f data/vm-appliance/compose.json logs --tail 50 device-syslog
```

## Rollback / Hoàn tác

If removing the new destination, remove only that logging host on the switch. If rolling back the image, keep network settings intact. Restore the printed Compose backup and recreate the Web services. If the backup already defines Device Syslog, also recreate that service with the old image. If the backup predates Device Syslog, stop and remove only the collector container before restoring the backup. Preserve the Syslog volume. / Khi gỡ đích mới, chỉ gỡ logging host tương ứng trên switch. Khi quay lại image cũ, giữ cấu hình mạng. Khôi phục file backup đã in và tạo lại hai dịch vụ Web. Nếu backup đã có Syslog, tạo lại cả service Syslog bằng image cũ. Nếu backup chưa có Syslog, dừng và gỡ riêng container collector trước khi phục hồi. Giữ volume Syslog.

[Cisco System Message Logging](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960x/software/15-2_2_e/consolidated_guide/configuration_guide/b_1522e_consolidated_2960x_cg/m_sm_log_cg.html) · [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424.html)
