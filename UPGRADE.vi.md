# Nâng cấp lên v1.1.0

[English](UPGRADE.md) · **Tiếng Việt**

Quy trình dành cho bản v1.0 một appliance mặc định tại ~/TNAC+, với container tnac-app, tnac-admin, tnac-proxy và tnac-db. Chọn thời gian bảo trì vì AAA và Web sẽ được tạo lại. Giữ một phiên quản trị thiết bị độc lập trong lúc nghiệm thu.

v1.0 đã có migration 037. v1.1.0 giữ manifest 37 migration nên không cần migration mới. Schema cũ hơn hoặc tùy biến cần đánh giá riêng. Bộ cài install.sh dành cho triển khai mới.

Tải TNAC-v1.1.0.zip cùng TNAC-v1.1.0.zip.sha256 tại [trang phát hành](https://github.com/Inoji00/TACACS/releases/tag/v1.1.0), chuyển cả hai file vào thư mục home trên Ubuntu. Repo private yêu cầu đăng nhập khi tải.

## Sao lưu bản đang chạy

```bash
(
set -euo pipefail
umask 077
cd "$HOME/TNAC+"
backup=$(mktemp -d "$HOME/tnac-pre-v1.1.0.XXXXXX")
sudo docker exec tnac-db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "$backup/tnac.dump"
sudo tar -czf "$backup/deployment-state.tar.gz" data/vm-appliance
sudo chmod 600 "$backup/deployment-state.tar.gz"
sudo docker image tag "$(sudo docker inspect --format '{{.Image}}' tnac-app)" tnac:pre-v1.1.0-app
sudo docker image tag "$(sudo docker inspect --format '{{.Image}}' tnac-admin)" tnac:pre-v1.1.0-web
sha256sum "$backup/tnac.dump" > "$backup/tnac.dump.sha256"
printf 'Thu muc backup rieng: %s\n' "$backup"
)
```

Giữ bản sao lưu được bảo vệ của các volume cấu hình/secret, gồm volume alerts nếu đã cấu hình Slack. ZIP phát hành ghi đè source cài đặt và loại trừ trạng thái triển khai, secret được sinh. Sao lưu các chỉnh sửa source riêng trước khi ghi đè.

## Áp dụng bản phát hành

```bash
(
set -euo pipefail
cd "$HOME"
sha256sum -c TNAC-v1.1.0.zip.sha256
unzip -o TNAC-v1.1.0.zip -d "$HOME"
cd "$HOME/TNAC+"
WEB_IMAGE=$(sudo python3 -c 'import json; print(json.load(open("data/vm-appliance/compose.json"))["services"]["admin"]["image"])')
AAA_IMAGE=$(sudo python3 -c 'import json; print(json.load(open("data/vm-appliance/compose.json"))["services"]["app"]["image"])')
sudo docker build -t "$WEB_IMAGE" .
if [ "$AAA_IMAGE" != "$WEB_IMAGE" ]; then
  sudo docker tag "$WEB_IMAGE" "$AAA_IMAGE"
fi
sudo .venv/bin/python scripts/repair_external_volumes.py
sudo .venv/bin/python scripts/prepare_slack_alerts.py
sudo env PYTHONPATH="$PWD/src" .venv/bin/python scripts/vm_appliance.py update-audit
sudo bash tnac enable-monitoring
sudo bash tnac status
sudo systemctl status tnac-alerts.service --no-pager
)
```

## Nghiệm thu và giữ bản quay lui

Làm mới trình duyệt, đăng nhập lại và kiểm tra Dashboard hiển thị 1.1.0 cùng trạng thái dịch vụ. Kiểm tra thiết bị, user, mapping và log đang có. Dùng tài khoản thử để xác minh kết quả xác thực và khóa/mở khóa. Với Slack, kiểm tra nhóm sự kiện được chọn, gửi tin thử rồi so sánh thời gian sự kiện và thời gian gửi. Muốn nhận lệnh, thiết bị phải được cấu hình gửi command accounting.

Worker giữ cấu hình và con trỏ hiện có. Lưu cấu hình sẽ đặt lại mốc theo dõi và xóa hàng đợi ở chu kỳ tiếp theo. Tránh lưu lại cấu hình không đổi trong lúc nghiệm thu.

Helper giữ bản sao lưu Compose cạnh compose.json. Giữ các file này và tag image trước nâng cấp đến khi nghiệm thu xong. Có thể quay lui image bằng Compose cũ và các tag đã giữ, cùng database hiện tại. Tắt tnac-alerts.service nếu quay về image chưa có bộ đọc hoạt động. Chỉ restore database khi đã chọn rõ thao tác phục hồi đó, vì dữ liệu phát sinh sau backup sẽ bị thay thế.
