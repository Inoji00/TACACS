# Vận hành TNAC+

[English](OPERATIONS.md) · **Tiếng Việt**

Chạy các lệnh sau từ thư mục chứa `tnac` trên máy chủ đã cài TNAC+.

| Lệnh | Công dụng |
| --- | --- |
| `sudo bash tnac status` | Xem trạng thái và cổng của các container trong stack. |
| `sudo bash tnac start` | Khởi động stack hiện có. |
| `sudo bash tnac stop` | Dừng stack. Lệnh giữ volume PostgreSQL. |
| `sudo bash tnac snapshot` | Cập nhật ảnh chụp trạng thái dịch vụ và endpoint. |
| `sudo bash tnac credentials` | Hiển thị thông tin khởi tạo và dữ liệu TOTP. Dùng terminal riêng và giữ kín output. |
| `sudo bash tnac rebind` | Áp dụng IP hoặc tên miền và chứng chỉ HTTPS mới. Thực hiện trong khung bảo trì vì có thể tạo lại dịch vụ. |

## Kiểm tra khi dịch vụ lỗi

```bash
sudo docker ps -a --filter name=tnac- \
  --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
sudo docker logs --tail 50 tnac-admin
sudo docker logs --tail 50 tnac-proxy
sudo docker logs --tail 50 tnac-app
sudo docker exec tnac-db pg_isready -h 127.0.0.1 -U tacacs_app -d tacacs
sudo docker stats --no-stream tnac-app tnac-admin tnac-proxy tnac-db
```

Lấy log của dịch vụ cần chẩn đoán và che thông tin nội bộ trước khi chia sẻ. Nếu HTTPS không phản hồi, kiểm tra `tnac-db`, `tnac-admin` và `tnac-proxy` cùng nhau vì chúng dùng chung network namespace. Nếu TACACS+ không phản hồi, kiểm tra TCP/49 và đối chiếu IP nguồn thiết bị với entry đã đăng ký.

## Dùng chứng chỉ quản trị của CA tin cậy

DNS phải trỏ về IPv4 quản trị của VM. Chuẩn bị file PEM chứa certificate và intermediate, private key có mode `0600`, và CA bundle dùng để xác minh chứng chỉ. Thay hostname và đường dẫn ví dụ bằng giá trị của môi trường.

```bash
sudo bash tnac rebind --admin-domain tnac.example.net \
  --cert-file /path/to/fullchain.pem \
  --key-file /path/to/privkey.pem \
  --ca-file /path/to/ca-bundle.pem
sudo bash tnac status
```

Mở `https://tnac.example.net:8443/` sau khi trạng thái ổn định.

## Giám sát Dashboard

Bản cài mới tự bật giám sát định kỳ. Với bản đã cài, chạy sau khi cập nhật source:

```bash
sudo bash tnac enable-monitoring
systemctl list-timers --all tnac-snapshot.timer
sudo journalctl -u tnac-snapshot.service -n 20 --no-pager
```

Timer lấy trạng thái container, tài nguyên VM và kiểm tra endpoint HTTPS đã cấu hình khoảng một phút một lần. Nếu Dashboard vẫn báo **Not currently verified**, kiểm tra `sudo bash tnac status` và nhật ký của service. Khi gỡ bản cài, tắt timer bằng `sudo systemctl disable --now tnac-snapshot.timer`.
