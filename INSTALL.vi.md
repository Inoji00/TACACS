# Cài TNAC+ trên Ubuntu VM

[English](INSTALL.md) · **Tiếng Việt**

Bộ cài Linux amd64 cần Internet để tải base image, PostgreSQL và dependency Python. Máy chạy cần Python 3.12 trở lên có venv, Docker Engine, Buildx, Compose plugin, unzip và iproute2. Gán IPv4 cho VM trước. Địa chỉ thuộc dải 192.0.2.0/24 trong tài liệu chỉ dùng làm ví dụ.

Kiểm tra các thành phần đã có trên VM.

```bash
dpkg --print-architecture
python3 --version
docker --version
docker buildx version
docker compose version
ip -br -4 addr
```

Nếu cần cài Docker Engine hoặc plugin, dùng [hướng dẫn Docker Engine cho Ubuntu](https://docs.docker.com/engine/install/ubuntu/). Cài `python3-venv`, `git`, `unzip` và `iproute2` từ kho Ubuntu nếu VM thiếu các gói này.

Bản cài mới tự bật Device Syslog qua UDP/514 trên IPv4 máy chủ đã chọn. Kiểm tra cổng còn trống và giới hạn nguồn gửi vào trong mạng quản trị. Bản đang chạy có thể dùng quy trình bật thủ công.

## Tải source và cài

```bash
git clone https://github.com/Inoji00/TACACS.git 'TNAC+'
cd 'TNAC+'
sudo bash install.sh
```

Với ZIP và checksum được cung cấp cùng nhau, có thể dùng:

```bash
sha256sum -c TNAC-v1.1.2.zip.sha256 && unzip TNAC-v1.1.2.zip
cd 'TNAC+'
sudo bash install.sh
```

Trình cài kiểm tra IP, cổng, Docker và tên container trước khi tải dependency hoặc build image. Trình cài hỏi subnet và chọn IPv4 khi có đúng một địa chỉ trên VM khớp CIDR. Nếu có nhiều địa chỉ, nhập CIDR /32 của đúng IPv4 đã gán. Stack dùng TCP/49 cho thiết bị và HTTPS/8443 cho mạng quản trị. HTTPS chỉ publish trên IPv4 quản trị đã chọn. Docker hiển thị mapping HTTPS ở tnac-db do proxy dùng chung network namespace. PostgreSQL TCP/5432 dùng nội bộ.

Trình cài build hai image local là `tnac:current` và `tnac-postgres:16.16-r2`. Image ứng dụng dùng Python 3.12 trên Alpine 3.23. Image PostgreSQL giữ major 16 và chạy database với UID 70 qua `su-exec`.

```bash
sudo bash tnac status
sudo bash tnac credentials
```

Chạy credentials trong terminal riêng. Mở URL HTTPS do trình cài in ra và đăng nhập bằng username và password khởi tạo. Xác minh chứng chỉ khởi tạo theo file công khai data/vm-appliance/localhost-ca.pem trước khi đăng nhập. Sau khi vào giao diện, đổi mật khẩu khởi tạo và thêm switch ở Network Resources → Devices. Mỗi thiết bị dùng IP nguồn và shared secret riêng.

Bộ cài dành cho khởi tạo mới. Nếu đã có trạng thái triển khai, dùng `sudo bash tnac status` để xác minh stack. Xem [CLI vận hành](OPERATIONS.vi.md) để kiểm tra dịch vụ và cài chứng chỉ CA cho tên miền quản trị.

Bộ cài bật systemd timer để cập nhật **Services** và **System resources** khoảng một phút một lần. Với bản đã cài, cập nhật source rồi chạy `sudo bash tnac enable-monitoring`.

- [Triển khai và rollback Device Syslog](DEVICE-SYSLOG.md)
