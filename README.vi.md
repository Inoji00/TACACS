# TNAC+ v1.1.0

[English](README.md) · **Tiếng Việt**

TNAC+ là máy chủ TACACS+ để quản trị thiết bị mạng. Web console quản lý thiết bị, identity group, ánh xạ quyền EXEC, command policy và nhật ký AAA. Khả năng thực tế phụ thuộc vào TACACS+ client, cấu hình và firmware của thiết bị.

v1.1.0 tích hợp cảnh báo hoạt động/sức khỏe qua Slack, báo khóa tài khoản nhanh, khóa thiết bị ở lần sai thứ 4 và bố cục Dashboard/Users đã được chấp nhận. Hoạt động được đọc mỗi 3 giây; mục tiêu gửi Slack khoảng 3–5 giây khi điều kiện bình thường. Muốn nhận lệnh, thiết bị cần gửi command accounting. Xem [thay đổi](CHANGELOG.vi.md) và [quy trình nâng cấp](UPGRADE.vi.md).

## Kiểm thử và bảo mật

[Workflow và artifact](https://github.com/Inoji00/TACACS/actions/workflows/ci.yml) · [CLI chạy lại test và Trivy](TESTING.vi.md). Tests và CI nằm trên `main`; bản cài v1.1.0 bất biến được xuất bản trước phần bổ sung này.

## Cài mới trên Ubuntu

Tải [ZIP cài đặt](https://github.com/Inoji00/TACACS/releases/download/v1.1.0/TNAC-v1.1.0.zip) và [SHA-256](https://github.com/Inoji00/TACACS/releases/download/v1.1.0/TNAC-v1.1.0.zip.sha256), hoặc clone tag bên dưới.

Cần Ubuntu amd64, Python 3.12 trở lên có venv, Docker Engine, Buildx, Compose v2 và IPv4 quản trị. VM cần Internet để tải image nền và dependency.

```bash
git clone --branch v1.1.0 https://github.com/Inoji00/TACACS.git 'TNAC+'
cd 'TNAC+'
sudo bash install.sh
sudo bash tnac status
```

Khi được hỏi subnet, nhập CIDR chứa IPv4 của VM. Mở URL HTTPS trình cài hiển thị. Chạy `sudo bash tnac credentials` trong terminal riêng để lấy tài khoản khởi tạo và đổi mật khẩu sau khi đăng nhập.

- [Cài đặt và xác minh HTTPS](INSTALL.vi.md)
- [CLI vận hành và xử lý sự cố](OPERATIONS.vi.md)
- [Kiểm soát bảo mật, bản vá CVE và phạm vi kiểm thử](SECURITY.vi.md)
- [Nâng cấp appliance v1.0 đang sử dụng](UPGRADE.vi.md)
- [Lịch sử phát hành](CHANGELOG.vi.md)
