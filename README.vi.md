# TNAC+

[English](README.md) · **Tiếng Việt**

TNAC+ là máy chủ TACACS+ để quản trị thiết bị mạng. Web console quản lý thiết bị, identity group, ánh xạ quyền EXEC, command policy và nhật ký AAA. Khả năng thực tế phụ thuộc vào TACACS+ client, cấu hình và firmware của thiết bị.

## Cài mới trên Ubuntu

Cần Ubuntu amd64, Python 3.12 trở lên có venv, Docker Engine, Buildx, Compose v2 và IPv4 quản trị. VM cần Internet để tải image nền và dependency.

```bash
git clone https://github.com/Inoji00/TNAC-.git 'TNAC+'
cd 'TNAC+'
sudo bash install.sh
sudo bash tnac status
```

Khi được hỏi subnet, nhập CIDR chứa IPv4 của VM. Mở URL HTTPS trình cài hiển thị. Chạy `sudo bash tnac credentials` trong terminal riêng để lấy tài khoản khởi tạo và đổi mật khẩu sau khi đăng nhập.

- [Cài đặt và xác minh HTTPS](INSTALL.vi.md)
- [CLI vận hành và xử lý sự cố](OPERATIONS.vi.md)
- [Kiểm soát bảo mật, bản vá CVE và phạm vi kiểm thử](SECURITY.vi.md)
