# TNAC+ v1.1.6

[English](README.md) · **Tiếng Việt**

[Giấy phép MIT](LICENSE) · [Sử dụng có trách nhiệm và miễn trừ trách nhiệm](DISCLAIMER.vi.md)

TNAC+ là máy chủ TACACS+ để quản trị thiết bị mạng. Web console quản lý thiết bị, identity group, ánh xạ quyền EXEC, command policy và nhật ký AAA. Khả năng thực tế phụ thuộc vào TACACS+ client, cấu hình và firmware của thiết bị.

TNAC+ tích hợp cảnh báo hoạt động/sức khỏe qua Slack, báo khóa tài khoản nhanh, khóa thiết bị ở lần sai thứ 4 và bố cục Dashboard/Users đã được chấp nhận. Hoạt động được đọc mỗi 3 giây; mục tiêu gửi Slack khoảng 3–5 giây khi điều kiện bình thường. Muốn nhận lệnh, thiết bị cần gửi command accounting. Xem [thay đổi](CHANGELOG.vi.md) và [quy trình nâng cấp](UPGRADE.vi.md).

> **[Kiểm chứng bảo mật](SECURITY-VALIDATION.vi.md)** · 66 bài bảo mật local · 512 bài hồi quy CI · 0 Critical / 0 High

> [!IMPORTANT]
> **Đã kiểm chứng trên switch Cisco.** TNAC+ đã được thử trên Cisco Catalyst 2960X trong lab với đăng nhập TACACS+, cấp quyền EXEC, ghi log phiên và lệnh, và thu Syslog vận hành. Khả năng tương thích phụ thuộc model, hệ điều hành, firmware và cấu hình switch.
>
> **Cần hỗ trợ tích hợp hãng khác?** Nếu chưa kết nối được, gửi email đến **[lehoangtuansang@gmail.com](mailto:lehoangtuansang@gmail.com)**. Ghi rõ hãng, model, OS/firmware, tính năng cần dùng và lỗi hoặc log mẫu đã che thông tin nhạy cảm. Phản hồi của bạn giúp xử lý vướng mắc, mở rộng phạm vi kiểm thử và cải thiện TNAC+ cho cộng đồng.

## Kiểm thử và bảo mật

[Workflow và artifact](https://github.com/Inoji00/TACACS/actions/workflows/ci.yml) · [CLI chạy lại test và Trivy](TESTING.vi.md). Clone mặc định lấy `main`. Dùng ZIP theo phiên bản khi cần cố định bản cài.

## Cài mới trên Ubuntu

Clone nhánh mặc định bên dưới để lấy bộ cài hiện tại.

Cần Ubuntu amd64, Python 3.12 trở lên có venv, Docker Engine, Buildx, Compose v2 và IPv4 quản trị. VM cần Internet để tải image nền và dependency.

```bash
git clone https://github.com/Inoji00/TACACS.git 'TNAC+'
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
- [Kết nối switch Cisco với TNAC+ (Anh–Việt)](CISCO-AAA.md)

- [Triển khai và rollback Device Syslog](DEVICE-SYSLOG.md)
