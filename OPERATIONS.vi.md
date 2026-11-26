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

## Cấp quyền xem nhật ký AAA

Trong **Users → Edit Web access**, chọn **View AAA logs**. User được xem xác thực, cấp quyền và accounting của thiết bị đã đăng ký khớp cả Location lẫn Device Type. Nếu chọn tất cả ở cả hai bộ lọc, quyền áp dụng cho mọi thiết bị đã đăng ký trong tenant. Activity Log và Reports yêu cầu quyền quản trị riêng.

User được ủy quyền chỉ thấy sự kiện trong lần gán phạm vi hiện tại. Với thiết bị đã có, mốc này bắt đầu từ migration 037. Đổi Location, Device Type, xóa hoặc đăng ký lại thiết bị sẽ bắt đầu một khoảng log mới. Lưu quyền sẽ kết thúc các phiên Web đang mở của user.

## Khôi phục mật khẩu Web Admin

Khi quên mật khẩu của admin đã tạo lúc cài TNAC+, chạy từ terminal riêng trên Ubuntu bằng tài khoản có quyền sudo. PostgreSQL phải đang chạy.

```bash
cd "$HOME/TNAC+"
sudo bash tnac reset-admin
```

Gõ `RESET` để xác nhận rồi nhập mật khẩu mới hai lần. Mật khẩu cần tối thiểu 12 ký tự, có chữ hoa, chữ thường, chữ số và ký hiệu ASCII. Lệnh đặt lại bộ đếm đăng nhập sai, mở khóa admin nếu tài khoản vẫn được bật và thu hồi các phiên Web của tài khoản đó. Xem sự kiện `admin.password.reset` trong Audit Logs.

Đăng nhập lại bằng mật khẩu mới và TOTP hiện có nếu VM yêu cầu MFA. Lệnh `credentials` vẫn hiển thị thông tin khởi tạo. Với bản source khôi phục giải nén riêng, thêm `--deploy-dir "$HOME/TNAC+"` để dùng cấu hình và cơ sở dữ liệu của bản đang chạy.

## Mở khóa tài khoản

Trong **Users**, chọn **Unlock** cho tài khoản đang bị khóa và xác nhận. Activity Log ghi lại thao tác. User đăng nhập lại sau khi được mở khóa.

## Tương thích cơ sở dữ liệu

v1.1.6 giữ 37 migration của bản v1.0 đã phát hành. Xem UPGRADE.vi.md để nâng cấp bản đang chạy. Sao lưu PostgreSQL và giữ image dịch vụ cũ trước khi nâng cấp.


## Khóa tài khoản đăng nhập thiết bị

Xác thực mật khẩu TACACS+ khóa tài khoản ngay lần sai liên tiếp thứ 4. Bộ đếm thuộc tài khoản và được lưu xuyên các kết nối SSH và thiết bị trong tenant. Xác thực mật khẩu thành công đặt lại bộ đếm. Tài khoản bị khóa cũng bị từ chối đăng nhập Web. Quản trị viên có quyền có thể mở khóa trong Users. Khi nghiệm thu switch, kiểm tra bốn lần nhập sai được gửi đến TNAC+ và trạng thái Locked.


## Cảnh báo qua webhook

Chọn một đích nhận bằng URL webhook trong trang Cảnh báo. Slack hiện có tiếp tục dùng URL `hooks.slack.com`. Với Mattermost, tạo Incoming Webhook ở kênh cần nhận và dùng URL HTTPS dạng `https://mattermost.example.com/hooks/<secret>`. TNAC+ xác định nền tảng từ URL.

Trước khi dùng Mattermost, quản trị viên Ubuntu đặt `TNAC_MATTERMOST_HOST` thành tên DNS tin cậy trong cấu hình systemd của cả `tnac-alerts.service` và `tnac-snapshot.service`. Host gửi sẽ chỉ kết nối đến đúng tên đã duyệt trên HTTPS và xác minh chứng chỉ. Sau khi thay đổi systemd, reload cấu hình, khởi động lại tiến trình cảnh báo và gửi thử từ Web Admin. URL webhook chỉ nhập vào ô mật khẩu trong Web Admin.

Lưu cấu hình webhook đặt lại mốc giám sát và hàng đợi theo cơ chế hiện có. Hãy kiểm tra mục cảnh báo đang chờ trước khi chuyển đích.

Mở System Administration → Alerts bằng tài khoản có quyền users.manage. Tạo Slack App, bật Incoming Webhooks, chọn kênh nhận rồi nhập webhook trực tiếp vào TNAC+. Lưu trước khi bấm Send test alert. Tin thử được xếp hàng và thường gửi trong vài giây khi tiến trình hoạt động nhanh đã bật. Bấm Refresh để xem trạng thái gửi.

Webhook là bí mật trong volume alerts riêng. File có quyền 0600, thư mục 0700 và thuộc UID 10001 của Web Admin. API đọc cấu hình không trả webhook. Giữ URL khỏi chat, ảnh chụp, Git và dòng lệnh. Ubuntu cần DNS và HTTPS đi ra hooks.slack.com. Không cần mở thêm cổng vào.

Ngưỡng mặc định gồm hai lần kiểm tra dịch vụ/kết nối lỗi liên tiếp, CPU hoặc RAM từ 90%, filesystem chứa Docker từ 85% liên tục 300 giây, và 10 sự kiện xác thực TACACS+ thất bại trong 5 phút. Có thể bật riêng từng nhóm cảnh báo. Nhắc lại mặc định sau 1800 giây. Readiness và nghiệm thu AAA trên switch là hai phép kiểm tra riêng.

Cảnh báo tài khoản so sánh các lần đọc database, tối đa 512 tài khoản đang khóa. Lần đọc đầu đặt mốc ban đầu. Tin khóa/mở khóa có tên user. Tài khoản mất khỏi danh sách được báo là hết khóa hoặc bị xóa. Thay đổi ngắn giữa các lần lấy mẫu có thể bị bỏ qua. Xác thực thất bại được tính tổng sự kiện của bản cài.

Timer Ubuntu gửi Slack độc lập với tình trạng container ứng dụng. Để đọc dữ liệu tài khoản cần Web Admin và PostgreSQL hoạt động. Trang Alerts báo khi dữ liệu tài khoản chưa đọc được hoặc monitor lâu chưa kiểm tra. VM tắt, timer ngừng hoặc mất mạng đi ra cần một máy giám sát bên ngoài.

Lưu cấu hình đặt lại mốc theo dõi và hàng đợi ở chu kỳ tiếp theo. Hàng đợi bền vững giữ tối đa 100 thông báo đã gom nhóm, thử lại khi lỗi mạng, tuân thủ giới hạn Slack và tự báo phục hồi. Nếu Slack nhận tin nhưng phản hồi bị timeout, lần thử lại có thể tạo tin trùng. Cấu hình còn sau khi tạo lại container Web và nằm ngoài PostgreSQL. Đưa volume alerts vào bản sao lưu được bảo vệ.

~~~bash
systemctl status tnac-snapshot.timer --no-pager
sudo journalctl -u tnac-snapshot.service -n 30 --no-pager
sudo bash tnac enable-monitoring
~~~

Bật lại monitoring sau khi cập nhật source giám sát host. Hướng dẫn tạo webhook tại https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/ .


### Chuyển tiếp hoạt động user được ghi nhận

Trang Alerts có thêm bốn lựa chọn gồm Xác thực thiết bị thành công, Lệnh thiết bị được ghi nhận, Hoạt động AAA khác được ghi nhận và Thao tác Web có nhật ký audit. Chủ động tick các nhóm cần gửi. Sau khi lưu, chờ một lần monitor mới để đặt mốc ban đầu rồi tạo hoạt động thử.

Authentication PASS là kết quả xác thực thiết bị. EXEC và command authorization là trao đổi riêng. Muốn thấy lệnh, thiết bị phải gửi command accounting. Sự kiện start và stop của cùng lệnh là các bản ghi riêng. Bản cập nhật gắn ID accounting chính xác vào audit mới trong cùng giao dịch. Giữ lịch sử cũ, không đoán liên kết từ session ID hoặc thời gian cho các bản ghi thiếu ID này.

Chỉ chuyển tiếp sự kiện đã lưu. Tính năng không thấy phím gõ, nội dung màn hình, mọi lượt click Web hoặc hoạt động local trên switch không được gửi qua AAA. Web gửi các sự kiện đăng nhập/đăng xuất và quản trị có audit. Lệnh dùng lại cơ chế redaction hiện có. Heuristic này không nhận diện được mọi cú pháp secret của mọi hãng.

Tin được gom nhóm, thường tối đa tám sự kiện đang chờ mỗi chu kỳ. Con trỏ audit chỉ đi tiếp khi sự kiện đã vào hàng đợi. Khi đầy hàng đợi hoặc Slack lỗi, phần còn lại chờ trong PostgreSQL để đọc tiếp. Hệ thống nhiều sự kiện có thể tồn backlog và được báo trên trang Alerts. Lưu cấu hình đặt lại mốc ban đầu và hàng đợi. Mỗi tin có số sequence để đối chiếu audit.

Cập nhật tính năng cần khởi động lại AAA và Web để áp dụng metadata accounting trong giao dịch. Không cần migration database. Test bằng tài khoản thử, lệnh vô hại như show clock trên thiết bị phù hợp và đăng xuất/đăng nhập Web. Kiểm tra log tương ứng đã được lưu trước khi chờ tin Slack.


### Gửi hoạt động gần realtime

Worker trên host tnac-alerts.service đọc hoạt động user mỗi 3 giây. Kết quả đăng nhập, lệnh và thao tác Web có audit thường đến Slack trong khoảng 3–5 giây khi mạng và hàng đợi bình thường. Đây là mục tiêu, độ trễ có thể tăng do Slack giới hạn, tồn hàng đợi hoặc lỗi mạng. Khóa/mở khóa tài khoản cũng dùng worker 3 giây và được ưu tiên trước các tin hoạt động thường trong hàng đợi. Snapshot sức khỏe, ngưỡng tài nguyên và tổng số lần xác thực thất bại vẫn kiểm tra khoảng một phút.

Worker dùng con trỏ bền vững và hàng đợi có khóa. Luồng nhanh giữ nguyên trạng thái cảnh báo của luồng snapshot. Xem Last activity check trên Alerts để xác nhận tiến trình đọc nhanh. Khi gỡ bản cài, tắt cả tnac-alerts.service và tnac-snapshot.timer.

~~~bash
systemctl status tnac-alerts.service --no-pager
sudo journalctl -u tnac-alerts.service -n 20 --no-pager
~~~

- [Triển khai và rollback Device Syslog](DEVICE-SYSLOG.md)
