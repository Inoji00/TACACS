# Chạy lại kiểm thử và quét image

[English](TESTING.md) · **Tiếng Việt**

[Workflow Tests and image security](https://github.com/Inoji00/TACACS/actions/workflows/ci.yml) chạy khi push vào `main`, tạo pull request hoặc bấm chạy thủ công. Đối chiếu **đúng commit** cần kiểm tra; kết quả cũ không chứng minh source hay image mới đã đạt. CI không dùng VM đang vận hành, webhook Slack hay cơ sở dữ liệu của người dùng.

## Chạy từ checkout sạch

Cần Linux, Python 3.12+, Docker Engine có Compose v2 và Node.js 22 có npm. Cần Internet để cài dependency, tải image nền và cơ sở dữ liệu CVE. Tài khoản chạy phải có quyền dùng Docker. Nên dùng máy dùng một lần cho integration test.

```bash
git clone https://github.com/Inoji00/TACACS.git
cd TACACS
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
python scripts/run_tests.py --report artifacts/python.json
cd tests/ui
npm ci --ignore-scripts
npm test
cd ../..
```

Lượt Python này có kiểm tra socket/loopback và TLS thật trên Linux. Bài cần PostgreSQL sẽ ghi rõ skip khi chưa có database dùng một lần; skip không tính là pass. Test UI đọc và render **bundle thực sự được đóng gói**, kiểm tra Slack Anh/Việt, escape đầu vào, ẩn webhook và điều hướng Users. Đây chưa phải nghiệm thu trực quan bằng trình duyệt.

## Image runtime và PostgreSQL thật

```bash
docker build --pull -t tnac:ci .
docker build --pull -f Dockerfile.postgres -t tnac-postgres:ci .
mkdir -p artifacts/integration
chmod 0777 artifacts/integration
python scripts/test_postgres.py --linux --full --image tnac:ci \
  --postgres-image tnac-postgres:ci --report artifacts/integration/postgres.json
python scripts/test_compose.py --admin --image tnac:ci --postgres-image tnac-postgres:ci
```

Chỉ thư mục bằng chứng vừa tạo được mở quyền ghi cho container test không chạy root; không áp quyền này lên secret hay trạng thái triển khai. Runner tự tạo mật khẩu ngẫu nhiên, container/network/volume có tên riêng, database và schema riêng; chạy migrations cùng kiểm tra quyền database, identity/lockout, session, policy và audit rồi dọn instance test. Không đọc DSN triển khai. Compose smoke kiểm tra one-shot initializer, TCP/49 readiness, Web Admin trực tiếp qua TLS 1.3, từ chối session vô danh và cách ly mount credential. Không thay thế nghiệm thu switch thật, CA công cộng, đường proxy đang triển khai hoặc gửi Slack thực tế.

`tests/` còn có parser/framing, challenge/sequence AUTHEN, authorization allow/deny, accounting bền vững và che dữ liệu, CSRF/session/RBAC, checksum migrations, phạm vi thiết bị/log và hàng đợi/retry cảnh báo. Bài mock và integration PostgreSQL thật được tách theo module. Số bài pass không phải chứng nhận mọi hãng/firmware.

## Trivy và điều kiện chặn

CI tải Trivy **0.76.2** từ release chính thức, kiểm tra SHA-256 của archive. Actions được chốt theo commit SHA, quyền repository chỉ đọc và không cần secret triển khai.

Sau khi cài đúng phiên bản Trivy, quét đúng hai image vừa build:

```bash
trivy image --scanners vuln --timeout 10m --format json --output artifacts/trivy-tnac.json tnac:ci
trivy image --scanners vuln --timeout 10m --format json --output artifacts/trivy-postgres.json tnac-postgres:ci
python scripts/check_trivy.py artifacts/trivy-tnac.json artifacts/trivy-postgres.json
```

Gate thất bại nếu có **HIGH hoặc CRITICAL**, kể cả chưa có bản vá; báo cáo thiếu/sai cũng thất bại. Không dùng `--ignore-unfixed`, ignore file hay thay quét image bằng filesystem xuất ra. Vì vậy phát hiện `gosu` từ layer cũ vẫn được thể hiện dù đường dẫn cuối đã thay thế. Test chức năng đạt không làm kết quả CVE thất bại trở thành đạt. Kết quả có thể thay đổi theo dữ liệu CVE và image nền.

Mở lần chạy workflow → **Artifacts**, tải `regression-<commit>` và `images-and-security-<commit>`. Các gói lưu 30 ngày gồm log, JSON tên/kết quả từng bài, image inspection, commit source, phiên bản Docker/Trivy và báo cáo CVE JSON/text đầy đủ. Build/tải scanner/quét lỗi là kiểm tra thất bại, không phải báo cáo sạch. Lưu riêng nếu cần giữ lâu hơn. Tag/ZIP `v1.1.0` bất biến được xuất bản trước khi bổ sung CI; clone `main` hoặc đúng commit mới để chạy các kiểm tra này.
