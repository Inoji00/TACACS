# Connect a Cisco switch to TNAC+ / Kết nối switch Cisco với TNAC+

This example uses Cisco IOS-style CLI. Verify each command for your switch model, OS and firmware. Command availability, syntax and behavior may differ. / Ví dụ dùng CLI kiểu Cisco IOS. Kiểm tra từng lệnh theo model, hệ điều hành và firmware của switch. Cú pháp, tính năng và hành vi có thể khác.

## TNAC+ Web Admin / Giao diện TNAC+

1. **Users & Identity → Users → Create device user.** Create `lab-user` in identity group `lab-operators`. / Tạo tài khoản thiết bị `lab-user` trong nhóm `lab-operators`.
2. **Network Resources → Devices.** Add and enable `SW-EXAMPLE-01` using TACACS+. Enter the switch source IP as seen by TNAC+, for example `198.51.100.10`, and a private shared key. / Thêm và bật thiết bị TACACS+. Nhập IP nguồn switch mà TNAC+ thực sự thấy và khóa dùng chung riêng.
3. **Device access mappings.** Map `lab-operators` to EXEC privilege 1 on this device. / Ánh xạ nhóm `lab-operators` với privilege EXEC 1 trên thiết bị này.

## Prerequisites / Điều kiện trước khi cấu hình

- Replace all example addresses. `192.0.2.20` is the TNAC+ server, `198.51.100.10` is the switch management address in this example, and `<SHARED_KEY>` is the same private key on both sides. / Thay toàn bộ IP mẫu. `192.0.2.20` là máy chủ TNAC+, `198.51.100.10` là IP quản trị switch trong ví dụ, và hai bên dùng cùng một khóa riêng.
- Configure the management interface or SVI, routing and VRF as required. Permit switch-to-TNAC+ TCP/49 through the firewalls and ACLs. Confirm the observed source IP. HTTPS/8443 is for Web Admin. / Cấu hình cổng quản trị hoặc SVI, định tuyến và VRF phù hợp. Cho phép switch tới TNAC+ qua TCP/49 và xác nhận IP nguồn. HTTPS/8443 dùng cho Web Admin.
- Configure SSH, its host keys, the VTY transport and the management ACL for your platform. Create and verify a recovery account on the switch, test independent local console/OOB access, back up the configuration, and keep the current session open. / Thiết lập SSH, khóa host, transport của VTY và ACL quản trị theo thiết bị. Tạo và thử tài khoản cứu hộ trên switch, kiểm tra console/OOB local độc lập, sao lưu cấu hình và giữ phiên hiện tại.
- Inspect existing defaults, named lists and console/VTY bindings before applying this global default example. Use a lab switch or an approved maintenance window. / Kiểm tra danh sách mặc định, danh sách theo tên và binding console/VTY trước khi áp dụng ví dụ toàn cục này. Thử trên switch lab hoặc trong cửa sổ bảo trì.

| Read-only CLI / Lệnh chỉ đọc | English | Tiếng Việt |
|---|---|---|
| `show version` | Identify the platform and firmware. | Xác định thiết bị và firmware. |
| `show running-config \| include ^aaa` | Review global AAA lists and console authorization. | Xem danh sách AAA toàn cục và authorization console. |
| `show running-config \| section ^line con` | Review console bindings. | Xem binding của console. |
| `show running-config \| section ^line vty` | Review VTY bindings, SSH and ACLs. | Xem binding VTY, SSH và ACL. |
| `show users` | Identify active sessions. | Xác định các phiên đang mở. |

## Example CLI / Cấu hình ví dụ

The server declaration below uses legacy IOS syntax. Where the switch uses named `tacacs server` objects, declare the address and key in that object and reference it by name in the group using the syntax supported by your firmware. If you need to pin the source interface, check whether your platform supports a group-level or global setting, and assess its impact on existing groups. / Khai báo server dưới đây dùng cú pháp IOS cũ. Nếu switch dùng đối tượng `tacacs server` theo tên, khai báo IP và khóa trong đối tượng rồi tham chiếu tên trong nhóm bằng cú pháp firmware hỗ trợ. Nếu cần cố định interface nguồn, kiểm tra tùy chọn theo nhóm hoặc toàn cục và tác động tới nhóm hiện có.

```text
configure terminal
aaa new-model
tacacs-server host 192.0.2.20 key <SHARED_KEY>
aaa group server tacacs+ TACACS-EXAMPLE
 server 192.0.2.20
exit
aaa authentication login default group TACACS-EXAMPLE local
aaa authorization exec default group TACACS-EXAMPLE local
aaa accounting exec default start-stop group TACACS-EXAMPLE
aaa accounting commands 1 default start-stop group TACACS-EXAMPLE
aaa accounting system default start-stop group TACACS-EXAMPLE
aaa session-id common
end
```

| CLI | English | Tiếng Việt |
|---|---|---|
| `configure terminal` | Enter global configuration. | Vào chế độ cấu hình toàn cục. |
| `aaa new-model` | Enable AAA globally if it is not already enabled. | Bật AAA toàn cục nếu chưa bật. |
| `tacacs-server host … key …` | Set the TACACS+ address and shared key. | Khai báo IP TACACS+ và khóa dùng chung. |
| `aaa group server tacacs+ TACACS-EXAMPLE` | Open a named server group. | Tạo và vào nhóm máy chủ theo tên. |
| `server 192.0.2.20` | Add the declared server to that group. | Thêm server đã khai báo vào nhóm. |
| `exit` | Leave server-group configuration. | Thoát chế độ cấu hình nhóm. |
| `aaa authentication login default group TACACS-EXAMPLE local` | Try TACACS+ for login first, then the local user database on error or no response. | Xác thực qua TACACS+ trước, dùng tài khoản local khi nhóm lỗi hoặc không phản hồi. |
| `aaa authorization exec default group TACACS-EXAMPLE local` | Use TACACS+ for shell authorization, with local authorization on error or no response. | Cấp quyền vào shell qua TACACS+, dự phòng cấp quyền local khi lỗi hoặc không phản hồi. |
| `aaa accounting exec default start-stop group TACACS-EXAMPLE` | Send EXEC session start and stop records. | Gửi bản ghi bắt đầu và kết thúc phiên EXEC. |
| `aaa accounting commands 1 default start-stop group TACACS-EXAMPLE` | Record commands at level 1. Configure one line per additional level you need, such as 2–15. | Ghi lệnh ở level 1. Thêm một dòng cho từng mức cần ghi, ví dụ từ 2 đến 15. |
| `aaa accounting system default start-stop group TACACS-EXAMPLE` | Send switch system accounting events. | Gửi sự kiện accounting cấp hệ thống. |
| `aaa session-id common` | Request common AAA session identification on the switch. Correlate records using user, device and time as well. | Yêu cầu switch dùng định danh phiên AAA chung. Khi đối chiếu, xem thêm user, thiết bị và thời gian. |
| `end` | Return to privileged EXEC. | Thoát về privileged EXEC. |

**VTY and console / VTY và console.** The example uses default lists. Check whether each VTY range has explicit named bindings and retain its SSH, ACL and timeout settings. Check which login list the console inherits. If `aaa authorization console` is already configured, it enables AAA authorization on console, so verify independent local EXEC authorization as well. If `aaa authorization config-commands` is present, it governs configuration commands when command authorization applies. Review any existing `aaa authorization commands` lists and their recovery behavior separately. / Ví dụ dùng danh sách mặc định. Kiểm tra từng dải VTY có gắn danh sách theo tên hay không và giữ SSH, ACL, timeout hiện có. Kiểm tra console kế thừa danh sách login nào. Nếu đã có `aaa authorization console`, nó bật áp dụng AAA authorization trên console, nên cần kiểm tra cả quyền EXEC local độc lập. Nếu có `aaa authorization config-commands`, lệnh điều khiển việc kiểm tra quyền lệnh cấu hình khi command authorization được áp dụng. Rà riêng các danh sách `aaa authorization commands` hiện có và đường cứu hộ tương ứng.

## Verify and save / Nghiệm thu và lưu

| CLI | English | Tiếng Việt |
|---|---|---|
| `ssh lab-user@198.51.100.10` | Start a fresh SSH session from the management client. | Mở phiên SSH mới từ máy quản trị. |
| `show privilege` | Check EXEC privilege against the device mapping. | Đối chiếu privilege EXEC với mapping trên TNAC+. |
| `show clock` | Run a permitted read-only command and check its accounting record. | Chạy lệnh chỉ đọc được phép và kiểm tra bản ghi accounting. |
| `exit` | Close the test session and look for `exec / stop`. | Đóng phiên thử và tìm bản ghi `exec / stop`. |
| `copy running-config startup-config` | Save after the TACACS+ and local fallback tests pass. | Lưu sau khi thử thành công TACACS+ và fallback local. |

In TNAC+, verify authentication `pass`, EXEC authorization `allow`, command accounting and EXEC stop. A wrong password should yield a rejection when TACACS+ responds. During an approved lab window, keep verified console/OOB available, isolate only the lab path to the TACACS+ group, and start a fresh SSH session with the switch-local recovery account. Check shell access and a permitted command, restore the lab path, and test TACACS+ again. Explicit authentication failure or authorization denial ends the respective request. / Trên TNAC+, kiểm tra xác thực `pass`, cấp quyền EXEC `allow`, log lệnh và EXEC stop. Sai mật khẩu phải bị từ chối khi TACACS+ phản hồi. Trong cửa sổ lab đã duyệt, giữ console/OOB đã thử, cô lập riêng đường lab tới nhóm TACACS+ rồi mở phiên SSH mới bằng tài khoản cứu hộ local. Kiểm tra vào shell và chạy lệnh được phép, sau đó khôi phục đường lab và thử lại TACACS+. Khi server trả lỗi xác thực hoặc từ chối quyền rõ ràng, IOS dừng yêu cầu tương ứng.

| Symptom / Triệu chứng | Check / Kiểm tra |
|---|---|
| No AAA event / Không có log AAA | Confirm VTY uses the intended list, TCP/49 is reachable, and TNAC+ sees the registered source IP. / Kiểm tra danh sách VTY, TCP/49 và IP nguồn đã đăng ký. |
| Request arrives but authentication fails / Có yêu cầu nhưng xác thực lỗi | Check the shared key, username, password and account status. / Kiểm tra khóa dùng chung, tài khoản, mật khẩu và trạng thái khóa. |
| Authentication passes but EXEC is denied / Xác thực đạt nhưng EXEC bị từ chối | Check device enablement and the user's identity-group mapping. / Kiểm tra thiết bị đã bật và mapping của nhóm user. |
| No command record / Thiếu log lệnh | Check accounting at the executed command's privilege level and line binding. / Kiểm tra accounting theo privilege của lệnh và binding của line. |

[Cisco IOS AAA command reference / Tham chiếu lệnh AAA của Cisco](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-cr-book/sec-cr-a1.html)
