// Static help for the Devices page. All addresses and credentials are examples.
(() => {
  const cli = {
    inspect: 'show version\nshow running-config | include ^aaa\nshow running-config | section ^line con\nshow running-config | section ^line vty\nshow users',
    configure: [
      'configure terminal',
      'tacacs-server host 192.0.2.20 key <SHARED_KEY>',
      'aaa group server tacacs+ TACACS-EXAMPLE',
      ' server 192.0.2.20',
      'exit',
      'aaa authentication login default group TACACS-EXAMPLE local',
      'aaa authorization exec default group TACACS-EXAMPLE local',
      'aaa accounting exec default start-stop group TACACS-EXAMPLE',
      ...Array.from({length: 15}, (_, level) =>
        `aaa accounting commands ${level + 1} default start-stop group TACACS-EXAMPLE`),
      'aaa accounting system default start-stop group TACACS-EXAMPLE',
      'aaa session-id common',
      'end',
    ].join('\n'),
    optional: 'configure terminal\naaa authorization console\naaa authorization config-commands\nend',
    verify: 'show privilege\nshow clock\nexit',
  };
  const messages = {
    en: {
      title: 'Connection guide', close: 'Close', copy: 'Copy CLI', copied: 'Copied.',
      failed: 'Clipboard unavailable. Select the commands and copy them manually.',
      intro: 'Cisco IOS-style example. Check syntax for your model, OS, and firmware. Replace example addresses and <SHARED_KEY> with your deployment values.',
      setup: '1. Register the switch in TNAC+',
      setupText: 'Create a device user and assign an identity group. Add the switch using its actual TACACS+ source IP and shared key. Enable it and map the group to EXEC privilege 1 for this example.',
      configure: '2. Prepare and configure Cisco AAA',
      prepare: 'Verify switch-to-server TCP/49, routing or VRF, SSH keys, VTY ACLs and an independent local console recovery account. Keep your current session open and check the active AAA lists. Enable aaa new-model only if needed and after verifying recovery access.',
      configureText: 'This legacy syntax uses 192.0.2.20 as the server. On platforms using tacacs server objects, use the supported named server syntax. Default lists can affect existing access. Check console/VTY bindings before applying. Login and EXEC fall back to local accounts on error or no response. An explicit rejection ends the request.',
      optional: 'Authorization options in the reference configuration',
      optionalText: 'Apply these only after checking your policy. The first applies AAA authorization to console access. Verify independent local console recovery. The second governs authorization of configuration commands when command authorization is in use.',
      accounting: 'EXEC accounting records session start and stop. Command accounting covers levels 1–15. System accounting records switch events. The common session ID setting helps correlate records on IOS.',
      verify: '3. Verify SSH and accounting',
      verifyText: 'Open a new SSH session with the test user. Check authentication pass, EXEC authorization allow, command records and EXEC stop in TNAC+. Verify local fallback during an approved lab outage while keeping console access. Restore connectivity and validate TACACS+ again before saving.',
      full: 'Read the full bilingual guide on GitHub',
    },
    vi: {
      title: 'Hướng dẫn kết nối', close: 'Đóng', copy: 'Sao chép CLI', copied: 'Đã sao chép.',
      failed: 'Không dùng được clipboard. Hãy chọn và sao chép lệnh thủ công.',
      intro: 'Ví dụ dùng CLI kiểu Cisco IOS. Kiểm tra cú pháp theo model, hệ điều hành và firmware. Thay IP mẫu và <SHARED_KEY> bằng giá trị triển khai.',
      setup: '1. Đăng ký switch trên TNAC+',
      setupText: 'Tạo tài khoản thiết bị và gán nhóm định danh. Thêm switch bằng IP nguồn TACACS+ thực tế và khóa dùng chung. Bật thiết bị rồi gán nhóm vào privilege EXEC 1 theo ví dụ này.',
      configure: '2. Chuẩn bị và cấu hình AAA trên Cisco',
      prepare: 'Kiểm tra TCP/49 từ switch, định tuyến hoặc VRF, khóa SSH, ACL trên VTY và tài khoản cứu hộ qua console local độc lập. Giữ phiên hiện tại và rà danh sách AAA đang dùng. Chỉ bật aaa new-model khi cần và sau khi thử đường cứu hộ.',
      configureText: 'Cú pháp cũ dùng 192.0.2.20 làm IP máy chủ. Nếu firmware dùng đối tượng tacacs server, chọn cú pháp theo tên phù hợp. Danh sách mặc định có thể ảnh hưởng truy cập hiện tại. Rà binding console/VTY trước khi áp dụng. Login và EXEC dùng local khi server lỗi hoặc không phản hồi. Server trả từ chối thì yêu cầu dừng.',
      optional: 'Tùy chọn authorization trong cấu hình tham chiếu',
      optionalText: 'Chỉ áp dụng sau khi rà chính sách. Dòng đầu áp dụng AAA authorization trên console. Hãy thử đường cứu hộ console local độc lập. Dòng thứ hai điều khiển kiểm tra quyền lệnh cấu hình khi đang dùng command authorization.',
      accounting: 'EXEC accounting ghi mở và đóng phiên. Command accounting ghi các mức 1–15. System accounting ghi sự kiện switch. Session ID chung giúp đối chiếu bản ghi bên IOS.',
      verify: '3. Kiểm tra SSH và accounting',
      verifyText: 'Mở phiên SSH mới bằng tài khoản thử. Trên TNAC+, kiểm tra xác thực pass, EXEC allow, bản ghi lệnh và EXEC stop. Thử fallback local trong cửa sổ lab được duyệt và giữ console. Nối lại máy chủ rồi thử TACACS+ trước khi lưu cấu hình.',
      full: 'Xem hướng dẫn song ngữ đầy đủ trên GitHub',
    },
  };

  globalThis.TnacConnectionGuide = function ConnectionGuide({jsx, jsxs, fragment, language}) {
    const t = messages[language] || messages.en;
    function commandBlock(commands) {
      return jsxs('div', {className: 'connection-guide-cli', children: [
        jsx('pre', {tabIndex: 0, children: jsx('code', {children: commands})}),
        jsxs('div', {className: 'actions', children: [
          jsx('button', {type: 'button', className: 'secondary', children: t.copy,
            onClick: async event => {
              const status = event.currentTarget.nextElementSibling;
              try {
                await navigator.clipboard.writeText(commands);
                status.textContent = t.copied;
              } catch {
                status.textContent = t.failed;
              }
            }}),
          jsx('span', {role: 'status'}),
        ]}),
      ]});
    }
    return jsxs(fragment, {children: [
      jsx('button', {type: 'button', className: 'secondary', 'aria-haspopup': 'dialog',
        onClick: event => {
          const dialog = event.currentTarget.nextElementSibling;
          for (const status of dialog.querySelectorAll('[role="status"]')) status.textContent = '';
          dialog.showModal();
        }, children: t.title}),
      jsxs('dialog', {className: 'connection-guide', 'aria-labelledby': 'connection-guide-title', children: [
        jsxs('div', {className: 'connection-guide-header', children: [
          jsx('h2', {id: 'connection-guide-title', children: t.title}),
          jsx('button', {type: 'button', className: 'secondary', autoFocus: true,
            onClick: event => event.currentTarget.closest('dialog').close(), children: t.close}),
        ]}),
        jsx('p', {children: t.intro}),
        jsx('h3', {children: t.setup}),
        jsx('p', {children: t.setupText}),
        jsx('h3', {children: t.configure}),
        jsx('p', {children: t.prepare}),
        commandBlock(cli.inspect),
        jsx('p', {children: t.configureText}),
        commandBlock(cli.configure),
        jsx('p', {children: t.accounting}),
        jsx('h3', {children: t.optional}),
        jsx('p', {children: t.optionalText}),
        commandBlock(cli.optional),
        jsx('h3', {children: t.verify}),
        jsx('p', {children: t.verifyText}),
        commandBlock(cli.verify),
        jsx('p', {children: jsx('a', {
          href: 'https://github.com/Inoji00/TACACS/blob/main/CISCO-AAA.md',
          target: '_blank', rel: 'noopener noreferrer', children: t.full,
        })}),
      ]}),
    ]});
  };
})();
