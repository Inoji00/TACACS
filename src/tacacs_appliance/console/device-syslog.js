(() => {
  const severity = ['Emergency','Alert','Critical','Error','Warning','Notice','Informational','Debug'];
  const severityVi = ['Khẩn cấp','Cảnh báo tức thời','Nghiêm trọng','Lỗi','Cảnh báo','Chú ý','Thông tin','Gỡ lỗi'];

  globalThis.TnacDeviceSyslog = function DeviceSyslog({hooks, jsx, jsxs, vietnamese}) {
    const t = (en, vi) => vietnamese ? vi : en;
    const [result, setResult] = hooks.useState(null);
    const [query, setQuery] = hooks.useState('');
    const [busy, setBusy] = hooks.useState(false);
    const [error, setError] = hooks.useState(false);
    const [invalid, setInvalid] = hooks.useState(false);
    const [profiles, setProfiles] = hooks.useState({});
    const [editing, setEditing] = hooks.useState(null);
    const [saving, setSaving] = hooks.useState(false);
    const [profileStatus, setProfileStatus] = hooks.useState('');
    const types = {switch: 'Switch', router: 'Router', firewall: 'Firewall',
      unclassified: t('Unclassified', 'Chưa phân loại')};
    const profileEndpoint = '/api/device-syslog/profiles';
    const profileError = t('Unable to update device profiles.', 'Không cập nhật được profile thiết bị.');

    hooks.useEffect(() => {
      const request = new AbortController();
      fetch(profileEndpoint, {cache: 'no-store', signal: request.signal})
        .then(response => {
          if (!response.ok) throw new Error('profile request failed');
          return response.json();
        })
        .then(data => setProfiles(data.profiles))
        .catch(error => {
          if (error.name !== 'AbortError') setProfileStatus('failed');
        });
      return () => request.abort();
    }, []);

    async function updateProfile(values) {
      setSaving(true);
      setProfileStatus('');
      try {
        const session = await fetch('/api/session', {cache: 'no-store'});
        if (!session.ok) throw new Error('session request failed');
        const {csrf_token} = await session.json();
        const response = await fetch(profileEndpoint, {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf_token},
          body: JSON.stringify(values),
        });
        if (!response.ok) throw new Error('profile update failed');
        const data = await response.json();
        setProfiles(data.profiles);
        setEditing(null);
        setResult(null);
        setProfileStatus('saved');
      } catch {
        setProfileStatus('failed');
      } finally {
        setSaving(false);
      }
    }

    function saveProfile(event) {
      event.preventDefault();
      const values = Object.fromEntries(new FormData(event.currentTarget));
      void updateProfile({...values, action: 'save'});
    }

    function removeProfile(source) {
      if (window.confirm(t('Remove this label and keep its log records?',
          'Gỡ nhãn này và giữ các bản ghi log?'))) {
        void updateProfile({action: 'remove', source});
      }
    }

    function profileOptions(keys) {
      return keys.map(key => jsx('option', {value: key, children: types[key]}, key));
    }


    async function load(filters, before) {
      const params = new URLSearchParams(filters);
      if (before) params.set('before', String(before));
      setBusy(true);
      setError(false);
      try {
        const response = await fetch('/api/device-syslog?' + params, {cache:'no-store'});
        if (!response.ok) throw new Error('syslog request failed');
        const next = await response.json();
        setResult(next);
      } catch {
        setError(true);
      } finally {
        setBusy(false);
      }
    }

    function filter(event) {
      event.preventDefault();
      const params = new URLSearchParams();
      setInvalid(false);
      for (const [key, value] of new FormData(event.currentTarget)) {
        if (!value) continue;
        params.set(key, key === 'since' || key === 'until' ? new Date(value).toISOString() : value);
      }
      if (params.has('since') && params.has('until') && params.get('since') > params.get('until')) {
        setInvalid(true);
        return;
      }
      setQuery(params.toString());
      void load(params);
    }

    const field = (name, label, type = 'text') => jsxs('label', {children:[
      label, jsx('input', {name, type, maxLength:256}),
    ]});
    const labels = vietnamese ? severityVi : severity;
    const headings = [t('Received','Thời điểm nhận'), t('Source IP','IP nguồn'),
      t('Device','Thiết bị'), t('Severity','Mức độ'), t('Message','Nội dung')];
    return jsxs('section', {className:'card', children:[
      jsx('h2',{children:t('Device Syslog','Syslog thiết bị')}),
      jsx('p',{className:'hint',children:t('Search the last 30 days by collector receive time. Time filters use your browser’s local time.',
        'Tra cứu 30 ngày gần nhất theo lúc máy chủ nhận. Bộ lọc giờ dùng múi giờ của trình duyệt.')}),
      jsxs('details',{className:'device-syslog-profiles', children:[
        jsx('summary',{children:t('Manage device profiles','Quản lý profile thiết bị')}),
        jsx('p',{className:'hint',children:t('Labels apply by source IP to all retained events.',
          'Nhãn áp dụng theo IP nguồn cho tất cả bản ghi còn lưu.')}),
        jsxs('form',{className:'list-toolbar device-syslog-filters', onSubmit:saveProfile, children:[
          jsxs('label',{children:[t('Source IP','IP nguồn'),jsx('input',{
            name:'source', required:true, maxLength:15, readOnly:Boolean(editing), defaultValue:editing?.source || '',
          })]}),
          jsxs('label',{children:[t('Device name','Tên thiết bị'),jsx('input',{
            name:'name', required:true, maxLength:80, defaultValue:editing?.name || '',
          })]}),
          jsxs('label',{children:[t('Profile','Profile'),jsx('select',{
            name:'profile', defaultValue:editing?.profile || 'switch',
            children:profileOptions(['switch','router','firewall']),
          })]}),
          jsx('button',{disabled:saving || busy,children:t('Save profile','Lưu profile')}),
          editing && jsx('button',{type:'button',className:'secondary',disabled:saving,
            onClick:()=>setEditing(null),children:t('Cancel edit','Hủy sửa')}),
        ]},editing?.source || 'new'),
        jsx('p',{role:profileStatus === 'failed' ? 'alert' : 'status',
          children:profileStatus === 'failed' ? profileError : profileStatus === 'saved'
            ? t('Profiles updated. Search again to apply the change.',
                'Đã cập nhật profile. Bấm Tìm kiếm để áp dụng thay đổi.') : ''}),
        Object.keys(profiles).length > 0 && jsx('ul',{className:'device-syslog-profile-list',children:
          Object.entries(profiles).map(([source,item])=>jsxs('li',{children:[
            jsx('span',{children:item.name+' · '+source+' · '+types[item.profile]}),
            jsxs('div',{className:'actions',children:[
              jsx('button',{type:'button',className:'secondary',disabled:saving,
                onClick:()=>setEditing({...item,source}),children:t('Edit','Sửa')}),
              jsx('button',{type:'button',className:'secondary',disabled:saving || busy,
                onClick:()=>removeProfile(source),children:t('Remove','Gỡ')}),
            ]}),
          ]},source)),
        }),
      ]}),
      jsxs('form',{className:'list-toolbar device-syslog-filters', onSubmit:filter, children:[
        field('source', t('Source IP','IP nguồn')),
        jsxs('label',{children:[t('Profile','Profile'),jsx('select',{name:'profile',children:[
          jsx('option',{value:'',children:t('All profiles','Tất cả profile')},'all'),
          ...profileOptions(['switch','router','firewall','unclassified']),
        ]})]}),
        field('since', t('From','Từ'), 'datetime-local'),
        field('until', t('To','Đến'), 'datetime-local'),
        jsxs('label',{children:[t('Severity','Mức độ'),jsx('select',{name:'severity',children:[
          jsx('option',{value:'',children:t('All severities','Tất cả mức độ')},'all'),
          ...labels.map((label,i)=>jsx('option',{value:i,children:i+' · '+label},i)),
        ]})]}),
        field('q',t('Message contains','Nội dung chứa')),
        jsx('button',{disabled:busy || saving,children:t('Search','Tìm kiếm')}),
      ]}),
      invalid && jsx('p',{role:'alert',children:t('From must be before To.','Thời điểm bắt đầu phải trước thời điểm kết thúc.')}),
      error && jsx('p',{role:'alert',children:t('Unable to load Syslog. Check access and filters and try again.','Không tải được Syslog. Kiểm tra quyền và bộ lọc rồi thử lại.')}),
      result && !result.collector_ready && jsx('p',{role:'status',children:t('The Syslog store is not ready.','Kho Syslog chưa sẵn sàng.')}),
      result?.collector_ready && !result.items.length && jsx('p',{role:'status',children:t('No matching events.','Không có sự kiện phù hợp.')}),
      result?.items.length > 0 && jsx('div',{className:'device-syslog-table',children:jsxs('table',{children:[
        jsx('thead',{children:jsx('tr',{children:headings.map(label=>jsx('th',{scope:'col',children:label},label))})}),
        jsx('tbody',{children:result.items.map(row=>jsxs('tr',{children:[
          jsx('td',{children:new Date(row.received).toLocaleString(vietnamese?'vi-VN':'en',{hourCycle:'h23'})}),
          jsx('td',{children:row.source}),
          jsx('td',{title:row.name ? row.name+' · '+types[row.profile] : types.unclassified,
            children:row.name ? row.name+' · '+types[row.profile] : types.unclassified}),
          jsx('td',{children:row.severity == null ? '—' : row.severity+' · '+labels[row.severity]}),
          jsx('td',{children:jsx('div',{className:'device-syslog-message',tabIndex:0,
            children:row.message.replace(/\r\n|[\r\n]/g,' ↵ ')})}),
        ]},row.id))}),
      ]})}),
      result?.next_before && jsx('button',{type:'button',className:'secondary',disabled:busy,
        onClick:()=>void load(query,result.next_before),children:t('Older events','Log cũ hơn')}),
      result && jsx('button',{type:'button',className:'secondary',disabled:busy,
        onClick:()=>void load(query),children:t('Latest events','Log mới nhất')}),
    ]});
  };
})();
