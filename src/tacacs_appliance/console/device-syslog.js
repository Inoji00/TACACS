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
      t('Severity','Mức độ'), t('Message','Nội dung')];
    return jsxs('section', {className:'card', children:[
      jsx('h2',{children:t('Device Syslog','Syslog thiết bị')}),
      jsx('p',{className:'hint',children:t('Search the last 30 days by collector receive time. Time filters use your browser’s local time.',
        'Tra cứu 30 ngày gần nhất theo lúc máy chủ nhận. Bộ lọc giờ dùng múi giờ của trình duyệt.')}),
      jsxs('form',{className:'list-toolbar device-syslog-filters', onSubmit:filter, children:[
        field('source', t('Source IP','IP nguồn')),
        field('since', t('From','Từ'), 'datetime-local'),
        field('until', t('To','Đến'), 'datetime-local'),
        jsxs('label',{children:[t('Severity','Mức độ'),jsx('select',{name:'severity',children:[
          jsx('option',{value:'',children:t('All severities','Tất cả mức độ')},'all'),
          ...labels.map((label,i)=>jsx('option',{value:i,children:i+' · '+label},i)),
        ]})]}),
        field('q',t('Message contains','Nội dung chứa')),
        jsx('button',{disabled:busy,children:t('Search','Tìm kiếm')}),
      ]}),
      invalid && jsx('p',{role:'alert',children:t('From must be before To.','Thời điểm bắt đầu phải trước thời điểm kết thúc.')}),
      error && jsx('p',{role:'alert',children:t('Unable to load Syslog. Check access and filters and try again.','Không tải được Syslog. Kiểm tra quyền và bộ lọc rồi thử lại.')}),
      result && !result.collector_ready && jsx('p',{role:'status',children:t('The Syslog store is not ready.','Kho Syslog chưa sẵn sàng.')}),
      result?.collector_ready && !result.items.length && jsx('p',{role:'status',children:t('No matching events.','Không có sự kiện phù hợp.')}),
      result?.items.length > 0 && jsx('div',{className:'device-syslog-table',children:jsxs('table',{children:[
        jsx('thead',{children:jsx('tr',{children:headings.map(label=>jsx('th',{scope:'col',children:label},label))})}),
        jsx('tbody',{children:result.items.map(row=>jsxs('tr',{children:[
          jsx('td',{children:new Date(row.received).toLocaleString(vietnamese?'vi-VN':'en')}),
          jsx('td',{children:row.source}),
          jsx('td',{children:row.severity == null ? '—' : row.severity+' · '+labels[row.severity]}),
          jsx('td',{className:'device-syslog-message',children:row.message}),
        ]},row.id))}),
      ]})}),
      result?.next_before && jsx('button',{type:'button',className:'secondary',disabled:busy,
        onClick:()=>void load(query,result.next_before),children:t('Older events','Log cũ hơn')}),
      result && jsx('button',{type:'button',className:'secondary',disabled:busy,
        onClick:()=>void load(query),children:t('Latest events','Log mới nhất')}),
    ]});
  };
})();
