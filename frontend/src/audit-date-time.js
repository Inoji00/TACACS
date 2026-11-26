export function auditDateTimeControls({jsx, jsxs, label, value, onChange, t, endOfDay = false}) {
  const [date = '', time = endOfDay ? '23:59' : '00:00'] = value.split('T');
  const [hours, minutes] = time.split(':').map(Number);
  const period = hours < 12 ? 'AM' : 'PM';
  const hour = hours % 12 || 12;
  const pad = (number) => String(number).padStart(2, '0');
  function setTime(nextHour, nextMinute, nextPeriod) {
    onChange(date + 'T' + pad(nextHour % 12 + (nextPeriod === 'PM' ? 12 : 0)) + ':' + pad(nextMinute));
  }
  function select(name, selected, choices, change) {
    return jsx('select', {
      'aria-label': label + ' · ' + t(name),
      value: selected,
      disabled: !date,
      onChange: (event) => change(event.target.value),
      children: choices.map((choice) => jsx('option', {value: choice, children: choice}, choice)),
    });
  }
  return jsxs('div', {className: 'audit-date-time', children: [
    jsxs('label', {children: [
      label,
      jsx('input', {
        type: 'date', value: date,
        onClick: (event) => {
          try { event.currentTarget.showPicker?.(); } catch { /* Native control remains usable. */ }
        },
        onChange: (event) => onChange(event.target.value ? event.target.value + 'T' + time : ''),
      }),
    ]}),
    jsxs('div', {className: 'audit-date-time-clock', children: [
      select('Hour', hour, Array.from({length: 12}, (_, index) => index + 1), (next) => setTime(Number(next), minutes, period)),
      select('Minute', pad(minutes), Array.from({length: 60}, (_, index) => pad(index)), (next) => setTime(hour, Number(next), period)),
      select('AM/PM', period, ['AM', 'PM'], (next) => setTime(hour, minutes, next)),
    ]}),
  ]});
}

export function auditDateTimeRange({jsx, jsxs, t, since, until, onSince, onUntil}) {
  const day = 86400000;
  const instant = (value) => Date.parse(value + '+07:00');
  const duration = instant(until) - instant(since);
  const error = duration < 0 ? 'Start must precede the end.' :
    duration > 31 * day ? 'The time range cannot exceed 31 days.' : '';
  const format = (value) => {
    if (!value) return '—';
    const [date, time] = value.split('T');
    return date.split('-').reverse().join('/') + ' ' + time;
  };
  const caption = since || until ? format(since) + ' → ' + format(until) : t('Last 24 hours');
  function boundary(label, value, change, defaultTime) {
    const [date, time = defaultTime] = value.split('T');
    return jsxs('div', {className:'audit-boundary', children:[
      jsxs('label', {children:[label, jsx('input', {
        type:'date', value:date,
        onClick:event=>{ try { event.currentTarget.showPicker?.(); } catch {} },
        onChange:event=>change(event.target.value ? event.target.value + 'T' + time : ''),
      })]}),
      jsx('input', {
        type:'text', inputMode:'numeric', maxLength:5, defaultValue:time,
        'aria-label':label + ' HH:mm', pattern:'(?:[01][0-9]|2[0-3]):[0-5][0-9]',
        disabled:!date, required:Boolean(date),
        onBlur:event=>{ if (event.currentTarget.validity.valid && date) change(date + 'T' + event.target.value); },
        onKeyDown:event=>{ if (event.key === 'Enter') { event.preventDefault(); event.currentTarget.blur(); } },
      }, value),
    ]});
  }
  function choose(minutes) {
    const end = Math.floor(Date.now()/60000)*60000;
    const local = (time) => new Date(time + 420*60000).toISOString().slice(0,16);
    onSince(local(end - minutes*60000));
    onUntil(local(end));
  }
  function close(details) {
    details.open = false;
    details.querySelector('summary').focus();
  }
  return jsxs('details', {className:'audit-time-range',
    onKeyDown:event=>{
      if (event.key !== 'Escape' || !event.currentTarget.open) return;
      event.stopPropagation();
      close(event.currentTarget);
    },
    children:[
      jsxs('summary', {children:[
        jsx('span',{children:t('Time range (UTC+07:00)')}),
        jsx('strong',{title:caption,children:caption}),
      ]}),
      jsxs('div',{className:'audit-time-panel',children:[
        jsx('div',{className:'audit-presets',children:[
          ['15 min',15],['1 h',60],['24 h',1440],['7 d',10080],['31 d',44640],
        ].map(([label,minutes])=>jsx('button',{type:'button',className:'secondary',onClick:()=>choose(minutes),children:t(label)},label))}),
        jsxs('div',{className:'audit-boundaries',children:[
          boundary(t('From (UTC+07:00)'),since,onSince,'00:00'),
          boundary(t('To (UTC+07:00)'),until,onUntil,'23:59'),
        ]}),
        error && jsx('p',{className:'error',role:'alert',children:t(error)}),
        jsx('button',{type:'button',disabled:Boolean(error),children:t('Apply'),onClick:event=>{
          const details = event.currentTarget.closest('details');
          const invalid = [...details.querySelectorAll('input')].find(input=>!input.checkValidity());
          if (invalid) { invalid.reportValidity(); return; }
          close(details);
        }}),
      ]}),
    ],
  });
}
