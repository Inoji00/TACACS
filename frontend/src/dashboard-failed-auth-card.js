export function dashboardFailedAuthCard({jsx, jsxs, t, language, data, formatTime, onViewLogs}) {
  const summary = data?.failure_summary;
  const rows = data?.failures ?? [];
  const highest = Math.max(1, ...rows.map(row => row.count));
  const number = new Intl.NumberFormat(language);
  const metrics = [['Failures', summary?.total], ['Users', summary?.users], ['Source IPs', summary?.source_ips]];

  return jsxs('section', {className: 'card dash-failures dash-auth-card', children: [
    jsxs('div', {className: 'dash-auth-header', children: [
      jsx('span', {className: 'dash-auth-icon', 'aria-hidden': true, children:
        jsx('svg', {viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round', strokeLinejoin: 'round', children:
          jsx('path', {d: 'M12 21s-7-3.4-7-9V6l7-3 7 3v6m-2 1v4m0 3h.01'})})}),
      jsxs('div', {children: [jsx('h2', {children: t('Top failed auth')}), jsx('span', {children: t('Last 24 hours')})]}),
      jsxs('button', {type: 'button', className: 'dash-text-button', onClick: onViewLogs, children: [
        t('View logs'), jsx('span', {'aria-hidden': true, children: ' →'}),
      ]}),
    ]}),
    jsx('dl', {className: 'dash-auth-metrics', children: metrics.map(([label, value]) => jsxs('div', {children: [
      jsx('dt', {children: t(label)}), jsx('dd', {children: value == null ? '—' : number.format(value)}),
    ]}, label))}),
    rows.length ? jsx('ul', {className: 'dash-auth-list', children: rows.map(row => {
      const count = t(row.count === 1 ? '{count} failure' : '{count} failures').replace('{count}', number.format(row.count));
      const initials = row.username ? Array.from(row.username).slice(0, 2).join('').toLocaleUpperCase(language) : '—';
      return jsxs('li', {className: row.count === highest ? 'dash-auth-leader' : undefined, children: [
        jsx('span', {className: 'dash-auth-avatar', 'aria-hidden': true, children: initials}),
        jsxs('div', {className: 'dash-auth-account', children: [
          jsxs('div', {className: 'dash-auth-identity', children: [
            jsx('strong', {children: row.username || t('Unknown username')}),
            jsx('code', {children: row.device}),
          ]}),
          jsxs('div', {className: 'dash-auth-time', children: [
            jsx('svg', {viewBox: '0 0 16 16', fill: 'none', stroke: 'currentColor', 'aria-hidden': true, children:
              jsx('path', {d: 'M8 2a6 6 0 1 0 0 12A6 6 0 0 0 8 2Zm0 3v3l2 2'})}),
            jsx('time', {dateTime: row.last_at, children: formatTime(row.last_at)}),
          ]}),
        ]}),
        jsxs('div', {className: 'dash-auth-count', children: [
          jsx('span', {children: count}),
          jsx('progress', {value: row.count, max: highest, 'aria-hidden': true}),
        ]}),
      ]}, JSON.stringify([row.device, row.username]));
    })}) : jsx('p', {className: 'dash-auth-empty', children: t(data ? 'No failed authentications in the last 24 hours.' : 'Waiting for data')}),
  ]});
}
