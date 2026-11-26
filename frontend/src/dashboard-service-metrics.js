export function dashboardServiceRow({jsx,jsxs,t,snapshot,service,formatTime}) {
  const name={app:'TACACS+',admin:'Web Admin',proxy:'HTTPS Proxy',postgres:'PostgreSQL'}[service];
  const status=snapshot?.services?.[service];
  const online=['healthy','unhealthy','starting','running'].includes(status);
  const offline=['exited','created','paused','restarting','dead','removing','missing'].includes(status);
  const tone=online?'good':offline?'bad':'neutral';
  const started=online?snapshot.service_started_at?.[service]:undefined;
  const seconds=Math.floor((Date.parse(snapshot?.observed_at)-Date.parse(started))/1000);
  const elapsed = seconds >= 86400 ? Math.floor(seconds / 86400) + 'd'
    : seconds >= 3600 ? Math.floor(seconds / 3600) + 'h'
    : seconds >= 60 ? Math.floor(seconds / 60) + 'm'
    : seconds + 's';
  const latency=online?snapshot.probe_latency_ms?.[service]:undefined;
  const probe=service==='app'?'TCP/49':'HTTPS/8443';
  const healthNote=status==='unhealthy'?t('Unhealthy'):status==='starting'?t('Starting'):undefined;
  return jsxs('li',{className:'dash-service-row',children:[
    jsx('i',{className:'dash-dot '+tone,'aria-hidden':'true'}),
    jsxs('div',{children:[
      jsx('strong',{children:name}),
      jsxs('span',{className:'dash-service-status '+tone,title:healthNote,children:[
        t(online?'Online':offline?'Offline':'Not currently verified'),
        typeof latency==='number'&&jsx('span',{className:'dash-service-latency',title:probe,children:latency.toFixed(1)+' ms'}),
      ]}),
    ]}),
    seconds>=0&&jsx('span',{className:'dash-service-metrics',title:formatTime(started),children:t('{time} ago').replace('{time}',elapsed)}),
  ]},service);
}
