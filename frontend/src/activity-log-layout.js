export function activityLogLayout({jsx, jsxs, hooks, t, address, formatTime, children}) {
  const [snapshot, setSnapshot] = hooks.useState(null);
  hooks.useEffect(() => {
    if (!address) return;
    const controller = new AbortController();
    setSnapshot(null);
    async function read(path) {
      const response = await fetch(path, {signal:controller.signal, credentials:'same-origin', cache:'no-store'});
      if (!response.ok) throw new Error('Configuration unavailable');
      return response.json();
    }
    async function load() {
      try {
        const query = new URLSearchParams({search:address,limit:'100'});
        const {devices} = await read('/api/devices?' + query);
        const device = devices.find(item => item.address === address);
        if (!device) {
          if (!controller.signal.aborted) setSnapshot({address});
          return;
        }
        const groups = device.location_id || device.device_type_id
          ? await read('/api/device-groups').then(data => data.groups, () => []) : [];
        if (!controller.signal.aborted) setSnapshot({address,device,groups});
      } catch {
        if (!controller.signal.aborted) setSnapshot({address});
      }
    }
    void load();
    return () => controller.abort();
  },[address]);
  const current = address && snapshot?.address === address ? snapshot : null;
  const device = current?.device;
  const date = value => value ? formatTime(value) : '—';
  function groupName(id) {
    const names = [];
    const visited = new Set();
    while (id && !visited.has(id)) {
      visited.add(id);
      const group = current.groups.find(item => item.id === id);
      if (!group) break;
      names.unshift(group.name);
      id = group.parent_id;
    }
    return names.join(' / ') || '—';
  }
  function rows(values) {
    return values.flatMap(([label,value])=>[
      jsx('dt',{children:t(label)},label+'-label'),
      jsx('dd',{children:value},label+'-value'),
    ]);
  }
  return jsxs('div',{className:'activity-log-layout',children:[
    jsxs('section',{className:'activity-log-results','aria-label':t('Activity'),children:[
      jsx('h3',{children:t('Activity')}),
      device && jsx('dl',{className:'activity-log-meta',children:rows([
        ['Last seen',date(device.runtime_observed_at)],['Saved at',date(device.saved_at)],
      ])}),
      children,
    ]}),
    jsxs('aside',{className:'activity-log-configuration','aria-label':t('Saved configuration'),children:[
      jsx('h3',{children:t('Saved configuration')}),
      device ? jsx('dl',{children:rows([
        ['Source IPv4',jsx('code',{children:device.address})],
        ['Location',groupName(device.location_id)],['Device Type',groupName(device.device_type_id)],
        ['Status',t(device.enabled?'Enabled':'Disabled')],['Saved at',date(device.saved_at)],
      ])}) : jsx('p',{className:'hint',children:t(!address?'Apply a Source IPv4 filter to view saved configuration.':
        current?'Saved configuration is unavailable for this address.':'Loading…')}),
    ]}),
  ]});
}
