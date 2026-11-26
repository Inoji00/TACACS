const refreshIntervals = [0, 10, 15, 30, 60];

export function LogRefreshControl({jsx, hooks, t, storageKey, defaultSeconds=0,
  onRefresh, isBlocked, pauseAuto=false, updated='', preview}) {
  const {useEffect,useId,useRef,useState} = hooks;
  const [seconds,setSeconds] = useState(()=>{
    if(preview) return preview.seconds;
    try {
      const saved = localStorage.getItem(storageKey);
      if(saved !== null && refreshIntervals.includes(Number(saved))) return Number(saved);
    } catch {}
    return defaultSeconds;
  });
  const [open,setOpen] = useState(Boolean(preview?.open));
  const [phase,setPhase] = useState(preview?.phase || 'idle');
  const [remaining,setRemaining] = useState(seconds);
  const [paused,setPaused] = useState(false);
  const root = useRef(null), trigger = useRef(null), menu = useRef(null);
  const latest = useRef(null), running = useRef(false), mounted = useRef(false);
  const deadline = useRef(0), focusIndex = useRef(0);
  const menuId = useId();
  latest.current = {onRefresh,isBlocked,pauseAuto,open,seconds};
  const phrase = (key,values)=>Object.entries(values).reduce(
    (label,[name,value])=>label.replace('{'+name+'}',String(value)),t(key));
  const intervalLabel = value=>phrase('Every {seconds} seconds',{seconds:value});

  function isPaused() {
    return document.visibilityState !== 'visible' || latest.current.open ||
      Boolean(document.querySelector('.audit-time-range[open], .ops-drawer[open], .log-table details[open], .audit-table details[open], .logging-workspace tbody details[open]'));
  }
  async function refresh() {
    if(running.current || latest.current.isBlocked?.()) return;
    running.current = true;
    setPhase('refreshing');
    try {
      const ok = await latest.current.onRefresh();
      if(mounted.current) setPhase(ok === false ? 'error' : 'idle');
    } catch {
      if(mounted.current) setPhase('error');
    } finally {
      running.current = false;
      deadline.current = Date.now() + latest.current.seconds * 1000;
      if(mounted.current) setRemaining(latest.current.seconds);
    }
  }
  useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;};},[]);
  useEffect(()=>{
    if(preview || !seconds) return;
    const reset = ()=>{deadline.current=Date.now()+seconds*1000;setRemaining(seconds);};
    reset();
    const timer = window.setInterval(()=>{
      const blocked = Boolean(latest.current.pauseAuto || isPaused() || latest.current.isBlocked?.());
      setPaused(blocked);
      if(blocked || running.current){reset();return;}
      const next = Math.max(0,Math.ceil((deadline.current-Date.now())/1000));
      setRemaining(next);
      if(!next) void refresh();
    },250);
    document.addEventListener('visibilitychange',reset);
    return ()=>{window.clearInterval(timer);document.removeEventListener('visibilitychange',reset);};
  },[seconds]);
  useEffect(()=>{
    if(!open || preview) return;
    const focus = ()=>menu.current?.querySelectorAll('[role="menuitemradio"]')[focusIndex.current]?.focus();
    focus();
    function outside(event){if(!root.current?.contains(event.target))setOpen(false);}
    document.addEventListener('pointerdown',outside);
    document.addEventListener('focusin',outside);
    return ()=>{
      document.removeEventListener('pointerdown',outside);
      document.removeEventListener('focusin',outside);
    };
  },[open]);

  function close() {setOpen(false);trigger.current?.focus();}
  function choose(value) {
    setSeconds(value);
    setRemaining(value);
    try {localStorage.setItem(storageKey,String(value));} catch {}
    close();
  }
  function openMenu(index) {focusIndex.current=index;setOpen(true);}
  function navigate(event,index) {
    if(event.key==='Escape'){event.preventDefault();close();return;}
    const target = {ArrowDown:(index+1)%5,ArrowUp:(index+4)%5,Home:0,End:4}[event.key];
    if(target===undefined)return;
    event.preventDefault();
    menu.current?.querySelectorAll('[role="menuitemradio"]')[target]?.focus();
  }

  const paths = {
    refresh:'M20 7v5h-5 M4 17v-5h5 M6 7a7 7 0 0 1 11.5-1L20 9 M4 15l2.5 3A7 7 0 0 0 18 17',
    chevron:'m6 9 6 6 6-6',check:'m5 12 4 4L19 6',pause:'M9 5v14 M15 5v14',
    clock:'M12 7v5l3 2 M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z',
  };
  function icon(name,key) {
    return jsx('svg',{viewBox:'0 0 24 24',width:16,height:16,fill:'none',stroke:'currentColor',
      strokeWidth:1.8,strokeLinecap:'round',strokeLinejoin:'round','aria-hidden':true,
      className:'refresh-icon refresh-icon-'+name,children:jsx('path',{d:paths[name]})},key);
  }

  const active = seconds > 0;
  const label = active?phrase('Every {seconds}s',{seconds}):t('Auto-refresh: Off');
  const title = active && (paused || pauseAuto)?t('Auto-refresh paused'):active?phrase('Auto-refresh every {seconds} seconds · next in {remaining}s',{seconds,remaining}):label;
  return jsx('div',{className:'log-refresh-toolbar',children:[
    updated&&jsx('span',{className:'log-refresh-updated',children:t('Last updated:')+' '+updated},'updated'),
    jsx('div',{ref:root,className:'log-refresh-control','data-enabled':active,'data-phase':phase,'data-paused':paused||pauseAuto,
      children:[
        jsx('div',{className:'log-refresh-split',children:[
          jsx('button',{type:'button',className:'log-refresh-now',onClick:refresh,'data-refresh-tip':title,
            'aria-label':t('Refresh')+' · '+label,'aria-disabled':phase==='refreshing','aria-busy':phase==='refreshing',
            children:[icon('refresh','refresh'),jsx('span',{className:'refresh-label',children:label},'label'),
              jsx('span',{className:'refresh-short-label','aria-hidden':true,children:active?seconds+'s':t('Off')},'short')]},'refresh'),
          jsx('button',{ref:trigger,type:'button',className:'log-refresh-select',
            'aria-label':t('Refresh interval'),'aria-haspopup':'menu','aria-expanded':open,'aria-controls':open?menuId:undefined,
            onClick:()=>open?close():openMenu(refreshIntervals.indexOf(seconds)),
            onKeyDown:event=>{
              if(event.key==='Escape'&&open){event.preventDefault();close();}
              if(['ArrowDown','ArrowUp'].includes(event.key)){event.preventDefault();openMenu(event.key==='ArrowDown'?0:4);}
            },children:icon('chevron')},'interval'),
        ]},'split'),
        phase==='error'&&jsx('span',{className:'log-refresh-error',tabIndex:0,role:'status','data-refresh-tip':t('Last refresh failed'),
          children:jsx('span',{className:'refresh-sr-only',children:t('Last refresh failed')})},'error'),
        open&&jsx('div',{className:'log-refresh-menu',children:[
          jsx('div',{className:'log-refresh-heading',children:t('Refresh interval')},'heading'),
          jsx('div',{id:menuId,ref:menu,role:'menu','aria-label':t('Refresh interval'),
            children:refreshIntervals.map((value,index)=>jsx('button',{
              type:'button',role:'menuitemradio',tabIndex:-1,'aria-checked':seconds===value,
              'data-preview-hover':preview?.hover===value||undefined,
              onClick:()=>choose(value),onKeyDown:event=>navigate(event,index),
              children:[icon(value?'clock':'pause','type'),jsx('span',{children:value?intervalLabel(value):t('Off')},'label'),
                seconds===value&&icon('check','check')],
            },value))},'items'),
        ]},'menu'),
      ]},'control'),
  ]});
}
