const actionGroups = [
  ['AAA', 'aaa', ['authentication', 'authorization', 'accounting']],
  ['Web access', 'web', ['login', 'logout']],
  ['Identity', 'identity', ['create', 'update', 'delete', 'enable', 'disable']],
  ['Identity group', 'identity-group', ['create', 'rename', 'delete']],
  ['Device', 'device', ['create', 'update', 'delete']],
  ['Device group', 'device-group', ['create', 'update', 'delete']],
  ['Policy', 'policy', ['discard']],
];

export function auditActionCombobox({jsx, jsxs, hooks, t, value, onChange, disabled = false}) {
  const {useEffect, useId, useRef, useState} = hooks;
  const id = useId();
  const trigger = useRef(null), panel = useRef(null), search = useRef(null);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [cursor, setCursor] = useState(null);
  const needle = query.trim().toLowerCase();
  const groups = actionGroups.map(([label, prefix, verbs]) => [
    label, verbs.map(verb => ({verb, key:prefix + '.' + verb}))
      .filter(item => item.key.includes(needle) || t(item.verb).toLowerCase().includes(needle)),
  ]).filter(([,items]) => items.length);
  const all = {verb:'All actions', key:''};
  const options = [...(needle ? [] : [all]), ...groups.flatMap(([,items]) => items)];
  const active = options.find(item => item.key === cursor) ??
    options.find(item => item.key === value) ?? options[0];
  const optionId = key => id + '-action-' + (key || 'all');

  function position() {
    const element = panel.current;
    if (!element?.matches(':popover-open')) return;
    const anchor = trigger.current.parentElement.getBoundingClientRect();
    const viewport = document.documentElement;
    const width = Math.min(Math.max(anchor.width,280),viewport.clientWidth-16);
    const below = viewport.clientHeight-anchor.bottom-12;
    const above = anchor.top-12;
    const flip = below < 360 && above > below;
    element.style.setProperty('--action-width',width+'px');
    element.style.setProperty('--action-left',Math.max(8,Math.min(anchor.left,viewport.clientWidth-width-8))+'px');
    element.style.setProperty('--action-top',flip ? 'auto' : anchor.bottom+4+'px');
    element.style.setProperty('--action-bottom',flip ? viewport.clientHeight-anchor.top+4+'px' : 'auto');
    element.style.setProperty('--action-height',Math.min(360,Math.max(0,flip ? above : below))+'px');
  }

  useEffect(() => {
    if (!open) return;
    window.addEventListener('resize',position);
    window.addEventListener('scroll',position,true);
    return () => {
      window.removeEventListener('resize',position);
      window.removeEventListener('scroll',position,true);
    };
  },[open]);

  function choose(key) {
    onChange(key);
    panel.current.hidePopover();
    trigger.current.focus();
  }

  function keyboard(event) {
    const key = event.key;
    if (!['ArrowDown','ArrowUp','Home','End','Enter','Escape'].includes(key)) return;
    if ((key === 'Home' || key === 'End') && event.shiftKey) return;
    event.preventDefault();
    if (key === 'Escape') { panel.current.hidePopover(); trigger.current.focus(); return; }
    if (key === 'Enter') { if (active) choose(active.key); return; }
    if (!options.length) return;
    const index = options.indexOf(active);
    const next = key === 'Home' ? 0 : key === 'End' ? options.length-1 :
      Math.max(0,Math.min(options.length-1,index+(key === 'ArrowDown' ? 1 : -1)));
    setCursor(options[next].key);
    document.getElementById(optionId(options[next].key))?.scrollIntoView({block:'nearest'});
  }

  function highlight(text) {
    const start = needle ? text.toLowerCase().indexOf(needle) : -1;
    return start < 0 ? text : [
      text.slice(0,start), jsx('mark',{children:text.slice(start,start+needle.length)},'match'),
      text.slice(start+needle.length),
    ];
  }

  function option({verb,key}) {
    return jsxs('div',{
      id:optionId(key), role:'option', 'aria-selected':value === key,
      'data-active':active?.key === key, className:'audit-action-option',
      onMouseDown:event=>event.preventDefault(), onClick:()=>choose(key),
      children:[
        jsx('i',{'aria-hidden':true,'data-verb':verb}),
        jsx('span',{children:highlight(t(verb))}),
        jsx('code',{children:highlight(key)}),
        jsx('span',{'aria-hidden':true,children:value === key ? '\u2713' : ''}),
      ],
    },key);
  }

  return jsxs('div',{className:'audit-action-filter',children:[
    jsx('span',{id:id+'-label',children:t('Event action')}),
    jsxs('div',{className:'audit-action-trigger',children:[
      jsxs('button',{
        type:'button',ref:trigger,disabled,popoverTarget:id+'-panel',
        'aria-haspopup':'listbox','aria-expanded':open,
        'aria-controls':id+'-panel','aria-labelledby':id+'-label '+id+'-value',
        onKeyDown:event=>{
          if (!['ArrowDown','ArrowUp'].includes(event.key)) return;
          event.preventDefault();
          panel.current.showPopover();
        },
        children:[
          jsx('span',{id:id+'-value',className:value ? 'audit-action-key' : '',children:value || t('All actions')}),
          jsx('i',{'aria-hidden':true,className:'audit-action-chevron'}),
        ],
      }),
      value && jsx('button',{type:'button',disabled,className:'audit-action-clear',
        'aria-label':t('Clear event action'),children:'\u00d7',onClick:()=>{onChange('');trigger.current.focus();}}),
    ]}),
    jsxs('div',{id:id+'-panel',popover:'auto',ref:panel,className:'audit-action-panel',
      onToggle:event=>{
        const visible = event.currentTarget.matches(':popover-open');
        setOpen(visible);
        if (visible) {
          setQuery(''); setCursor(value); position(); search.current.focus();
        }
      },
      children:[
        jsxs('div',{className:'audit-action-search',children:[
          jsx('i',{'aria-hidden':true}),
          jsx('input',{
            ref:search,type:'text',role:'combobox','aria-label':t('Search actions'),
            'aria-autocomplete':'list','aria-expanded':open,'aria-controls':id+'-list',
            'aria-activedescendant':open && active ? optionId(active.key) : undefined,
            placeholder:t('Search actions')+'\u2026',value:query,
            onChange:event=>{setQuery(event.target.value);setCursor(null);},onKeyDown:keyboard,
          }),
        ]}),
        jsxs('div',{id:id+'-list',role:'listbox','aria-labelledby':id+'-label',className:'audit-action-list',children:[
          !needle && option(all),
          ...groups.map(([label,items])=>jsxs('div',{role:'group','aria-label':t(label),children:[
            jsx('div',{className:'audit-action-section','aria-hidden':true,children:t(label)}),
            ...items.map(option),
          ]},label)),
        ]}),
        !options.length && jsxs('div',{className:'audit-action-empty',children:[
          jsx('span',{role:'status',children:t('No matching action')}),
          jsx('button',{type:'button',children:t('Clear search'),onClick:()=>{setQuery('');setCursor(null);search.current.focus();}}),
        ]}),
      ],
    }),
  ]});
}
