import {LogRefreshControl} from './log-refresh-select';
import {jsx,jsxs} from 'react/jsx-runtime';
import {logPageControls} from './log-page-controls';
import {PagedTable,useCursorPages} from './pagination';
import {vietnamTime,vietnamIso,vietnamInputToIso} from './audit-time';
import {useEffect,useId,useRef,useState,type FormEvent} from 'react';
import {csvCell,download} from './logging';
import {useI18n} from './i18n';
import {InfoTip} from './info-tip';
type SystemMetrics={uptime_seconds:number;cpu_percent:number;memory_percent:number;disk_percent:number};
export type Deployment={state:'unknown'|'snapshot'|'stale';observed_at?:string;services?:Record<string,string>;system?:SystemMetrics;live_resources?:{observed_at:string;system:SystemMetrics};mode?:string;endpoints:{service:string;address:string;port:number}[];tcp_probe?:boolean;https_probe?:boolean;runtime_acknowledgement:string;switch_test:string};
export function DeploymentPanel({load}:{load:()=>Promise<Deployment>}){
  const {t}=useI18n(),[data,setData]=useState<Deployment|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState('');
  async function refresh(){setBusy(true);setError('');try{setData(await load());}catch{setData(null);setError('Deployment status unavailable.');}finally{setBusy(false);}}
  const tacacs=data?.endpoints.filter(item=>item.service==='tacacs')??[];
  const loopback=tacacs.length>0&&tacacs.every(item=>item.address.startsWith('127.')||item.address==='::1');
  return <section className="card"><div className="section-heading"><h2>{t('Deployment status')} <InfoTip label={t('Deployment status')}>{t('Recorded by the host launcher from Docker bindings and local readiness probes. This is a timestamped snapshot, not continuous monitoring or a successful switch AAA test. Refresh reads the latest saved snapshot; rerun the launcher to take a new measurement.')}</InfoTip></h2><button className="secondary" disabled={busy} onClick={()=>void refresh()}>{t('Load deployment status')}</button></div>
    {error&&<p role="alert">{t(error)}</p>}{data&&<details><summary>{t('Technical details')}</summary><p><span className="badge">{t(data.state)}</span> {data.observed_at??''}</p>
      {data.state==='unknown'?<p className="notice">{t('No verified host snapshot is available. Do not infer the server LAN IP from container addresses.')}</p>:<>
      {data.state==='stale'&&<p className="notice">{t('Snapshot is older than five minutes. Current bindings and readiness are not verified.')}</p>}
      <div className="table-scroll"><PagedTable><thead><tr><th>{t('Service')}</th><th>{t('Published host address')}</th><th>{t('TCP port')}</th></tr></thead><tbody>{data.endpoints.map((item,index)=><tr key={index}><td>{t(item.service)}</td><td><code>{item.address}</code></td><td>{item.port}</td></tr>)}</tbody></PagedTable></div>
      <p>{t('Recorded local checks')}: {'TCP/49'} {t(data.tcp_probe?'Passed':'Failed')} · {'HTTPS'} {t(data.https_probe?'Passed':'Failed')}</p>
      {loopback&&data.state==='snapshot'&&<p className="inline-warning">{t('Loopback-only binding: switches outside this host cannot connect.')}</p>}</>}
      <p className="hint">{t('Runtime configuration acknowledgement and real-switch AAA remain unverified. Host IP, routing and firewall are not changed by this page.')}</p>
    </details>}
  </section>;
}
export type AccountingEvent={id:string;timestamp:string;session:string;username:string;device:string;action:string;kind?:string;command?:string|null;redacted?:boolean;task_id?:string|null;privilege?:number|null};
export type AccountingPage={items:AccountingEvent[];next_before:string|null;scope:string};
export function AccountingTable({items}:{items:AccountingEvent[]}){
  const {t}=useI18n();
  const command=(item:AccountingEvent)=>item.redacted?t('Sensitive command hidden'):item.command??'—';
  return <div className="table-scroll"><PagedTable className="ops-log-table">
    <thead><tr>{['Created (UTC+07:00)','Username','Source IP','Event type','Command','Privilege','Task ID','Session ID','Action'].map(label=><th key={label}>{t(label)}</th>)}</tr></thead>
    <tbody>{items.map(item=><tr key={item.id}>
      <td><time dateTime={item.timestamp} title={item.timestamp}>{vietnamTime(item.timestamp)}</time></td>
      <td>{item.username}</td><td><code>{item.device}</code></td><td>{t(item.kind??'other')}</td>
      <td><code>{command(item)}</code></td>
      <td>{item.privilege??'—'}</td><td><code>{item.task_id??'—'}</code></td>
      <td><code>{item.session}</code></td><td>{t(item.action)}</td>
    </tr>)}</tbody>
  </PagedTable></div>;
}
export function accountingCsv(items:AccountingEvent[]){return [['Timestamp (UTC+07:00)','Timestamp (original ISO)','Username','Source IP','Event type','Command','Privilege','Task ID','TACACS session','Action'],...items.map(item=>[vietnamIso(item.timestamp),item.timestamp,item.username,item.device,item.kind??'other',item.redacted?'[redacted]':item.command??'',String(item.privilege??''),item.task_id??'',item.session,item.action])].map(row=>row.map(csvCell).join(',')).join('\r\n');}
export function AccountingPanel({load}:{load:(query:string)=>Promise<AccountingPage>}){
  const {t}=useI18n(),[filters,setFilters]=useState({username:'',device:'',action:'',since:'',until:''}),[page,setPage]=useState<AccountingPage|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState(''),[updated,setUpdated]=useState('');
  const [pageSize,setPageSize]=useState(20);
  const pages=useCursorPages<string>();
  const loader=useRef(load);loader.current=load;const generation=useRef(0),inFlight=useRef(false);
  useEffect(()=>{void refresh();return()=>{generation.current++;};},[]);
  function change(key:keyof typeof filters,value:string){generation.current++;setFilters({...filters,[key]:value});setPage(null);setBusy(false);inFlight.current=false;}
  async function refresh(number=1,size=pageSize,preserve=false,silent=false){const request=++generation.current;inFlight.current=true;if(!silent){setBusy(true);setError('');}try{const query=new URLSearchParams({...filters,since:filters.since?vietnamInputToIso(filters.since):'',until:filters.until?vietnamInputToIso(filters.until):'',limit:String(size)});const before=pages.cursor(number);if(before)query.set('before',before);const result=await loader.current(query.toString());if(request===generation.current){setError('');setPage(result);pages.accept(number,result.next_before,preserve);setPageSize(size);setUpdated(vietnamTime(new Date().toISOString()).slice(-8));return true;}}catch{if(request===generation.current){setError('Accounting query failed. Check permissions and filters.');}return false;}finally{if(request===generation.current){setBusy(false);inFlight.current=false;}}}
  function submit(event:FormEvent){event.preventDefault();void refresh();}
  return <section className="card"><div className="section-heading"><h2>{t('Accounting events')} <InfoTip label={t('Accounting events')}>{t('Commands appear only when the device sends command accounting. This is not a keystroke recorder or command output capture. Sensitive commands are hidden; redaction is heuristic. Task IDs correlate records within a device context, not a complete SSH session. Start and stop may describe the same command.')}</InfoTip></h2><div className="actions"><button className="secondary" title={t('Export displayed rows')} disabled={!page?.items.length||busy} onClick={()=>download('tacacs-accounting-page.csv','\uFEFF'+accountingCsv(page!.items),'text/csv;charset=utf-8')}>{t('Export')}</button><LogRefreshControl jsx={jsx} hooks={{useEffect,useId,useRef,useState}} t={t} storageKey="tnac.accounting.refresh" defaultSeconds={10} updated={updated}
    isBlocked={()=>inFlight.current} pauseAuto={pages.page!==1||!page} onRefresh={()=>refresh(pages.page,pageSize,pages.page!==1,true)}/></div></div>
    <form onSubmit={submit} className="accounting-filters">
      <div className="form-columns">
        <label>{t('Username')}<input value={filters.username} maxLength={253} disabled={busy} onChange={event=>change('username',event.target.value)}/></label>
        <label>{t('Source IPv4')}<input value={filters.device} maxLength={15} disabled={busy} onChange={event=>change('device',event.target.value)}/></label>
        <label>{t('Action')}<select value={filters.action} disabled={busy} onChange={event=>change('action',event.target.value)}><option value="">{t('All actions')}</option>{['start','stop','watchdog'].map(value=><option key={value} value={value}>{t(value)}</option>)}</select></label>
        {(['since','until'] as const).map(key=><label key={key}>{t(key==='since'?'From (UTC+07:00)':'To (UTC+07:00)')}
          <input type="datetime-local" value={filters[key]} disabled={busy} onChange={event=>change(key,event.target.value)}/></label>)}
      </div>
      <button disabled={busy}>{t('Search accounting')}</button>
    </form>{error&&<p role="alert">{t(error)}</p>}{page&&<><AccountingTable items={page.items}/>{!page.items.length&&<p className="empty-state">{t('No accounting records match these filters.')}</p>}{logPageControls({jsx,jsxs,t,page:pages.page,last:pages.last,count:page.items.length,size:pageSize,busy,
      onPage:number=>{void refresh(number,pageSize,true);},
      onSize:size=>{void refresh(1,size);}})}</>}
  </section>;
}
