import {LogRefreshControl} from './log-refresh-select';
import {logPageControls} from './log-page-controls';
import {activityLogLayout as ActivityLogLayout} from './activity-log-layout';
import {PagedTable,useCursorPages} from './pagination';
import {auditActionCombobox as AuditActionCombobox} from './audit-action-combobox';
import {jsx,jsxs} from 'react/jsx-runtime';
import {auditDateTimeRange} from './audit-date-time';
import {vietnamTime,vietnamIso,vietnamInputToIso} from './audit-time';
import {useEffect,useId,useRef,useState,type FormEvent} from 'react';
import {useI18n} from './i18n';
import {InfoTip} from './info-tip';
import {auditActionLabel,auditActor,auditTarget} from './audit-action-labels';

export type LogEvent={event_id:string;sequence:number;timestamp:string;actor:string;actor_name:string|null;attempted_username?:string|null;source:string;source_ip?:string;destination_ip?:string;remote_address?:string;action:string;target:string;target_name?:string|null;target_name_source?:string|null;identity_details?:Record<string,string|boolean|string[]>;authorization_details?:Record<string,string>;result:string;session:string|null;policy_version:string|null};
export type LogPage={items:LogEvent[];next_before:number|null;window:{since:string;until:string};scope:string};
export type LogReport={window:{since:string;until:string};total:number;aaa_events:number;issues:number;breakdown:{action:string;result:string;count:number}[];breakdown_truncated:boolean;devices:{device:string;count:number;last_at:string}[];scope:string};
export type LogLoader=(query:string,report?:boolean)=>Promise<LogPage|LogReport>;
type Filters={search:string;action:string;result:string;device:string;since:string;until:string};
export function csvCell(value:unknown){const text=String(value??'');return '"'+(/^[\s\uFEFF]*[=+\-@]/.test(text)?"'"+text:text).replaceAll('"','""')+'"';}
export function logCsv(items:LogEvent[]){return [['Timestamp (UTC+07:00)','Timestamp (original ISO)','Action','Result','Actor','Attempted username','Source','Target','Target name','Target name source','TACACS session','Policy version','Event ID','Source IP','Destination IP','Remote address'],...items.map(item=>[vietnamIso(item.timestamp),item.timestamp,item.action,item.result,item.actor_name||item.actor,item.attempted_username??'',item.source,item.target,item.target_name,item.target_name_source,item.session,item.policy_version,item.event_id,item.source_ip,item.destination_ip,item.remote_address??item.source_ip])].map(row=>row.map(csvCell).join(',')).join('\r\n');}
export function download(name:string,text:string,type:string){const url=URL.createObjectURL(new Blob([text],{type}));const anchor=document.createElement('a');anchor.href=url;anchor.download=name;anchor.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
export function LogTable({items}:{items:LogEvent[]}){
  const {t}=useI18n();
  return <div className="table-scroll"><PagedTable className="log-table ops-log-table audit-log-table">
    <thead><tr>{['Timestamp (UTC+07:00)','Action','Actor','Attempted username','Target','Remote address'].map(label=><th key={label} scope="col">{t(label)}</th>)}<th className="audit-log-result" scope="col">{t('Result')}</th></tr></thead>
    <tbody>{items.map(item=>{
      const target=auditTarget(item.action,item.target,t,item.target_name);
      const namedDevice=item.source==='tacacs'&&target.reference!==item.target&&!!item.target_name;
      const tone=['pass','allow','success','committed'].includes(item.result)?'good':['fail','deny','error','no-reply','unclassified','unknown'].includes(item.result)?'bad':'neutral';
      return <tr key={item.event_id} className={tone==='bad'?'ops-failed':undefined}>
        <td><time dateTime={item.timestamp} title={item.timestamp}>{vietnamTime(item.timestamp)}</time></td>
        <td><span className="log-action">{auditActionLabel(item.action,t)}</span><small>{item.source}</small></td>
        <td>{auditActor(item)}</td><td>{item.attempted_username||'—'}</td>
        <td>{!namedDevice&&target.label&&<small>{target.label}</small>}<code>{target.reference}</code>{namedDevice&&<small><code>{item.target}</code></small>}</td>
        <td><code>{item.remote_address??item.source_ip??'—'}</code></td>
        <td className="audit-log-result"><span className={'log-result '+tone}>{t(item.result)}</span></td>
      </tr>;
    })}</tbody>
  </PagedTable></div>;
}
export function Logging({kind,load,report=false,fixedAction}:{fixedAction?:'aaa.authentication'|'aaa.authorization';kind:'aaa'|'activity'|'issues'|'all';load:LogLoader;report?:boolean}){
  const {t,language}=useI18n();
  const [filters,setFilters]=useState<Filters>({search:'',action:'',result:'',device:'',since:'',until:''});
  const [applied,setApplied]=useState<Filters>(filters),[data,setData]=useState<LogPage|null>(null),[summary,setSummary]=useState<LogReport|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState(false),[updated,setUpdated]=useState('');
  const [pageSize,setPageSize]=useState(20);
  const pages=useCursorPages<number>();
  const latest=useRef(load);latest.current=load;const generation=useRef(0),inFlight=useRef(false);
  function change(key:keyof Filters,value:string){setFilters(previous=>({...previous,[key]:value}));}
  async function read(values:Filters,page=1,keepWindow=false,size=pageSize,silent=false){
    const request=++generation.current;inFlight.current=true;if(!silent){setBusy(true);setError(false);}
    try{
    const query=new URLSearchParams({kind,limit:String(size)});
    const before=pages.cursor(page);
    for(const [key,value] of Object.entries(values))if(value)query.set(key,(key==='since'||key==='until')?vietnamInputToIso(value):value);
    if(fixedAction)query.set('action',fixedAction);
    if(before)query.set('before',String(before));
    // Keep the applied window stable while paging; a manual refresh starts a new snapshot window.
    if(keepWindow&&data){query.set('since',data.window.since);query.set('until',data.window.until);}
    const result=await latest.current(query.toString(),report);if(request!==generation.current)return;setError(false);
      if(report)setSummary(result as LogReport);else {const log=result as LogPage;setData(log);pages.accept(page,log.next_before,keepWindow);setPageSize(size); }setUpdated(vietnamTime(new Date().toISOString()).slice(-8));return true;
    }catch{if(request===generation.current)setError(true);return false;}finally{if(request===generation.current){inFlight.current=false;setBusy(false);}}
  }
  useEffect(()=>{void read(applied);return()=>{generation.current++;};},[kind,report,fixedAction]);
  function submit(event:FormEvent){event.preventDefault();setApplied({...filters});setData(null);setSummary(null);void read(filters);}
  function renderResults(data:LogPage){return <><LogTable items={data.items}/>{!data.items.length&&<p className="empty-state">{t('No persisted events match these filters.')}</p>}{logPageControls({jsx,jsxs,t,page:pages.page,last:pages.last,count:data.items.length,size:pageSize,busy,
    onPage:page=>{void read(applied,page,true);},
    onSize:size=>{void read(applied,1,false,size);}})}</>;}
  return <div className="logging-workspace"><section className="card"><div className="section-heading"><h2>{t(report?'Audit summary report':fixedAction==='aaa.authentication'?'Authentication Log':fixedAction==='aaa.authorization'?'Authorization Log':kind==='aaa'?'AAA request log':kind==='activity'?'Administrative activity':'Failures & errors')} <InfoTip label={t('Log coverage')}>{t('Only persisted events are shown. For TACACS+ authentication, the device supplies the attempted username. Historical events without a recorded username show a dash. Raw commands and passwords are excluded.')}</InfoTip></h2><div className="actions">{report&&<button className="secondary" disabled={busy} onClick={()=>void read(applied,1,false,pageSize,Boolean(summary))}>{t('Refresh')}</button>}{report?<button className="secondary" disabled={!summary||busy||error} onClick={()=>download('tacacs-report.json',JSON.stringify({...summary,filters:applied},null,2),'application/json')}>{t('Export report')}</button>:<button className="secondary" title={t('Export displayed rows')} disabled={!data?.items.length||busy||error} onClick={()=>download('tacacs-log-page.csv','\uFEFF'+logCsv(data!.items),'text/csv;charset=utf-8')}>{t('Export')}</button>}</div></div>
      <form onSubmit={submit} className="log-filters"><label>{t('Search')}<input value={filters.search} maxLength={256} onChange={e=>change('search',e.target.value)} placeholder={t('User, event, device or IP')}/></label>{!fixedAction&&<AuditActionCombobox jsx={jsx} jsxs={jsxs} hooks={{useEffect,useId,useRef,useState}} t={t} value={filters.action} onChange={value=>change('action',value)}/>}<label>{t('Result')}<select value={filters.result} onChange={e=>change('result',e.target.value)}><option value="">{t('All results')}</option>{['pass','fail','allow','deny','error','challenge','success','committed','no-reply'].map(value=><option key={value} value={value}>{t(value)}</option>)}</select></label><label>{t('Source IPv4')}<input value={filters.device} maxLength={15} onChange={e=>change('device',e.target.value)} placeholder="192.0.2.2"/></label>{auditDateTimeRange({jsx,jsxs,t,since:filters.since,until:filters.until,onSince:value=>change('since',value),onUntil:value=>change('until',value)})}<div className="actions"><button disabled={busy}>{t('Apply filters')}</button><button className="secondary" type="button" disabled={busy} onClick={()=>{const cleared={search:'',action:'',result:'',device:'',since:'',until:''};setFilters(cleared);setApplied(cleared);void read(cleared);}}>{t('Reset')}</button></div></form>
      <div className="log-refresh-status-strip">{applied.until&&<div className="log-meta"><span>{t('The To date limits results. Reset filters to see newer activity.')}</span></div>} { !report&&<LogRefreshControl jsx={jsx} hooks={{useEffect,useId,useRef,useState}} t={t} storageKey="tnac.audit.refresh" updated={updated}
        isBlocked={()=>inFlight.current} pauseAuto={pages.page!==1} onRefresh={()=>read(applied,pages.page,pages.page!==1,pageSize,true)}/> }</div>
      {error&&<p className="error" role="alert">{t('Log query failed. Check access, filters and the 31-day range. Previous results may be stale.')}</p>}{busy&&<p role="status">{t('Loading…')}</p>}
      {report&&updated&&<p className="hint">{t('Last updated:')} {updated}</p>}
      {data&&(kind==='activity'&&!report
        ? <ActivityLogLayout jsx={jsx} jsxs={jsxs} hooks={{useEffect,useState}} t={t} address={applied.device} formatTime={vietnamTime}>{renderResults(data)}</ActivityLogLayout>
        : renderResults(data))}
      {summary&&<><div className="report-kpis">{[['Persisted events',summary.total],['AAA exchanges',summary.aaa_events],['Failure / error events',summary.issues]].map(([label,value])=><div key={label}><span>{t(String(label))}</span><strong>{Number(value).toLocaleString(language)}</strong></div>)}</div><div className="table-scroll"><PagedTable><thead><tr><th>{t('Action')}</th><th>{t('Result')}</th><th>{t('Count')}</th></tr></thead><tbody>{summary.breakdown.map(row=><tr key={row.action+':'+row.result}><td>{auditActionLabel(row.action,t)}</td><td>{t(row.result)}</td><td>{row.count}</td></tr>)}</tbody></PagedTable></div>{summary.breakdown_truncated&&<p className="hint">{t('First 200 action/result groups shown. Totals include all matching events.')}</p>}<h3>{t('Top devices by AAA exchanges')}</h3><div className="table-scroll"><PagedTable><thead><tr><th>{t('Source IPv4')}</th><th>{t('Count')}</th><th>{t('Last event')}</th></tr></thead><tbody>{summary.devices.map(row=><tr key={row.device}><td>{row.device}</td><td>{row.count}</td><td>{vietnamTime(row.last_at)}</td></tr>)}</tbody></PagedTable></div><p className="hint">{t('Reports count stored events, including challenges. They do not count unique SSH sessions or certify audit-chain integrity.')}</p></>}
    </section></div>;
}
