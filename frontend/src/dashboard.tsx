import {vietnamTime} from './audit-time';
import {jsx,jsxs} from 'react/jsx-runtime';
import {useEffect,useRef,useState} from 'react';
import {useI18n} from './i18n';
import type {Deployment} from './operations';
import {dashboardFailedAuthCard} from './dashboard-failed-auth-card';

export type DashboardData={observed_at:string;version?:string;window:string;inventory:{users:number;usable_users:number;locked_users:number;groups:number;devices:number;enabled_devices:number;pending_devices:number};policies:Record<string,number>;daily_auth?:{day:string;passed:number;failed:number}[];activity:{hour:string;action:string;result:string;count:number}[];failures:{username?:string|null;device:string;count:number;last_at:string}[];failure_summary?:{total:number;users:number;source_ips:number};recent:{timestamp:string;action:string;target:string;result:string}[];totals?:number[];hourly?:{hour:string;values:number[]}[];denied_devices?:Rank[];active_users?:Rank[];latest?:{timestamp:string;device:string;result:string;action:string;username?:string|null}[]};
type Area='network'|'identity'|'policy'|'monitor'|'groups'|'diagnostics'|'audit';
type Rank={label:string;count:number};
const eventLanes=[
  {id:'aaa.authentication',label:'Authentication',tone:'authentication'},
  {id:'aaa.authorization',label:'Authorization',tone:'authorization'},
  {id:'aaa.accounting',label:'Accounting',tone:'accounting'},
  {id:'error',label:'Processing errors',tone:'errors'},
] as const;

function line(values:number[],width:number,height:number,maximum=Math.max(1,...values)){
  return values.map((value,index)=>[width*index/Math.max(1,values.length-1),height-height*value/maximum].join(',')).join(' ');
}

export function Dashboard({load,loadDeployment,navigate}:{load:()=>Promise<DashboardData>;loadDeployment?:()=>Promise<Deployment>;navigate:(area:Area)=>void}){
  const [data,setData]=useState<DashboardData|null>(null),[deployment,setDeployment]=useState<Deployment|null>(null),[error,setError]=useState(false),[busy,setBusy]=useState(false);
  const loaders=useRef({load,loadDeployment});loaders.current={load,loadDeployment};
  useEffect(()=>{
    let stopped=false,timer:ReturnType<typeof setTimeout>;
    async function read(){
      if(document.visibilityState==='visible'){
        setBusy(true);
        try{
          await Promise.allSettled([
            loaders.current.load().then(facts=>{
              if(!stopped){setData(facts);setError(false);}
            },()=>{if(!stopped)setError(true);}),
            loaders.current.loadDeployment?.().then(snapshot=>{
              if(stopped)return;
              setDeployment(snapshot);
            },()=>{if(!stopped)setDeployment(null);}),
          ]);
        }catch{if(!stopped)setError(true);}finally{if(!stopped)setBusy(false);}
      }
      if(!stopped)timer=setTimeout(read,5000);
    }
    void read();return ()=>{stopped=true;clearTimeout(timer);};
  },[]);
  return <DashboardView data={data} deployment={deployment} error={error} busy={busy} navigate={navigate}/>;
}
export function DashboardView({data,deployment,error,busy,navigate}:{data:DashboardData|null;deployment:Deployment|null;error:boolean;busy:boolean;navigate:(area:Area)=>void}){
  const {t,language}=useI18n();
  const end=new Date(data?.observed_at??Date.now());
  end.setUTCMinutes(0,0,0);
  const hours=Array.from({length:24},(_,index)=>{
    const time=end.getTime()-(23-index)*3600000;
    const rows=data?.activity.filter(row=>Date.parse(row.hour)===time&&row.action==='aaa.authentication')??[];
    const count=(result:string)=>rows.filter(row=>row.result===result).reduce((sum,row)=>sum+row.count,0);
    return {time:new Date(time).toISOString(),pass:count('pass'),fail:count('fail'),metrics:data?.hourly?.find(row=>Date.parse(row.hour)===time)?.values};
  });
  const passed=hours.map(hour=>hour.pass),failed=hours.map(hour=>hour.fail);
  const maximum=Math.max(4,Math.ceil(Math.max(...passed,...failed)/4)*4);
  const [selectedHour,setSelectedHour]=useState(23);
  const selected=hours[selectedHour];
  const format=(value:number)=>value.toLocaleString(language);
  const metrics=['Authentications (24h)','Failed logins','Active devices','Commands authorized'];
  const good=['pass','allow','committed'];
  const bad=['fail','deny','error'];
  return <div className="ops-overview dashboard-console" aria-busy={busy}>
    {error&&<p className="error" role="alert"><strong>{t('Data may be stale')}</strong> · {t('Dashboard unavailable. Check access permissions or try again. Previously loaded data may be stale.')}</p>}
    <div className="ops-kpis">
      {metrics.map((label,index)=><section className="card ops-kpi" key={label}>
        <h2>{t(label)}</h2>
        <strong>{data?.totals?.[index]===undefined?'—':format(data.totals[index])}</strong>
        {data?.hourly&&<svg viewBox="0 0 120 27" className="ops-sparkline" aria-hidden="true">
          <polyline points={line(hours.map(hour=>hour.metrics?.[index]??0),120,24)}/>
        </svg>}
        {index===3&&<small>{t('Counts command authorizations recorded by this release.')}</small>}
      </section>)}
    </div>
    <section className="ops-board" aria-labelledby="ops-board-heading">
      <div className="section-heading ops-board-heading">
        <h2 id="ops-board-heading">{t('Latest AAA events')}</h2>
        <button className="secondary" onClick={()=>navigate('monitor')}>{t('View logs')}</button>
      </div>
      <div className="ops-board-grid">
        {eventLanes.map(lane=>{
          const events=(data?.latest??[]).filter(event=>(event.result==='error'?'error':event.action)===lane.id);
          return <section className={'ops-lane ops-lane-'+lane.tone} key={lane.id}>
            <header><h3>{t(lane.label)}</h3>{data&&<span className="ops-lane-count">{format(events.length)}</span>}</header>
            {events.length?<ul>{events.map((event,index)=><li key={index}>
              <div className="ops-event-heading">
                <strong>{event.username??t(event.action)}</strong>
                <span className={'log-result '+(good.includes(event.result)?'good':bad.includes(event.result)?'bad':'neutral')}>{t(event.result)}</span>
              </div>
              <dl>
                <div><dt>{t('Source IP')}</dt><dd><code>{event.device}</code></dd></div>
                <div><dt>{t('Timestamp')}</dt><dd><time dateTime={event.timestamp}>{vietnamTime(event.timestamp)}</time></dd></div>
              </dl>
            </li>)}</ul>:<p className="hint">{data?t('No events in this snapshot.'):error?t('Dashboard unavailable'):t('Waiting for data')}</p>}
          </section>;
        })}
      </div>
    </section>
    <div className="ops-bento">
      <section className="card ops-trend">
        <div className="section-heading"><h2>{t('AAA activity')}</h2><span className="badge">{t('24 hours')}</span></div>
        {data&&<>
          <div className="ops-plot">
            <div className="ops-axis" aria-hidden="true">{[4,3,2,1,0].map(level=><span key={level}>{maximum*level/4}</span>)}</div>
            <svg viewBox="0 0 460 140" preserveAspectRatio="none" role="img" aria-label={t('TACACS+ authentication results')}>
              {[0,35,70,105,140].map(y=><line key={y} x1="0" x2="460" y1={y} y2={y}/>)}
              <polyline className="ops-chart-good" points={line(passed,460,140,maximum)}/>
              <polyline className="ops-chart-bad" points={line(failed,460,140,maximum)}/>
            </svg>
          </div>
          <div className="ops-chart-times" aria-hidden="true">{[0,6,12,18,23].map(index=><span key={index}>{vietnamTime(hours[index].time).slice(-8,-3)}</span>)}</div>
          <div className="ops-chart-detail">
            <label>{t('Hour')} <select value={selectedHour} onChange={event=>setSelectedHour(Number(event.target.value))}>
              {hours.map((hour,index)=><option value={index} key={hour.time}>{vietnamTime(hour.time)}</option>)}
            </select></label>
            <span className="ops-good">{t('Success')} <b>{format(selected.pass)}</b></span>
            <span className="ops-bad">{t('Failed')} <b>{format(selected.fail)}</b></span>
          </div>
        </>}
      </section>
      {([['Top denied devices',data?.denied_devices],['Top active users',data?.active_users]] as const).map(([label,rows])=>
        <section className="card ops-ranking" key={label}>
          <h2>{t(label)}</h2>
          {rows?.length?<ol>{rows.map(row=><li key={row.label}><span>{row.label}</span><strong>{format(row.count)}</strong></li>)}</ol>
            :<p className="hint">{data?t('No persisted events match these filters.'):t('Waiting for data')}</p>}
        </section>)}
      {dashboardFailedAuthCard({jsx,jsxs,t,language,data,formatTime:vietnamTime,onViewLogs:()=>navigate('monitor')})}
    </div>
    <div className="ops-toolbar ops-foot">
      <span>{deployment?.state==='snapshot'?t('Last checked')+' '+vietnamTime(deployment.observed_at??''):t('Not currently verified')}</span>
      <button className="secondary" onClick={()=>navigate('diagnostics')}>{t('Deployment details')}</button>
    </div>
  </div>;
}
