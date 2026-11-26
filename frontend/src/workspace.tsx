import type {ComponentProps} from 'react';
import type {DeviceGroup} from './device-group-model';
import {Logging,type LogLoader} from './logging';
import {AccountingPanel,type AccountingPage} from './operations';
import {useI18n} from './i18n';
import {sections,pages,aaaLogPages,monitorLogPages,resolvePage,defaultPage,type Area,type Page} from './navigation';
import {Children,cloneElement,isValidElement,type ReactNode,useState,useEffect,useRef} from 'react';
import {IdentityManager} from './identity-manager';
import {UserDirectory,type UserActions} from './user-directory';
import {DeviceManager,type Devices,type DeviceInput} from './device-manager';
import {InfoTip} from './info-tip';
import {DeploymentPanel,type Deployment} from './operations';
import {Dashboard,type DashboardData} from './dashboard';
import {NetworkResources,type GroupActions} from './network-resources';
import {IdentityGroupDirectory,type IdentityGroupActions} from './identity-groups';

export type Inventory={users:{id:string;username:string;enabled:boolean;locked:boolean}[];groups:{id:string;name:string}[];truncated:boolean};
function MenuIcon({page}:{page:Area}){
  const paths:Record<Area,string>={
    overview:'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
    network:'M8 3h8v6H8z M3 16h6v5H3z M15 16h6v5h-6z M12 9v4 M6 16v-3h12v3',
    identity:'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M17 4a4 4 0 0 1 0 7 M22 21v-2a4 4 0 0 0-3-4',
    policy:'m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6z M9 12l2 2 4-4',
    monitor:'M3 3v18h18 M5 14l4-5 4 3 6-7',
    system:'M4 6h16 M4 12h16 M4 18h16 M8 3v6 M16 9v6 M10 15v6'
  };
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[page]}/></svg>;
}
function compactPanel(node:ReactNode,t:(message:string)=>string):ReactNode{
  if(!isValidElement<{children?:ReactNode}>(node))return node;
  if(node.type==='div')return cloneElement(node,{},...Children.toArray(node.props.children).map(child=>compactPanel(child,t)));
  if(node.type!=='section')return node;
  const parts=Children.toArray(node.props.children);
  const heading=parts.find(child=>isValidElement(child)&&child.type==='h2');
  if(!isValidElement<{children?:ReactNode;'data-ui-key'?:string}>(heading)||typeof heading.props.children!=='string')return node;
  const title=heading.props['data-ui-key']??heading.props.children;
  if(!['Create a policy draft','Policy workflow','Policy simulation','Audit trail'].includes(title))return node;
  const descriptions=parts.filter(child=>isValidElement<{children?:ReactNode}>(child)&&child.type==='p'&&typeof child.props.children==='string');
  if(!descriptions.length)return node;
  const help=descriptions.map(child=>isValidElement<{children?:ReactNode}>(child)?child.props.children:null);
  const updated=parts.filter(child=>!descriptions.includes(child)).map(child=>child===heading?cloneElement(heading,{},t(title),<InfoTip key="help" label={t(title)}>{help.map((text,index)=><span className="tooltip-paragraph" key={index}>{text}</span>)}</InfoTip>):child);
  if(title==='Policy workflow')updated.splice(1,0,<p key="approval" className="notice">{t("Independent approval required before activation.")}</p>);
  return cloneElement(node,{},...updated);
}
function panelPage(node:ReactNode):Page|undefined{
  return isValidElement<{'data-page'?:Page}>(node)?node.props['data-page']:undefined;
}
export function Workspace({currentUser,deviceOperator=false,deviceAaaLogs=false,userActions,userRevision=0,profileRequest=0,children,inventory,onRefresh,busy,mfaRequired,policyCount,onCreateIdentity,onIdentityState,devices,onLoadDevices,onSaveDevice,loadDeployment,loadDashboard,loadLogs,loadAccounting,groupActions,identityGroupActions,onDeleteDevice,onRevealDevice}:{currentUser?:string;deviceOperator?:boolean;deviceAaaLogs?:boolean;userActions?:UserActions;userRevision?:number;profileRequest?:number;children:ReactNode;inventory:Inventory|null;onRefresh:()=>void;busy:boolean;mfaRequired:boolean;policyCount:number;onCreateIdentity:(payload:{username:string;password:string;group_name:string})=>Promise<void>;onIdentityState:(payload:{user_id:string;enabled:boolean})=>Promise<void>;devices:Devices|null;onLoadDevices:(query?:string)=>void|Promise<Devices|undefined>;onSaveDevice:(payload:DeviceInput)=>Promise<void>;loadDeployment?:()=>Promise<Deployment>;loadDashboard?:()=>Promise<DashboardData>;loadLogs?:LogLoader;loadAccounting?:(query:string)=>Promise<AccountingPage>;groupActions?:GroupActions;identityGroupActions?:IdentityGroupActions;onDeleteDevice?:(address:string)=>Promise<void>;onRevealDevice?:(address:string,password:string)=>Promise<string>}){
  const {t}=useI18n();

  const [requestedPage,setPage]=useState<Page>(()=>resolvePage(typeof window==='undefined'?'':window.location.hash));
  const [collapsed,setCollapsed]=useState(()=>typeof window!=='undefined'&&typeof window.matchMedia==='function'&&window.matchMedia('(max-width:760px)').matches),[open,setOpen]=useState<Partial<Record<Area,boolean>>>({});
  const requestedAaaLog=aaaLogPages.some(([id])=>id===requestedPage);
  const page=deviceOperator&&!['devices','locations','device-types','password'].includes(requestedPage)
    &&!(deviceAaaLogs&&requestedAaaLog)?'devices':requestedPage;
  const selected=pages.find(item=>item.id===page)!;
  const [aaaOpen,setAaaOpen]=useState(true);
  const isAaaPage=aaaLogPages.some(([id])=>id===page);
  useEffect(()=>{if(isAaaPage)setAaaOpen(true);},[page,isAaaPage]);
  const shell=useRef<HTMLDivElement>(null);
  useEffect(()=>{
    const header=document.querySelector('header');
    if(!header)return;
    const measure=()=>shell.current?.style.setProperty('--workspace-header-height',`${Math.ceil(header.getBoundingClientRect().height)}px`);
    measure();
    if(typeof ResizeObserver!=='undefined'){const observer=new ResizeObserver(measure);observer.observe(header);return()=>observer.disconnect();}
    window.addEventListener('resize',measure);return()=>window.removeEventListener('resize',measure);
  },[]);
  function navigate(target:Page){window.location.hash='/'+target;setPage(target);setOpen({[pages.find(item=>item.id===target)!.area]:true});if(window.matchMedia?.('(max-width:760px)').matches)setCollapsed(true);}
  useEffect(()=>{const changed=()=>setPage(resolvePage(window.location.hash));window.addEventListener('hashchange',changed);return()=>window.removeEventListener('hashchange',changed);},[]);
  useEffect(()=>{setOpen({[selected.area]:true});},[selected.area]);
  useEffect(()=>{const media=window.matchMedia('(max-width:760px)');const resize=()=>setCollapsed(media.matches);media.addEventListener('change',resize);return()=>media.removeEventListener('change',resize);},[]);
  useEffect(()=>{if(profileRequest)navigate('password');},[profileRequest]);
  function navLink(id:Page,label:string){
    const active=page===id||(page==='user-create'&&id==='users');
    return <a key={id} href={'#/'+id} className={active?'nav-child selected':'nav-child'}
      aria-current={active?'page':undefined} onClick={()=>navigate(id)}>
      <span aria-hidden="true" className="nav-bullet"/>{t(label)}
    </a>;
  }
  return <div ref={shell} className={collapsed?'workspace menu-collapsed':'workspace'}><aside className="sidebar"><div className="sidebar-header"><button className="menu-toggle" aria-label={t("Toggle navigation")} aria-expanded={!collapsed} aria-controls="workspace-navigation" onClick={()=>setCollapsed(!collapsed)}><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16"/></svg></button><span className="sidebar-title">{t("Navigation")}</span></div><nav id="workspace-navigation" aria-label={t("Administration workspaces")}>{sections.filter(section=>!deviceOperator||section.id==='network'||section.id==='system'||(deviceAaaLogs&&section.id==='monitor')).map(section=>{
    const active=selected.area===section.id,expanded=open[section.id]??active;
    return <div className="nav-group" key={section.id}><button className={active?'nav-item selected':'nav-item'} title={collapsed?t(section.label):undefined} aria-label={t(section.label)} aria-expanded={section.id==='overview'?undefined:expanded&&!collapsed} aria-controls={section.id==='overview'?undefined:'nav-'+section.id} aria-current={section.id==='overview'&&active?'page':undefined} onClick={()=>{if(section.id==='overview')navigate('overview');else if(collapsed){setCollapsed(false);setOpen(value=>({...value,[section.id]:true}));}else setOpen(value=>({...value,[section.id]:!expanded}));}}><span className="nav-symbol"><MenuIcon page={section.id}/></span><span className="nav-label">{t(section.label)}</span>{section.id!=='overview'&&<svg className={expanded?'nav-chevron expanded':'nav-chevron'} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.7" aria-hidden="true"><path d="m6 4 4 4-4 4"/></svg>}</button>{section.id!=='overview'&&<div id={'nav-'+section.id} className="nav-children" hidden={!expanded||collapsed}>{section.id==='monitor'?<>
      <button type="button" className={isAaaPage?'nav-child nav-log-group selected':'nav-child nav-log-group'}
        aria-expanded={aaaOpen} aria-controls="nav-aaa-logs" onClick={()=>setAaaOpen(value=>!value)}>
        <span>{t('AAA Logs')}</span><svg className={aaaOpen?'nav-chevron expanded':'nav-chevron'} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.7" aria-hidden="true"><path d="m6 4 4 4-4 4"/></svg>
      </button>
      <div id="nav-aaa-logs" className="nav-log-children" hidden={!aaaOpen}>
        {aaaLogPages.map(([id,label])=>navLink(id,label))}
      </div>
      {!deviceOperator&&section.pages.slice(aaaLogPages.length).map(([id,label])=>navLink(id,label))}
    </>:section.pages.filter(([id])=>!deviceOperator||section.id==='network'||id==='password').map(([id,label])=>navLink(id,label))}</div>}</div>;
  })}</nav></aside>
    <div className="workspace-content"><div className="page-heading"><div><p className="page-parent">{t(selected.parent)}</p><h1 tabIndex={-1}>{t(selected.label)}{selected.area==='policy'&&<InfoTip label={t("Command policies (optional)")}>{t("Use this workspace only for server-side per-command authorization. Assigning shell privilege through EXEC authorization does not require creating a policy.")}</InfoTip>}</h1></div></div>
    {selected.area==='policy'&&page!=='policies'&&<div className="page-actions"><a className="button-link secondary" href="#/policies">{t('Back to list')}</a>{page!=='policy-workflow'&&<a className="button-link secondary" href="#/policy-workflow">{t('Policy workflow')}</a>}{page==='policy-workflow'&&<><a className="button-link secondary" href="#/policy-simulation">{t('Policy simulation')}</a><a className="button-link secondary" href="#/policy-evidence">{t('Saved simulation evidence')}</a></>}</div>}
    {page==='overview'&&loadDashboard&&<Dashboard load={loadDashboard} loadDeployment={loadDeployment} navigate={area=>navigate(area==='groups'||area==='diagnostics'||area==='audit'?area:defaultPage(area))}/>}
    {(!deviceOperator||deviceAaaLogs&&isAaaPage)&&(page==='overview'||selected.area==='monitor')&&(loadLogs||loadAccounting)&&
      <DashboardLogs key={page} initialPage={page} loadLogs={loadLogs} loadAccounting={loadAccounting} aaaOnly={deviceOperator}/>}
    {page==='groups'&&identityGroupActions&&<IdentityGroupDirectory actions={identityGroupActions} revision={userRevision}/>}
    {page==='users'&&userActions&&<UserDirectory currentUser={currentUser} groups={inventory?.groups.map(group=>group.name)??[]} actions={userActions} revision={userRevision}/>}
    {selected.area==='network'&&(groupActions?<NetworkResources identityGroups={inventory?.groups.map(group=>group.name)??[]} key={page} page={page==='locations'?'location':page==='device-types'?'device_type':'devices'} actions={groupActions} busy={busy} devices={devices} onLoad={onLoadDevices} onSave={onSaveDevice} onDelete={onDeleteDevice} onReveal={onRevealDevice} loadDeployment={loadDeployment}/>:<DeviceManager identityGroups={inventory?.groups.map(group=>group.name)??[]} busy={busy} devices={devices} onLoad={onLoadDevices} onSave={onSaveDevice} onDelete={onDeleteDevice} onReveal={onRevealDevice}/>)}
    {Children.toArray(children).map((node,index)=><div key={index} hidden={panelPage(node)!==page}>{compactPanel(node,t)}</div>)}
    {page==='user-create'&&<><div className="page-actions"><a href="#/users" className="button-link secondary">{t('Back to list')}</a></div><IdentityManager groups={inventory?.groups.map(group=>group.name)??[]} busy={busy} onCreate={async payload=>{await onCreateIdentity(payload);navigate('users');}} onState={onIdentityState}/></>}
    {page==='diagnostics'&&loadDeployment&&<DeploymentPanel load={loadDeployment}/>}
    {page==='security'&&<section className="card"><h2>{t("Security")} <InfoTip label={t("Security & operations")}>{t("Sessions last 15 minutes. Password changes invalidate existing sessions. HTTPS, CSRF protection, access permissions and secure cookies remain enforced.")}</InfoTip></h2><dl className="settings-list"><dt>{t("Authentication")}</dt><dd>{mfaRequired?t("Password + MFA"):t("Password only")}</dd><dt>{t("Session lifetime")}</dt><dd>{t("15 minutes")}</dd><dt>{t("Administration")}</dt><dd>HTTPS</dd></dl></section>}
    </div></div>;
}


type DashboardLogPage = typeof monitorLogPages[number][0];

function DashboardLogs({initialPage,loadLogs,loadAccounting,aaaOnly=false}:{
  initialPage:Page;aaaOnly?:boolean;loadLogs?:LogLoader;loadAccounting?:(query:string)=>Promise<AccountingPage>;
}){
  const {t}=useI18n();
  const available=(aaaOnly?aaaLogPages:monitorLogPages).filter(([id])=>id==='accounting'?loadAccounting:loadLogs);
  const [active,setActive]=useState<DashboardLogPage>(()=>
    available.find(([id])=>id===initialPage)?.[0]??available[0][0]);
  const action=active==='authentication-log'?'aaa.authentication':active==='authorization-log'?'aaa.authorization':undefined;
  return <section className="dashboard-logs" aria-label={t('Logging & Reports')}>
    <nav className="actions dashboard-log-nav" aria-label={t('Logging & Reports')}>
      {available.map(([id,label])=><button type="button" key={id}
        className={active===id?undefined:'secondary'} aria-pressed={active===id}
        onClick={()=>setActive(id)}>{t(label)}</button>)}
    </nav>
    {active==='accounting'&&loadAccounting&&<AccountingPanel load={loadAccounting}/>}
    {active!=='accounting'&&loadLogs&&<Logging key={active}
      kind={action?'aaa':active==='audit'?'activity':active==='log-issues'?'issues':'all'} fixedAction={action}
      report={active==='reports'} load={loadLogs}/>}
  </section>;
}
