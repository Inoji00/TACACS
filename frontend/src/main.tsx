import {jsx,jsxs} from 'react/jsx-runtime';
import {profileLayout} from './profile-layout';
import {PAGE_SIZE,useCursorPages} from './pagination';
import {useI18n,LanguageProvider,LanguageSwitcher} from './i18n';
import {useEffect, useRef, useState, useMemo, type FormEvent} from 'react';
import {createRoot} from 'react-dom/client';
import type {LogPage,LogReport} from './logging';
import {LoginStars} from './login-stars';
import {actionFeedback} from './action-feedback';
import {AccountMenu} from './account-menu';
import {InfoTip} from './info-tip';
import {PolicyVersions} from './policy-versions';
import type {IdentityGroupActions} from './identity-groups';
import {type UserActions,type UserPage} from './user-directory';
import {RuleEditor,compileRules,type RuleDraft} from './rule-editor';
import {CaseEditor,compileCases,compileSamples,type CaseDraft} from './case-editor';
import {ImpactView,type Impact} from './impact-view';
import {EvidenceView,type EvidencePage,type EvidenceRecord,type ReplayResult} from './evidence-view';
import {Workspace,type Inventory} from './workspace';
import {type Devices} from './device-manager';
import type {DashboardData} from './dashboard';
import type {DeviceGroup,GroupActions} from './network-resources';
import {AccountingPanel,type AccountingPage,type Deployment} from './operations';

type Policy = {version_id:string; revision:number; state:string; author_id:string; approver_id:string|null};
type AuditEvent = {sequence:number; timestamp:string; action:string; actor:string; target:string; result:string};
type Page<T> = {items:T[]; next_before:number|null};
const initialRules:RuleDraft[] = [{key:1,rule_id:'show',groups:'',device_ids:'',command_prefix:'show',decision:'allow'}];
const initialCases:CaseDraft[] = [{key:1,subject:'admin',device_id:'router',command:'show version',groups:'',expected:'allow'},{key:2,subject:'admin',device_id:'router',command:'reload',groups:'',expected:'deny'}];

function Confirmation({action,version,onCancel,onConfirm}:{action:string;version:string;onCancel:()=>void;onConfirm:()=>void}) {
  const {t}=useI18n();

  const dialog=useRef<HTMLDialogElement>(null);
  useEffect(()=>{
    const previous=document.activeElement instanceof HTMLElement?document.activeElement:null;
    const current=dialog.current!;current.showModal();
    return ()=>{current.close();previous?.focus();};
  },[]);
  return <dialog ref={dialog} aria-labelledby="confirm-title" onCancel={event=>{event.preventDefault();onCancel();}}>
    <h2 id="confirm-title">{t("Confirm")} {action==='simulation-records'?t("evidence recording"):t(action)}</h2>{action==='discard'?<p>{t('Remove this policy from the working list? It cannot be activated afterward. Audit history and test evidence are retained.')} <strong>{version}</strong></p>:action==='simulation-records'?<p>{t("Re-evaluate the current samples for policy")} {version}  {t("and save an immutable report with an audit event. The server uses the active baseline at save time, which may differ from a previous comparison. No policy is activated.")}</p>:<p>{t("Apply")} {t(action)}  {t("to policy")} {version}{t("? Activation changes live authorization decisions.")}</p>}
    <div className="actions"><button autoFocus onClick={onCancel}>{t("Cancel")}</button><button onClick={onConfirm}>{t("Confirm")}</button></div>
  </dialog>;
}

function App() {
  const {t}=useI18n();

  const [theme,setTheme]=useState<'dark'|'light'>(()=>localStorage.getItem('tnac-theme')==='light'?'light':'dark');
  useEffect(()=>{
    document.documentElement.dataset.theme=theme;
    localStorage.setItem('tnac-theme',theme);
  },[theme]);
  const [user,setUser]=useState<string|null>(null),[csrf,setCsrf]=useState<string|null>(null);
  const [deviceOperator,setDeviceOperator]=useState(false);
  const [deviceAaaLogs,setDeviceAaaLogs]=useState(false);
  const [mfaRequired,setMfaRequired]=useState(true);
  const [sessionReady,setSessionReady]=useState(false);
  const [accountName,setAccountName]=useState('');
  const [profileRequest,setProfileRequest]=useState(0);
  const [userRevision,setUserRevision]=useState(0);
  const userActions=useMemo<UserActions>(()=>({
    list:after=>api<UserPage>('/api/identities/list'+(after?'?after='+encodeURIComponent(after):''),undefined,csrf),
    update:async input=>{await api('/api/identities/update',input,csrf);},
    remove:async id=>{await api('/api/identities/delete',{user_id:id},csrf);},
    unlock:async id=>{await api('/api/identities/unlock',{user_id:id},csrf);},
    setConsoleAccess:async (id,enabled,access)=>{await api('/api/identities/console-access',{user_id:id,enabled,access},csrf);},
    listDeviceGroups:()=>api<{groups:DeviceGroup[]}>('/api/device-groups')
  }),[csrf]);
  const identityGroupActions=useMemo<IdentityGroupActions>(()=>({list:after=>api('/api/identity-groups'+(after?'?after='+encodeURIComponent(after):''),undefined,csrf),save:async payload=>{const result=await api('/api/identity-groups',payload,csrf);try{setInventory(await api<Inventory>('/api/inventory'));}catch{/* Suggestions are optional; the mutation already succeeded. */}return result;}}),[csrf]);
  const groupActions=useMemo<GroupActions>(()=>({list:()=>api<{groups:DeviceGroup[]}>('/api/device-groups'),save:payload=>api('/api/device-groups',payload)}),[csrf]);
  const [inventory,setInventory]=useState<Inventory|null>(null);
  const deviceScope=useRef(0);
  const [devices,setDevices]=useState<Devices|null>(null);
  useEffect(()=>{if(user===null)setDevices(null);},[user]);
  const [busy,setBusy]=useState(false),[notice,setNotice]=useState('Checking session…'),[error,setError]=useState(false);
  useEffect(()=>{
    if(!user||!actionFeedback(notice,error))return;
    const timer=window.setTimeout(()=>setNotice(''),6000);
    return ()=>window.clearTimeout(timer);
  },[user,notice,error]);
  const working=useRef(false);
  const policyPages=useCursorPages<number>();
  const evidencePages=useCursorPages<string>();
  const [policies,setPolicies]=useState<Page<Policy>>({items:[],next_before:null});
  const [version,setVersion]=useState(''),[policy,setPolicy]=useState<Policy|null>(null);
  const [rules,setRules]=useState<RuleDraft[]>(initialRules),[cases,setCases]=useState(initialCases);
  const [editingRevision,setEditingRevision]=useState<number|null>(null);
  const [pending,setPending]=useState<string|null>(null);
  const [impact,setImpact]=useState<Impact|null>(null);
  const [evidenceId,setEvidenceId]=useState<string|null>(null);
  const [evidencePage,setEvidencePage]=useState<EvidencePage|null>(null),[storedReport,setStoredReport]=useState<EvidenceRecord|null>(null);
  const [replay,setReplay]=useState<ReplayResult|null>(null);
  useEffect(()=>{setReplay(null);},[version,cases,storedReport]);
  useEffect(()=>{setEvidencePage(null);setStoredReport(null);},[version]);
  useEffect(()=>{setImpact(null);setEvidenceId(null);},[version,cases]);
  function signedOut(){deviceScope.current++;setDevices(null);setInventory(null);setUser(null);setCsrf(null);setDeviceOperator(false);setDeviceAaaLogs(false);setPolicy(null);setImpact(null);setEvidenceId(null);setEvidencePage(null);setStoredReport(null);setPolicies({items:[],next_before:null});}
  async function api<T>(path:string,body?:unknown,key=csrf):Promise<T>{
    const headers:Record<string,string>={};
    if(body!==undefined){headers['Content-Type']='application/json';if(key)headers['X-CSRF-Token']=key;}
    const response=await fetch(path,{method:body===undefined?'GET':'POST',body:body===undefined?undefined:JSON.stringify(body),headers,credentials:'same-origin',cache:'no-store'});
    if(!(response.headers.get('Content-Type')||'').toLowerCase().startsWith('application/json'))throw new Error('Administration service unavailable. Verify the HTTPS runtime and configuration.');
    let result;try{result=await response.json();}catch{throw new Error('Invalid service response. Please try again later.');}
    if(!response.ok){if(response.status===401)signedOut();throw new Error(result.error||'Request failed');}
    return result as T;
  }
  async function refreshDevices(query='?limit='+PAGE_SIZE){
    const scope=deviceScope.current;
    const result=await api<Devices>('/api/devices'+query,undefined,csrf);
    if(scope===deviceScope.current){setDevices(result);return result;}
  }
  async function work(action:()=>Promise<void>){if(working.current)return;working.current=true;setBusy(true);setError(false);try{await action();}catch(e){setNotice(e instanceof Error?e.message:'Service unavailable');setError(true);}finally{working.current=false;setBusy(false);}}
  async function listPolicies(number=1,preserve=false){const before=policyPages.cursor(number);const result=await api<Page<Policy>>('/api/policies?limit='+PAGE_SIZE+(before?`&before=${before}`:''));setPolicies(result);policyPages.accept(number,result.next_before,preserve);}
  async function loadPolicy(id=version){if(!id)throw new Error('Enter a policy version ID.');setImpact(null);setEvidenceId(null);setEvidencePage(null);setStoredReport(null);setPolicy(await api<Policy>(`/api/policies/${encodeURIComponent(id)}`));setVersion(id);}
  async function editPolicy(id:string){const source=await api<Policy&{rules:ReturnType<typeof compileRules>}>(`/api/policies/${encodeURIComponent(id)}`);setRules(source.rules.map((rule,index)=>({...rule,key:index+1,groups:rule.groups.join('\n'),device_ids:rule.device_ids.join('\n')})));setEditingRevision(source.revision);}
  async function loadEvidence(number=1,preserve=false){
    const before=evidencePages.cursor(number);
    setStoredReport(null);
    const result=await api<EvidencePage>(`/api/policies/${encodeURIComponent(version)}/simulation-records?limit=50${before?`&before=${encodeURIComponent(before)}`:''}`);
    setEvidencePage(result);evidencePages.accept(number,result.next_before,preserve);
    setNotice('Stored evidence summaries loaded. Integrity has not been verified.');
  }
  async function inspectEvidence(id:string){setStoredReport(null);setStoredReport(await api<EvidenceRecord>(`/api/policies/${encodeURIComponent(version)}/simulation-records/${encodeURIComponent(id)}`));setNotice('Historical report loaded. It does not describe the current form inputs.');}
  async function replayEvidence(){setReplay(null);if(!storedReport)throw new Error('Open a stored report first.');setReplay(await api<ReplayResult>(`/api/policies/${encodeURIComponent(version)}/simulation-records/${encodeURIComponent(storedReport.report_id)}/verify`,{samples:compileSamples(cases)}));setNotice('Recorded-version replay completed. Provenance and signatures have not been verified.');}
async function session(){const result=await api<{user_id:string;csrf_token:string;device_operator?:boolean;device_aaa_logs?:boolean}>('/api/session');setDeviceOperator(result.device_operator===true);setDeviceAaaLogs(result.device_aaa_logs===true);setUser(result.user_id);setCsrf(result.csrf_token);try{const data=await api<Inventory>('/api/inventory');setInventory(data);setAccountName(data.users.find(item=>item.id===result.user_id)?.username??'');}catch{setAccountName('');}if(!result.device_operator)await listPolicies();setNotice('Authenticated session.');}
useEffect(()=>{void work(async()=>{const options=await api<{mfa_required:boolean}>('/api/login-options');setMfaRequired(options.mfa_required!==false);try{await session();}catch(e){signedOut();if(e instanceof Error&&e.message==='authentication required'){setNotice('Sign in to manage this appliance.');return;}throw e;}}).finally(()=>setSessionReady(true));},[]);
  function login(event:FormEvent<HTMLFormElement>){event.preventDefault();const form=event.currentTarget;const values=Object.fromEntries(new FormData(form));void work(async()=>{try{await api('/api/login',values);await session();}finally{(form.elements.namedItem('password') as HTMLInputElement).value='';const code=form.elements.namedItem('code') as HTMLInputElement|null;if(code)code.value='';}});}
  function changePassword(event:FormEvent<HTMLFormElement>){event.preventDefault();const form=event.currentTarget;const values=Object.fromEntries(new FormData(form));if(values.new_password!==values.confirm_password){setNotice('New password confirmation does not match.');setError(true);form.reset();return;}void work(async()=>{try{await api('/api/password',{current_password:values.current_password,new_password:values.new_password});signedOut();setNotice('Password changed. Sign in again with your new password.');}finally{form.reset();}});}
  async function transition(action:string){if(action==='discard'){await api(`/api/policies/${encodeURIComponent(version)}/discard`,{});setVersion('');setPolicy(null);setImpact(null);setEvidencePage(null);setStoredReport(null);await listPolicies();setNotice('Changes saved.');return;}const result=await api<{version_id?:string;total?:number}>(`/api/policies/${encodeURIComponent(version)}/${action}`,action==='test'?{cases:compileCases(cases)}:{});await loadPolicy(result.version_id||version);await listPolicies();setNotice(action==='test'?`${result.total} policy tests passed.`:`Policy ${action} committed.`);}
  async function saveEvidence(){setImpact(null);setEvidenceId(null);const result=await api<{report_id:string;report:Impact}>(`/api/policies/${encodeURIComponent(version)}/simulation-records`,{samples:compileSamples(cases)});setImpact(result.report);setEvidenceId(result.report_id);setEvidencePage(null);setStoredReport(null);setNotice('Simulation evidence and audit event committed. No policy state changed.');}
  function action(name:string){if(!version){setNotice('Enter a policy version ID.');setError(true);return;}if(['approve','activate','rollback','discard'].includes(name)){setPending(name);return;}void work(()=>transition(name));}
  const policySelector=<label>{t('Policy version')}<select value={policies.items.some(item=>item.version_id===version)?version:''} disabled={busy} onChange={event=>{const id=event.target.value;if(id)void work(()=>loadPolicy(id));}}><option value="">{t('Choose a policy version')}</option>{policies.items.map(item=><option key={item.version_id} value={item.version_id}>{t('Revision')} {item.revision} · {t(item.state)}</option>)}</select></label>;
  if(!sessionReady)return <main className="session-loading" aria-busy="true"><span role="status">{t("Loading…")}</span></main>;
return <><header className={user?"app-header":"login-header"}><span className="brand">TACACS<span>+</span></span><span>{t("Administration")}</span><LanguageSwitcher/><button type="button" className="secondary theme-toggle" onClick={()=>setTheme(theme==='dark'?'light':'dark')}>{t(theme==='dark'?'Light mode':'Dark mode')}</button>{user&&<AccountMenu name={accountName||t("Account")} busy={busy} onProfile={()=>setProfileRequest(value=>value+1)} onSignOut={()=>void work(async()=>{await api('/api/logout',{});signedOut();setNotice('Signed out.');})}/>}</header><main className={user?"app-main":"login-page"}>
    {!user&&<LoginStars/>}
{!user?<div className="login-layout">
      <div className="login-art">
        <img src="/login-tnac.svg" width={1000} height={480} alt="TNAC+"/>
      </div>
      <section className="card" id="login-panel"><h2>{t("Sign in")}</h2><form onSubmit={login}><label>{t("Username")}<input autoCapitalize="none" spellCheck={false} placeholder={t("Enter username")} name="username" autoComplete="username" required maxLength={253}/></label><label>{t("Password")}<input placeholder={t("Enter password")} name="password" type="password" autoComplete="current-password" required maxLength={1024}/></label>{mfaRequired&&<><label>{t("MFA factor ID")}<input name="factor_id" placeholder={t("Enrolled factor UUID")} required/></label><label>{t("Authenticator code")}<input name="code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" minLength={6} maxLength={6} required/></label></>}<button disabled={busy}>{busy?t("Signing in…"):t("Sign in")}</button></form></section></div>:<>
    <Workspace currentUser={user} deviceOperator={deviceOperator} deviceAaaLogs={deviceAaaLogs} onRevealDevice={async (address,password)=>(await api<{secret:string}>('/api/devices/secret',{address,password},csrf)).secret} identityGroupActions={identityGroupActions} onDeleteDevice={async address=>{const scope=deviceScope.current;await api('/api/devices/delete',{address},csrf);if(scope===deviceScope.current)await refreshDevices('?'+new URLSearchParams({limit:String(PAGE_SIZE),search:devices?.search??'',status:devices?.status??'all',location_id:devices?.location_id??'',device_type_id:devices?.device_type_id??''}));setNotice('Action completed.');}} groupActions={groupActions} userActions={userActions} userRevision={userRevision} profileRequest={profileRequest} inventory={inventory} busy={busy} mfaRequired={mfaRequired} policyCount={policies.items.length} onRefresh={()=>void work(async()=>{setInventory(await api<Inventory>('/api/inventory'));setNotice('Local identity inventory loaded.');})}
      loadLogs={(query,report)=>api<LogPage|LogReport>((report?'/api/reports?':'/api/logs?')+query)} loadAccounting={query=>api<AccountingPage>('/api/accounting?'+query)} loadDeployment={()=>api<Deployment>('/api/deployment')} loadDashboard={()=>api<DashboardData>('/api/dashboard')}
      devices={devices} onLoadDevices={async query=>{let result:Devices|undefined;await work(async()=>{result=await refreshDevices(query);setNotice('Managed device configuration loaded.');});return result;}}
      onSaveDevice={async payload=>{const scope=deviceScope.current;setError(false);try{await api('/api/devices',payload,csrf);}catch(error){setNotice('Unable to save device. Check fields and permissions.');setError(true);throw error;}if(scope===deviceScope.current)await refreshDevices('?'+new URLSearchParams({limit:String(PAGE_SIZE),search:devices?.search??'',status:devices?.status??'all',location_id:devices?.location_id??'',device_type_id:devices?.device_type_id??''}));setNotice('Saved to database. Runtime acknowledgement and switch connectivity have not been verified.');}}
      onCreateIdentity={async payload=>{await api('/api/identities',payload,csrf);try{setInventory(await api<Inventory>('/api/inventory'));}catch{/* Keep successful creation independent of suggestions. */}setUserRevision(value=>value+1);setNotice('Action completed.');}}
      onIdentityState={payload=>work(async()=>{await api('/api/identities/state',payload,csrf);setInventory(await api<Inventory>('/api/inventory'));setNotice('Device user state committed with audit event.');})}>
    {profileLayout({jsx,jsxs,t,name:accountName||t("Account"),mfaRequired,passwordForm:<form onSubmit={changePassword}><p>{t("Use 12+ characters with A–Z, a–z, 0–9 and a symbol. Changing your password signs you out.")}</p><label>{t("Current password")}<input name="current_password" type="password" autoComplete="current-password" required maxLength={1024} disabled={busy}/></label><label>{t("New password")}<input name="new_password" type="password" autoComplete="new-password" required pattern={"(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[\\x21-\\x2f\\x3a-\\x40\\x5b-\\x60\\x7b-\\x7e]).{12,1024}"} minLength={12} maxLength={1024} disabled={busy}/></label><label>{t("Confirm new password")}<input name="confirm_password" type="password" autoComplete="new-password" required minLength={12} maxLength={1024} disabled={busy}/></label><button disabled={busy}>{t("Change password")}</button></form>,languageControl:<LanguageSwitcher/>})}
    <div data-page="policies"><PolicyVersions items={policies.items} user={user} busy={busy} pageNumber={policyPages.page} lastPage={policyPages.last} onPage={number=>void work(()=>listPolicies(number,true))} nextBefore={null} onRefresh={()=>void work(()=>listPolicies())} onOlder={()=>{}} onLoad={id=>void work(async()=>{await loadPolicy(id);window.location.hash='/policy-workflow';})} onEdit={id=>void work(async()=>{await editPolicy(id);window.location.hash='/policy-editor';})} onDelete={id=>{setVersion(id);setPending('discard');}}/></div>
    <section data-page="policy-editor" className="card"><h2 data-ui-key="Create a policy draft">{t("Create a policy draft")}</h2><p>{t("Drafts are immutable. Test before submitting for independent approval.")}</p><form onSubmit={event=>{event.preventDefault();void work(async()=>{const result=await api<{version_id:string}>('/api/policies',{rules:compileRules(rules)});await loadPolicy(result.version_id);await listPolicies();setEditingRevision(null);setNotice('Immutable draft created. Run tests before submitting.');window.location.hash='/policy-workflow';});}}>{editingRevision!==null&&<p className="notice">{t('Editing a copy of revision')} {editingRevision}. {t('Saving creates a new draft; the original and its history remain unchanged.')} <button type="button" className="secondary" disabled={busy} onClick={()=>{setEditingRevision(null);setRules(initialRules);}}>{t('Cancel edit')}</button></p>}<RuleEditor rows={rules} onChange={setRules} disabled={busy}/><button disabled={busy}>{t("Create draft")}</button></form></section>
    <section data-page="policy-workflow" className="card"><h2 data-ui-key="Policy workflow">{t("Policy workflow")}</h2><form onSubmit={event=>{event.preventDefault();void work(()=>loadPolicy());}}><label>{t("Version ID")}<input disabled={busy} value={version} onChange={event=>{setVersion(event.target.value);setPolicy(null);setNotice('Policy version selection changed. Load the version to inspect its metadata.');}} required placeholder={t("Policy version UUID")}/></label><button className="secondary" disabled={busy}>{t("Load policy")}</button></form>{policy&&<dl>{Object.entries(policy).filter(([key])=>['version_id','revision','state','author_id','approver_id'].includes(key)).map(([key,value])=><div key={key}><dt>{t(key.replaceAll('_',' '))}</dt><dd>{t(String(value??'—'))}</dd></div>)}</dl>}<CaseEditor rows={cases} onChange={setCases} disabled={busy}/><div className="actions">{['test','submit','approve','activate','rollback'].map(name=><button key={name} disabled={busy} onClick={()=>action(name)}>{({test:t("Run tests"),submit:t("Submit"),approve:t("Approve"),activate:t("Activate"),rollback:t("Create rollback draft")})[name]}</button>)}</div><p className="hint">{t("Permissions and state transitions are enforced by the server. The author cannot approve their own draft. Rollback requires the same gates.")}</p></section>
    <section data-page="policy-simulation" className="card"><h2 data-ui-key="Policy simulation">{t("Policy simulation")}</h2>{policySelector}<CaseEditor rows={cases} onChange={setCases} disabled={busy}/><p>{t("Compare the selected version with the active policy using the current test-case inputs. Expected results are ignored for simulation; no policy is activated.")}</p><div className="actions"><button disabled={busy||!version} onClick={()=>void work(async()=>{setImpact(null);setEvidenceId(null);setImpact(await api<Impact>(`/api/policies/${encodeURIComponent(version)}/simulate`,{samples:compileSamples(cases)}));setNotice('Read-only sampled comparison completed.');})}>{t("Compare with active policy")}</button><button className="secondary" disabled={busy||!version} onClick={()=>setPending('simulation-records')}>{t("Save simulation evidence")}</button></div><p className="hint">{t("Comparison is read-only. Saving requires policy.draft permission and records a fresh snapshot, sample digests and an audit event, not raw sample commands. Sampled evidence does not replace regression tests or independent approval.")}</p>{evidenceId&&<p>{t("Committed evidence ID:")} <code>{evidenceId}</code></p>}{impact&&<ImpactView impact={impact}/>}</section>
    <div data-page="policy-evidence"><section className="card">{policySelector}<a href="#/policy-workflow">{t("Policy workflow")}</a></section><EvidenceView version={version} page={evidencePage} record={storedReport} busy={busy} replay={replay} onReplay={()=>void work(()=>replayEvidence())} onRefresh={()=>void work(()=>loadEvidence())} pageNumber={evidencePages.page} lastPage={evidencePages.last} onPage={number=>void work(()=>loadEvidence(number,true))} onOlder={()=>{}} onInspect={id=>void work(()=>inspectEvidence(id))} onClear={()=>setStoredReport(null)}/></div>
    </Workspace></>}
    <p id="message" hidden={!notice||!actionFeedback(notice,error)} className={(user?'ops-toast ':'')+(error?'error':'')} role="status" aria-live="polite">{t(actionFeedback(notice,error))}</p>
    {pending&&<Confirmation action={pending} version={pending==='discard'?`${t("Revision")} ${policies.items.find(item=>item.version_id===version)?.revision??version}`:version} onCancel={()=>setPending(null)} onConfirm={()=>{const name=pending;setPending(null);void work(()=>name==='simulation-records'?saveEvidence():transition(name));}}/>}
  </main></>;
}
createRoot(document.getElementById('root')!).render(<LanguageProvider><App/></LanguageProvider>);
