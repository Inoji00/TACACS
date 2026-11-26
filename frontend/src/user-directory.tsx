import {PagedTable} from './pagination';
import {useCallback,useEffect,useRef,useState,type FormEvent} from 'react';
import {useI18n} from './i18n';
import {InfoTip} from './info-tip';
import {GroupNameInput} from './group-name-input';
import {groupPath,type DeviceGroup,type DeviceAction,type DeviceScope} from './device-group-model';

type User={id:string;username:string;enabled:boolean;locked:boolean;unlockable?:boolean;editable:boolean;groups:string[];console_permissions?:string[];device_access?:DeviceScope|null}
export type UserPage={users:User[];next_after:string|null;command_policy?:{id:string;revision:number}|null};
export type UserUpdate={user_id:string;username:string;password:string;group_name:string;enabled:boolean};
export type UserActions={list:(after?:string)=>Promise<UserPage>;update:(input:UserUpdate)=>Promise<void>;remove:(id:string)=>Promise<void>;unlock?:(id:string)=>Promise<void>;setConsoleAccess?:(id:string,enabled:boolean,access?:DeviceScope)=>Promise<void>;listDeviceGroups?:()=>Promise<{groups:DeviceGroup[]}>};

const deviceActions:Record<DeviceAction,string>={
  create:'Add device',edit:'Edit device details',set_enabled:'Change device status',delete:'Delete device',
  reveal_secret:'View saved key',rotate_secret:'Rotate TACACS+ key',edit_mappings:'Edit CLI mappings',
  view_aaa_logs:'View AAA logs',
};

export function WebAccessCell({permissions=[],self=false,busy,onChange,onEdit,scope}:{permissions?:string[];self?:boolean;busy:boolean;onChange?:(enabled:boolean)=>void;onEdit?:()=>void;scope?:DeviceScope|null}){
  const {t}=useI18n();
  const hasWebAccess=permissions.includes('console.read');
  const hasDeviceAccess=hasWebAccess&&permissions.includes('devices.manage');
  const canDelegate=!self&&permissions.every(permission=>permission==='console.read'||permission==='devices.manage');
  return <td>
    <div className="user-web-access">
      <div className="user-web-access-status">
        {hasWebAccess?<><span className="badge">{t('Console access')}</span>
          {hasDeviceAccess&&canDelegate
            ? <span className="user-web-access-scope">{t(scope?'Scoped device access':'Legacy device access')}</span>
            : <InfoTip label={t('Web permissions')}>{permissions.join(', ')}</InfoTip>}
        </>:t('No console access')}
      </div>
      {canDelegate&&onChange&&<div className="actions">
        {hasDeviceAccess&&onEdit&&<button type="button" className="secondary" disabled={busy} onClick={onEdit}>{t('Edit Web access')}</button>}
        <button type="button" className="secondary" disabled={busy} onClick={()=>onChange(!hasDeviceAccess)}>
          {t(hasDeviceAccess?'Revoke Web access':'Grant device configuration access')}
        </button>
      </div>}
    </div>
  </td>;
}

export function UserDirectory({actions,revision=0,groups=[],currentUser}:{groups?:string[];actions:UserActions;revision?:number;currentUser?:string}){
  const {t}=useI18n();
  const [users,setUsers]=useState<User[]>([]),[busy,setBusy]=useState(false),[error,setError]=useState('');
  const [selected,setSelected]=useState<User|null>(null),[deleting,setDeleting]=useState<User|null>(null);
  const [policy,setPolicy]=useState<{id:string;revision:number}|null>(null);
  const [search,setSearch]=useState('');
  const [webEditor,setWebEditor]=useState<{user:User;groups:DeviceGroup[]}|null>(null);
  const [scopeFilters,setScopeFilters]=useState({location_id:'',device_type_id:''});
  const [canCreate,setCanCreate]=useState(false);
  const limitedScope=!!(scopeFilters.location_id||scopeFilters.device_type_id);
  const generation=useRef(0);
  const load=useCallback(async()=>{
    const request=++generation.current;
    setBusy(true);setError('');
    try{
      const all:User[]=[];
      const seen=new Set<string>();
      let after:string|undefined;
      do{
        const page=await actions.list(after);
        if(request!==generation.current)return;
        if(!after)setPolicy(page.command_policy??null);
        all.push(...page.users);
        after=page.next_after??undefined;
        if(after&&seen.has(after))throw new Error();
        if(after)seen.add(after);
      }while(after);
      setUsers(all.sort((a,b)=>a.username.localeCompare(b.username)));
    }catch{if(request===generation.current)setError('Unable to load users. Try again.');}
    finally{if(request===generation.current)setBusy(false);}
  },[actions]);
  useEffect(()=>{void load();return()=>{generation.current++;};},[load,revision]);
  async function save(event:FormEvent<HTMLFormElement>){
    event.preventDefault();if(!selected)return;
    const data=new FormData(event.currentTarget),password=String(data.get('password'));
    if(password!==String(data.get('confirm_password'))){setError('Passwords do not match.');return;}
    setBusy(true);setError('');
    try{
      await actions.update({user_id:selected.id,username:String(data.get('username')),password,
        group_name:String(data.get('group_name')),enabled:data.get('enabled')==='on'});
      setSelected(null);await load();
    }catch{setError('Unable to update user. Check fields and permissions.');setBusy(false);}
  }
  async function remove(){
    if(!deleting)return;
    setBusy(true);setError('');
    try{await actions.remove(deleting.id);setDeleting(null);await load();}
    catch(error){setError(error instanceof Error&&error.message==='identity protected'?'This account is protected or unavailable. Console accounts and your own account cannot be removed here.':error instanceof Error&&error.message==='permission denied'?'You do not have permission for this action.':'Unable to remove user. Check access permissions and try again.');setBusy(false);}
  }
  async function unlock(user:User){
    if(!actions.unlock||!window.confirm(t('Unlock this account?')+' '+user.username))return;
    setBusy(true);setError('');
    try{await actions.unlock(user.id);await load();}
    catch{setError('Unable to unlock this account.');setBusy(false);}
  }
  async function openWebAccess(user:User){
    if(!actions.listDeviceGroups)return;
    setBusy(true);setError('');
    try{
      const {groups}=await actions.listDeviceGroups();
      setScopeFilters({location_id:user.device_access?.location_id??'',device_type_id:user.device_access?.device_type_id??''});
      setCanCreate(user.device_access?.actions.includes('create')??false);
      setWebEditor({user,groups});
    }
    catch{setError('Unable to load device groups.');}
    finally{setBusy(false);}
  }
  async function changeConsoleAccess(user:User,enabled:boolean,access?:DeviceScope){
    if(!actions.setConsoleAccess)return;
    setBusy(true);setError('');
    try{await actions.setConsoleAccess(user.id,enabled,access);setWebEditor(null);await load();}
    catch{setError('Unable to change Web access.');setBusy(false);}
  }
  function saveWebAccess(event:FormEvent<HTMLFormElement>){
    event.preventDefault();
    if(!webEditor)return;
    const fields=new FormData(event.currentTarget);
    void changeConsoleAccess(webEditor.user,true,{
      location_id:String(fields.get('location_id')??'')||null,
      device_type_id:String(fields.get('device_type_id')??'')||null,
      actions:fields.getAll('actions') as DeviceAction[],
      creation_addresses:String(fields.get('creation_addresses')??'').split(/[\s,]+/).filter(Boolean),
    });
  }
  return <section className={selected||webEditor?"card configuration-editor":"card"}>{!selected&&!webEditor&&<><div className="section-heading"><h2>{t('Local users')} <InfoTip label={t('Remove user')}>{t('Removing a user disables login, removes memberships and hides the account. Audit and policy history are retained. The username remains reserved.')}</InfoTip></h2><div className="actions"><a className="button-link" href="#/user-create">{t("Create device user")}</a><button className="secondary" disabled={busy} onClick={()=>void load()}>{t('Refresh')}</button></div></div>
    <p className="hint">{t('Command policy (optional)')}: {policy?policy.revision:t('None')} <InfoTip label={t('Command policy (optional)')}>{t('EXEC shell privilege is assigned by group mappings. An active policy is needed only for command authorization requests sent here. Group names do not grant rights.')}</InfoTip></p>
    <label className="directory-search">{t('Search users')}<input type="search" value={search} onChange={e=>setSearch(e.target.value)}/></label>

    {busy&&<p role="status">{t('Loading…')}</p>}
    <div className="table-scroll"><PagedTable><thead><tr><th>{t('Username')}</th><th>{t('Identity groups')}</th><th>{t('Web access')}</th><th>{t('Status')}</th><th>{t('Action')}</th></tr></thead><tbody>
      {users.filter(user=>user.username.toLowerCase().includes(search.toLowerCase())).map(user=><tr key={user.id}><td>{user.username}</td><td>{user.groups.join(', ')||'—'}</td>
        <WebAccessCell permissions={user.console_permissions} self={user.id===currentUser} busy={busy}
          scope={user.device_access} onEdit={actions.listDeviceGroups?()=>void openWebAccess(user):undefined}
          onChange={actions.setConsoleAccess?enabled=>{if(enabled)void openWebAccess(user);else void changeConsoleAccess(user,false);}:undefined}/>
        <td>{user.locked?t('Locked'):user.enabled?t('Enabled'):t('Disabled')}</td><td><div className="actions">
        {user.unlockable&&actions.unlock&&<button type="button" className="secondary" disabled={busy} onClick={()=>void unlock(user)}>{t('Unlock')}</button>}<button className="secondary" disabled={busy||!user.editable} onClick={()=>{setDeleting(null);setSelected(user);setError('');}}>{t('Edit')}</button><button className="danger" disabled={busy||!user.editable} onClick={()=>{setSelected(null);setDeleting(user);setError('');}}>{t('Delete')}</button></div></td></tr>)}
    </tbody></PagedTable></div>
    </>}
    {error&&<p role="alert" className="error">{t(error)}</p>}
    {webEditor&&<form className="user-edit" key={webEditor.user.id} onSubmit={saveWebAccess}>
      <div className="section-heading"><h2>{t('Edit Web access')} · {webEditor.user.username}</h2><button type="button" className="secondary" disabled={busy} onClick={()=>{setWebEditor(null);setError('');}}>{t('Back to list')}</button></div>
      <p className="hint">{t('Devices must match both selected filters. Parent groups do not include child groups.')}</p>
      <div className="form-columns">{(['location','device_type'] as const).map(kind=><label key={kind}>{t(kind==='location'?'Location':'Device Type')}
        <select name={kind+'_id'} value={scopeFilters[`${kind}_id`]} disabled={busy} onChange={event=>setScopeFilters({...scopeFilters,[kind+'_id']:event.target.value})}>
          <option value="">{t(kind==='location'?'All Locations':'All Device Types')}</option>
          {webEditor.groups.filter(group=>group.kind===kind).map(group=><option key={group.id} value={group.id}>{groupPath(webEditor.groups,group.id)}</option>)}
        </select></label>)}</div>
      <fieldset className="access-mappings" disabled={busy}><legend>{t('Device actions')}</legend>
        <p className="hint">{t('Leave all actions unchecked for view-only access. Saving Web access ends this user’s current Web sessions.')}</p>
        <div className="form-columns">{(Object.entries(deviceActions) as [DeviceAction,string][]).map(([action,label])=><label key={action} className="checkbox-row">
          {action==='create'
            ? <input type="checkbox" name="actions" value={action} checked={canCreate} onChange={event=>setCanCreate(event.target.checked)}/>
            : <input type="checkbox" name="actions" value={action} defaultChecked={webEditor.user.device_access?.actions.includes(action)??false}/>}
          {t(label)}</label>)}</div>
        {limitedScope&&<label>{t('Approved source IPv4 addresses')}
          <textarea name="creation_addresses" rows={3} maxLength={1024} required={canCreate} disabled={!canCreate}
            defaultValue={webEditor.user.device_access?.creation_addresses?.join('\n')??''}/>
          <span className="field-hint">{t('Enter up to 64 unused TACACS+ source IPv4 addresses assigned to this scope, one per line. Exclude addresses in startup configuration.')}</span>
        </label>}
      </fieldset>
      <div className="actions"><button disabled={busy}>{t('Save changes')}</button></div>
    </form>}
    {selected&&<form key={selected.id} onSubmit={save} className="user-edit"><div className="section-heading"><h2>{t('Edit user')} · {selected.username}</h2><button type="button" className="secondary" disabled={busy} onClick={()=>{setSelected(null);setError('');}}>{t('Back to list')}</button></div>
      <div className="form-columns"><label>{t('Username')}<input name="username" defaultValue={selected.username} required pattern="[A-Za-z0-9_.@-]{1,64}" maxLength={64} disabled={busy}/></label>
      <label>{t('Identity group')}<GroupNameInput groups={groups} name="group_name" defaultValue={selected.groups.length===1?selected.groups[0]:''} required disabled={busy}/></label></div>
      {selected.groups.length>1&&<p className="notice">{t('Saving replaces all memberships with the selected group.')}</p>}
      <div className="form-columns"><label>{t('New password')}<input name="password" type="password" autoComplete="new-password" pattern={"(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[\\x21-\\x2f\\x3a-\\x40\\x5b-\\x60\\x7b-\\x7e]).{12,1024}"} minLength={12} maxLength={1024} disabled={busy}/></label><label>{t('Confirm password')}<input name="confirm_password" type="password" autoComplete="new-password" minLength={12} maxLength={1024} disabled={busy}/></label></div>
      <p className="hint">{t('Leave blank to keep the current password. Use 12+ characters with A–Z, a–z, 0–9 and a symbol.')}</p>
      <label className="checkbox-row"><input type="checkbox" name="enabled" defaultChecked={selected.enabled} disabled={busy}/>{t('Enabled')}</label>
      <div className="actions"><button disabled={busy}>{t('Save changes')}</button><button type="button" className="secondary" disabled={busy} onClick={()=>setSelected(null)}>{t('Back to list')}</button></div>
    </form>}
    {deleting&&<div className="inline-warning" role="alert"><span>{t('Remove this user? Login will be disabled and history retained.')} {deleting.username}</span><button className="danger" disabled={busy} onClick={()=>void remove()}>{t('Confirm delete')}</button><button className="secondary" disabled={busy} onClick={()=>setDeleting(null)}>{t('Cancel')}</button></div>}
  </section>;
}
