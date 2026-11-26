import {PagedTable,PageButtons,PAGE_SIZE,useCursorPages} from './pagination';
import {vietnamTime} from './audit-time';
import {useI18n} from './i18n';
import {useEffect,useRef,useState,type FormEvent} from 'react';
import {SharedSecretField} from './shared-secret-field';
import {InfoTip} from './info-tip';
import {AccessMappings,type AccessMapping} from './access-mappings';
import {groupPath,type DeviceAction,type DeviceGroup,type DeviceScope} from './device-group-model';
export type Device={address:string;name:string;enabled:boolean;shell_group:string;privilege:number;saved_at?:string;access_mappings?:AccessMapping[];description?:string;location_id?:string|null;device_type_id?:string|null;revision?:number;runtime_revision?:number|null;runtime_state?:string;runtime_observed_at?:string|null};
export type Devices={devices:Device[];truncated:boolean;application:string;transport:string;next_after?:string|null;search?:string;status?:string;location_id?:string;device_type_id?:string;access?:DeviceScope|null};
export type DeviceInput=Device&{secret:string;operation?:'create'|'edit'};
export function DeviceManager({busy:externalBusy,devices,onLoad,onSave,onDelete,onReveal,groups=[],identityGroups=[],initialView='list'}:{identityGroups?:string[];initialView?:'list'|'create';onDelete?:(address:string)=>Promise<void>;onReveal?:(address:string,password:string)=>Promise<string>;groups?:DeviceGroup[];busy:boolean;devices:Devices|null;onLoad:(query?:string)=>void|Promise<Devices|undefined>;onSave:(payload:DeviceInput)=>Promise<void>}){
  const {t}=useI18n();

  const [editing,setEditing]=useState(initialView==='create'),[saving,setSaving]=useState(false),[saveError,setSaveError]=useState(false);
  const [selected,setSelected]=useState<Device|null>(null),[revision,setRevision]=useState(0);
  const [removal,setRemoval]=useState<Device|null>(null),[removing,setRemoving]=useState(false),[removeError,setRemoveError]=useState(false);
  const busy=externalBusy||removing||saving;
  const access=devices?.access;
  const creationAddresses=selected?[]:access?.creation_addresses??[];
  const can=(action:DeviceAction)=>!access||access.actions.includes(action);
  const canModify=can('edit')||can('set_enabled')||can('rotate_secret')||can('edit_mappings');
  const canOpen=canModify||(can('reveal_secret')&&!!onReveal);
  const [search,setSearch]=useState(devices?.search??''),[status,setStatus]=useState(devices?.status??'all');
  const [location,setLocation]=useState(devices?.location_id??''),[deviceType,setDeviceType]=useState(devices?.device_type_id??'');
  const [dirty,setDirty]=useState(false),[rotate,setRotate]=useState<DeviceInput|null>(null);
  const searchInput=useRef<HTMLInputElement>(null),rotationDialog=useRef<HTMLDialogElement>(null);
  useEffect(()=>{if(rotate&&!rotationDialog.current?.open)rotationDialog.current?.showModal();},[rotate]);
  useEffect(()=>{
    function shortcut(event:KeyboardEvent){
      if(!editing&&(event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'){
        event.preventDefault();
        searchInput.current?.focus();
      }
    }
    window.addEventListener('keydown',shortcut);
    return ()=>window.removeEventListener('keydown',shortcut);
  },[editing]);
  useEffect(()=>{
    if(!dirty)return;
    const route=window.location.hash;
    function leave(event:BeforeUnloadEvent){event.preventDefault();event.returnValue='';}
    function routeChange(){
      if(window.location.hash!==route&&!window.confirm(t('Discard unsaved changes?'))){
        window.history.replaceState(null,'',route||window.location.pathname+window.location.search);
      }
    }
    window.addEventListener('beforeunload',leave);
    window.addEventListener('hashchange',routeChange,true);
    return ()=>{window.removeEventListener('beforeunload',leave);window.removeEventListener('hashchange',routeChange,true);};
  },[dirty,t]);
  function openEditor(device:Device|null){
    setSelected(device);
    setDirty(false);setEditing(true);setSaveError(false);setRevision(value=>value+1);
  }
  function closeEditor(){
    if(dirty&&!window.confirm(t('Discard unsaved changes?')))return;
    setDirty(false);setSelected(null);setEditing(false);setSaveError(false);
  }
  const pages=useCursorPages<string>();
  async function list(number=1,keepFilters=false){
    const query=new URLSearchParams({
      search:keepFilters?devices?.search??'':search,
      status:keepFilters?devices?.status??'all':status,
      location_id:keepFilters?devices?.location_id??'':location,
      device_type_id:keepFilters?devices?.device_type_id??'':deviceType,
      limit:String(PAGE_SIZE),
    });
    const after=pages.cursor(number)??(number===2&&pages.page===1?devices?.next_after:undefined);
    if(after)query.set('after',after);
    const result=await onLoad('?'+query.toString());
    if(result)pages.accept(number,result.next_after??null,keepFilters,after??undefined);
  }
  function submit(event:FormEvent<HTMLFormElement>){
    event.preventDefault();
    const form=event.currentTarget;
    const invalid=form.querySelector<HTMLInputElement>(':is(input,select,textarea):invalid:not(dialog input)');
    if(invalid){invalid.reportValidity();return;}
    const data=new FormData(form);
    if(selected?!canModify:!can('create'))return;
    const payload:DeviceInput={operation:selected?'edit':'create',address:String(data.get('address')),name:String(data.get('name')),enabled:can('set_enabled')?data.get('enabled')==='on':selected?.enabled??false,shell_group:can('edit_mappings')?'':selected?.shell_group??'',privilege:can('edit_mappings')?1:selected?.privilege??1,access_mappings:can('edit_mappings')?JSON.parse(String(data.get('access_mappings'))):selected?.access_mappings??[],secret:String(data.get('secret')??''),description:String(data.get('description')),location_id:String(data.get('location_id')??selected?.location_id??access?.location_id??'')||null,device_type_id:String(data.get('device_type_id')??selected?.device_type_id??access?.device_type_id??'')||null};
    if(selected&&payload.secret){setRotate(payload);return;}
    save(payload);
  }
  function save(payload:DeviceInput){
    setSaving(true);setSaveError(false);void onSave(payload).then(()=>{pages.accept(1,null);setDirty(false);setEditing(false);setSelected(null);setRevision(value=>value+1);}).catch(()=>setSaveError(true)).finally(()=>setSaving(false));
  }
  return <>
    {!editing&&<>
    <section className="card"><div className="section-heading"><h2>{t("Registered devices")} <InfoTip label={t("Device inventory")}>{t("Only managed registry entries appear here. Startup-config clients remain separate. Saving the same source IP overrides that registration; disabling it blocks it. Changes apply to new requests, not existing SSH sessions.")}{onDelete&&can('delete')&&<span className="tooltip-paragraph">{t('Disable a switch before deleting it. Removal preserves an IP block and audit history; re-adding requires a new shared secret.')}</span>}</InfoTip></h2><div className="actions">{devices&&can('create')&&<button disabled={busy} onClick={()=>openEditor(null)}>{t("Add device")}</button>}<button className="secondary" disabled={busy} onClick={()=>list()}>{t("Refresh devices")}</button></div></div>
      <form className="list-toolbar device-toolbar" onSubmit={event=>{event.preventDefault();list();}}><label>{t('Search devices')}<input ref={searchInput} aria-keyshortcuts="Control+K Meta+K" value={search} maxLength={64} disabled={busy} onChange={event=>setSearch(event.target.value)} placeholder={t('Name or source IP')}/></label>{(['location','device_type'] as const).map(kind=><label key={kind}>{t(kind==='location'?'Location':'Device Type')}
        <select disabled={busy} value={kind==='location'?location:deviceType} onChange={event=>(kind==='location'?setLocation:setDeviceType)(event.target.value)}>
          <option value="">{t('All')}</option>{groups.filter(group=>group.kind===kind).map(group=><option key={group.id} value={group.id}>{groupPath(groups,group.id)}</option>)}
        </select></label>)}<label>{t('Status')}<select value={status} disabled={busy} onChange={event=>setStatus(event.target.value)}><option value="all">{t('All statuses')}</option><option value="enabled">{t('Enabled')}</option><option value="disabled">{t('Disabled')}</option></select></label><button className="secondary" disabled={busy}>{t('Search')}</button></form>
      {!devices?<div className="empty-state">{t("Refresh to load registered switches.")}</div>:devices.devices.length===0?<div className="empty-state">{t('No devices match this search.')}</div>:<div className="table-scroll"><PagedTable className="device-list">
        <thead><tr>{['Name','Source IP','Device Type','Protocol','Location','Status'].map(label=><th key={label} scope="col">{t(label)}</th>)}
          {(canOpen||(onDelete&&can('delete')))&&<th scope="col">{t('Actions')}</th>}</tr></thead>
        <tbody>{devices.devices.map(item=><tr key={item.address}>
          <td><strong>{item.name}</strong>{item.description&&<small className="device-description">{item.description}</small>}</td>
          <td><code className="device-ip">{item.address}</code></td>
          <td>{groupPath(groups,item.device_type_id)||'—'}</td>
          <td><span className="badge device-protocol">{'TACACS+'}</span></td>
          <td>{groupPath(groups,item.location_id)||'—'}</td>
          <td><span className={'badge '+(item.enabled?'status-enabled':'status-disabled')}>{t(item.enabled?'Enabled':'Disabled')}</span></td>
          {(canOpen||(onDelete&&can('delete')))&&<td><div className="actions device-actions">
            {canOpen&&<button type="button" className="secondary" disabled={busy} onClick={()=>openEditor(item)}>{t(canModify?'Edit':'View saved key')}</button>}
            {onDelete&&can('delete')&&<button type="button" className="secondary device-delete" disabled={busy||item.enabled}
              title={item.enabled?t('Disable this device before deleting it.'):undefined}
              onClick={()=>{setRemoval(item);setRemoveError(false);}}>{t('Delete')}</button>}
          </div></td>}
        </tr>)}</tbody></PagedTable></div>}
      <PageButtons page={pages.page} last={Math.max(pages.last,devices?.next_after?pages.page+1:1)} busy={busy} onPage={number=>void list(number,true)}/>

    </section>
    {removeError&&<p className="notice" role="alert">{t('Unable to remove device. Disable it first and check permissions.')}</p>}
    {removal&&onDelete&&<div className="notice">{t('Remove this disabled switch?')} <strong>{removal.name} · {removal.address}</strong><div className="actions"><button className="danger" disabled={removing} onClick={()=>{setRemoving(true);void onDelete(removal.address).then(()=>{pages.accept(1,null);setRemoval(null);setSelected(null);setRevision(value=>value+1);}).catch(()=>setRemoveError(true)).finally(()=>setRemoving(false));}}>{t('Confirm delete')}</button><button className="secondary" disabled={removing} onClick={()=>setRemoval(null)}>{t('Cancel')}</button></div></div>}
    </>}
    {editing&&<section className="card configuration-editor device-editor">
      <div className="section-heading">
        <h2>{selected?selected.name:t('Add device')}</h2>
        <button type="button" className="secondary" disabled={busy} onClick={closeEditor}>{t('Back to list')}</button>
      </div>
      {saveError&&<p className="error" role="alert">{t("Unable to save device. Check fields and permissions.")}</p>}
      <form key={revision} noValidate onSubmit={submit} onChange={()=>setDirty(true)}>
        <div className="device-editor-grid">
        <div className="device-editor-fields"><h3>{t('Device details')}</h3>
        <div className="form-columns"><label>{t("Device name")}<input name="name" defaultValue={selected?.name??''} pattern="[A-Za-z0-9_. \-]{1,64}" required maxLength={64} readOnly={!!selected&&!can('edit')} disabled={busy} placeholder="SW-LAB-01"/></label>
        <label><span className="field-caption">{t("Source IPv4")} <InfoTip label={t("Source IPv4")}>{t("Use the switch interface IP that sends TACACS+ packets, not the server IP. This IP is also the device ID used by command policies. To change an existing IP, create a new entry and disable the old one.")}</InfoTip></span>
          {creationAddresses.length>0
            ? <select aria-label={t('Source IPv4')} name="address" defaultValue="" required disabled={busy}>
                <option value="" disabled>{t('Select an approved IP')}</option>
                {creationAddresses.map(address=><option key={address} value={address}>{address}</option>)}
              </select>
            : <input aria-label={t("Source IPv4")} name="address" defaultValue={selected?.address??''} readOnly={!!selected} required disabled={busy} placeholder="192.168.100.2"/>}
        </label></div>
        <label>{t('Description')}<textarea name="description" maxLength={256} defaultValue={selected?.description??''} readOnly={!!selected&&!can('edit')} disabled={busy}/></label>
        <div className="form-columns">{(['location','device_type'] as const).map(kind=>{
          const field=kind==='location'?'location_id':'device_type_id';
          return <label key={kind}><span className="field-caption">{t(kind==='location'?'Location':'Device Type')} <InfoTip label={t('Network device groups')}>{t('Shell identity groups and Access Policies control permissions separately.')}</InfoTip></span><select name={field} defaultValue={selected?.[field]??access?.[field]??''} disabled={busy||!!access?.[field]||(!!selected&&!can('edit'))}><option value="">{t('Unassigned')}</option>{groups.filter(group=>group.kind===kind).map(group=><option key={group.id} value={group.id}>{groupPath(groups,group.id)}</option>)}</select></label>;
        })}</div>
        </div><div className="device-editor-protocol"><h3>{t('Protocol support')}</h3>
        <div className="device-protocol-row">
          <label className="device-protocol-toggle">
            <input name="enabled" type="checkbox" role="switch" aria-label={t('Enable TACACS+')} defaultChecked={selected?.enabled??false} disabled={busy||!can('set_enabled')}/>
            <span>{'TACACS+'}</span>
          </label>
          <span className="device-protocol-port">{'TCP/49'}</span>
          <InfoTip label={t('Enable TACACS+')}>{t('After saving, turning this off blocks TACACS+ requests from this device.')}</InfoTip>
        </div>
        {(!selected||can('rotate_secret')||(can('reveal_secret')&&onReveal))&&<SharedSecretField existing={!!selected} busy={busy} readOnly={!!selected&&!can('rotate_secret')} onDraft={()=>setDirty(true)} reveal={selected&&can('reveal_secret')&&onReveal?password=>onReveal(selected.address,password):undefined}/>}
        {selected?.saved_at&&<p className="field-hint device-saved-at">{t('Saved at')} · {vietnamTime(selected.saved_at)}</p>}
        </div></div>
        <AccessMappings groups={identityGroups} initial={selected?.access_mappings??(selected?.shell_group?[{group:selected.shell_group,privilege:selected.privilege,mode:'policy'}]:[])} busy={busy||!can('edit_mappings')} onChange={()=>setDirty(true)}/>
        {selected&&<aside className="device-saved-details"><h3>{t('Saved configuration')}</h3>
          <dl>{[
            [t('Status'),<span className="badge">{t(selected.enabled?'Enabled':'Disabled')}</span>],
            [t('Device name'),selected.name],[t('Source IPv4'),<code>{selected.address}</code>],
            [t('Protocol support'),'TACACS+ · TCP/49'],[t('Location'),groupPath(groups,selected.location_id)||'—'],
            [t('Device Type'),groupPath(groups,selected.device_type_id)||'—'],
            [t('Saved at'),selected.saved_at?vietnamTime(selected.saved_at):'—'],
          ].map(([label,value],index)=><div key={index}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
        </aside>}
        <div className="actions device-editor-footer">
          <button type="button" className="secondary" disabled={busy} onClick={closeEditor}>{t('Cancel')}</button>
          {(selected?canModify:can('create'))&&<button disabled={busy}>{t(selected?'Save changes':'Create device')}</button>}
        </div>
      </form>
    </section>}
    {rotate&&<dialog ref={rotationDialog} aria-label={t('Rotate TACACS+ key')} onClose={()=>setRotate(null)}>
      <h2>{t('Rotate TACACS+ key')}</h2><p>{t('Save the new key for this device?')}</p>
      <div className="actions"><button className="secondary" type="button" onClick={()=>rotationDialog.current?.close()}>{t('Cancel')}</button>
      <button className="danger" type="button" onClick={()=>{rotationDialog.current?.close();save(rotate);}}>{t('Rotate TACACS+ key')}</button></div>
    </dialog>}
  </>;
}
