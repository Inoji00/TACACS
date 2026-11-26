import {PagedTable,PageButtons,useCursorPages} from './pagination';
import {useCallback,useEffect,useRef,useState,type FormEvent} from 'react';
import {useI18n} from './i18n';
import {InfoTip} from './info-tip';
type Group={id:string;name:string;members:number;devices:number;policies:number;editable:boolean};
export type IdentityGroupActions={list:(after?:string)=>Promise<{groups:Group[];next_after:string|null}>;save:(payload:Record<string,unknown>)=>Promise<unknown>};
export function IdentityGroupDirectory({actions,revision=0}:{actions:IdentityGroupActions;revision?:number}){
  const {t}=useI18n(),[groups,setGroups]=useState<Group[]>([]),[selected,setSelected]=useState<Group|null>(null),[deleting,setDeleting]=useState<Group|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState(false),[formKey,setFormKey]=useState(0);
  const [editing,setEditing]=useState(false);
  const pages=useCursorPages<string>();
  const generation=useRef(0);
  const load=useCallback(async(cursor?:string,number=1)=>{const request=++generation.current;setBusy(true);setError(false);try{const page=await actions.list(cursor);if(request===generation.current){setGroups(page.groups);pages.accept(number,page.next_after);}}catch{if(request===generation.current)setError(true);}finally{if(request===generation.current)setBusy(false);}},[actions]);
  useEffect(()=>{void load();return()=>{generation.current++;};},[load,revision]);
  async function mutate(payload:Record<string,unknown>){setBusy(true);setError(false);try{await actions.save(payload);setSelected(null);setEditing(false);setDeleting(null);setFormKey(key=>key+1);await load();}catch{setError(true);setBusy(false);}}
  function submit(event:FormEvent<HTMLFormElement>){event.preventDefault();const values=new FormData(event.currentTarget);void mutate(selected?{operation:'rename',id:selected.id,name:String(values.get('name'))}:{operation:'create',name:String(values.get('name'))});}
  return <section className={editing?"card configuration-editor":"card"}>{!editing&&<><div className="section-heading"><h2>{t('Identity groups')} <InfoTip label={t('Identity groups')}>{t('Create groups before assigning users or switch access. Referenced groups cannot be renamed or deleted; move users and mappings first. Policy history references remain protected.')}</InfoTip></h2><div className="actions"><button disabled={busy} onClick={()=>{setSelected(null);setDeleting(null);setEditing(true);setFormKey(key=>key+1);}}>{t("Create identity group")}</button><button className="secondary" disabled={busy} onClick={()=>void load()}>{t('Refresh')}</button></div></div>

    <div className="table-scroll"><PagedTable><thead><tr><th>{t('Name')}</th><th>{t('Users')}</th><th>{t('Switches')}</th><th>{t('Policy references')}</th><th>{t('Action')}</th></tr></thead><tbody>{groups.map(group=><tr key={group.id}><td>{group.name}</td><td>{group.members}</td><td>{group.devices}</td><td>{group.policies}</td><td><div className="actions"><button className="secondary" disabled={busy||!group.editable} onClick={()=>{setSelected(group);setEditing(true);setDeleting(null);setFormKey(key=>key+1);}}>{t('Edit')}</button><button className="secondary" disabled={busy||!group.editable} onClick={()=>setDeleting(group)}>{t('Delete')}</button></div></td></tr>)}</tbody></PagedTable></div>
    <PageButtons page={pages.page} last={pages.last} busy={busy} onPage={number=>void load(pages.cursor(number),number)}/>
    {deleting&&<div className="notice">{t('Delete unused group?')} <strong>{deleting.name}</strong><div className="actions"><button disabled={busy} onClick={()=>void mutate({operation:'delete',id:deleting.id})}>{t('Confirm delete')}</button><button className="secondary" disabled={busy} onClick={()=>setDeleting(null)}>{t('Cancel')}</button></div></div>}
    </>}
    {error&&<p className="notice" role="alert">{t('Group operation failed. Check permissions, duplicate names and dependencies.')}</p>}
    {editing&&<><div className="section-heading"><h2>{t(selected?'Rename unused group':'Create identity group')}</h2><button className="secondary" disabled={busy} onClick={()=>{setSelected(null);setEditing(false);setError(false);}}>{t('Back to list')}</button></div><form key={formKey} onSubmit={submit}><label>{t(selected?'Rename unused group':'Create identity group')}<input name="name" defaultValue={selected?.name??''} required pattern="[A-Za-z0-9_.-]{1,64}" maxLength={64} disabled={busy}/></label><div className="actions"><button disabled={busy}>{t('Save changes')}</button>{<button type="button" className="secondary" disabled={busy} onClick={()=>{setSelected(null);setEditing(false);setFormKey(key=>key+1);}}>{t('Cancel edit')}</button>}</div></form></>}
  </section>;
}
