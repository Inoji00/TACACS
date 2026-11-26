import {PageButtons} from './pagination';
import {useI18n} from './i18n';
import {InfoTip} from './info-tip';
export type PolicyVersion={version_id:string;revision:number;state:string;author_id:string;approver_id:string|null};
export function PolicyVersions({items,user,busy,nextBefore,onRefresh,onOlder,pageNumber=1,lastPage=1,onPage,onLoad,onEdit,onDelete}:{items:PolicyVersion[];user:string;busy:boolean;nextBefore:number|null;onRefresh:()=>void;onOlder:()=>void;pageNumber?:number;lastPage?:number;onPage?:(number:number)=>void;onLoad:(id:string)=>void;onEdit:(id:string)=>void;onDelete:(id:string)=>void}){
  const {t}=useI18n();
  return <section className="card"><h2>{t('Policy versions')} <InfoTip label={t('Delete policy')}>{t('Only the author can remove unapproved draft, tested or submitted versions. Active and approved policies are protected; audit and evidence are retained.')}</InfoTip></h2>
    <div className="actions"><a className="button-link" href="#/policy-editor">{t("Create draft")}</a><button disabled={busy} onClick={onRefresh}>{t('Refresh')}</button>{nextBefore&&<button disabled={busy} onClick={onOlder}>{t('Older versions')}</button>}</div>
    <div className="policy-version-list">{items.map(item=><div className="policy-version-row" key={item.version_id}><button className="secondary" disabled={busy} onClick={()=>onLoad(item.version_id)}>{t('Revision')} {item.revision} · {t(item.state)}</button><div className="actions"><button className="secondary" disabled={busy} onClick={()=>onEdit(item.version_id)}>{t('Edit as new draft')}</button><button className="policy-delete" disabled={busy||item.author_id!==user||!['draft','test','approval'].includes(item.state)||!!item.approver_id} onClick={()=>onDelete(item.version_id)}>{t('Delete policy')}</button></div></div>)}</div>
    {onPage&&<PageButtons page={pageNumber} last={lastPage} onPage={onPage} busy={busy}/>}
    {!items.length&&<p>{t('No policy versions found.')}</p>}
  </section>;
}
