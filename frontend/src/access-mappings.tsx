import {useState} from 'react';
import {useI18n} from './i18n';
import {InfoTip} from './info-tip';
import {availableDeviceGroups,deviceMappingForGroup} from './device-mapping-selection';
export type AccessMapping={group:string;privilege:number;mode:'policy'|'read_only'};
export function AccessMappings({initial,busy,groups=[],onChange}:{onChange?:()=>void;initial:AccessMapping[];busy:boolean;groups?:string[]}){
  const {t}=useI18n(),[rows,setRows]=useState<AccessMapping[]>(initial);
  function change(next:AccessMapping[]){setRows(next);onChange?.();}
  function update(index:number,changes:Partial<AccessMapping>){change(rows.map((row,i)=>i===index?{...row,...changes}:row));}
  return <fieldset disabled={busy} className="access-mappings"><legend>{t('Device access mappings')} <InfoTip label={t('Device access mappings')}>{t('Assign the group a shell privilege for this switch. EXEC authorization does not require an active command policy. If the switch sends command authorization here, its commands still require active policy rules. Conflicting group mappings deny access.')}</InfoTip></legend>
    <input type="hidden" name="access_mappings" value={JSON.stringify(rows)}/>
    {rows.map((row,index)=><div className="access-grant" key={index}>
      <div className="access-grant-main access-mapping-row">
        <label>{t('Identity group')}<select value={row.group} required aria-label={t('Identity group')} onChange={event=>update(index,deviceMappingForGroup(initial,event.target.value))}>
          <option value="" disabled>—</option>
          {availableDeviceGroups(groups,rows,index).map(group=><option key={group} value={group}>{group}</option>)}
        </select></label>
        <label>{t('EXEC access')}<select aria-label={t('EXEC access')} value={row.privilege} disabled={row.mode==='read_only'} onChange={event=>update(index,{privilege:Number(event.target.value)})}>
          {Array.from({length:16},(_,value)=><option key={value} value={value}>{value}</option>)}
        </select>{row.mode==='read_only'&&<span className="badge">{t('Read-only cap')}</span>}</label>
        <button type="button" className="secondary" onClick={()=>change(rows.filter((_,i)=>i!==index))}>{t('Remove')}</button>
      </div>
    </div>)}
    {!rows.length&&<p className="hint">{t('No group mapped. Shell and command authorization will be denied.')}</p>}
    <button type="button" className="secondary" disabled={busy||rows.length>=64} onClick={()=>change([...rows,{group:'',privilege:1,mode:'policy'}])}>{t('Add group mapping')}</button>
    <p className="hint">{t('Levels 2–14 follow command assignments on the switch; they do not create predefined roles. Privilege 1 is User EXEC, not unrestricted read-only access.')}</p>
  </fieldset>;
}
