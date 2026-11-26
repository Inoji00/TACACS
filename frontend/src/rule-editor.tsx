import {useI18n} from './i18n';
export type RuleDraft={key:number;rule_id:string;groups:string;device_ids:string;command_prefix:string;decision:'allow'|'deny'};
export function compileRules(rows:RuleDraft[]) {
  if(rows.length>4096)throw new Error('A policy may contain at most 4096 rules.');
  const ids=new Set<string>();
  function scope(value:string){
    const values=value.split('\n').map(item=>item.trim()).filter(Boolean);
    if(values.length>1024 || values.some(item=>/[\u0000-\u001f\u007f]/.test(item)))throw new Error('Invalid group or device scope.');
    return [...new Set(values)];
  }
  return rows.map(row=>{
    const id=row.rule_id.trim(),prefix=row.command_prefix.trim();
    if(!id || ids.has(id))throw new Error('Each rule must have a unique, non-empty ID.');
    if(!prefix || prefix.length>1024 || /[\u0000-\u001f\u007f]/.test(prefix))throw new Error('Each rule needs a command prefix of at most 1024 characters without control characters.');
    ids.add(id);
    return {rule_id:id,groups:scope(row.groups),device_ids:scope(row.device_ids),command_prefix:prefix,decision:row.decision};
  });
}

export function RuleEditor({rows,onChange,disabled}:{rows:RuleDraft[];onChange:(rows:RuleDraft[])=>void;disabled:boolean}) {
  const {t}=useI18n();

  function update(index:number,change:Partial<RuleDraft>){onChange(rows.map((row,i)=>i===index?{...row,...change}:row));}
  function move(index:number,offset:number){const next=[...rows];[next[index],next[index+offset]]=[next[index+offset],next[index]];onChange(next);}
  return <div className="rule-editor">
    <p className="hint">{t("Rules are evaluated in order. The first matching rule wins; unmatched commands are denied. Empty scopes match all groups or devices.")}</p>
    {rows.map((row,index)=><fieldset key={row.key} disabled={disabled}>
      <legend>{t("Rule")} {index+1}</legend>
      <label>{t("Rule ID")}<input value={row.rule_id} required onChange={event=>update(index,{rule_id:event.target.value})}/></label>
      <label>{t("Command prefix")}<input value={row.command_prefix} required maxLength={1024} placeholder="show version" onChange={event=>update(index,{command_prefix:event.target.value})}/></label>
      <label>{t("Decision")}<select value={row.decision} onChange={event=>update(index,{decision:event.target.value as 'allow'|'deny'})}><option value="deny">{t("Deny")}</option><option value="allow">{t("Allow")}</option></select></label>
      <label>{t("Groups — one ID per line")}<textarea rows={2} value={row.groups} placeholder={t("Empty means all groups")} onChange={event=>update(index,{groups:event.target.value})}/></label>
      <label>{t("Devices — one ID per line")}<textarea rows={2} value={row.device_ids} placeholder={t("Empty means all devices")} onChange={event=>update(index,{device_ids:event.target.value})}/></label>
      <div className="actions"><button type="button" className="secondary" disabled={index===0} onClick={()=>move(index,-1)}>{t("Move up")}</button><button type="button" className="secondary" disabled={index===rows.length-1} onClick={()=>move(index,1)}>{t("Move down")}</button><button type="button" className="secondary" onClick={()=>onChange(rows.filter((_,i)=>i!==index))}>{t("Remove rule")} {index+1}</button></div>
    </fieldset>)}
    {!rows.length&&<p>{t("No rules: this draft denies all commands.")}</p>}
    <button type="button" className="secondary" disabled={disabled||rows.length>=4096} onClick={()=>onChange([...rows,{key:Math.max(0,...rows.map(row=>row.key))+1,rule_id:'',groups:'',device_ids:'',command_prefix:'',decision:'deny'}])}>{t("Add rule")}</button>
  </div>;
}
