import {useI18n} from './i18n';
export type CaseDraft={key:number;subject:string;device_id:string;command:string;groups:string;expected:'allow'|'deny'};
export function compileCases(rows:CaseDraft[]) {
  if(rows.length<2 || rows.length>1024)throw new Error('Provide between 2 and 1024 policy test cases.');
  if(!rows.some(row=>row.expected==='allow') || !rows.some(row=>row.expected==='deny'))throw new Error('Include both Allow and Deny expectations.');
  return compileSamples(rows).map((sample,index)=>({...sample,expected:rows[index].expected}));
}

export function compileSamples(rows:CaseDraft[]) {
  if(rows.length<1 || rows.length>1024)throw new Error('Provide between 1 and 1024 simulation samples.');
  return rows.map(row=>{
    for(const name of ['subject','device_id','command'] as const){
      if(!row[name].length || row[name].length>1024)throw new Error('Each test needs a subject, device and command of at most 1024 characters.');
    }
    const groups=row.groups.split('\n').map(value=>value.trim()).filter(Boolean);
    if(groups.length>128 || groups.some(value=>value.length>253))throw new Error('Test groups allow at most 128 IDs of 253 characters each.');
    return {subject:row.subject,device_id:row.device_id,command:row.command,groups:[...new Set(groups)]};
  });
}

export function CaseEditor({rows,onChange,disabled}:{rows:CaseDraft[];onChange:(rows:CaseDraft[])=>void;disabled:boolean}) {
  const {t}=useI18n();

  function update(index:number,change:Partial<CaseDraft>){onChange(rows.map((row,i)=>i===index?{...row,...change}:row));}
  return <div className="case-editor"><h3>{t("Policy test cases")}</h3>
    <p className="hint">{t("Include both Allow and Deny expectations. These are simulated inputs, not live identity or device records.")}</p>
    {rows.map((row,index)=><fieldset disabled={disabled} key={row.key}><legend>{t("Test case")} {index+1}</legend>
      <label>{t("Subject")}<input value={row.subject} maxLength={1024} onChange={event=>update(index,{subject:event.target.value})}/></label>
      <label>{t("Device ID")}<input value={row.device_id} maxLength={1024} onChange={event=>update(index,{device_id:event.target.value})}/></label>
      <label>{t("Command")}<input value={row.command} maxLength={1024} onChange={event=>update(index,{command:event.target.value})}/></label>
      <label>{t("Test groups — one ID per line")}<textarea rows={2} value={row.groups} onChange={event=>update(index,{groups:event.target.value})}/></label>
      <label>{t("Expected result")}<select value={row.expected} onChange={event=>update(index,{expected:event.target.value as 'allow'|'deny'})}><option value="deny">{t("Deny")}</option><option value="allow">{t("Allow")}</option></select></label>
      <button type="button" className="secondary" onClick={()=>onChange(rows.filter((_,i)=>i!==index))}>{t("Remove test case")} {index+1}</button>
    </fieldset>)}
    <button type="button" className="secondary" disabled={disabled||rows.length>=1024} onClick={()=>onChange([...rows,{key:Math.max(0,...rows.map(row=>row.key))+1,subject:'',device_id:'',command:'',groups:'',expected:'deny'}])}>{t("Add test case")}</button>
  </div>;
}
