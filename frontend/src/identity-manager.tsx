import {useI18n} from './i18n';
import {useState,type FormEvent} from 'react';
import {InfoTip} from './info-tip';
import {GroupNameInput} from './group-name-input';
export function IdentityManager({busy,onCreate,onState,groups=[]}:{groups?:string[];busy:boolean;onCreate:(payload:{username:string;password:string;group_name:string})=>Promise<void>;onState:(payload:{user_id:string;enabled:boolean})=>Promise<void>}){
  const {t}=useI18n();

  const [error,setError]=useState('');
  function create(event:FormEvent<HTMLFormElement>){
    event.preventDefault();const form=event.currentTarget,data=new FormData(form),password=String(data.get('password'));
    if(password!==String(data.get('confirm_password'))){setError('Passwords do not match.');return;}
    setError('');const payload={username:String(data.get('username')),password,group_name:String(data.get('group_name'))};
    void onCreate(payload).then(()=>form.reset()).catch(()=>setError('Creation failed. Check the status message.'));
  }
  return <section className="card">
    <h2>{t('Create device user')} <InfoTip label={t('Create device user')}>{t('Creates a local TACACS+ identity and assigns one group, creating that group if needed. It grants no console access, shell privilege or command permission automatically.')}</InfoTip></h2>
    <form onSubmit={create}>
      <div className="form-columns">
        <label>{t('Username')}<input name="username" required pattern="[A-Za-z0-9_.@-]{1,64}" maxLength={64} disabled={busy} autoComplete="off" placeholder="operator01"/></label>
        <label>{t('Identity group')}<GroupNameInput groups={groups} name="group_name" required disabled={busy} placeholder="network-operators"/></label>
      </div>
      <p className="field-hint">{t('Choose an existing group or enter a new group name. Device privilege is assigned to that group in Devices.')}</p>
      <div className="form-columns">
        <label>{t('Password')}<input name="password" type="password" required pattern={"(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[\\x21-\\x2f\\x3a-\\x40\\x5b-\\x60\\x7b-\\x7e]).{12,1024}"} minLength={12} maxLength={1024} autoComplete="new-password" disabled={busy}/></label>
        <label>{t('Confirm password')}<input name="confirm_password" type="password" required minLength={12} maxLength={1024} autoComplete="new-password" disabled={busy}/></label>
      </div>
      <p className="field-hint">{t('Use 12+ characters with A–Z, a–z, 0–9 and a symbol.')}</p>
      <div className="form-footer"><button disabled={busy}>{t('Create device user')}</button></div>
    </form>
    {error&&<p className="error" role="alert">{t(error)}</p>}
  </section>;
}
