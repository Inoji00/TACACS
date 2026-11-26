import {useEffect,useId,useRef,useState} from 'react';
import {useI18n} from './i18n';
import {InfoTip} from './info-tip';

// 64 symbols: each random byte maps uniformly to six bits without modulo bias.
export function generateSharedSecret(length:number=16):string{
  if(!Number.isInteger(length)||length<14||length>128)throw new Error('Invalid secret length');
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  return Array.from(globalThis.crypto.getRandomValues(new Uint8Array(length)),value=>alphabet[value&63]).join('');
}

const iconPaths={
  copy:'M9 9h11v11H9z M15 6V4H4v11h2',
  eye:'M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6Z M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z',
  hide:'M3 3l18 18 M10 6.2c.6-.1 1.3-.2 2-.2 6.5 0 10 6 10 6a17 17 0 0 1-3 3.5 M6.1 7.5C3.4 9.3 2 12 2 12s3.5 6 10 6c1.4 0 2.7-.3 3.8-.8',
  key:'M14 4a5 5 0 0 0-4.6 7L4 16.5V20h3.5l2-2H12v-2.5l1.4-1.5A5 5 0 1 0 14 4Z M16 8h.01',
};

function KeyIcon({name}:{name:keyof typeof iconPaths}){
  return <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round"><path d={iconPaths[name]}/></svg>;
}

export function SharedSecretField({existing,busy,reveal,onDraft,readOnly=false}:{existing:boolean;busy:boolean;reveal?:(password:string)=>Promise<string>;onDraft?:()=>void;readOnly?:boolean}){
  const {t}=useI18n();const input=useRef<HTMLInputElement>(null),generator=useRef<HTMLButtonElement>(null),id=useId();
  const [length,setLength]=useState(32),[visible,setVisible]=useState(false),[message,setMessage]=useState('');
  const [hasDraft,setHasDraft]=useState(false),[generatorOpen,setGeneratorOpen]=useState(false);
  const [saved,setSaved]=useState(''),[revealing,setRevealing]=useState(false);
  const confirm=useRef<HTMLDialogElement>(null),passwordInput=useRef<HTMLInputElement>(null);
  const [verificationFailed,setVerificationFailed]=useState(false);
  useEffect(()=>{
    if(!saved)return;
    const timer=window.setTimeout(()=>setSaved(''),30000);
    return ()=>window.clearTimeout(timer);
  },[saved]);
  function generate(){
    try{if(input.current)input.current.value=generateSharedSecret(length);onDraft?.();setHasDraft(true);setSaved('');setVisible(false);setGeneratorOpen(false);generator.current?.focus();setMessage('Key generated. Save the device to apply it.');}
    catch{setMessage('Secure generation unavailable. Use HTTPS and try again.');}
  }
  async function copy(value:string){
    if(!value){setMessage('Enter or generate a key first.');return;}
    try{await navigator.clipboard.writeText(value);setMessage('Key copied.');}
    catch{setMessage('Clipboard unavailable. Show the key and copy it manually.');}
  }
  async function viewSaved(){
    const field=passwordInput.current;
    if(!reveal||!field||!field.reportValidity())return;
    const password=field.value;
    field.value='';
    setRevealing(true);setMessage('');
    try{const key=await reveal(password);if(confirm.current?.open&&input.current&&!input.current.value)setSaved(key);confirm.current?.close();}
    catch{setVerificationFailed(true);}
    finally{setRevealing(false);}
  }
  const showing=hasDraft?visible:!!saved;
  const eyeLabel=t(hasDraft?(visible?'Hide secret':'Show secret'):(saved?'Hide saved key':'View saved key'));
  return <>
    <div className="field-caption"><label htmlFor={saved?id+'-saved':id}>{t('TACACS+ key')}</label> <InfoTip label={t('Shared secret')}>{t('Use the same key on TNAC+ and the device. A new key takes effect when you save.')}</InfoTip></div>
    <div className="device-key-control">
      <input id={id} ref={input} hidden={!!saved} aria-label={t('Shared secret')} name="secret" type={visible?'text':'password'} autoComplete="new-password" required={!existing} minLength={14} maxLength={128} pattern="[!-~]{14,128}" spellCheck={false} readOnly={readOnly} disabled={busy} placeholder={readOnly?t('Saved key'):existing?t('Leave blank to keep current secret'):t('Enter shared secret')} onInput={event=>{setHasDraft(!!event.currentTarget.value);setSaved('');if(!event.currentTarget.value)setVisible(false);}}/>
      {saved&&<input id={id+'-saved'} aria-label={t('Saved key')} value={saved} readOnly spellCheck={false} autoComplete="off"/>}
      <button type="button" className="secondary device-key-icon" aria-label={t('Copy key')} title={t('Copy key')} disabled={busy||(!hasDraft&&!saved)} onClick={()=>void copy(input.current?.value||saved)}><KeyIcon name="copy"/></button>
      <button type="button" className="secondary device-key-icon" aria-label={eyeLabel} title={eyeLabel} aria-pressed={showing} disabled={busy||revealing||!hasDraft&&!saved} onClick={()=>hasDraft?setVisible(!visible):setSaved('')}><KeyIcon name={showing?'hide':'eye'}/></button>
      {!readOnly&&<button ref={generator} type="button" className="device-key-icon device-key-trigger" aria-label={t('Key generator')} title={t('Key generator')} disabled={busy} aria-expanded={generatorOpen} aria-controls={id+'-generator'} onClick={()=>setGeneratorOpen(!generatorOpen)}><KeyIcon name="key"/></button>}
    </div>
    {reveal&&<button type="button" className="danger" disabled={busy||revealing||hasDraft} onClick={()=>{setVerificationFailed(false);confirm.current?.showModal();}}>{t('Reveal saved key')}</button>}
    {reveal&&<dialog ref={confirm} aria-label={t('Reveal saved key')} onClose={()=>{if(passwordInput.current)passwordInput.current.value='';}}>
      <h2>{t('Reveal saved key')}</h2>
      <label>{t('Current password')}<input ref={passwordInput} type="password" autoComplete="current-password" required maxLength={1024}
        onChange={event=>event.stopPropagation()} onKeyDown={event=>{if(event.key==='Enter'){event.preventDefault();if(!revealing)void viewSaved();}}}/></label>
      {verificationFailed&&<p className="error" role="alert">{t('Unable to view the saved key. Check permissions and try again.')}</p>}
      <div className="actions"><button type="button" className="secondary" onClick={()=>confirm.current?.close()}>{t('Cancel')}</button>
        <button type="button" className="danger" disabled={revealing} onClick={()=>void viewSaved()}>{t('Reveal saved key')}</button></div>
    </dialog>}
    {saved&&<p className="field-hint">{t('Saved key is hidden after 30 seconds. Access is audited.')}</p>}
    {!readOnly&&<><div id={id+'-generator'} className="device-generator" hidden={!generatorOpen}>
      <div className="actions device-generator-presets">{[32,48,63].map(value=><button key={value} type="button" className="secondary" disabled={busy} aria-pressed={length===value} onClick={()=>setLength(value)}>{value}</button>)}</div>
      <label>{t('Generated key length')} <output>{length}</output>
        <input type="range" min={16} max={128} value={length} disabled={busy} onChange={event=>setLength(Number(event.target.value))}/></label>
      <p className="field-hint">{t('Randomness estimate')} · {length*6} {t('bits')}</p>
      <p className="field-hint">{t('Key length support depends on the device firmware.')}</p>
      <button type="button" className="device-key-icon device-key-trigger" aria-label={t('Generate secret')} title={t('Generate secret')} disabled={busy} onClick={generate}><KeyIcon name="key"/></button>
    </div>
    <p className="field-hint">{t('14–128 ASCII characters, no spaces. RFC 8907 recommends at least 16 characters.')}{existing?' '+t('Blank keeps the existing secret.'):''}</p></>}
    {message&&<p className="field-hint" role="status">{t(message)}</p>}
  </>;
}
