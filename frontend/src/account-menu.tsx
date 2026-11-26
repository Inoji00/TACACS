import {useEffect,useRef,useState} from 'react';
import {useI18n} from './i18n';

export function AccountMenu({name,busy,onProfile,onSignOut}:{name:string;busy:boolean;onProfile:()=>void;onSignOut:()=>void}){
  const {t}=useI18n();
  const [open,setOpen]=useState(false);
  const root=useRef<HTMLDivElement>(null);
  const trigger=useRef<HTMLButtonElement>(null);
  useEffect(()=>{
    if(!open)return;
    function outside(event:PointerEvent){
      if(!root.current?.contains(event.target as Node))setOpen(false);
    }
    function escape(event:KeyboardEvent){
      if(event.key==='Escape'){setOpen(false);trigger.current?.focus();}
    }
    document.addEventListener('pointerdown',outside);
    document.addEventListener('keydown',escape);
    return()=>{
      document.removeEventListener('pointerdown',outside);
      document.removeEventListener('keydown',escape);
    };
  },[open]);
  return <div className="account-menu" ref={root}>
    <button className="account-trigger" ref={trigger} aria-expanded={open} aria-controls="account-popover" onClick={()=>setOpen(!open)}>
      <span className="account-avatar" aria-hidden="true">{name.charAt(0).toUpperCase()}</span>
      <span className="account-label"><span className="account-name">{name}</span><small>{t("Local account")}</small></span><svg className="account-arrow" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m6 8 4 4 4-4"/></svg>
    </button>
    {open&&<div className="account-popover" id="account-popover">
      <div className="account-summary"><span className="account-avatar" aria-hidden="true">{name.charAt(0).toUpperCase()}</span><div><strong>{name}</strong><small>{t("Account")}</small></div></div>
      <button type="button" onClick={()=>{setOpen(false);onProfile();}}>{t("My Profile")}</button>
      <button className="account-signout" disabled={busy} onClick={()=>{setOpen(false);onSignOut();}}>{t("Sign out")}</button>
    </div>}
  </div>;
}
