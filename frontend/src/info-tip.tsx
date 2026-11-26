import {useI18n} from './i18n';
import {useEffect,useId,useRef,useState,type ReactNode} from 'react';
import {createPortal} from 'react-dom';

/** Supplemental help: hover, keyboard focus and touch; never the only warning. */
export function InfoTip({label,children}:{label:string;children:ReactNode}){
  const {t}=useI18n();

  const id=useId(),[open,setOpen]=useState(false),[position,setPosition]=useState({left:16,top:80});
  const timer=useRef<ReturnType<typeof setTimeout>|null>(null),button=useRef<HTMLButtonElement>(null);
  function cancel(){if(timer.current!==null)clearTimeout(timer.current);}
  function hideLater(){cancel();timer.current=setTimeout(()=>{if(document.activeElement!==button.current)setOpen(false);},180);}
  useEffect(()=>()=>cancel(),[]);
  useEffect(()=>{if(!open)return;const close=()=>setOpen(false);window.addEventListener('resize',close);window.addEventListener('scroll',close,true);return()=>{window.removeEventListener('resize',close);window.removeEventListener('scroll',close,true);};},[open]);
  function show(button:HTMLButtonElement){
    const rect=button.getBoundingClientRect(),width=Math.min(300,window.innerWidth-32);
    cancel();setPosition({left:Math.max(16,Math.min(rect.left,window.innerWidth-width-16)),top:Math.max(16,Math.min(rect.bottom+8,window.innerHeight-210))});setOpen(true);
  }
  return <span className="info-anchor" onMouseLeave={hideLater}>
    <button ref={button} type="button" className="info-button" aria-label={`${t('Information:')} ${t(label)}`} aria-describedby={open?id:undefined}
      onMouseEnter={event=>show(event.currentTarget)} onFocus={event=>show(event.currentTarget)} onClick={event=>show(event.currentTarget)}
      onBlur={()=>setOpen(false)} onKeyDown={event=>{if(event.key==='Escape'){setOpen(false);event.stopPropagation();}}}>i</button>
    {open&&createPortal(<span id={id} role="tooltip" className="info-tooltip" style={position} onMouseEnter={cancel} onMouseLeave={hideLater}>{children}</span>,document.body)}
  </span>;
}
