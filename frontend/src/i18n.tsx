import {createContext,useContext,useEffect,useState,type ReactNode} from 'react';
import {vi} from './locales-vi';
export type Language='en'|'vi';
export function translate(message:string,language:Language):string{
  if(language==='en')return message;
  if(vi[message]!==undefined)return vi[message];
  const tests=/^(\d+) policy tests passed\.$/.exec(message);
  if(tests)return `${tests[1]} kiểm thử chính sách đã đạt.`;
  const committed=/^Policy (test|submit|approve|activate|rollback) committed\.$/.exec(message);
  if(committed)return `Đã hoàn tất thao tác ${vi[committed[1]]??committed[1]} chính sách.`;
  return message;
}
const Context=createContext<{language:Language;setLanguage:(value:Language)=>void}>({language:'en',setLanguage:()=>{}});
export function validationMessage(validity:ValidityState,language:Language){
  const message=validity.valueMissing?'Please fill out this field.':validity.patternMismatch?'Please match the requested format.':
    validity.tooShort?'Input is too short.':validity.tooLong?'Input is too long.':'Please enter a valid value.';
  return translate(message,language);
}
export function LanguageProvider({children,initialLanguage}:{children:ReactNode;initialLanguage?:Language}){
  const [language,setLanguage]=useState<Language>(()=>{if(initialLanguage)return initialLanguage;try{return localStorage.getItem('tacacs.ui.language')==='vi'?'vi':'en';}catch{return 'en';}});
  useEffect(()=>{document.documentElement.lang=language;document.title=language==='vi'?'Quản trị TACACS+':'TACACS+ Administration';try{localStorage.setItem('tacacs.ui.language',language);}catch{/* Storage may be unavailable; switching still works. */}},[language]);
  useEffect(()=>{
    const isField=(target:EventTarget|null):target is HTMLInputElement|HTMLTextAreaElement|HTMLSelectElement=>target instanceof HTMLInputElement||target instanceof HTMLTextAreaElement||target instanceof HTMLSelectElement;
    document.querySelectorAll<HTMLInputElement|HTMLTextAreaElement|HTMLSelectElement>('input,textarea,select').forEach(field=>field.setCustomValidity(''));
    const invalid=(event:Event)=>{if(isField(event.target))event.target.setCustomValidity(validationMessage(event.target.validity,language));};
    const clear=(event:Event)=>{if(isField(event.target))event.target.setCustomValidity('');};
    document.addEventListener('invalid',invalid,true);document.addEventListener('input',clear,true);document.addEventListener('change',clear,true);
    return()=>{document.removeEventListener('invalid',invalid,true);document.removeEventListener('input',clear,true);document.removeEventListener('change',clear,true);};
  },[language]);
  return <Context.Provider value={{language,setLanguage}}>{children}</Context.Provider>;
}
export function useI18n(){const context=useContext(Context);return {...context,t:(message:string)=>translate(message,context.language)};}
export function LanguageSwitcher(){const {language,setLanguage}=useI18n();return <label className="language-picker"><span>{language==='vi'?'Ngôn ngữ':'Language'}</span><select aria-label={language==='vi'?'Ngôn ngữ giao diện':'Interface language'} value={language} onChange={event=>setLanguage(event.target.value==='vi'?'vi':'en')}><option value="en">English</option><option value="vi">Tiếng Việt</option></select></label>;}
