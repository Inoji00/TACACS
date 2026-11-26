import {Children,cloneElement,isValidElement,useState,type HTMLAttributes,type ReactElement,type ReactNode} from 'react';
import {useI18n} from './i18n';

export const PAGE_SIZE=100;

export function PageButtons({page,last,onPage,busy=false}:{
  page:number;last:number;onPage:(page:number)=>void;busy?:boolean;
}){
  const {t}=useI18n();
  const pages=[...new Set([1,...Array.from({length:5},(_,i)=>page-2+i),last])]
    .filter(number=>number>=1&&number<=last).sort((a,b)=>a-b);
  if(last<=1)return null;
  return <nav className="actions" aria-label={t('Pagination')}>
    <button type="button" className="secondary" disabled={busy||page===1} onClick={()=>onPage(page-1)}>{t('Previous page')}</button>
    {pages.map((number,index)=><span key={number}>
      {index>0&&number>pages[index-1]+1&&<span aria-hidden="true">… </span>}
      <button type="button" className={number===page?undefined:'secondary'} disabled={busy}
        aria-current={number===page?'page':undefined} onClick={()=>{if(number!==page)onPage(number);}}>{number}</button>
    </span>)}
    <button type="button" className="secondary" disabled={busy||page===last} onClick={()=>onPage(page+1)}>{t('Next page')}</button>
  </nav>;
}

export function PagedTable({children,...props}:HTMLAttributes<HTMLTableElement>){
  const [requested,setRequested]=useState(1);
  const sections=Children.toArray(children);
  const body=sections.find((child):child is ReactElement<{children?:ReactNode}>=>isValidElement(child)&&child.type==='tbody');
  const rows=Children.toArray(body?.props.children);
  const last=Math.max(1,Math.ceil(rows.length/PAGE_SIZE));
  const page=Math.min(requested,last);
  return <><table {...props}>{last===1?children:sections.map(section=>section===body
    ?cloneElement(body!,{},rows.slice((page-1)*PAGE_SIZE,page*PAGE_SIZE)):section)}</table>
    <PageButtons page={page} last={last} onPage={setRequested}/></>;
}

// Retain only navigation cursors, not previously returned audit data.
export function useCursorPages<Cursor>(){
  const [state,setState]=useState<{page:number;starts:(Cursor|undefined)[]}>({page:1,starts:[undefined]});
  function accept(page:number,next:Cursor|null,preserve=false,start?:Cursor){
    setState(previous=>{
      const starts=page===1?[undefined]:previous.starts.slice(0,page);
      if(page>1&&start!==undefined)starts[page-1]=start;
      if(next!=null) {
        if((preserve||page>1)&&previous.starts[page]===next)return {...previous,page};
        starts.push(next);
      }
      return {page,starts};
    });
  }
  return {page:state.page,last:state.starts.length,cursor:(page:number)=>state.starts[page-1],accept};
}
