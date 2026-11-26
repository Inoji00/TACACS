export function logPageControls({jsx,jsxs,t,page,last,count,size,busy,onPage,onSize}) {
  const first=count?(page-1)*size+1:0;
  const numbers=[...new Set([1,page-2,page-1,page,page+1,page+2,last])]
    .filter(number=>number>=1&&number<=last).sort((a,b)=>a-b);
  const go=(number,label,content,disabled=false)=>jsx('button',{
    type:'button',className:number===page?'log-page-current':'secondary',
    disabled:busy||disabled,'aria-label':label,
    'aria-current':number===page?'page':undefined,
    onClick:()=>{if(number!==page)onPage(number);},children:content,
  });
  return jsxs('div',{className:'log-page-controls',children:[
    jsxs('div',{className:'log-page-summary',children:[
      jsx('span',{children:t('Showing')+' '+first+'–'+(count?first+count-1:0)}),
      jsx('select',{'aria-label':t('Rows per page'),value:size,disabled:busy,
        onChange:event=>onSize(Number(event.target.value)),
        children:[10,20,50,100].map(value=>jsx('option',{value,children:value+' '+t('per page')},value)),
      }),
    ]}),
    last>1&&jsxs('nav',{'aria-label':t('Pagination'),className:'log-page-buttons',children:[
      go(page-1,t('Previous page'),'‹',page===1),
      ...numbers.map((number,index)=>jsxs('span',{children:[
        index>0&&number>numbers[index-1]+1&&jsx('span',{'aria-hidden':true,children:'…'}),
        go(number,t('Page')+' '+number,number),
      ]},number)),
      go(page+1,t('Next page'),'›',page===last),
    ]}),
  ]});
}

export function logPageState(previous,page,next,size,preserve) {
  const starts=page===1&&!preserve?[null]:previous.starts.slice(0,page);
  if (next!=null) {
    if (preserve&&previous.starts[page]===next) return {...previous,page,size};
    starts.push(next);
  }
  return {page,starts,size};
}
