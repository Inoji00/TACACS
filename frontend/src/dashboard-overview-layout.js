export function dashboardOverviewKpis({jsx,t,available,passed,failed,inventory,navigate}){
  const total=passed+failed,rate=total?100*passed/total:null;
  const stats=[
    ['Auth attempts',available?total:null,'monitor'],
    ['Authentication success',available&&rate!==null?rate.toFixed(1)+'%':null,'monitor'],
    ['Failed logins',available?failed:null,'monitor'],
    ['Locked accounts',inventory?.locked_users,'identity'],
    ['Enabled switches',inventory?inventory.enabled_devices+' / '+inventory.devices:null,'network'],
  ];
  return jsx('section',{className:'overview-kpis','aria-label':t('Overview'),children:stats.map(([label,value,area],index)=>
    jsx('button',{type:'button',className:'card overview-kpi'+(index===1&&available&&rate!==null&&rate<90?' overview-critical':''),
      onClick:()=>navigate(area),children:[jsx('span',{children:t(label)},'label'),jsx('strong',{children:value??'—'},'value')]},label))});
}

export function dashboardOverviewResource({jsx,label,value,language}){
  const known=Number.isFinite(value)&&value>=0&&value<=100;
  const text=known?new Intl.NumberFormat(language,{maximumFractionDigits:1}).format(value)+'%':'—';
  return jsx('li',{className:'overview-resource',children:[
    jsx('div',{className:'overview-resource-label',children:[jsx('span',{children:label},'label'),jsx('strong',{children:text},'value')]},'label'),
    known&&jsx('meter',{min:0,max:100,value,'aria-label':label,className:value>=90?'critical':value>=70?'warning':''},'meter'),
  ]});
}
