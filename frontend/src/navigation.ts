export const aaaLogPages = [
  ['authentication-log','Authentication Log'],
  ['authorization-log','Authorization Log'],
  ['accounting','Accounting Log'],
] as const;
export const monitorLogPages = [
  ...aaaLogPages,['audit','Activity Log'],['log-issues','Failures & Errors'],['reports','Reports'],
] as const;

export const sections = [
  {id:'overview',label:'Overview',pages:[['overview','Dashboard']]},
  {id:'network',label:'Network Resources',pages:[['devices','Devices'],['locations','Locations'],['device-types','Device Types']]},
  {id:'identity',label:'Users & Identity',pages:[['users','Users'],['groups','Identity groups']]},
  {id:'policy',label:'Access Policies',pages:[['policies','Policy versions'],['policy-editor','Policy editor'],['policy-workflow','Policy workflow'],['policy-simulation','Policy simulation'],['policy-evidence','Saved simulation evidence']]},
  {id:'monitor',label:'Logging & Reports',pages:monitorLogPages},
  {id:'system',label:'System Administration',pages:[['password','My Profile'],['security','Security'],['diagnostics','Diagnostics']]}
] as const;
export type Area=typeof sections[number]['id'];
export type Page=typeof sections[number]['pages'][number][0]|'user-create';
const menuPages=sections.flatMap(section=>section.pages.map(([id,label])=>({id,label,area:section.id,parent:section.label})));
export const pages=[...menuPages,{id:'user-create' as const,label:'Create device user',area:'identity' as const,parent:'Users & Identity'}];
export function resolvePage(hash:string):Page{if(hash==='#/aaa-logs')return 'authentication-log';return pages.find(page=>'#/'+page.id===hash)?.id??'overview';}
export function defaultPage(area:Area):Page{return sections.find(section=>section.id===area)!.pages[0][0];}
