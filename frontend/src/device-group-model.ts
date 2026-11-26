export type DeviceGroup={id:string;kind:'location'|'device_type';name:string;description:string;parent_id:string|null};
export type GroupActions={list:()=>Promise<{groups:DeviceGroup[];read_only?:boolean}>;save:(payload:Record<string,unknown>)=>Promise<unknown>};
export type DeviceAction='create'|'edit'|'set_enabled'|'delete'|'reveal_secret'|'rotate_secret'|'edit_mappings'|'view_aaa_logs';
export type DeviceScope={location_id:string|null;device_type_id:string|null;actions:DeviceAction[];creation_addresses?:string[]};
export function groupPath(groups:DeviceGroup[],id:string|null|undefined):string{
  const names:string[]=[],seen=new Set<string>();
  while(id){if(seen.has(id))break;seen.add(id);const node=groups.find(group=>group.id===id);if(!node)break;names.unshift(node.name);id=node.parent_id;}
  return names.join(' / ');
}
