import {useId,type ChangeEventHandler} from 'react';
export function GroupNameInput({groups=[],...props}:{groups?:string[];name?:string;value?:string;defaultValue?:string;required?:boolean;disabled?:boolean;onChange?:ChangeEventHandler<HTMLInputElement>;placeholder?:string}){
  const id=useId();
  return <><input {...props} list={id} pattern="[A-Za-z0-9_.-]{1,64}" maxLength={64} autoComplete="off"/><datalist id={id}>{[...new Set(groups)].sort().map(name=><option key={name} value={name}/>)}</datalist></>;
}
