import type {jsx} from 'react/jsx-runtime';
import type {useEffect,useId,useRef,useState} from 'react';
export function LogRefreshControl(props:{
  jsx:typeof jsx;hooks:{useEffect:typeof useEffect;useId:typeof useId;useRef:typeof useRef;useState:typeof useState};
  t:(key:string)=>string;storageKey:string;defaultSeconds?:number;onRefresh:()=>Promise<boolean|void>;
  isBlocked?:()=>boolean;pauseAuto?:boolean;updated?:string;
  preview?:{seconds:number;open?:boolean;phase?:'idle'|'refreshing'|'error';hover?:number};
}):ReturnType<typeof jsx>;
