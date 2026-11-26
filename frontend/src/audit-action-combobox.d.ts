import type {useEffect,useId,useRef,useState} from 'react';
import type {jsx,jsxs} from 'react/jsx-runtime';

export function auditActionCombobox(props: {
  jsx:typeof jsx; jsxs:typeof jsxs;
  hooks:{useEffect:typeof useEffect;useId:typeof useId;useRef:typeof useRef;useState:typeof useState};
  t:(key:string)=>string; value:string; onChange:(value:string)=>void; disabled?:boolean;
}): ReturnType<typeof jsx>;
