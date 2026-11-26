import type {useEffect,useState} from 'react';
import type {jsx,jsxs} from 'react/jsx-runtime';
import type {ReactNode} from 'react';
export function activityLogLayout(props:{
  jsx:typeof jsx;jsxs:typeof jsxs;hooks:{useEffect:typeof useEffect;useState:typeof useState};
  t:(label:string)=>string;address:string;formatTime:(value:string)=>string;children:ReactNode;
}):ReturnType<typeof jsx>;
