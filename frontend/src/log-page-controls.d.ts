import type {jsx,jsxs} from 'react/jsx-runtime';
export function logPageControls(props:{
 jsx:typeof jsx;jsxs:typeof jsxs;t:(label:string)=>string;page:number;last:number;
 count:number;size:number;busy:boolean;onPage:(page:number)=>void;onSize:(size:number)=>void;
}):ReturnType<typeof jsx>;
