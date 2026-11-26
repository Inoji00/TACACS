/** Presentation only: immutable API/audit instants remain unchanged. */
const OFFSET_MS=7*60*60*1000;
export function vietnamIso(value:string):string{
  const milliseconds=Date.parse(value);if(!Number.isFinite(milliseconds))return '';
  return new Date(milliseconds+OFFSET_MS).toISOString().slice(0,-1)+'+07:00';
}
export function vietnamTime(value:string):string{
  const iso=vietnamIso(value);if(!iso)return '—';
  return `${iso.slice(8,10)}/${iso.slice(5,7)}/${iso.slice(0,4)} ${iso.slice(11,19)}`;
}
export function vietnamInputToIso(value:string):string{
  // datetime-local values have no offset: always interpret as Vietnam wall time.
  if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(value))throw new Error('Invalid date');
  const iso=vietnamIso(value+'+07:00');if(!iso||iso.slice(0,16)!==value.slice(0,16))throw new Error('Invalid date');
  return iso;
}
