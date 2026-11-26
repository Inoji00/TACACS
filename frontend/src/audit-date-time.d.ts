import type {jsx,jsxs} from 'react/jsx-runtime';
import type {ReactElement} from 'react';

export function auditDateTimeControls(props: {
  jsx: typeof jsx; jsxs: typeof jsxs; label: string; value: string;
  onChange: (value: string) => void; t: (label: string) => string; endOfDay?: boolean;
}): ReactElement;

export function auditDateTimeRange(props: {
  jsx: typeof jsx; jsxs: typeof jsxs; t: (label: string) => string;
  since: string; until: string; onSince: (value:string)=>void; onUntil: (value:string)=>void;
}): ReactElement;
