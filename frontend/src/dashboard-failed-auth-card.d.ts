import type {jsx, jsxs} from 'react/jsx-runtime';
import type {ReactElement} from 'react';
import type {DashboardData} from './dashboard';

export function dashboardFailedAuthCard(options: {
  jsx: typeof jsx;
  jsxs: typeof jsxs;
  t: (message: string) => string;
  language: string;
  data: DashboardData | null;
  formatTime: (value: string) => string;
  onViewLogs: () => void;
}): ReactElement;
