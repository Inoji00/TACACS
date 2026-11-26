import type {AccessMapping} from './access-mappings';

export function deviceMappingForGroup(savedMappings: AccessMapping[], group: string): AccessMapping;
export function availableDeviceGroups(groups: string[], rows: AccessMapping[], index: number): string[];
