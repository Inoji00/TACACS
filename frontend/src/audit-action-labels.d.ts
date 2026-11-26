export function auditActionLabel(action: string, translate: (label: string) => string): string;
export function auditTarget(action: string, target: string, translate: (label: string) => string, name?: string | null): {label: string; reference: string};
export function auditIdentityRows(event: {action?: string; source?:string; source_ip?:string; destination_ip?:string; remote_address?:string; target?:string; authorization_details?: Record<string,string>; policy_version?:string|null; target_name?: string | null; target_name_source?: string | null; identity_details?: Record<string, string | boolean | string[]>}, translate: (label: string) => string): [string, string][];

export function auditActor(event:{actor:string;actor_name?:string|null}):string;
