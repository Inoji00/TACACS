const auditActions = new Map([
  ['device.create', 'Added device'],
  ['device.update', 'Updated device configuration'],
  ['device.delete', 'Removed device'],
  ['device.secret.reveal', 'Viewed saved TACACS+ key'],
  ['device-group.create', 'Created device group'],
  ['device-group.update', 'Updated device group'],
  ['device-group.delete', 'Removed device group'],
  ['identity.create', 'Created user account'],
  ['identity.update', 'Updated user account'],
  ['identity.enable', 'Enabled user account'],
  ['identity.disable', 'Disabled user account'],
  ['identity.delete', 'Removed user account'],
  ['identity.unlock', 'Unlocked user account'],
  ['identity.console.grant', 'Granted Web access'],
  ['identity.console.scope', 'Updated Web access scope'],
  ['identity.console.revoke', 'Revoked Web access'],
  ['web.login', 'Web sign-in'],
  ['web.logout', 'Web sign-out'],
  ['admin.password.change', 'Changed Web password'],
  ['identity-group.create', 'Created identity group'],
  ['identity-group.rename', 'Renamed identity group'],
  ['identity-group.delete', 'Removed identity group'],
  ['policy.discard', 'Removed policy revision'],
]);

export function auditActionLabel(action, translate) {
  return translate(auditActions.get(action) ?? action);
}

const targetLabels = new Map([
    ['device', 'Audit device'], ['aaa', 'Audit device'],
    ['device-group', 'Audit device group'], ['identity', 'Audit user account'],
    ['identity-group', 'Audit identity group'], ['policy', 'Audit policy version'],
]);

const uuidPattern = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;

export function auditActor(event) {
  return event.actor_name || (event.actor && !uuidPattern.test(event.actor) ? event.actor : '—');
}

export function auditTarget(action, target, translate, name) {
  if (!target || target === 'web-ui') return {label: '', reference: '—'};
  const kind = targetLabels.get(action.split('.', 1)[0]);
  return {
    label: kind ? translate(kind).replace(/^Audit /, '') : '',
    reference: name || (uuidPattern.test(target) ? '—' : target),
  };
}

const identityLabels = new Map([
  ['previous_name', 'Previous username'],
  ['identity_group', 'Identity group'],
  ['enabled', 'Account status'],
  ['password_changed', 'Password changed'],
  ['web_access', 'Web access'],
  ['location_id', 'Location'],
  ['device_type_id', 'Device Type'],
  ['actions', 'Allowed device actions'],
  ['changed_fields', 'Changed fields'],
]);
const fieldLabels = new Map([
  ['name', 'Name'], ['description', 'Description'], ['enabled', 'Status'],
  ['location', 'Location'], ['device_type', 'Device Type'], ['access_mappings', 'Device access mappings'],
  ['shared_secret', 'Shared secret'], ['parent', 'Parent group'],
]);
const deviceActions = new Map([
  ['create', 'Add device'], ['edit', 'Edit device details'],
  ['set_enabled', 'Change device status'], ['delete', 'Delete device'],
  ['reveal_secret', 'View saved key'], ['rotate_secret', 'Rotate TACACS+ key'],
  ['edit_mappings', 'Edit CLI mappings'],
]);

const authorizationReasons = new Map([
  ['exec-granted','EXEC access granted'], ['exec-not-granted','EXEC access not granted'],
  ['matched-rule','Matched policy rule'], ['no-matching-rule','No policy rule matched'],
  ['invalid-command','Invalid command'], ['identity-unavailable','Identity unavailable'],
  ['device-access-denied','Device access denied'], ['unsupported-profile','Unsupported authorization profile'],
  ['invalid-request','Invalid authorization request'], ['authorization-error','Authorization processing error'],
]);

export function auditIdentityRows(event, t) {
  const rows = [];
  if (event.source_ip) rows.push([t('Source IP'),event.source_ip]);
  if (event.destination_ip) rows.push([t('Destination IP'),event.destination_ip]);
  if (event.remote_address) rows.push([t('Remote address'),event.remote_address]);
  if (event.target_name) rows.push([
    t(event.action?.startsWith('identity.')
      ? event.target_name_source === 'event' ? 'Username at time of event' : 'Current username'
      : 'Target name'),
    event.target_name,
  ]);
  for (const [key, label] of identityLabels) {
    const value = event.identity_details?.[key];
    if (typeof value === 'boolean') {
      rows.push([t(label), t(key === 'password_changed' ? value ? 'Yes' : 'No' : value ? 'Enabled' : 'Disabled')]);
    } else if (Array.isArray(value)) {
      const names = key === 'changed_fields' ? fieldLabels : deviceActions;
      rows.push([t(label), value.map((entry) => t(names.get(entry) ?? entry)).join(', ') || '—']);
    } else if (value && !uuidPattern.test(value)) {
      rows.push([t(label), value]);
    }
  }
  if (event.source === 'tacacs' && event.target_name && event.target) rows.push([t('Source IP'),event.target]);
  const authorization = event.authorization_details;
  if (authorization) {
    if (authorization.authorization_kind) rows.push([t('Authorization request'),
      t(authorization.authorization_kind === 'exec' ? 'EXEC authorization' : 'Command authorization')]);
    const reason = authorizationReasons.get(authorization.reason);
    if (reason) rows.push([t('Decision reason'),t(reason)]);
    if (authorization.matched_rule_id) rows.push([t('Matched rule'),authorization.matched_rule_id]);
    if (event.policy_version) rows.push([t('Policy version'),event.policy_version]);
  }
  return rows;
}
