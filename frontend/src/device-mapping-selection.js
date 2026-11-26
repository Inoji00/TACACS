export function deviceMappingForGroup(savedMappings, group) {
  const saved = savedMappings.find((mapping) => mapping.group === group);
  return saved
    ? {group, privilege: saved.privilege, mode: saved.mode}
    : {group, privilege: 1, mode: 'policy'};
}

export function availableDeviceGroups(groups, rows, index) {
  const current = rows[index].group;
  const assigned = new Set(rows.filter((_, row) => row !== index).map((mapping) => mapping.group));
  return [...new Set([...groups, current])].filter((group) => group && !assigned.has(group)).sort();
}
