"""Server-owned EXEC profiles for explicit device grants."""
from dataclasses import dataclass
import ipaddress

CISCO_IOS = 'cisco-ios'
RUCKUS_FASTIRON = 'ruckus-fastiron'
_PROFILE_LEVELS = {
    CISCO_IOS: range(16),
    RUCKUS_FASTIRON: (0, 4, 5),
}
_PROFILE_ATTRIBUTE = {
    CISCO_IOS: 'priv-lvl',
    RUCKUS_FASTIRON: 'foundry-privlvl',
}


@dataclass(frozen=True)
class ShellGrant:
    device: str
    group: str
    privilege: int
    profile: str = CISCO_IOS


def shell_reply(profile, privilege):
    if type(privilege) is not int or privilege not in _PROFILE_LEVELS.get(profile, ()):
        return ()
    return ('service=shell', f'{_PROFILE_ATTRIBUTE[profile]}={privilege}')


def decode_shell_grants(values,devices):
    if not isinstance(values,list) or len(values)>4096:raise ValueError('invalid shell grants')
    grants=[];seen=set();profiles={}
    for value in values:
        if not isinstance(value,dict) or set(value)!={'device','group','privilege','profile'}:raise ValueError('invalid shell grant')
        profile=value['profile']
        if not isinstance(profile,str) or profile not in _PROFILE_LEVELS:raise ValueError('unimplemented shell profile')
        device=str(ipaddress.IPv4Address(value['device']));group=value['group'];privilege=value['privilege']
        if device not in devices or not isinstance(group,str) or not 1<=len(group)<=253 or any(ord(c)<32 or ord(c)>126 for c in group):raise ValueError('invalid shell scope')
        if not shell_reply(profile,privilege):raise ValueError('invalid shell privilege')
        if profiles.setdefault(device,profile)!=profile:raise ValueError('conflicting shell profiles')
        if (device,group) in seen:raise ValueError('duplicate shell grant')
        seen.add((device,group));grants.append(ShellGrant(device,group,privilege,profile))
    return tuple(grants)
