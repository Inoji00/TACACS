"""Vendor-neutral conservative command normalization/classification."""
from dataclasses import dataclass
class CommandError(ValueError):pass
@dataclass(frozen=True,slots=True)
class NormalizedCommand: canonical:str; verb:str; arguments:tuple[str,...]
def normalize(raw:str,max_length:int=1024)->NormalizedCommand:
 if not raw or len(raw)>max_length or any(ord(c)<32 or ord(c)==127 for c in raw):raise CommandError("invalid command")
 canonical=" ".join(raw.strip().split())
 # Shell separators make a single-command decision unsafe without vendor parser.
 if not canonical or any(token in canonical for token in (";","|","&&","||","`","$(")):raise CommandError("ambiguous command syntax")
 parts=canonical.split(" ");return NormalizedCommand(canonical,parts[0].lower(),tuple(parts[1:]))
