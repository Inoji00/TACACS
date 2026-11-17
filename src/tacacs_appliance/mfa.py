"""Local TOTP verifier; secret material is bytes and never serialized/logged."""
import hmac,hashlib,time
def totp(secret:bytes,now:int|None=None,period:int=30,digits:int=6)->str:
 if period<=0 or digits not in (6,8) or (now is not None and now<0):raise ValueError("invalid TOTP parameters")
 if len(secret)<20:raise ValueError("MFA secret too short")
 counter=int((time.time() if now is None else now)//period).to_bytes(8,"big")
 digest=hmac.new(secret,counter,hashlib.sha256).digest();offset=digest[-1]&15
 value=(int.from_bytes(digest[offset:offset+4],"big")&0x7fffffff)%(10**digits)
 return f"{value:0{digits}d}"
def verify_totp(secret:bytes,code:str,now:int|None=None,window:int=1)->bool:
 if window not in (0,1,2):raise ValueError("invalid TOTP window")
 if not code.isascii() or not code.isdecimal() or len(code)!=6:return False
 timestamp=int(time.time() if now is None else now)
 return any(hmac.compare_digest(code,totp(secret,timestamp+(step*30))) for step in range(-window,window+1) if timestamp+(step*30)>=0)
