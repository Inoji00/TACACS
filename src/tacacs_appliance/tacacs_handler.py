"""Composition of the first secure TACACS+ authentication request/reply slice."""
from __future__ import annotations
import threading
import time
from .authentication import AuthenticationReply,encode_authentication_reply,parse_authentication_start
from .authentication import parse_authentication_continue
from .authentication_service import AuthenticationService,PendingPasswordChallenge,PendingUsernameChallenge
from .obfuscation import xor_body
from .protocol import AUTHENTICATION,Frame,Header,encode_frame
from .secrets import DeviceSecretProvider,SecretNotFoundError

class TacacsAuthenticationHandler:
 def __init__(self,secrets:DeviceSecretProvider,service:AuthenticationService,max_pending:int=4096,pending_ttl_seconds:float=60):
  if max_pending<1 or pending_ttl_seconds<=0:raise ValueError("invalid pending challenge limits")
  self._secrets,self._service=secrets,service;self._pending:dict[tuple[str,int],tuple[PendingPasswordChallenge|PendingUsernameChallenge,float,int,int,str]]={};self._max_pending=max_pending;self._ttl=pending_ttl_seconds;self._pending_lock=threading.Lock()
  self.attempted_username=None
  self.remote_address=None
 def new_connection(self):
  """Return isolated session state; the listener must use this as its factory."""
  return TacacsAuthenticationHandler(self._secrets,self._service,self._max_pending,self._ttl)
 def __call__(self,remote_ip:str,frame:Frame)->bytes|None:
  self.attempted_username=None
  self.remote_address=None
  if frame.header.packet_type!=AUTHENTICATION or frame.header.sequence not in (1,3,5):return None
  try:
   secret=self._secrets.resolve(remote_ip);clear=xor_body(frame,secret);key=(remote_ip,frame.header.session_id)
   if frame.header.sequence==1:
    start=parse_authentication_start(clear)
    self.attempted_username=start.username
    self.remote_address=start.remote_address
    reply,pending=self._service.begin(start)
    if pending is not None:
     with self._pending_lock:
      self._remove_expired_locked()
      if key in self._pending or len(self._pending)>=self._max_pending:return None
      self._pending[key]=(pending,time.monotonic(),3,frame.header.version,start.remote_address)
   else:
    with self._pending_lock:
     value=self._pending.get(key)
     if value is None or value[2:4]!=(frame.header.sequence,frame.header.version):return None
     del self._pending[key]
    pending=None if value is None or time.monotonic()-value[1]>self._ttl else value[0]
    if pending is None:return None
    request=parse_authentication_continue(clear)
    self.remote_address=value[4]
    if isinstance(pending,PendingUsernameChallenge):
     reply,next_pending=self._service.continue_username(request)
     if next_pending is not None:
      self.attempted_username=next_pending.username
      with self._pending_lock:
       if key in self._pending or len(self._pending)>=self._max_pending:return None
       self._pending[key]=(next_pending,value[1],5,value[3],value[4])
    else:
     self.attempted_username=pending.username
     reply=self._service.continue_password(pending,request)
  except (SecretNotFoundError,ValueError):
   # An unknown/malformed client receives no oracle or sensitive error.
   return None
  body=encode_authentication_reply(reply)
  response=Frame(Header(frame.header.version,AUTHENTICATION,frame.header.sequence+1,frame.header.flags,frame.header.session_id,len(body)),body)
  encrypted=xor_body(response,secret)
  return encode_frame(response.header,encrypted)
 def _remove_expired_locked(self)->None:
  cutoff=time.monotonic()-self._ttl
  for key,(_,created,_,_,_) in tuple(self._pending.items()):
   if created<cutoff:del self._pending[key]
