"""Thread-safe source rate limit; callers fail closed when capacity is exhausted."""
from dataclasses import dataclass
import threading,time
@dataclass
class _Bucket: tokens:float; updated:float
class SourceRateLimiter:
 def __init__(self,capacity:int=30,refill_per_second:float=1.0,max_sources:int=4096,idle_seconds:float=300):
  if capacity<1 or refill_per_second<=0 or max_sources<1 or idle_seconds<capacity/refill_per_second:raise ValueError("invalid limiter configuration")
  self.capacity,self.refill=capacity,refill_per_second;self._buckets={};self._lock=threading.Lock();self._max_sources=max_sources;self._idle=idle_seconds
 def allow(self,source:str,now:float|None=None)->bool:
  current=time.monotonic() if now is None else now
  with self._lock:
   bucket=self._buckets.get(source)
   if bucket is None:
    if len(self._buckets)>=self._max_sources:
     for key,value in tuple(self._buckets.items()):
      if current-value.updated>=self._idle:del self._buckets[key]
     if len(self._buckets)>=self._max_sources:return False
    bucket=_Bucket(float(self.capacity),current);self._buckets[source]=bucket
   bucket.tokens=min(self.capacity,bucket.tokens+(current-bucket.updated)*self.refill);bucket.updated=current
   if bucket.tokens<1:return False
   bucket.tokens-=1;return True
