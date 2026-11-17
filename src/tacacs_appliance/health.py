"""Minimal local health endpoints with no sensitive diagnostics."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
import threading


class BoundedHealthServer(ThreadingHTTPServer):
 daemon_threads = True
 def __init__(self,address,handler,*,worker_limit=8):
  if type(worker_limit) is not int or not 1<=worker_limit<=64:
   raise ValueError("invalid health worker limit")
  self._worker_slots=threading.BoundedSemaphore(worker_limit)
  self._clients=set()
  self._clients_lock=threading.Lock()
  self._closing=False
  super().__init__(address,handler)
 def process_request(self,request,client_address):
  if not self._worker_slots.acquire(blocking=False):
   self.shutdown_request(request)
   return
  with self._clients_lock:
   if self._closing:
    self._worker_slots.release();self.shutdown_request(request);return
   self._clients.add(request)
  try:super().process_request(request,client_address)
  except BaseException:
   with self._clients_lock:self._clients.discard(request)
   self._worker_slots.release();self.shutdown_request(request);raise
 def process_request_thread(self,request,client_address):
  try:super().process_request_thread(request,client_address)
  finally:
   with self._clients_lock:self._clients.discard(request)
   self._worker_slots.release()
 def server_close(self):
  import socket
  with self._clients_lock:
   self._closing=True
   for client in self._clients:
    try:client.shutdown(socket.SHUT_RDWR)
    except OSError:pass
    client.close()
  super().server_close()

class HealthHandler(BaseHTTPRequestHandler):
 readiness:Callable[[],bool]=staticmethod(lambda:False)
 metrics:Callable[[],str]|None=None
 def setup(self):
  self.request.settimeout(3)
  super().setup()
 def do_GET(self):
  if self.path=="/health/live": self._reply(200,b'{"status":"live"}')
  elif self.path=="/health/ready":
   try:ready=bool(self.readiness())
   except Exception:ready=False
   self._reply(200 if ready else 503,b'{"status":"ready"}' if ready else b'{"status":"unavailable"}')
  elif self.path=="/metrics" and self.metrics is not None:
   self._reply(200,self.metrics().encode(),"text/plain; version=0.0.4; charset=utf-8")
  else:self._reply(404,b'{"error":"not found"}')
 def _reply(self,status,body,content_type="application/json"):
  self.send_response(status);self.send_header("Content-Type",content_type);self.send_header("Content-Length",str(len(body)));self.send_header("Cache-Control","no-store");self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
 def handle(self):
  try:super().handle()
  except (OSError,TimeoutError):pass
def create_health_server(address:tuple[str,int], readiness:Callable[[],bool], *, metrics:Callable[[],str]|None=None,worker_limit:int=8)->ThreadingHTTPServer:
 handler=type("ConfiguredHealthHandler",(HealthHandler,),{"readiness":staticmethod(readiness),"metrics":staticmethod(metrics) if metrics else None})
 return BoundedHealthServer(address,handler,worker_limit=worker_limit)
