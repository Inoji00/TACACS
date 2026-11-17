"""Immutable policy-version lifecycle with separation of duties."""
from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum
from .authorization import PolicyRule

class PolicyState(StrEnum): DRAFT="draft"; TEST="test"; APPROVAL="approval"; ACTIVE="active"; ARCHIVED="archived"
@dataclass(frozen=True, slots=True)
class PolicyVersion:
 version_id:str; revision:int; state:PolicyState; author:str; approver:str|None; rules:tuple[PolicyRule,...]
class PolicyLifecycle:
 def __init__(self, policy_id:str): self.policy_id=policy_id;self._versions:list[PolicyVersion]=[]
 def draft(self, author:str, rules:tuple[PolicyRule,...])->PolicyVersion:
  v=PolicyVersion(f"{self.policy_id}:{len(self._versions)+1}",len(self._versions)+1,PolicyState.DRAFT,author,None,rules);self._versions.append(v);return v
 def submit(self, version_id:str)->PolicyVersion:return self._transition(version_id,PolicyState.DRAFT,PolicyState.APPROVAL)
 def approve(self, version_id:str, approver:str)->PolicyVersion:
  v=self._get(version_id)
  if v.state is not PolicyState.APPROVAL or v.author==approver: raise ValueError("independent approval required")
  return self._replace(v,PolicyState.APPROVAL,approver)
 def activate(self, version_id:str, actor:str)->PolicyVersion:
  v=self._get(version_id)
  if v.state is not PolicyState.APPROVAL or not v.approver or actor==v.author: raise ValueError("approved version and separate activator required")
  for old in tuple(self._versions):
   if old.state is PolicyState.ACTIVE:self._replace(old,PolicyState.ARCHIVED,old.approver)
  return self._replace(v,PolicyState.ACTIVE,v.approver)
 def active(self)->PolicyVersion|None:return next((v for v in self._versions if v.state is PolicyState.ACTIVE),None)
 def _transition(self,i,old,new):
  v=self._get(i)
  if v.state is not old:raise ValueError("invalid policy transition")
  return self._replace(v,new,v.approver)
 def _get(self,i):
  for v in self._versions:
   if v.version_id==i:return v
  raise ValueError("unknown policy version")
 def _replace(self,v,state,approver):
  updated=PolicyVersion(v.version_id,v.revision,state,v.author,approver,v.rules);self._versions[self._versions.index(v)]=updated;return updated
