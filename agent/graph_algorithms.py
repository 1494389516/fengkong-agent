"""Pluggable, bounded graph feature algorithms.

Outputs are association features, never fraud labels or autonomous enforcement.
"""
import hashlib
import json
import math
import time
import networkx as nx

MAX_ROWS=5000
MAX_NODES=4000


class CommunityV1:
    name="community_v1"
    version="1"

    def compute(self,rows,target_device,target_generation,*,truncated=False):
        g=nx.Graph()
        target=("device",target_device,target_generation)
        for _,uid,device,generation,ip,observed_at,recorded_at in rows:
            d=("device",device,generation)
            if len(g)>=MAX_NODES and d not in g: truncated=True;continue
            g.add_node(d,kind="device")
            if uid:
                u=("uid",uid)
                if len(g)>=MAX_NODES and u not in g: truncated=True;continue
                g.add_edge(u,d,kind="device_account")
        if target not in g:
            return self._empty(target_device,target_generation,truncated)
        component=g.subgraph(nx.node_connected_component(g,target)).copy()
        communities=(list(nx.community.greedy_modularity_communities(component))
                     if component.number_of_edges() and component.number_of_nodes()>2
                     else [frozenset(component.nodes)])
        community=next((set(c) for c in communities if target in c),{target})
        accounts=sorted(n[1] for n in community if n[0]=="uid")
        devices=sorted((n[1],n[2]) for n in community if n[0]=="device")
        density=nx.density(component) if component.number_of_nodes()>1 else 0.0
        target_accounts=sorted(n[1] for n in component.neighbors(target) if n[0]=="uid")
        churn=0
        for uid in target_accounts:
            node=("uid",uid)
            churn=max(churn,sum(1 for n in component.neighbors(node) if n[0]=="device"))
        community_key=hashlib.sha256(json.dumps(
            [accounts,devices],sort_keys=True,separators=(",",":")).encode()).hexdigest()[:20]
        # Bipartite device-account components are structurally sparse by design.
        # Use observed edge fill against the bipartite maximum instead of generic
        # graph density, otherwise a perfectly shared 1-device/3-account star is
        # incorrectly treated as low density.
        account_nodes=[n for n in component if n[0]=="uid"]
        device_nodes=[n for n in component if n[0]=="device"]
        possible=max(1,len(account_nodes)*len(device_nodes))
        bipartite_density=min(1.0,component.number_of_edges()/possible)
        dense=len(accounts)>=3 and bipartite_density>=0.6
        structural=min(1.0,max(0.0,(len(target_accounts)-1)/5.0
                    +max(0,churn-2)/8.0+(0.25 if dense else 0.0)))
        return {
          "algorithm":self.name,"algorithm_version":self.version,
          "community_id":community_key,
          "community_account_count":len(accounts),"community_device_count":len(devices),
          "account_count":len(target_accounts),"shared_account_count":max(0,len(target_accounts)-1),
          "max_account_device_churn":churn,"component_density":round(density,6),"bipartite_density":round(bipartite_density,6),
          "is_dense_subgraph":dense,"community_risk_density":round(structural,6),
          "risk_tags":[tag for tag,hit in (
              ("shared_device",len(target_accounts)>1),("identity_churn",churn>2),
              ("dense_subgraph",dense)) if hit],
          "truncated":bool(truncated),"interpretation":"association_features_only",
        }

    def _empty(self,device,generation,truncated):
        return {"algorithm":self.name,"algorithm_version":self.version,
                "community_id":None,"community_account_count":0,"community_device_count":0,
                "account_count":0,"shared_account_count":0,"max_account_device_churn":0,
                "component_density":0.0,"is_dense_subgraph":False,
                "community_risk_density":0.0,"risk_tags":[],"truncated":bool(truncated),
                "interpretation":"association_features_only"}


class TemporalCommunityV1(CommunityV1):
    """Time-decayed weighted community features for fast-changing abuse graphs."""
    name="temporal_community_v1"
    version="1"

    def __init__(self,half_life_seconds=7*86400):
        self.half_life_seconds=max(3600,float(half_life_seconds))

    def compute(self,rows,target_device,target_generation,*,truncated=False):
        if not rows:
            return self._empty(target_device,target_generation,truncated)
        anchor=max(float(r[6]) for r in rows)
        weighted=[]
        for row in rows:
            age=max(0.0,anchor-float(row[6]))
            weight=math.exp(-math.log(2.0)*age/self.half_life_seconds)
            if weight>=0.01:
                weighted.append((row,weight))
        base=super().compute([row for row,_ in weighted],target_device,target_generation,
                             truncated=truncated)
        target_accounts={}
        account_devices={}
        for row,weight in weighted:
            _,uid,device,generation,ip,observed_at,recorded_at=row
            if uid:
                account_devices.setdefault(uid,set()).add((device,generation))
            if device==target_device and generation==target_generation and uid:
                target_accounts[uid]=max(target_accounts.get(uid,0.0),weight)
        effective_shared=sum(target_accounts.values())
        effective_churn=max((len(account_devices.get(uid,())) for uid in target_accounts),default=0)
        temporal_score=min(1.0,max(0.0,
            max(0.0,effective_shared-1.0)/5.0+
            max(0,effective_churn-2)/8.0+
            (0.25 if base.get("is_dense_subgraph") else 0.0)))
        base.update(
            algorithm=self.name,algorithm_version=self.version,
            temporal_half_life_seconds=int(self.half_life_seconds),
            effective_account_mass=round(effective_shared,6),
            community_risk_density=round(temporal_score,6),
        )
        return base


def graph_algorithm(name="community_v1"):
    if name=="community_v1":
        return CommunityV1()
    if name=="temporal_community_v1":
        return TemporalCommunityV1()
    raise ValueError("unsupported graph algorithm: "+str(name))
