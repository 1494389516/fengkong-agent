"""Build an auditable claim-to-evidence graph from an investigation report.

This is not GraphRAG and does not extract new entities from prose. It only
materializes links the report already declared to evidence that the server
actually registered during the investigation.
"""


def build_claim_evidence_graph(report, event_registry, knowledge_registry, support_audit=None):
    if not isinstance(report, dict):
        return {"schema_version": 1, "nodes": [], "edges": [],
                "unresolved_refs": [], "status": "invalid_report"}

    event_registry = event_registry if isinstance(event_registry, dict) else {}
    knowledge_registry = knowledge_registry if isinstance(knowledge_registry, dict) else {}
    support_rows = {
        row.get("index"): row for row in (support_audit or {}).get("claims", [])
        if isinstance(row, dict) and isinstance(row.get("index"), int)
    }

    nodes, edges, unresolved = [], [], []
    seen = set()

    def add_node(node):
        ident = node["id"]
        if ident not in seen:
            seen.add(ident)
            nodes.append(node)

    for index, claim in enumerate(report.get("claims", [])):
        if not isinstance(claim, dict):
            continue
        claim_id = f"claim:{index}"
        support = support_rows.get(index, {})
        add_node({
            "id": claim_id,
            "kind": "claim",
            "index": index,
            "role": claim.get("role", ""),
            "confidence": claim.get("confidence", ""),
            "support_status": support.get("status", "not_evaluated"),
            "semantic_entailment_verified": bool(
                support.get("semantic_entailment_verified", False)),
        })

        for ref in claim.get("event_evidence", []):
            if ref not in event_registry:
                unresolved.append({"claim": claim_id, "ref": ref, "kind": "event"})
                continue
            metadata = event_registry[ref]
            add_node({"id": ref, "kind": metadata.get("kind", "event_evidence")})
            edges.append({"from": ref, "to": claim_id, "relation": "supports",
                          "verified_reference": True})

        for citation in claim.get("knowledge_citations", []):
            if not (isinstance(citation, str) and citation.startswith("[K:")
                    and citation.endswith("]")):
                unresolved.append({"claim": claim_id, "ref": citation, "kind": "knowledge"})
                continue
            chunk_id = citation[3:-1]
            if chunk_id not in knowledge_registry:
                unresolved.append({"claim": claim_id, "ref": citation, "kind": "knowledge"})
                continue
            metadata = knowledge_registry[chunk_id]
            node_id = "knowledge:" + chunk_id
            add_node({
                "id": node_id,
                "kind": "knowledge",
                "chunk_id": chunk_id,
                "source": metadata.get("source", ""),
                "section": metadata.get("section", ""),
                "content_hash": metadata.get("content_hash", ""),
            })
            edges.append({"from": node_id, "to": claim_id, "relation": "supports",
                          "verified_reference": True})

    return {
        "schema_version": 1,
        "status": "unresolved_references" if unresolved else "ok",
        "nodes": nodes,
        "edges": edges,
        "unresolved_refs": unresolved,
        "claim_count": sum(node["kind"] == "claim" for node in nodes),
        "evidence_node_count": sum(node["kind"] != "claim" for node in nodes),
    }
