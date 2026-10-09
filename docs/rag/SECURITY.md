# RAG knowledge admission and poisoning boundary

The runtime does not treat every JSON file under `knowledge/` as trusted input.

`knowledge/admission_manifest.json` pins every admitted document by its Git blob
SHA. Index replacement fails closed when a file is added, removed, or modified
without an explicit manifest update. This separates "a file exists in the corpus"
from "the file was admitted for retrieval".

## Review flow

1. Review the knowledge change and provenance.
2. Recompute the changed file's Git blob SHA.
3. Update the admission manifest in the same reviewed change.
4. Rebuild the dataset-local index; admission validation must succeed.

The historical benchmark covered injected files and tampering with an already-admitted
file; its harness was removed on 2026-10-09. The admission boundary does **not**
claim protection if an attacker can also approve/update the
manifest or compromise the repository review process. That remains a control-plane
and supply-chain boundary.

Retrieved knowledge remains reference material only. It cannot directly execute
production actions; investigation output remains proposal-only and subject to the
existing policy/human gates.
