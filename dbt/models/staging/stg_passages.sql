-- Retrieval passages as built by scripts/build_passages.py (ATT&CK in scope + KEV), one row each.
select
    p.passage_id,
    p.doc_id,
    p.source,
    p.name,
    p.section,
    p.text,
    p.n_tokens,
    p.url,
    p.passage_hash
from (select unnest(passages) as p from read_json('data/processed/passages.json', maximum_object_size = 268435456))
