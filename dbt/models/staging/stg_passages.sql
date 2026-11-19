-- Retrieval passages as built by scripts/build_passages.py (ATT&CK in scope + KEV), one row each.
SELECT
    p.passage_id,
    p.doc_id,
    p.source,
    p.name,
    p.section,
    p.text,
    p.n_tokens,
    p.url,
    p.passage_hash
FROM (
    SELECT
        UNNEST(passages) AS p
    FROM {{ source('generated', 'passages') }}
)
