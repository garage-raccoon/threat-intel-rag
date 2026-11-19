-- bge-small-en-v1.5 reads at most 512 tokens; anything longer would be silently truncated (research.md D9).
{{ config(severity='error') }}  -- guards the search data: stops the run (D61)
SELECT
    passage_id,
    n_tokens
FROM {{ ref('stg_passages') }}
WHERE n_tokens > 512
