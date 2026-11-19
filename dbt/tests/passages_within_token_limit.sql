-- bge-small-en-v1.5 reads at most 512 tokens; anything longer would be silently truncated.
{{ config(severity='error') }}  -- guards the search data: stops the run
SELECT
    passage_id,
    n_tokens
FROM {{ ref('stg_passages') }}
WHERE n_tokens > 512
