-- bge-small-en-v1.5 reads at most 512 tokens; anything longer would be silently truncated (research.md D9).
select passage_id, n_tokens from {{ ref('stg_passages') }} where n_tokens > 512
