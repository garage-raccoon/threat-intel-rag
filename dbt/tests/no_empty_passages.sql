-- A passage must have content beyond its one-line header (roadmap Stage 2: "no empty passages").
select passage_id
from {{ ref('stg_passages') }}
where text is null or length(trim(text)) = 0 or position(chr(10) in text) = 0
