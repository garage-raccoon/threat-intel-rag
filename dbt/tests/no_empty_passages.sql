-- A passage must have content beyond its one-line header (roadmap Stage 2: "no empty passages").
{{ config(severity='error') }}  -- guards the search data: stops the run (D61)
SELECT
    passage_id
FROM {{ ref('stg_passages') }}
WHERE text IS NULL OR LENGTH(TRIM(text)) = 0 OR POSITION(CHR(10) IN text) = 0
