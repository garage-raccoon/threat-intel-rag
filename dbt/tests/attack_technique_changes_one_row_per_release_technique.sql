-- Grain: at most one change per technique per release; a duplicate would double-count it in the release summary.
SELECT
    version,
    attack_id,
    COUNT(*) AS n
FROM {{ ref('attack_technique_changes') }}
GROUP BY ALL
HAVING COUNT(*) > 1
