SELECT
    version,
    attack_id,
    COUNT(*) AS n
FROM {{ ref('stg_attack_history') }}
GROUP BY ALL
HAVING COUNT(*) > 1
