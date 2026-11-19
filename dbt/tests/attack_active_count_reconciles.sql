-- For every release after the first: previous active count + the net effect of its change rows = its active count.
-- Returns the releases where that fails, i.e. the change logic missed or double-counted a technique.
WITH net AS (
    SELECT
        version_order,
        SUM(CASE WHEN status_after = 'active' THEN 1 ELSE 0 END
            - CASE WHEN status_before = 'active' THEN 1 ELSE 0 END) AS net_active
    FROM {{ ref('attack_technique_changes') }}
    WHERE change_type <> 'initial'
    GROUP BY version_order
),
releases AS (
    SELECT
        version,
        version_order,
        techniques_active,
        LAG(techniques_active) OVER (ORDER BY version_order) AS prev_active
    FROM {{ ref('stg_attack_versions') }}
)
SELECT
    r.version,
    r.prev_active,
    COALESCE(n.net_active, 0) AS net_active,
    r.techniques_active
FROM releases AS r
LEFT JOIN net AS n USING (version_order)
WHERE r.version_order > 1
    AND r.prev_active + COALESCE(n.net_active, 0) <> r.techniques_active
