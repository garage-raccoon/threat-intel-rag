-- One row per ATT&CK release: how many techniques were added, changed, revoked, deprecated, ...
SELECT
    v.version,
    v.version_order,
    v.approx_release_date,
    v.techniques_active,
    COUNT(*) FILTER (WHERE c.change_type = 'added') AS added,
    COUNT(*) FILTER (WHERE c.change_type = 'returned') AS returned,
    COUNT(*) FILTER (WHERE c.change_type = 'changed') AS changed,
    COUNT(*) FILTER (WHERE c.change_type = 'changed' AND c.tactics_changed) AS tactics_changed,
    COUNT(*) FILTER (WHERE c.change_type = 'revoked') AS revoked,
    COUNT(*) FILTER (WHERE c.change_type = 'deprecated') AS deprecated,
    COUNT(*) FILTER (WHERE c.change_type = 'reactivated') AS reactivated,
    COUNT(*) FILTER (WHERE c.change_type = 'status_changed') AS status_changed,
    COUNT(*) FILTER (WHERE c.change_type = 'dropped') AS dropped
FROM {{ ref('stg_attack_versions') }} AS v
LEFT JOIN {{ ref('attack_technique_changes') }} AS c USING (version)
GROUP BY ALL
ORDER BY v.version_order DESC
