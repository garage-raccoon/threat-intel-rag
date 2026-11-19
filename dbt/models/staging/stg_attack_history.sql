-- One row per technique per ATT&CK release (backfilled from all releases: scripts/backfill_attack_history.py).
SELECT
    h.version,
    v.version_order,
    h.attack_id,
    h.name,
    h.is_subtechnique = 'true' AS is_subtechnique,
    h.tactics,
    h.platforms,
    h.status,
    h.content_hash,
    h.stix_modified
FROM {{ source('history', 'attack_history') }} AS h
JOIN {{ ref('stg_attack_versions') }} AS v USING (version)
