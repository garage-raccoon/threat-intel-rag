-- What happened to each technique in each release, compared with the previous release.
-- LAG looks at the technique's previous *appearance*, which is the previous release unless the technique was missing
-- in between (then it is 'returned'). status_before / status_after let a test reconcile active-technique counts.
WITH h AS (
    SELECT
        *,
        LAG(version_order) OVER w AS prev_version_order,
        LAG(status) OVER w AS prev_status,
        LAG(content_hash) OVER w AS prev_hash,
        LAG(name) OVER w AS prev_name,
        LAG(tactics) OVER w AS prev_tactics,
        LEAD(version_order) OVER w AS next_seen_order
    FROM {{ ref('stg_attack_history') }}
    WINDOW w AS (PARTITION BY attack_id ORDER BY version_order)
),
releases AS (
    SELECT
        version,
        version_order
    FROM {{ ref('stg_attack_versions') }}
),
present AS (
    SELECT
        version,
        version_order,
        attack_id,
        name,
        CASE
            WHEN version_order = 1 THEN 'initial'
            WHEN prev_version_order IS NULL THEN 'added'
            WHEN prev_version_order < version_order - 1 THEN 'returned'
            WHEN prev_status = 'active' AND status = 'revoked' THEN 'revoked'
            WHEN prev_status = 'active' AND status = 'deprecated' THEN 'deprecated'
            WHEN prev_status <> 'active' AND status = 'active' THEN 'reactivated'
            WHEN prev_status <> status THEN 'status_changed'  -- between inactive statuses, e.g. deprecated -> revoked
            WHEN status = 'active' AND content_hash <> prev_hash THEN 'changed'
            ELSE NULL  -- unchanged since the previous release: no row
        END AS change_type,
        prev_version_order IS NOT NULL AND name IS DISTINCT FROM prev_name AS name_changed,
        -- revoked/deprecated techniques lose their tactics, so only an active -> active move counts
        COALESCE(prev_status = 'active' AND status = 'active' AND tactics IS DISTINCT FROM prev_tactics, FALSE)
            AS tactics_changed,
        CASE WHEN prev_version_order = version_order - 1 THEN prev_status END AS status_before,
        status AS status_after,
        prev_tactics AS tactics_before,
        tactics AS tactics_after
    FROM h
),
dropped AS (  -- present in one release, missing from the next one
    SELECT
        r.version,
        r.version_order,
        h.attack_id,
        h.name,
        'dropped' AS change_type,
        FALSE AS name_changed,
        FALSE AS tactics_changed,
        h.status AS status_before,
        CAST(NULL AS VARCHAR) AS status_after,
        h.tactics AS tactics_before,
        CAST(NULL AS VARCHAR) AS tactics_after
    FROM h
    JOIN releases AS r ON r.version_order = h.version_order + 1
    WHERE h.next_seen_order IS NULL OR h.next_seen_order > h.version_order + 1
)
SELECT
    version,
    version_order,
    attack_id,
    name,
    change_type,
    name_changed,
    tactics_changed,
    status_before,
    status_after,
    tactics_before,
    tactics_after
FROM present
WHERE change_type IS NOT NULL
UNION ALL
SELECT
    version,
    version_order,
    attack_id,
    name,
    change_type,
    name_changed,
    tactics_changed,
    status_before,
    status_after,
    tactics_before,
    tactics_after
FROM dropped
