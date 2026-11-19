-- One row per ATT&CK Enterprise release, with a numeric order (versions sort wrong as text: "10.0" < "9.0").
SELECT
    version,
    CAST(approx_release_date AS DATE) AS approx_release_date,
    CAST(techniques_active AS INTEGER) AS techniques_active,
    CAST(techniques_revoked AS INTEGER) AS techniques_revoked,
    CAST(techniques_deprecated AS INTEGER) AS techniques_deprecated,
    file_sha256,
    ROW_NUMBER() OVER (
        ORDER BY CAST(SPLIT_PART(version, '.', 1) AS INTEGER),
                 CAST(COALESCE(NULLIF(SPLIT_PART(version, '.', 2), ''), '0') AS INTEGER)
    ) AS version_order
FROM {{ source('history', 'attack_versions') }}
