SELECT
    cve_id
FROM {{ ref('stg_kev') }}
WHERE NOT REGEXP_MATCHES(cve_id, '^CVE-\d{4}-\d{4,}$')
