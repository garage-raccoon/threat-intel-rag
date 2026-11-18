select cve_id from {{ ref('stg_kev') }} where not regexp_matches(cve_id, '^CVE-\d{4}-\d{4,}$')
