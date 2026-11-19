-- Current CISA KEV catalog (scripts/fetch_kev.py keeps data/history/kev_state.csv up to date).
SELECT
    cveID AS cve_id,
    vendorProject AS vendor,
    product,
    vulnerabilityName AS vulnerability_name,
    CAST(dateAdded AS DATE) AS date_added,
    shortDescription AS short_description,
    requiredAction AS required_action,
    TRY_CAST(dueDate AS DATE) AS due_date,
    knownRansomwareCampaignUse AS known_ransomware_use,
    cwes,
    row_hash
FROM {{ source('history', 'kev_state') }}
