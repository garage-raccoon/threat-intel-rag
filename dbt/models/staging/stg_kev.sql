-- Current CISA KEV catalog (scripts/fetch_kev.py keeps data/history/kev_state.csv up to date).
select
    cveID as cve_id,
    vendorProject as vendor,
    product,
    vulnerabilityName as vulnerability_name,
    cast(dateAdded as date) as date_added,
    shortDescription as short_description,
    requiredAction as required_action,
    try_cast(dueDate as date) as due_date,
    knownRansomwareCampaignUse as known_ransomware_use,
    cwes,
    row_hash
from read_csv('data/history/kev_state.csv', header = true, all_varchar = true)
