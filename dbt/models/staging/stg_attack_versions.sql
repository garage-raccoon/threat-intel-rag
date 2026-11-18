-- One row per ATT&CK Enterprise release, with a numeric order (versions sort wrong as text: "10.0" < "9.0").
select
    version,
    cast(approx_release_date as date) as approx_release_date,
    cast(techniques_active as integer) as techniques_active,
    cast(techniques_revoked as integer) as techniques_revoked,
    cast(techniques_deprecated as integer) as techniques_deprecated,
    file_sha256,
    row_number() over (
        order by cast(split_part(version, '.', 1) as integer),
                 cast(coalesce(nullif(split_part(version, '.', 2), ''), '0') as integer)
    ) as version_order
from read_csv('data/history/attack_versions.csv', header = true, all_varchar = true)
