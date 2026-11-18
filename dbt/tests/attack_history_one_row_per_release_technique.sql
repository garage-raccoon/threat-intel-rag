select version, attack_id, count(*) as n
from {{ ref('stg_attack_history') }}
group by all
having count(*) > 1
