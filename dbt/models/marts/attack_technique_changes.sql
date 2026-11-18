-- What happened to each technique in each release, compared with the previous release.
-- change_type: initial (first release) | added | changed | revoked | deprecated | reactivated | dropped
with h as (
    select
        *,
        lag(status) over w as prev_status,
        lag(content_hash) over w as prev_hash,
        lag(name) over w as prev_name,
        lag(tactics) over w as prev_tactics,
        lead(version_order) over w as next_seen_order
    from {{ ref('stg_attack_history') }}
    window w as (partition by attack_id order by version_order)
),
releases as (
    select version, version_order from {{ ref('stg_attack_versions') }}
),
present as (
    select
        version, version_order, attack_id, name,
        case
            when version_order = 1 then 'initial'
            when prev_status is null then 'added'
            when prev_status = 'active' and status = 'revoked' then 'revoked'
            when prev_status = 'active' and status = 'deprecated' then 'deprecated'
            when prev_status <> 'active' and status = 'active' then 'reactivated'
            when status = 'active' and content_hash <> prev_hash then 'changed'
        end as change_type,
        prev_name is not null and name <> prev_name as name_changed,
        prev_tactics is not null and tactics <> prev_tactics as tactics_changed,
        prev_tactics as tactics_before,
        tactics as tactics_after
    from h
),
dropped as (  -- present in one release, missing from the next one
    select r.version, r.version_order, h.attack_id, h.name, 'dropped' as change_type,
           false as name_changed, false as tactics_changed, h.tactics as tactics_before, null as tactics_after
    from h
    join releases as r on r.version_order = h.version_order + 1
    where h.next_seen_order is null or h.next_seen_order > h.version_order + 1
)
select * from present where change_type is not null
union all
select * from dropped
