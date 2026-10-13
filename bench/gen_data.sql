-- Synthetic daily OHLCV table for the benchmark and parity script. Deterministic (hash-based, no random()).
-- psql -v ON_ERROR_STOP=1 -f bench/gen_data.sql   (connection via PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE)
drop table if exists ohlcv_daily;
create table ohlcv_daily (
  asset varchar(32) not null,
  day date not null,
  open numeric, high numeric, low numeric, close numeric, volume numeric,
  source varchar(16),
  primary key (asset, day)
);
insert into ohlcv_daily
with s as (
  select k, 'asset_' || lpad(k::text, 2, '0') as asset, 1300 + (k * 7919) % 10600 as n
  from generate_series(1, 22) k
), d as (
  select s.k, s.asset, i, date '2026-10-12' - (s.n - i) as day,
         (hashint8(s.k * 1000000 + i) % 100000) / 2.5e6::float8 as r,
         abs(hashint8(-(s.k * 1000000 + i)) % 1000000) / 1e6::float8 as u
  from s, generate_series(1, s.n) i
), p as (
  select k, asset, i, day, u, 10 * k * exp(sum(r) over (partition by k order by i)) as c from d
)
select asset, day,
       round((c * (1 + (u - 0.5) * 0.02))::numeric, 10),
       round((c * (1 + u * 0.03))::numeric, 10),
       round((c * (1 - u * 0.03))::numeric, 10),
       round(c::numeric, 10),
       case when u < 0.005 then null else round((1e6 + u * 3e10)::numeric) end,
       case when k % 2 = 0 and i % 3 = 0 then 'stooq' else 'yahoo' end
from p;
analyze ohlcv_daily;
select count(*) as rows, count(distinct asset) as assets, min(close), max(close), count(*) filter (where volume is null) as null_volume from ohlcv_daily;
