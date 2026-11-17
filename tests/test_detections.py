import sqlite3
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, "src")
from load_db import haversine_km

T0 = 1_800_000_000      # any fixed starting second


def make_db(rows):
    """rows: (seconds after T0, username, ip, country, result)"""
    con = sqlite3.connect(":memory:")
    con.executescript(Path("sql/schema.sql").read_text())
    for n, (sec, user, ip, country, result) in enumerate(rows):
        con.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (f"E{n}", "", T0 + sec, user, ip, country, result))
    con.execute("INSERT INTO country_distance VALUES ('US', 'SG', 15000), ('SG', 'US', 15000)")
    return con


def run(con, rule):
    return pd.read_sql(Path("sql", rule).read_text(), con, params={"detect_from": T0})


def test_brute_force_fires_at_20_failures_in_10_minutes():
    rows = [(i * 10, "sam", "1.1.1.1", "US", "FAIL") for i in range(20)]
    assert len(run(make_db(rows), "01_brute_force.sql")) == 20


def test_brute_force_ignores_19_failures_and_slow_failures():
    fast_but_few = [(i * 10, "sam", "1.1.1.1", "US", "FAIL") for i in range(19)]
    many_but_slow = [(i * 120, "sam", "1.1.1.1", "US", "FAIL") for i in range(40)]
    assert len(run(make_db(fast_but_few), "01_brute_force.sql")) == 0
    assert len(run(make_db(many_but_slow), "01_brute_force.sql")) == 0


def test_spray_needs_many_different_accounts():
    spray = [(i * 20, f"user{i}", "2.2.2.2", "US", "FAIL") for i in range(15)]
    one_account = [(i * 20, "sam", "2.2.2.2", "US", "FAIL") for i in range(15)]
    assert len(run(make_db(spray), "02_password_spray.sql")) == 15
    assert len(run(make_db(one_account), "02_password_spray.sql")) == 0


def test_impossible_travel_depends_on_the_time_gap():
    one_hour = [(0, "sam", "3.3.3.3", "US", "SUCCESS"), (3600, "sam", "4.4.4.4", "SG", "SUCCESS")]
    one_day = [(0, "sam", "3.3.3.3", "US", "SUCCESS"), (86400, "sam", "4.4.4.4", "SG", "SUCCESS")]
    assert len(run(make_db(one_hour), "03_impossible_travel.sql")) == 1
    assert len(run(make_db(one_day), "03_impossible_travel.sql")) == 0


def test_haversine_new_york_to_london():
    km = haversine_km(40.71, -74.01, 51.51, -0.13)
    assert 5500 < km < 5650
