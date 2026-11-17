"""Loads the CSV files into SQLite and builds the country distance table."""

import math
import sqlite3
from pathlib import Path

import pandas as pd


def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance between two points on the globe."""
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    a = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(a))


def build_database(db_path="outputs/auth.db"):
    Path(db_path).unlink(missing_ok=True)
    con = sqlite3.connect(db_path)
    con.executescript(Path("sql/schema.sql").read_text())

    events = pd.read_csv("data/auth_events.csv")
    events["ts_epoch"] = (pd.to_datetime(events["ts"]) - pd.Timestamp("1970-01-01")) // pd.Timedelta(seconds=1)
    events.to_sql("events", con, if_exists="append", index=False)

    users = pd.read_csv("data/users.csv")
    users["is_admin"] = users["is_admin"].astype(int)
    users.to_sql("users", con, if_exists="append", index=False)

    c = pd.read_csv("data/countries.csv", keep_default_na=False)
    pairs = [(a.country, b.country, haversine_km(a.lat, a.lon, b.lat, b.lon))
             for a in c.itertuples() for b in c.itertuples()]
    con.executemany("INSERT INTO country_distance VALUES (?, ?, ?)", pairs)
    con.commit()
    return con
