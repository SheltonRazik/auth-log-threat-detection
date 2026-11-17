"""
Runs the four SQL rules and the anomaly model, then scores them against the answer key.

Run:  python run_detections.py
"""

import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

sys.path.insert(0, "src")
from anomaly import FEATURES, score_logins
from load_db import build_database

DAY = 86400
BLUE, ORANGE = "#2E5FA3", "#C8691C"
Path("outputs").mkdir(exist_ok=True)

con = build_database()
events = pd.read_sql("SELECT * FROM events", con)
users = pd.read_sql("SELECT * FROM users", con)
start_epoch = int(events["ts_epoch"].min() // DAY * DAY)
detect_from = start_epoch + 14 * DAY

# ---- SQL rules
rule_files = ["01_brute_force.sql", "02_password_spray.sql", "03_impossible_travel.sql", "04_unknown_source_spike.sql"]
flagged = [pd.read_sql(Path("sql", f).read_text(), con, params={"detect_from": detect_from}) for f in rule_files]

# ---- anomaly model on successful logins
scored, cutoff = score_logins(events, users, DAY, start_epoch)
model_alerts = scored[scored["is_alert"]].merge(events[["event_id", "username", "ts"]], on="event_id")
model_alerts["detector"] = "anomaly_model"
model_alerts["alert_key"] = model_alerts["username"] + " " + model_alerts["ts"].str[:10]
flagged.append(model_alerts[["event_id", "detector", "alert_key"]])

flagged = pd.concat(flagged, ignore_index=True)
con.close()

# ---- score against the answer key
truth = pd.read_csv("answer_key/attack_events.csv")
flagged = flagged.merge(truth, on="event_id", how="left")
flagged["is_attack"] = flagged["attack_id"].notna()

# an alert is one thing an analyst would open: all flagged events sharing a detector and key
alerts = flagged.groupby(["detector", "alert_key"]).agg(
    events=("event_id", "count"), attack_events=("is_attack", "sum"),
    incidents=("attack_id", lambda s: ", ".join(sorted(s.dropna().unique())))).reset_index()
alerts["true_alert"] = alerts["attack_events"] > 0
alerts.to_csv("outputs/alerts.csv", index=False)

detectors = ["brute_force", "password_spray", "impossible_travel", "unknown_source_spike", "anomaly_model"]
attack_types = ["brute_force", "password_spray", "credential_stuffing", "takeover_foreign", "admin_off_hours"]
incidents = truth.groupby("attack_type")["attack_id"].unique()

coverage = pd.DataFrame(index=attack_types, columns=detectors + ["any detector"], dtype=object)
for a in attack_types:
    total = len(incidents[a])
    for d in detectors:
        caught = flagged[(flagged["detector"] == d) & (flagged["attack_type"] == a)]["attack_id"].nunique()
        coverage.loc[a, d] = f"{caught}/{total}" if caught else "-"
    caught_any = flagged[flagged["attack_type"] == a]["attack_id"].nunique()
    coverage.loc[a, "any detector"] = f"{caught_any}/{total}"
coverage.index.name = "attack"
coverage.to_csv("outputs/coverage.csv")

precision = alerts.groupby("detector").agg(alerts=("true_alert", "count"), true_alerts=("true_alert", "sum")).reindex(detectors)
precision["false_alerts"] = precision["alerts"] - precision["true_alerts"]
precision["precision"] = (precision["true_alerts"] / precision["alerts"]).round(2)
precision.to_csv("outputs/alert_precision.csv")

# accounts where an attacker actually got in: a successful login that belongs to an attack
breaches = truth.merge(events[events["result"] == "SUCCESS"], on="event_id")
breached = breaches.groupby("attack_id").agg(attack_type=("attack_type", "first"), username=("username", "first")).reset_index()
breached["detected"] = breached["attack_id"].isin(flagged["attack_id"])
breached.to_csv("outputs/breached_accounts.csv", index=False)

pd.set_option("display.width", 200)
print(f"events: {len(events):,}   detection period events: {(events['ts_epoch'] >= detect_from).sum():,}")
print(f"\nIncidents caught, by detector\n{coverage.to_string()}")
print(f"\nAlert quality\n{precision.to_string()}")
total_inc = truth["attack_id"].nunique()
print(f"\nincidents caught by at least one detector: {flagged['attack_id'].nunique()} of {total_inc}")
print(f"incidents where the attacker got in: {len(breached)}, of which detected: {int(breached['detected'].sum())}")
print(f"total alerts to review: {len(alerts)}  ({int((~alerts['true_alert']).sum())} false)")

# ---- chart: what the anomaly model sees
scored = scored.merge(truth, on="event_id", how="left")
scored["kind"] = np.where(scored["attack_id"].notna(), "Attacker login", "Normal login")
fig, ax = plt.subplots(figsize=(9, 4.2))
bins = np.linspace(scored["anomaly_score"].min(), scored["anomaly_score"].max(), 45)
ax.hist(scored.loc[scored["kind"] == "Normal login", "anomaly_score"], bins=bins, color=BLUE, label="Normal login")
ax.hist(scored.loc[scored["kind"] == "Attacker login", "anomaly_score"], bins=bins, color=ORANGE, label="Attacker login")
ax.axvline(cutoff, color="#333333", linewidth=1, linestyle=":")
ax.text(cutoff - 0.004, ax.get_ylim()[1] * 0.5, "alert cut-off", rotation=90, ha="right", va="center", fontsize=9, color="#555555")
ax.set_yscale("log")
ax.set_xlabel("Anomaly score (further left = more unusual)")
ax.set_ylabel("Successful logins (log scale)")
ax.set_title("Attacker logins sit in the unusual tail, but so do some normal ones", loc="left", fontsize=12)
ax.legend(frameon=False)
ax.spines[["top", "right"]].set_visible(False)
fig.tight_layout()
fig.savefig("outputs/anomaly_scores.png", dpi=160)

# ---- chart: failed logins per hour, with attack hours marked
ev = events[events["ts_epoch"] >= detect_from].merge(truth, on="event_id", how="left")
ev["hour"] = pd.to_datetime(ev["ts"]).dt.floor("h")
fails = ev[ev["result"] == "FAIL"]
normal = fails[fails["attack_id"].isna()].groupby("hour").size()
attack = fails[fails["attack_id"].notna()].groupby("hour").size()
hours = pd.date_range(ev["hour"].min(), ev["hour"].max(), freq="h")
normal, attack = normal.reindex(hours, fill_value=0), attack.reindex(hours, fill_value=0)
fig, ax = plt.subplots(figsize=(10, 3.8))
ax.bar(hours, normal, width=0.04, color=BLUE, label="Normal failed logins")
ax.bar(hours, attack, width=0.04, bottom=normal, color=ORANGE, label="Attack failed logins")
ax.set_ylabel("Failed logins per hour")
ax.set_title("Failed logins per hour, days 15-30", loc="left", fontsize=12)
ax.legend(frameon=False, loc="upper left")
ax.spines[["top", "right"]].set_visible(False)
fig.autofmt_xdate()
fig.tight_layout()
fig.savefig("outputs/failed_logins_timeline.png", dpi=160)
