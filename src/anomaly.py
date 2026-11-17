"""
Anomaly model for successful logins.

The SQL rules look for known attack shapes. This looks for logins that are simply unusual
for that user, which is the only way to catch an attacker who already has the right password
and logs in once from the same country.

Timeline:
  days 1-10    build each user's profile (usual addresses, countries, hours)
  days 11-14   measure how unusual normal logins are against that profile, fit the model
  days 15-30   score every successful login
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

FEATURES = ["new_ip", "new_country", "hour_rarity", "is_admin", "ip_accounts_24h", "user_fails_1h"]


def build_features(events, users, profile_end, score_from):
    """One row per successful login on or after score_from, described relative to the user's profile."""
    events = events.sort_values("ts_epoch").reset_index(drop=True)
    events["hour"] = (events["ts_epoch"] // 3600) % 24

    profile = events[(events["ts_epoch"] < profile_end) & (events["result"] == "SUCCESS")]
    known_ips = profile.groupby("username")["src_ip"].agg(set).to_dict()
    known_countries = profile.groupby("username")["country"].agg(set).to_dict()
    # share of each user's logins in each hour of the day
    hour_share = (profile.groupby(["username", "hour"]).size() / profile.groupby("username").size()).to_dict()
    admins = set(users.loc[users["is_admin"] == 1, "username"])

    # lookups for the two "recent activity" features
    by_ip = {ip: g[["ts_epoch", "username"]].values for ip, g in events.groupby("src_ip")}
    fails_by_user = {u: g["ts_epoch"].values for u, g in events[events["result"] == "FAIL"].groupby("username")}

    rows = []
    target = events[(events["ts_epoch"] >= score_from) & (events["result"] == "SUCCESS")]
    for e in target.itertuples():
        # how common is this hour (give or take one) for this user?
        near = sum(hour_share.get((e.username, (e.hour + d) % 24), 0) for d in (-1, 0, 1))
        seen = by_ip[e.src_ip]
        recent = seen[(seen[:, 0] <= e.ts_epoch) & (seen[:, 0] > e.ts_epoch - 86400)]
        fails = fails_by_user.get(e.username, np.array([]))
        rows.append({
            "event_id": e.event_id,
            "new_ip": int(e.src_ip not in known_ips.get(e.username, set())),
            "new_country": int(e.country not in known_countries.get(e.username, set())),
            "hour_rarity": 1 - near,
            "is_admin": int(e.username in admins),
            "ip_accounts_24h": len(set(recent[:, 1])),
            "user_fails_1h": int(((fails <= e.ts_epoch) & (fails > e.ts_epoch - 3600)).sum()),
        })
    return pd.DataFrame(rows)


def score_logins(events, users, day_seconds, start_epoch):
    profile_end = start_epoch + 10 * day_seconds
    detect_from = start_epoch + 14 * day_seconds

    feats = build_features(events, users, profile_end, score_from=profile_end)
    epoch = events.set_index("event_id")["ts_epoch"]
    feats["ts_epoch"] = feats["event_id"].map(epoch)

    fit = feats[feats["ts_epoch"] < detect_from]
    score = feats[feats["ts_epoch"] >= detect_from].copy()

    model = IsolationForest(n_estimators=300, random_state=0)
    model.fit(fit[FEATURES])

    # lower score = more unusual. the cut-off is the most unusual 0.5% of the normal period.
    cutoff = np.percentile(model.score_samples(fit[FEATURES]), 0.5)
    score["anomaly_score"] = model.score_samples(score[FEATURES])
    score["is_alert"] = score["anomaly_score"] < cutoff
    return score, cutoff
