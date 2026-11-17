"""
Builds 30 days of login events for a made-up company (Harbor Supply Co., about 400 staff)
and hides five kinds of attack in the second half.

Days 1-14 are clean and are used to learn what normal looks like.
Days 15-30 contain the attacks. Which events belong to which attack is written to
answer_key/ and is never read by the detection code.

IP addresses come from ranges reserved for testing and carrier NAT, so none of them
point at a real host.

Run:  python generate_logs.py
"""

import random
from datetime import datetime, timedelta

import pandas as pd

random.seed(404)
START = datetime(2026, 10, 1)
DAYS = 30
ATTACK_START_DAY = 14          # zero-based, so attacks begin on day 15
N_USERS = 400

# country -> (UTC offset used for working hours, latitude, longitude)
COUNTRIES = {
    "US": (-5, 39.8, -98.6), "CA": (-5, 56.1, -106.3), "GB": (0, 54.0, -2.0), "PH": (8, 12.9, 121.8),
    "IN": (5, 20.6, 79.0), "NL": (1, 52.1, 5.3), "BR": (-3, -14.2, -51.9), "SG": (8, 1.35, 103.8),
    "DE": (1, 51.2, 10.4), "VN": (7, 14.1, 108.3), "RO": (2, 45.9, 25.0), "MX": (-6, 23.6, -102.5),
    "JP": (9, 36.2, 138.3), "AU": (10, -25.3, 133.8), "ZA": (2, -30.6, 22.9), "TH": (7, 15.9, 101.0),
}
HOME_WEIGHTS = {"US": 86, "CA": 4, "GB": 3, "PH": 4, "IN": 3}
ATTACK_SOURCES = ["NL", "BR", "SG", "DE", "VN", "RO", "US", "MX", "ZA", "TH"]
FIRST = ["alex", "sam", "jordan", "taylor", "morgan", "casey", "riley", "jamie", "drew", "quinn", "avery",
         "blake", "cameron", "dana", "eli", "frankie", "gray", "harper", "jesse", "kai", "lee", "max",
         "noel", "parker", "reese", "sky", "toni", "val", "wes", "robin"]
LAST = ["nguyen", "patel", "smith", "garcia", "kim", "brown", "rossi", "cohen", "ali", "murphy", "tanaka",
        "silva", "olsen", "novak", "reyes", "walker", "young", "diaz", "evans", "ford", "hall", "ito",
        "jones", "klein", "lopez", "moore", "nash", "owens", "price", "reed"]

events = []     # dicts: ts, username, src_ip, country, result
labels = []     # dicts: event index, attack_id, attack_type


def user_ip():
    return f"100.{random.randint(64, 127)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def attacker_ip():
    return f"198.{random.choice([18, 19])}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def add(ts, user, ip, country, result, attack=None):
    events.append({"ts": ts, "username": user, "src_ip": ip, "country": country, "result": result})
    if attack:
        labels.append({"row": len(events) - 1, "attack_id": attack[0], "attack_type": attack[1]})


# ------------------------------------------------------------------ users
users = []
names = random.sample([f"{f}.{l}" for f in FIRST for l in LAST], N_USERS)
for i, name in enumerate(names):
    home = random.choices(list(HOME_WEIGHTS), weights=list(HOME_WEIGHTS.values()))[0]
    users.append({
        "username": name,
        "home_country": home,
        "is_admin": i < 20,
        "start_hour": random.choice([7, 8, 8, 9, 9, 10]),       # local time
        "ips": [user_ip() for _ in range(random.choice([1, 2, 2, 3]))],   # office, home, phone
        "logins_per_day": random.choice([2, 3, 4, 5, 6]),
    })

# people who travel for work. while they are away they don't log in from home.
trips = {}
for u in random.sample(users[20:], 12):
    first_day = random.randint(15, 25)
    trips[u["username"]] = (first_day, first_day + random.randint(2, 5),
                            random.choice([c for c in COUNTRIES if c != u["home_country"]]))

# ----------------------------------------------------------- normal traffic
for day in range(DAYS):
    date = START + timedelta(days=day)
    weekend = date.weekday() >= 5
    for u in users:
        if u["username"] in trips and trips[u["username"]][0] <= day <= trips[u["username"]][1]:
            continue
        if weekend and random.random() > 0.08:
            continue
        if not weekend and random.random() < 0.06:      # day off
            continue
        offset = COUNTRIES[u["home_country"]][0]
        n = max(1, int(random.gauss(u["logins_per_day"], 1)))
        for _ in range(n):
            local_hour = u["start_hour"] + abs(random.gauss(0, 3.2))
            if random.random() < 0.03:                  # the odd late-night login is normal
                local_hour = random.uniform(0, 24)
            ts = date + timedelta(hours=(local_hour - offset) % 24, seconds=random.randint(0, 59))
            ip = random.choices(u["ips"], weights=[6] + [2] * (len(u["ips"]) - 1))[0]
            if random.random() < 0.04:                  # mistyped password, then gets it right
                for k in range(random.choice([1, 1, 2])):
                    add(ts - timedelta(seconds=20 * (k + 1)), u["username"], ip, u["home_country"], "FAIL")
            add(ts, u["username"], ip, u["home_country"], "SUCCESS")

# legitimate things that look suspicious
# 1. the travellers: a few days of logins from another country
for name, (first_day, last_day, dest) in trips.items():
    hotel_ip = user_ip()
    for day in range(first_day, min(last_day, DAYS - 1) + 1):
        date = START + timedelta(days=day)
        for _ in range(random.randint(1, 3)):
            hour = (9 + abs(random.gauss(0, 4)) - COUNTRIES[dest][0]) % 24
            add(date + timedelta(hours=hour), name, hotel_ip, dest, "SUCCESS")
# 2. people who get a new phone or move house: a new IP in the same country
for u in random.sample(users, 30):
    new_ip = user_ip()
    first_day = random.randint(15, 28)
    offset = COUNTRIES[u["home_country"]][0]
    for day in range(first_day, DAYS):
        if random.random() < 0.6:
            hour = (u["start_hour"] + abs(random.gauss(0, 3)) - offset) % 24
            add(START + timedelta(days=day, hours=hour), u["username"], new_ip, u["home_country"], "SUCCESS")
# 3. someone who forgot their password and hammered the login page
for n in range(3):
    u = random.choice(users)
    ts = START + timedelta(days=random.randint(15, 28), hours=random.uniform(13, 20))
    for k in range(random.randint(9, 14)):
        add(ts + timedelta(seconds=15 * k), u["username"], u["ips"][0], u["home_country"], "FAIL")


def attack_time():
    return START + timedelta(days=random.randint(ATTACK_START_DAY, DAYS - 2), hours=random.uniform(0, 24))


# ------------------------------------------------------------------ attacks
# 1. brute force: one address hammers one account
for n in range(6):
    tag = (f"BF-{n + 1}", "brute_force")
    ip, country, target, ts = attacker_ip(), random.choice(ATTACK_SOURCES), random.choice(users), attack_time()
    for k in range(random.randint(40, 200)):
        ts += timedelta(seconds=random.uniform(1, 8))
        add(ts, target["username"], ip, country, "FAIL", tag)
    if n < 2:      # two of them get in
        add(ts + timedelta(seconds=5), target["username"], ip, country, "SUCCESS", tag)

# 2. password spraying: one address tries a few common passwords against many accounts
for n in range(4):
    tag = (f"PS-{n + 1}", "password_spray")
    ip, country, ts = attacker_ip(), random.choice(ATTACK_SOURCES), attack_time()
    targets = random.sample(users, random.randint(80, 200))
    lucky = set(u["username"] for u in random.sample(targets, random.choice([0, 1, 2])))
    for u in targets:
        ts += timedelta(seconds=random.uniform(10, 50))
        add(ts, u["username"], ip, country, "SUCCESS" if u["username"] in lucky else "FAIL", tag)

# 3. credential stuffing, slow and spread out: many addresses, each used only a couple of times
for n in range(2):
    tag = (f"CS-{n + 1}", "credential_stuffing")
    pool = [(attacker_ip(), random.choice(ATTACK_SOURCES)) for _ in range(60)]
    ts = attack_time()
    targets = random.sample(users, 150)
    lucky = set(u["username"] for u in random.sample(targets, 2))
    for u in targets:
        ts += timedelta(seconds=random.uniform(60, 420))
        ip, country = random.choice(pool)
        add(ts, u["username"], ip, country, "SUCCESS" if u["username"] in lucky else "FAIL", tag)

# 4. account takeover with a stolen password: no failures at all, but the login is from
#    another country an hour or two after the real user logged in at home
real_logins = pd.DataFrame(events)
real_logins = real_logins[(real_logins["result"] == "SUCCESS") & (real_logins["ts"] >= START + timedelta(days=ATTACK_START_DAY))]
for n, (_, row) in enumerate(real_logins.sample(8, random_state=3).iterrows()):
    tag = (f"TO-{n + 1}", "takeover_foreign")
    country = random.choice([c for c in ATTACK_SOURCES if c != row["country"]])
    ip = attacker_ip()
    ts = row["ts"] + timedelta(minutes=random.uniform(40, 150))
    for k in range(random.randint(1, 3)):
        add(ts + timedelta(minutes=7 * k), row["username"], ip, country, "SUCCESS", tag)

# 5. admin account used at 2-4am from a new address in the SAME country. nothing geographic to catch.
for n, u in enumerate(random.sample(users[:20], 5)):
    tag = (f"AD-{n + 1}", "admin_off_hours")
    offset = COUNTRIES[u["home_country"]][0]
    ts = START + timedelta(days=random.randint(ATTACK_START_DAY, DAYS - 2), hours=(random.uniform(2, 4) - offset) % 24)
    ip = user_ip()
    for k in range(random.randint(1, 2)):
        add(ts + timedelta(minutes=11 * k), u["username"], ip, u["home_country"], "SUCCESS", tag)

# -------------------------------------------------------------------- write
df = pd.DataFrame(events)
lab = pd.DataFrame(labels)
df["row"] = range(len(df))
df = df.sort_values("ts").reset_index(drop=True)
df["event_id"] = [f"E{n:06d}" for n in range(1, len(df) + 1)]
lab = lab.merge(df[["row", "event_id"]], on="row")[["event_id", "attack_id", "attack_type"]]
df["ts"] = df["ts"].dt.strftime("%Y-%m-%d %H:%M:%S")

df[["event_id", "ts", "username", "src_ip", "country", "result"]].to_csv("data/auth_events.csv", index=False)
pd.DataFrame(users)[["username", "home_country", "is_admin"]].to_csv("data/users.csv", index=False)
pd.DataFrame([{"country": c, "lat": v[1], "lon": v[2]} for c, v in COUNTRIES.items()]).to_csv("data/countries.csv", index=False)
lab.to_csv("answer_key/attack_events.csv", index=False)

print(f"events: {len(df):,}   attack events: {len(lab):,}   incidents: {lab['attack_id'].nunique()}")
print(lab.groupby("attack_type")["attack_id"].nunique().to_string())
