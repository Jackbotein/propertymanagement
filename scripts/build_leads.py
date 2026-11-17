#!/usr/bin/env python3
"""
Build the encrypted lead file for the Copia partner portal.

  pip install pandas openpyxl cryptography
  python scripts/build_leads.py path/to/housing_kpi_ranking.xlsx --email you@example.com --password 'secret'

Lead rules (an entry is dropped unless all hold):
  * it has an occupancy figure between 0 and 100%
  * that occupancy is dated 1 Sep 2025 or later (and not in the future)
  * the figure is either derived from reported rent/vacancy (GPR, vacancy loss, net rent)
    or appears next to the word "occupancy" in the filing text (KPI evidence sheet);
    figures parsed from unrelated text (rent caps, "% of AMI", reserve rules, fee growth,
    bed counts, refund percentages) are rejected
  * it is a housing property (hospital / health-system bonds are dropped)

Everything the spreadsheet holds from EMMA is carried into the lead: KPIs with dates, rent
roll figures, management agreement terms, stakeholders, CUSIPs, the issue link and every
document listed for the issue. Owner research in research/owners.json is merged in by EMMA
issue key. Output: data/leads.enc.js (AES-256-GCM, key from PBKDF2-SHA256 of "email:password").
Do NOT commit the spreadsheet.
"""
import argparse, base64, json, math, os, re, sys
from datetime import date
import pandas as pd
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
SHEETS = [("Student Housing", "Student Housing"), ("Multifamily - Affordable", "Multifamily"),
          ("Senior Living - CCRC", "Senior Living"), ("Military Housing", "Military"),
          ("Single-Family HFA", "Single-Family"), ("Other Housing", "Other Housing")]
MIN_ASOF = pd.Timestamp("2025-09-01")
ITERATIONS = 250_000

# ---------------------------------------------------------------- helpers
def nz(v):
    if v is None: return None
    if isinstance(v, float) and math.isnan(v): return None
    if isinstance(v, str) and not v.strip(): return None
    return v

def tidy(s):
    return re.sub(r"\s+", " ", str(s).replace("_x000D_", " ")).strip()

def txt(v, maxlen=None):
    v = nz(v)
    if v is None: return None
    s = tidy(v)
    if maxlen and len(s) > maxlen: s = s[:maxlen - 1].rstrip() + "…"
    return s

def num(v, nd=1):
    v = nz(v)
    try: return round(float(v), nd) if v is not None else None
    except (TypeError, ValueError): return None

def dstr(v):
    v = nz(v)
    if v is None: return None
    t = pd.to_datetime(v, errors="coerce")
    return t.strftime("%Y-%m-%d") if not pd.isna(t) else tidy(v)

def smart_title(s):
    if s.isupper():
        s = s.title()
        s = re.sub(r"\b(Llc|Lp|Hfa|Hud|Ii|Iii|Iv|Ksu|Sdsu|Ccrc|Voa)\b", lambda m: m.group(0).upper(), s)
    return s

# ---------------------------------------------------------------- names
GENERIC = re.compile(r"[“”\"]|^the project\b|^project$|federally taxable|term rate|fannie mae|limited obligation|"
                     r"^series\b|^non-amt$|^social$|^formerly\b|^the property\b|^together\b|^see note|^california$|"
                     r"^m-tems$|^authority and\b|^workforce and affordable housing units$|project administrator|"
                     r"housing revenue bonds|^the \w+ project$|^sustainability bonds$|housing finance (corporation|agency)$|"
                     r"^(alabama|alaska|arizona|arkansas|colorado|connecticut|delaware|florida|georgia|hawaii|idaho|illinois|indiana|iowa|kansas|kentucky|louisiana|maine|maryland|massachusetts|michigan|minnesota|mississippi|missouri|montana|nebraska|nevada|new \w+|north \w+|ohio|oklahoma|oregon|pennsylvania|rhode island|south \w+|tennessee|texas|utah|vermont|virginia|washington|west virginia|wisconsin|wyoming)$", re.I)
BOND_WORDS = re.compile(r"\bBONDS?\b|\bSERIES\b|\bNTS\b|\bREV\b|\bREVENUE\b", re.I)
TITLE_NAME = re.compile(r"(?:Annual Report|Operating Data|Audited Financial Statements|Annual Financials(?: Series [\w ]+?)?|"
                        r"Audited Financials?|Financial Statements?)\s*[-–]\s*(.+?)\s+(?:for the|as of)\b", re.I)

def name_from_parens(text):
    if not text: return None
    for m in re.finditer(r"\(([^()]{4,80})\)", tidy(text)):
        inner = m.group(1).strip()
        if not re.search(r"SERIES|TAXABLE|TAX-EXEMPT|MBS|SECURED|GUARANTEED|NOT TO EXCEED|^\d{4}|AMT", inner, re.I):
            return inner
    return None

def name_from_docs(titles):
    for t in titles:
        m0 = re.match(r"(?:OHCS\s+)?([A-Z][\w&'.\- ]{3,60}?)\s+(?:Apartments\s+)?Annual (?:Report|Financials)\b", str(t))
        if m0 and not re.search(r"^\d|^(FY|Annual|Audited|Financial)", m0.group(1)):
            n0 = m0.group(1).strip()
            if not re.search(r"\b(Report|Series|Bonds?)\b", n0, re.I): return n0
        m = TITLE_NAME.search(str(t))
        if m:
            n = m.group(1).strip(" ,.-–")
            n = re.sub(r",?\s*(L\.?L\.?C\.?|LP|L\.P\.)$", "", n).strip()
            if 4 <= len(n) <= 70 and not re.search(r"\d{4}|year ended", n): return n
        m = re.match(r"(.+?(?:LLC|L\.P\.|LP))\s+(?:Audited|Financial|for the)", str(t))
        if m and len(m.group(1)) < 60: return re.sub(r",?\s*(LLC|L\.P\.|LP)$", "", m.group(1)).strip()
    return None

def short_name(n):
    n = re.sub(r"^(Green M-Tebs --|Mtebs|Hsg[- ]Bldg|Hsg[- ]?Bds|Hsg-|Bds|Taxable-Govtl Nts-\w+)\s*", "", n, flags=re.I)
    n = re.sub(r"\s+(Preservation )?(LP|L\.P\.)?\s*\d{4}\s*[A-Z]?-?\d?$", "", n)
    n = re.sub(r"\bL\.L\.C\.?|\bLLC\b,?|, L\.P\.?|\bL\.P\.?$|\bLP$", "", n)
    n = re.sub(r"^SFP\s*[–-]\s*PUFW I\s*[–-]\s*", "Purdue Fort Wayne ", n)
    n = re.sub(r"^(Provident Group|NCCD|PRG)\s*[–-]\s*", "", n)
    n = re.sub(r"\s+(Project|Projects)$", "", n)
    n = re.sub(r"\s{2,}", " ", n).strip(" ,.-–")
    n = n.replace("Aparments", "Apartments")
    n = re.sub(r"\s+Proj\b", "", n)
    n = re.sub(r"\b(.{4,40}?)\s+\1\b", r"\1", n)
    n = re.sub(r"\s+Preservation$", "", n) if re.search(r"Apts|Apartments", n) else n
    return n

def clean_name(prop, issuer, borrower, titles):
    p = tidy(prop) if nz(prop) else ""
    if p and BOND_WORDS.search(p): p = name_from_parens(p) or ""
    p = re.sub(r"^(collectively, |as more particularly described herein, )", "", p, flags=re.I).strip()
    if not p or GENERIC.search(p) or len(p) < 4:
        p = name_from_docs(titles) or ""
    if not p:
        q = name_from_parens(issuer) or ""
        if q and not re.search(r"AUTH|AGENCY|CORP|FINANCE|COMMISSION|DEPARTMENT", q, re.I): p = q
    if not p:
        b = tidy(borrower) if nz(borrower) else ""
        if b and len(b) < 60 and not re.search(r"audited|proceeds|loan|lend|will be|borrower", b, re.I): p = b
    if not p: return None
    n = short_name(smart_title(p))
    return None if not n or len(n) < 4 or not n[0].isupper() and not n[0].isdigit() or GENERIC.search(n) else n

# ---------------------------------------------------------------- people / managers
JUNK_MGR = re.compile(r"factset|^property management$|^local management$|^management$|^llc$|^liability company$|"
                      r"^obligated group$|^inc$|^management services, l\.?p$", re.I)
def clean_mgr(m, quote):
    m = txt(m)
    if m:
        m = re.sub(r"^.*?(agreement with|will be|managed by|manager is|manager,)\s+", "", m, flags=re.I)
        m = re.sub(r"^Guarantor,\s*", "", m).strip().rstrip(".")
    if not m or JUNK_MGR.search(m) or len(m) > 70:
        m = None
        q = txt(quote) or ""
        mm = re.search(r"(?:managed by|management agreement with|engaged|Property Manager)\s+(?:the\s+)?([A-Z][A-Za-z&.,'\- ]{3,60}?(?:LLC|L\.L\.C\.|Inc\.?|Company|Management|Corporation|LP|Services))", q)
        if mm and not JUNK_MGR.search(mm.group(1)): m = mm.group(1).strip(" ,")
    return m

BAD_PERSON = re.compile(r"pro tempore|auditor|authentication|assistant secretary|communications|certificate|trustee|"
                        r"bank|ltd|llc|inc\b|\d|non-profit|restaurant|operations strategy|reservation sales|redevelopment|"
                        r"chapter|mortgage bankers|tax credit|heidelberg|waypoint commercial", re.I)
def person_ok(n):
    n = txt(n)
    return n if n and not BAD_PERSON.search(n) and 2 <= len(n.split()) <= 5 and len(n) <= 40 else None

def parse_people(v):
    out = []
    for part in str(nz(v) or "").split(";"):
        m = re.match(r"\s*(.+?)\s+—\s+([^()]+?)\s*\((.*?)\)\s*$", part)
        if not m: continue
        name = person_ok(m.group(1))
        if not name: continue
        out.append({"name": name, "title": m.group(2).strip(), "org": m.group(3).strip() or None})
    return out[:6]

# ---------------------------------------------------------------- occupancy validation
HOSP = re.compile(r"HEALTH ?CARE|HOSPITAL|HEALTH SYSTEM|MEDICAL CENTER|CLINIC", re.I)
BADCTX = re.compile(r"office and occupancy|occupancy (costs|expense)|re-occupancy|qualified occupancy|"
                    r"occupancy of \d+% of the units|licensed beds|beds in service|staffed beds|refundable|"
                    r"single occupancy|double occupancy|reserve", re.I)

def occupancy_evidence(ev, key, v):
    """Return (ok, snippet, doc, page) for a quoted occupancy figure."""
    q = ev[(ev["Issue key"] == key) & (ev["Value"].round(1) == round(v, 1))]
    for _, row in q.iterrows():
        quote = str(row["Quote"])
        for m in re.finditer(r"occupan\w*", quote, re.I):
            if BADCTX.search(quote[max(0, m.start() - 40):m.end() + 40]): continue
            after = quote[m.end():m.end() + 70]
            hit = None
            for p in (f"{v:.2f}", f"{v:.1f}", f"{v:.0f}"):
                hm = re.search(r"(?<![\d.])" + re.escape(p) + r"\s*%", after)
                if hm: hit = hm; break
            if not hit: continue
            between = after[:hit.start()]
            if len(between.split()) > 13: continue
            if "%" in between[:-1] and "Economic" not in between: continue
            if re.search(r"\b(LTV|revenue|fee|increase|decrease)", between, re.I): continue
            if re.search(r"\b[A-Z][a-z]{2}-(0\d|1\d|2[0-4])\b", quote[max(0, m.start() - 80):m.end() + 80]): continue
            snip = quote[max(0, m.start() - 160):m.end() + hit.end() + 120]
            return True, tidy(snip), nz(row.get("Link")), nz(row.get("Page"))
    return False, None, None, None

def validate(r, ev, today):
    v = nz(r.get("1 Econ occupancy %"))
    if v is None or not (0 < float(v) <= 100): return "no occupancy", None
    asof = pd.to_datetime(r.get("1 as-of"), errors="coerce")
    if pd.isna(asof) or asof < MIN_ASOF or asof > today: return "occupancy not dated Sep 2025 or later", None
    if HOSP.search(" ".join(str(r.get(c, "")) for c in ("Property", "Issuer", "Borrower"))): return "hospital / health system", None
    basis = str(r.get("1 Occupancy basis"))
    if "derived" in basis:
        sc = str(r.get("Occupancy sense check"))
        if "CHECK" in sc and "economic" in sc: return "economic and physical occupancy conflict", None
        return "ok", {"method": "derived", "basis": "Economic, derived from reported rent roll (potential rent, vacancy loss, net rent)"}
    ok, snip, link, page = occupancy_evidence(ev, r.get("Issue key"), float(v))
    if not ok: return "occupancy figure not confirmed in filing text", None
    return "ok", {"method": "quoted", "basis": ("Physical" if "physical" in basis else "Economic") + ", as stated in filing",
                  "quote": snip, "link": link, "page": page}

# ---------------------------------------------------------------- build
KPIS = [("1", "Occupancy %"), ("2", "Controllable opex / unit-bed $"), ("3", "NOI growth %"), ("4", "Rent growth %"),
        ("5", "Renewal rate %"), ("6", "Delinquency / bad debt %"), ("7", "Days vacant / turn"), ("8", "Budget variance %"),
        ("9", "Inspection score"), ("10", "Staff turnover %")]
KPI_COLS = {"1": "1 Econ occupancy %", "2": "2 Ctrl opex / unit-bed $", "3": "3 NOI growth %", "4": "4 Rent growth %",
            "5": "5 Renewal rate %", "6": "6 Delinq/bad debt %", "7": "7 Days vacant/turn", "8": "8 Budget variance %",
            "9": "9 Inspection score", "10": "10 Staff turnover %"}

def build(xlsx, research):
    x = pd.ExcelFile(xlsx)
    today = pd.Timestamp(date.today())
    ev = pd.read_excel(x, "KPI evidence")
    ev = ev[ev["KPI"].astype(str).str.contains("occup", case=False)]
    src = pd.read_excel(x, "Sources")
    src["_d"] = pd.to_datetime(src["Date"], errors="coerce")
    docs_by = {k: g.sort_values("_d", ascending=False) for k, g in src.groupby("Issue key")}
    leads, dropped = [], {}
    for sheet, label in SHEETS:
        df = pd.read_excel(x, sheet)
        for _, r in df.iterrows():
            status, occ_info = validate(r, ev, today)
            if status != "ok":
                dropped[status] = dropped.get(status, 0) + 1
                continue
            key = r.get("Issue key")
            g = docs_by.get(key)
            docs = [] if g is None else [{"date": dstr(d.Date), "type": txt(d["Doc type"]), "title": txt(d.Title, 160), "link": nz(d.Link)}
                                         for _, d in g.iterrows()]
            name = clean_name(r.get("Property"), r.get("Issuer"), r.get("Borrower"), [d["title"] for d in docs])
            res = research.get(key) if isinstance(key, str) else None
            if res and res.get("name"): name = res["name"]
            units, beds = num(r.get("Units"), 0), num(r.get("Beds"), 0)
            size = f"{int(beds):,} beds" if beds else (f"{int(units):,} units" if units else None)
            if res and res.get("units"): size = res["units"]
            os_dates = [d["date"] for d in docs if d["type"] == "official_statement" and d["date"]]
            recent_issue = bool(os_dates) and max(os_dates) >= "2023-01-01"
            failure = any(re.search(r"failure to (report|file)", d["title"] or "", re.I) for d in docs)
            kpis = []
            for k, label_k in KPIS:
                val = num(r.get(KPI_COLS[k]), 2)
                if val is None: continue
                kpis.append({"k": label_k, "v": val, "asof": dstr(r.get(f"{k} as-of")), "vs": num(r.get(f"{k} vs peer median"), 1),
                             "pctl": num(r.get(f"{k} pctl"), 0)})
            pcontact = person_ok(r.get("PRIMARY CONTACT"))
            mgmt = {
                "agreementDate": dstr(r.get("Mgmt agreement date")), "commencement": dstr(r.get("Mgmt commencement")),
                "initialTermYrs": num(r.get("Initial term (yrs)")), "lastRenewal": dstr(r.get("Last renewal / amendment")),
                "statedExpiration": dstr(r.get("Stated expiration")), "nextRenewal": dstr(r.get("Next renewal / expiry")),
                "monthsToExpiry": num(r.get("Months to expiry"), 0), "expiryBasis": txt(r.get("Expiry basis"), 200),
                "autoRenewal": txt(r.get("Auto-renewal"), 200), "termination": txt(r.get("Termination rights"), 300),
                "trusteeReplace": txt(r.get("Trustee/bondholder replace rights"), 300), "feePct": num(r.get("Mgmt fee %"), 2),
                "rfpNotice": txt(r.get("Manager change / RFP notice"), 300), "quote": txt(r.get("Mgmt agreement quote"), 600),
                "quoteLink": nz(r.get("Mgmt agreement source link")),
            }
            mgmt = {k: v for k, v in mgmt.items() if v is not None}
            lead = {
                "key": key, "name": name or f"Unnamed {label.lower()} property", "generic": not name,
                "sector": label, "state": nz(r.get("State")), "region": nz(r.get("Region")), "size": size,
                "opp": round(float(r["Opportunity score"])) if nz(r.get("Opportunity score")) is not None else None,
                "perf": num(r.get("Performance score")), "complete": num(r.get("Data completeness %"), 0),
                "kpiCount": num(r.get("KPIs scored"), 0), "ranked": nz(r.get("Rank")) is not None,
                "occ": num(r.get("1 Econ occupancy %"), 2), "occAsof": dstr(r.get("1 as-of")), "occVs": num(r.get("1 vs peer median")),
                "occPctl": num(r.get("1 pctl"), 0), "physOcc": num(r.get("Physical occupancy %"), 2), "occInfo": occ_info,
                "senseCheck": txt(r.get("Occupancy sense check")),
                "rent": {k2: num(r.get(c), 0 if "$" in c else 1) for k2, c in [
                    ("potential", "Potential rent $ (GPR+TAP)"), ("vacancyLoss", "Vacancy loss $"), ("concessions", "Concessions $"),
                    ("netRent", "Net rent $"), ("totalRevenue", "Total revenue $"), ("vacancyPctPotential", "Vacancy loss % of potential rent"),
                    ("vacancyPctRevenue", "Vacancy loss % of total revenue")] if num(r.get(c)) is not None},
                "rentAsof": txt(r.get("Rent figures as-of")), "rentSource": nz(r.get("Rent figures source")),
                "dscr": num(r.get("DSCR"), 2), "dscrCovenant": num(r.get("DSCR covenant"), 2), "daysCash": num(r.get("Days cash"), 0),
                "distressed": str(nz(r.get("Distressed")) or "").upper() == "YES", "distressFlags": txt(r.get("Distress flags"), 300),
                "kpis": kpis, "kpiAsof": txt(r.get("KPI as-of date(s)")), "stale": nz(r.get("Stale data")) is not None,
                "latestAnnual": dstr(r.get("Latest annual report period")), "latestReport": dstr(r.get("Latest report period (any)")),
                "underspend": txt(r.get("Underspend flag (K8)")), "capex": txt(r.get("Capex status (K9)")),
                "hud": txt(r.get("HUD inspection"), 200), "hudProperty": txt(r.get("HUD property (match)"), 120),
                "mgr": clean_mgr(r.get("Current property manager"), r.get("Manager source quote")),
                "mgrQuote": txt(r.get("Manager source quote"), 500), "mgrLink": nz(r.get("Manager source link")),
                "window": nz(r.get("Renewal window")) or "Unknown", "mgmt": mgmt,
                "contact": {"name": pcontact, "title": txt(r.get("Primary title"), 80) if pcontact else None,
                            "org": txt(r.get("Primary org"), 80) if pcontact else None, "role": txt(r.get("Primary role"), 80) if pcontact else None,
                            "info": txt(r.get("Primary contact info"), 120), "source": nz(r.get("Primary source"))},
                "stakeholders": {lbl: parse_people(r.get(col)) for lbl, col in [
                    ("University leaders", "P1 University housing/RE/finance leader"), ("Bondholder advisers", "P2 Bondholder adviser/counsel"),
                    ("Covenant consultants", "P3 Covenant consultant"), ("Borrower leadership", "P4 Borrower ED/board chair")]},
                "issuer": smart_title(tidy(r["Issuer"])) if nz(r.get("Issuer")) else None,
                "borrower": txt(r.get("Borrower"), 120) if nz(r.get("Borrower")) and len(tidy(r.get("Borrower"))) < 120 and not re.search(r"audited", str(r.get("Borrower")), re.I) else None,
                "cusips": txt(r.get("CUSIPs"), 400), "emma": nz(r.get("EMMA issue link")), "docCount": num(r.get("# docs"), 0),
                "docs": docs, "recentIssue": recent_issue, "failureToFile": failure,
                "research": res,
            }
            lead["stakeholders"] = {k: v for k, v in lead["stakeholders"].items() if v}
            leads.append(lead)
    # de-duplicate identical rows (same property reported under several bond issues)
    seen, uniq = set(), []
    for l in sorted(leads, key=lambda l: -(l["opp"] or 0)):
        sig = (l["name"], l["state"], l["occ"], l["opp"])
        if sig in seen and not l["research"]: continue
        seen.add(sig); uniq.append(l)
    for i, l in enumerate(uniq): l["id"] = i + 1
    return uniq, dropped

def encrypt(payload, email, password):
    salt, iv = os.urandom(16), os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS).derive(f"{email.strip().lower()}:{password}".encode())
    ct = AESGCM(key).encrypt(iv, json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(), None)
    b64 = lambda b: base64.b64encode(b).decode()
    return {"v": 1, "kdf": "PBKDF2-SHA256", "iter": ITERATIONS, "salt": b64(salt), "iv": b64(iv), "data": b64(ct)}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("xlsx"); ap.add_argument("--email", required=True); ap.add_argument("--password", required=True)
    ap.add_argument("--research", default=os.path.join(ROOT, "research", "owners.json"))
    ap.add_argument("--out", default=os.path.join(ROOT, "data", "leads.enc.js"))
    a = ap.parse_args()
    research = {}
    if os.path.exists(a.research):
        research = {k: v for k, v in json.load(open(a.research)).items() if not k.startswith("_")}
    leads, dropped = build(a.xlsx, research)
    payload = {"generated": date.today().isoformat(), "source": "EMMA municipal bond disclosures",
               "rules": {"minOccupancyDate": MIN_ASOF.strftime("%Y-%m-%d")}, "dropped": dropped, "leads": leads}
    with open(a.out, "w") as f:
        f.write("// Encrypted lead data. Generated by scripts/build_leads.py. Do not edit by hand.\n")
        f.write("window.COPIA_LEADS_ENC = " + json.dumps(encrypt(payload, a.email, a.password)) + ";\n")
    print(f"{len(leads)} leads kept; dropped: {dropped}", file=sys.stderr)
    print(f"Wrote {os.path.abspath(a.out)}", file=sys.stderr)
