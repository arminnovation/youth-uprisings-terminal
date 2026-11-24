#!/usr/bin/env python3
"""YUT live runner: polls trusted outlets' official feeds and keeps the site's live.json current.

  python3 tools/live_runner.py --once            # one poll, then exit (for a scheduler such as cron or GitHub Actions)
  python3 tools/live_runner.py --watch 10        # poll every 10 minutes until stopped (on a machine that stays on)

Two lanes, never mixed:
  1. HEADLINES (automatic). Headlines from Tier A/B outlets that mention a tracked country together with a protest term
     go straight into live.json, shown on the page as "Headline as published, not checked by YUT". Only the headline,
     the outlet, the time and the link are kept: no article text, and no figures.
  2. FIGURES (checked). Items whose headline or summary contains numbers are appended to ledger/review-queue.jsonl.
     Nothing in the queue reaches the page. A person (or a verification run) opens the article, writes an evidence file
     into ledger/inbox/, and the claim engine decides the label. Then run apply_claims.py and build_site.js.

Safety: only feeds listed in FEEDS are read, through the claim engine's SSRF-safe fetcher (public https hosts only,
redirects re-checked, size-capped). Every item link must belong to a Tier A or B outlet in ledger/register.json.
XML with a DOCTYPE is refused (no entity expansion). Keys come only from environment variables (GUARDIAN_API_KEY).
Poll no more often than every 5 minutes and keep to each outlet's feed terms."""
import argparse, hashlib, html, json, os, re, sys, time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, ".claude", "skills", "yut-claim-engine"))
from engine import netcheck                     # noqa: E402
from engine.policy import Register              # noqa: E402

FEED_FILE = os.path.join(ROOT, "tracker", "live.json")
QUEUE = os.path.join(ROOT, "ledger", "review-queue.jsonl")
DATA = os.path.join(ROOT, "tracker", "tracker-data.json")
REGISTER = os.path.join(ROOT, "ledger", "register.json")

FEEDS = [  # official RSS feeds of Tier B outlets (checked 17 Nov 2026)
    ("Al Jazeera", "https://www.aljazeera.com/xml/rss/all.xml"),
    ("BBC News", "https://feeds.bbci.co.uk/news/world/rss.xml"),
    ("BBC News", "https://feeds.bbci.co.uk/news/world/europe/rss.xml"),
    ("BBC News", "https://feeds.bbci.co.uk/news/world/asia/rss.xml"),
    ("BBC News", "https://feeds.bbci.co.uk/news/world/africa/rss.xml"),
    ("BBC News", "https://feeds.bbci.co.uk/news/world/latin_america/rss.xml"),
    ("France 24", "https://www.france24.com/en/rss"),
    ("Deutsche Welle", "https://rss.dw.com/rdf/rss-en-all"),
    ("NPR", "https://feeds.npr.org/1004/rss.xml"),
    ("Euronews", "https://www.euronews.com/rss"),
]
GUARDIAN = "https://content.guardianapis.com/search?q={q}&order-by=newest&page-size=20&show-fields=headline&api-key={key}"

PROTEST = re.compile(r"\b(protest\w*|strik\w*|march\w*|demonstrat\w*|student\w*|pupils?|riot\w*|clash\w*|"
                     r"rall(y|ies)|blockad\w*|uprising|gen ?z|resign\w*|tear ?gas|crackdown|curfew|unrest|walkout)\b", re.I)
DEMONYM = {"fr": ["French"], "be": ["Belgian"], "it": ["Italian"], "al": ["Albanian"], "rs": ["Serbian", "Belgrade"], "bg": ["Bulgarian", "Sofia"],
           "ar": ["Argentine", "Argentinian"], "pe": ["Peruvian"], "py": ["Paraguayan"], "mx": ["Mexican"], "ke": ["Kenyan", "Nairobi"],
           "mg": ["Malagasy"], "ma": ["Moroccan"], "tg": ["Togolese", "Lome", "Lomé"], "np": ["Nepali", "Nepalese", "Kathmandu"],
           "in": ["Indian", "New Delhi"], "bd": ["Bangladeshi", "Dhaka"], "id": ["Indonesian", "Jakarta"], "ph": ["Filipino", "Philippine", "Manila"],
           "tl": ["East Timor", "Timorese", "Dili"], "mn": ["Mongolian", "Ulaanbaatar"]}
LABOUR = re.compile(r"\b(workers?|unions?|staff|employees|teachers?|students?|pupils?|nurses|doctors|national strike|general strike|walkout|pay|wages?|cost[- ]of[- ]living|pensions?|public[- ]sector)\b", re.I)
SPORT = re.compile(r"\b(afcon|qualif\w*|world cup|cup|league|fifa|uefa|match|goal\w*|coach|striker|olympic\w*|tournament|grand prix|tennis|cricket|rugby)\b", re.I)
NUMBER = re.compile(r"\b\d{1,3}(?:[,.\s]\d{3})+\b|\b\d{2,}\b")
KEEP_HOURS, MAX_HEADLINES = 48, 30

def utc_iso(dt): return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def now(): return datetime.now(timezone.utc)

def countries():
    with open(DATA, encoding="utf-8") as f: return sorted({m["country"] for m in json.load(f)["movements"]})

def movement_matchers():
    with open(DATA, encoding="utf-8") as f: movs = json.load(f)["movements"]
    out = []
    for m in movs:
        words = [m["country"]] + DEMONYM.get(m["id"], [])
        out.append((m["id"], re.compile(r"\b(" + "|".join(re.escape(w) for w in words) + r")\b", re.I)))
    return out

def text(el, *names):
    for n in names:
        x = el.find(n)
        if x is not None and (x.text or "").strip(): return x.text.strip()
    return ""

def parse_feed(body):
    """Return [(title, link, published_dt, summary)] from RSS 2.0, RSS 1.0 (RDF) or Atom. Refuses DOCTYPE."""
    # No DOCTYPE anywhere means no entity can be declared, which rules out XXE and entity-expansion ("billion laughs")
    # attacks; expat never fetches external resources itself. Checked over the whole body, not just its start.
    if re.search(rb"<!\s*(DOCTYPE|ENTITY)", body, re.I):
        raise ValueError("feed contains a DOCTYPE or ENTITY declaration; refused")
    root = ET.fromstring(body)
    items = [e for e in root.iter() if e.tag.split("}")[-1] in ("item", "entry")]
    out = []
    for it in items:
        kids = {c.tag.split("}")[-1]: c for c in it}
        title = (kids.get("title").text or "").strip() if kids.get("title") is not None else ""
        link = ""
        if kids.get("link") is not None: link = (kids["link"].text or "").strip() or kids["link"].get("href", "")
        date = ""
        for n in ("pubDate", "published", "updated", "date"):
            if kids.get(n) is not None and (kids[n].text or "").strip(): date = kids[n].text.strip(); break
        summ = (kids.get("description").text or "") if kids.get("description") is not None else ((kids.get("summary").text or "") if kids.get("summary") is not None else "")
        try:
            dt = parsedate_to_datetime(date) if "," in date or "GMT" in date else datetime.fromisoformat(date.replace("Z", "+00:00"))
            if dt.tzinfo is None: dt = None          # no time zone given: the time is unknown, never guessed
        except Exception:
            dt = None
        out.append((html.unescape(re.sub(r"<[^>]+>", "", title)).strip(), link.strip(), dt, html.unescape(re.sub(r"<[^>]+>", " ", summ))))
    return out

def poll(reg, matchers, log=print):
    found, queue = [], []
    sources = list(FEEDS)
    key = os.environ.get("GUARDIAN_API_KEY")
    for outlet, url in sources:
        try:
            st, hd, body = netcheck.safe_get(url, timeout=25, max_bytes=3000000)
            if st != 200: log("skip %s: HTTP %s" % (url, st)); continue
            items = parse_feed(body)
        except Exception as ex:
            log("skip %s: %s" % (url, str(ex)[:100])); continue
        for title, link, dt, summ in items:
            found.append((outlet, title, link, dt, summ))
    if key:                                         # one Guardian search per run, by tracked country, to stay within its limits
        from urllib.parse import quote
        q = "(" + " OR ".join('"%s"' % c for c in countries()) + ") AND (protest OR strike OR students)"
        try:
            st, hd, body = netcheck.safe_get(GUARDIAN.format(q=quote(q), key=quote(key)), timeout=25, max_bytes=2000000)
            for r in (json.loads(body.decode("utf-8")).get("response", {}).get("results", []) if st == 200 else []):
                dt = datetime.fromisoformat(r["webPublicationDate"].replace("Z", "+00:00"))
                found.append(("The Guardian", r.get("webTitle", ""), r.get("webUrl", ""), dt, ""))
        except Exception as ex:
            log("skip Guardian API: %s" % str(ex)[:100])
    cutoff = now() - timedelta(hours=KEEP_HOURS)
    heads, seen = [], set()
    for outlet, title, link, dt, summ in found:
        if not title or not link.startswith("https://") or dt is None or dt < cutoff or dt > now() + timedelta(minutes=5): continue
        tier, reg_outlet, _ = reg.lookup(link)
        if tier not in ("A", "B"): continue                         # only trusted outlets reach the page
        # precision first: the headline itself must name a tracked country and a protest term; sport is screened out.
        # The summary is used only to spot figures for the review queue, never to decide relevance.
        if not PROTEST.search(title) or SPORT.search(title): continue
        # "strike" alone is ambiguous (military strikes): then the headline must also show a labour or student context
        if all(re.match(r"strik", m.group(0), re.I) for m in PROTEST.finditer(title)) and not LABOUR.search(title): continue
        mids = [m for m, rx in matchers if rx.search(title)]
        if not mids: continue
        hay = title + " " + summ
        hid = hashlib.sha1(link.split("#")[0].encode()).hexdigest()[:16]
        if hid in seen: continue
        seen.add(hid)
        heads.append({"id": hid, "m": mids[0], "outlet": reg_outlet[:80], "title": title[:200], "url": link[:500], "published": utc_iso(dt)})
        nums = NUMBER.findall(hay)
        if nums:
            queue.append({"seen_utc": utc_iso(now()), "movement": mids[0], "outlet": reg_outlet, "url": link, "title": title[:300],
                          "published_utc": utc_iso(dt), "numbers_seen": nums[:10], "status": "needs check",
                          "note": "Open the article, confirm each figure and who reported it, then write an evidence file in ledger/inbox/."})
    heads.sort(key=lambda x: x["published"], reverse=True)
    return heads[:MAX_HEADLINES], queue

def write_outputs(heads, queue, log=print):
    if not os.path.exists(FEED_FILE):
        log("tracker/live.json not found: run node tools/build_site.js first"); return 1
    with open(FEED_FILE, encoding="utf-8") as f: feed = json.load(f)
    feed["headlines"] = heads
    feed["headlines_checked_utc"] = utc_iso(now())
    txt = json.dumps(feed, ensure_ascii=True)
    if re.search(r"</|<!--", txt): log("refusing: markup in feed"); return 1
    tmp = FEED_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: f.write(txt + "\n")
    os.replace(tmp, FEED_FILE)
    known = set()
    if os.path.exists(QUEUE):
        with open(QUEUE, encoding="utf-8") as f:
            for line in f:
                try: known.add(json.loads(line)["url"])
                except Exception: pass
    new = [q for q in queue if q["url"] not in known]
    if new:
        with open(QUEUE, "a", encoding="utf-8") as f:
            for q in new: f.write(json.dumps(q, ensure_ascii=False) + "\n")
    log("%s headlines on the page; %d new items in the review queue" % (len(heads), len(new)))
    return 0

def network_allowed():
    """IP privacy guard: on a personal computer, every fetch shows the outlets this computer's IP address. Fetch only
    when running on GitHub's servers, or when the person has switched on a VPN (YUT_NETWORK=vpn), or has knowingly accepted that the IP will show (YUT_NETWORK=allowed)."""
    if os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("YUT_NETWORK") in ("vpn", "allowed"):   # "allowed": Lexi accepted showing this IP (23 Nov)
        return True
    print("Network access refused: this would reveal this computer's IP address to every outlet polled.\n"
          "Run it on GitHub Actions, or switch on a VPN first and run:  YUT_NETWORK=vpn python3 tools/live_runner.py --once")
    return False

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--once", action="store_true"); g.add_argument("--watch", type=int, metavar="MINUTES")
    a = ap.parse_args()
    if a.watch is not None and a.watch < 5: ap.error("poll no more often than every 5 minutes")
    if not network_allowed():
        return 2
    reg, matchers = Register.load(REGISTER), movement_matchers()
    while True:
        heads, queue = poll(reg, matchers)
        rc = write_outputs(heads, queue)
        if a.once: return rc
        time.sleep(a.watch * 60)

if __name__ == "__main__":
    sys.exit(main())
