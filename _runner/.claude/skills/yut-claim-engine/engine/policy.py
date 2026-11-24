"""Sourcing policy: tiers, roles, party rules, limits. Mirrors the yut-source-register skill.
The submitter can never declare a tier: tier comes from the outlet register, matched on the exact host."""
import json, re
from urllib.parse import urlparse

STANCES = ("supports", "contradicts", "updates", "supersedes", "no_figure")
ROLES = ("primary_record", "independent_monitor", "scholarly", "media_report", "social")
REPORTER_TYPES = ("government", "security_forces", "protest_organisers", "government_commission",
                  "independent_commission", "independent_monitor", "news_organisation", "academic", "unknown")
PARTY_TYPES = ("government", "security_forces", "protest_organisers", "government_commission", "unknown")  # unknown is treated as a party: conservative
CRITERIA = ("primary_source", "independent_of_existing", "more_recent", "higher_tier", "same_scope",
            "corrects_earlier", "corroborates", "first_report", "scholarly_review", "official_record")
LABELS = ("Confirmed", "Estimated", "Disputed", "Not reported", "Unverified")
TIER_BASE = {"A": 1.0, "B": 0.8, "P": 0.3, "U": 0.1, "X": 0.0}
ROLE_FACTOR = {"primary_record": 1.0, "independent_monitor": 1.0, "scholarly": 0.95, "media_report": 0.85, "social": 0.1}
RELIABLE_TIERS = ("A", "B")
PRIOR = {"A": (8, 1), "B": (6, 2), "P": (2, 2), "U": (1, 1), "X": (1, 1)}
LIMITS = {"url": 2000, "title": 400, "publisher": 200, "reporter": 200, "reason": 1000, "min_reason": 15,
          "scope_note": 500, "quote_words": 15, "quote_chars": 200, "criteria": 10, "depth": 6, "value_max": 1e10}
TOLERANCE_REL = 0.02
STALE_DAYS = 7

DEFAULT_REGISTER = {
    "tier_a": {"amnesty.org": "Amnesty International", "hrw.org": "Human Rights Watch", "ohchr.org": "UN OHCHR", "un.org": "United Nations",
               "reliefweb.int": "ReliefWeb", "acleddata.com": "ACLED", "nvdatabase.swarthmore.edu": "Swarthmore Nonviolent Action Database",
               "britannica.com": "Britannica", "gwu.edu": "National Security Archive (GWU)", "loc.gov": "Library of Congress",
               "sahistory.org.za": "South African History Online", "saha.org.za": "SAHA (TRC archive)", "cia.gov": "CIA Reading Room",
               "state.gov": "US Department of State", "unesco.org": "UNESCO", "adst.org": "ADST", "refworld.org": "Refworld",
               "jstor.org": "JSTOR (abstract)", "cambridge.org": "Cambridge Core", "knchr.org": "Kenya National Commission on Human Rights",
               "carnegieendowment.org": "Carnegie Endowment", "civicus.org": "CIVICUS Monitor",
               "rsf.org": "Reporters Without Borders (RSF)"},
    "tier_b": {"reuters.com": "Reuters", "apnews.com": "Associated Press", "afp.com": "AFP", "bbc.com": "BBC", "bbc.co.uk": "BBC",
               "theguardian.com": "The Guardian", "nytimes.com": "The New York Times", "washingtonpost.com": "The Washington Post",
               "lemonde.fr": "Le Monde", "aljazeera.com": "Al Jazeera", "france24.com": "France 24", "dw.com": "Deutsche Welle",
               "economist.com": "The Economist", "time.com": "Time", "npr.org": "NPR", "cbsnews.com": "CBS News",
               "euronews.com": "Euronews", "bloomberg.com": "Bloomberg", "rte.ie": "RTÉ", "ft.com": "Financial Times",
               "pbs.org": "PBS", "newsweek.com": "Newsweek", "usnews.com": "U.S. News & World Report", "thenation.com": "The Nation (US)",
               "theintercept.com": "The Intercept", "icij.org": "ICIJ", "propublica.org": "ProPublica"},
    "pending": {"irrawaddy.com": "The Irrawaddy", "dvb.no": "DVB", "bdnews24.com": "bdnews24", "tovima.com": "To Vima",
                "tribune.com.pk": "Express Tribune", "connexionfrance.com": "Connexion France", "albaniandailynews.com": "Albanian Daily News",
                "nationthailand.com": "The Nation (Thailand)", "bangkokpost.com": "Bangkok Post", "slate.fr": "Slate.fr",
                "lanacion.com.ar": "La Nación", "infobae.com": "Infobae", "losandes.com.ar": "Los Andes"},
    "excluded": {"wikipedia.org": "Wikipedia", "wikipedia.com": "Wikipedia mirror", "grokipedia.com": "Grokipedia", "fandom.com": "Fandom",
                 "onwar.com": "OnWar", "chinasage.info": "China Sage", "tactics4change.org": "Tactics4Change", "greeceindex.com": "Greeceindex",
                 "wsws.org": "WSWS", "jacobin.com": "Jacobin", "libcom.org": "libcom", "marxists.org": "marxists.org", "organiser.org": "Organiser", "thegatewaypundit.com": "The Gateway Pundit",
                 "cnn.com": "CNN"},
}

def host_of(url):
    """Exact host: lowercase, no trailing dot, userinfo ignored (urlparse.hostname). Returns None if unusable."""
    try:
        p = urlparse(url)
        h = (p.hostname or "").lower().rstrip(".")
    except Exception:
        return None
    return h or None

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
def host_is_ip_or_local(h):
    return bool(h) and (_IPV4.match(h) is not None or ":" in h or h == "localhost" or h.endswith(".localhost") or h.endswith(".local") or "." not in h)

class Register:
    """host -> (tier, outlet). Matching is exact host or a true subdomain: reuters.com.evil.com never matches reuters.com."""
    def __init__(self, data=None):
        data = data or DEFAULT_REGISTER
        self.rows = {}
        for key, tier in (("excluded", "X"), ("tier_a", "A"), ("tier_b", "B"), ("pending", "P")):
            for dom, outlet in data.get(key, {}).items():
                self.rows[dom.lower()] = (tier, outlet)
    @classmethod
    def load(cls, path):
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))
    def lookup(self, url):
        h = host_of(url)
        if not h:
            return ("U", "unknown", None)
        labels = h.split(".")
        for i in range(len(labels) - 1):           # longest suffix first; never match a bare TLD
            cand = ".".join(labels[i:])
            if cand in self.rows:
                tier, outlet = self.rows[cand]
                return (tier, outlet, cand)
        return ("U", h, None)
