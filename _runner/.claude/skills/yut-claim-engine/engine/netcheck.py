"""Link re-verification. Public https hosts only: localhost, private, link-local and metadata addresses are blocked, and every
redirect hop is re-checked. Results are logged as separate audit events; they inform people and never change a claim's label."""
import ipaddress, re, socket, urllib.error, urllib.parse, urllib.request

class BlockedURL(Exception):
    pass

def check_url(url):
    u = urllib.parse.urlparse(url)
    if u.scheme != "https" or not u.hostname:
        raise BlockedURL("only https links with a host are allowed")
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or 443)
    except socket.gaierror:
        raise BlockedURL("host does not resolve")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise BlockedURL("non-public address")
    return url

class _Safe(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

_opener = urllib.request.build_opener(_Safe)

def safe_get(url, timeout=20, max_bytes=400000):
    check_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": "yut-claim-engine/1.0"})
    try:
        with _opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(max_bytes)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), b""

def classify(title, fetched):
    """fetched = (status, headers, body). Returns verified | verified-weak | title-mismatch | unresolved."""
    status, hdr, body = fetched
    if status >= 400:
        return "unresolved"
    ct = next((v for k, v in hdr.items() if k.lower() == "content-type"), "")
    if any(x in ct for x in ("html", "json", "xml", "text")):
        text = body.decode("utf-8", "ignore").lower()
        toks = [t for t in re.findall(r"\w+", (title or "").lower()) if len(t) > 3]
        if toks and sum(t in text for t in toks) / len(toks) >= 0.5:
            return "verified"
        return "title-mismatch" if toks else "verified-weak"
    return "verified-weak"
