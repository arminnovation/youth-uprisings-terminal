"""Link re-verification. Public https hosts only: localhost, private, link-local and metadata addresses are blocked, and every
redirect hop is re-checked. Results are logged as separate audit events; they inform people and never change a claim's label."""
import http.client, ipaddress, re, socket, ssl, urllib.error, urllib.parse, urllib.request

class BlockedURL(Exception):
    pass

def resolve_public(host, port=443):
    """Resolve a host and return its addresses, raising BlockedURL if it does not resolve or ANY address is not globally routable."""
    try:
        infos = socket.getaddrinfo(host, port)
    except socket.gaierror:
        raise BlockedURL("host does not resolve")
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise BlockedURL("non-public address")
        ips.append(str(ip))
    return ips

def check_url(url):
    u = urllib.parse.urlparse(url)
    if u.scheme != "https" or not u.hostname:
        raise BlockedURL("only https links with a host are allowed")
    resolve_public(u.hostname, u.port or 443)
    return url

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to an address it has just validated, in the same step. A hostile DNS server therefore cannot answer with a public
    address for the check and an internal one for the connection (DNS rebinding). The certificate is still checked against the host name."""
    def connect(self):
        port = self.port or 443
        ip = resolve_public(self.host, port)[0]
        sock = socket.create_connection((ip, port), self.timeout, self.source_address)
        self.sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.host)

class _PinnedHTTPS(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PinnedHTTPSConnection, req)

class _Safe(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

_opener = urllib.request.build_opener(_Safe, _PinnedHTTPS)

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
