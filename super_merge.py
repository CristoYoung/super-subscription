#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Super merger: aggregate multiple free-node subscriptions into one Clash Meta YAML.

Zero third-party deps. Supports three input formats per source:
  - v2ray link list  (vmess:// vless:// trojan:// ss:// hysteria2:// per line)
  - base64 v2ray subscription (whole-blob or per-line base64 of link list / JSON)
  - (raw Clash YAML sources are skipped; use their base64/link-list variant URL)

Sources are listed in sources.txt (one URL per line, # = comment).
Each source is fetched (direct; on GitHub Actions the runner has direct internet).
On total failure the merge still proceeds with whatever parsed.

Output: SuperMerge.yaml next to this script (or SUPER_OUT_DIR if set, e.g. CI).
"""
import os, sys, io, base64, ssl, json, re, time, ipaddress, urllib.parse, urllib.request

WS = os.path.dirname(os.path.abspath(__file__))
# In CI, github.workspace (repo root). Locally, beside this script.
OUT_DIR = os.environ.get("SUPER_OUT_DIR") or WS
OUT_FILE = os.path.join(OUT_DIR, "SuperMerge.yaml")
SOURCES_FILE = os.path.join(WS, "sources.txt")

PROTO_PREFIXES = ("vmess://", "vless://", "trojan://", "ss://", "ssr://",
                  "hysteria2://", "hy2://", "tuic://", "socks://", "socks5://")

# Shadowsocks ciphers mihomo/Clash.Meta actually accepts. Validated against
# Mihomo Meta v1.19.29 (`verge-mihomo -t`): a single unknown name makes the core
# reject the ENTIRE config -- "proxy N: ss ... initialize error: unknown method"
# -- which is exactly how one junk node ("i5p") killed a 14k-node subscription.
# Aliases are repaired rather than dropped; anything else is dropped at build time.
SS_ALIASES = {
    "chacha20-poly1305": "chacha20-ietf-poly1305",
    "chacha20-poly1305-ietf": "chacha20-ietf-poly1305",
    "xchacha20-poly1305": "xchacha20-ietf-poly1305",
    "xchacha20-ietf": "xchacha20-ietf-poly1305",
}
SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5", "chacha20-ietf", "chacha20-ietf-poly1305",
    "xchacha20", "xchacha20-ietf-poly1305", "none",
}


def ssl_create():
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    except Exception:
        return None


def b64d(s):
    s = s.strip()
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")
    except Exception:
        return ""


def looks_base64(s):
    s = s.strip()
    if len(s) < 16:
        return False
    # base64 alphabet is A-Za-z0-9+/= ; reject only plaintext/link markers
    # (':' never appears in base64, but '/' and '+' DO -- so they stay allowed)
    if ":" in s or "#" in s or " " in s or "\t" in s:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", s))


def parse_port(v, default=None):
    """Extract a usable port from a messy value.

    Free lists contain ports glued to paths or queries, e.g.
    `ss://...@host:48172/?POST` -> "48172/". Take the leading digits and
    range-check instead of letting int() raise and kill the whole source.
    """
    if isinstance(v, bool):
        return default
    if isinstance(v, int):
        n = v
    else:
        m = re.match(r"\s*(\d{1,5})", str(v))
        if not m:
            return default
        n = int(m.group(1))
    return n if 1 <= n <= 65535 else default


_DIRECT_OPENER = None


def direct_opener(ctx):
    """Opener that bypasses env proxies.

    NOTE: urllib.request.urlopen() has NO `proxies` kwarg -- passing one raises
    TypeError and every fetch silently fails. Disable proxies via ProxyHandler({})
    on a custom opener instead.
    """
    global _DIRECT_OPENER
    if _DIRECT_OPENER is None:
        handlers = [urllib.request.ProxyHandler({})]
        if ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        _DIRECT_OPENER = urllib.request.build_opener(*handlers)
    return _DIRECT_OPENER


def fetch(url, ctx):
    last_err = None
    # 1) direct (env proxies ignored by design) -- with retries.
    #    raw.githubusercontent.com drops connections intermittently; with ~17
    #    sources even a 5% per-request failure rate costs a source per build.
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with direct_opener(ctx).open(req, timeout=30) as r:
                d = r.read().decode("utf-8", "ignore")
            if d.strip():
                return d
            last_err = "empty response body"
        except Exception as e:
            last_err = e
            if attempt < 2:
                time.sleep(2 * (attempt + 1))
    # 2) via host Clash proxy (only when env SUPER_USE_PROXY is set, e.g. local test)
    if os.environ.get("SUPER_USE_PROXY"):
        proxy = urllib.request.ProxyHandler({
            "http": "http://127.0.0.1:7897",
            "https": "http://127.0.0.1:7897",
        })
        try:
            opener = urllib.request.build_opener(proxy)
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with opener.open(req, timeout=25) as r:
                d = r.read().decode("utf-8", "ignore")
            if d.strip():
                return d
        except Exception as e:
            last_err = e
    raise RuntimeError(f"fetch failed: {last_err}")


# ---- single link -> clash node -------------------------------------------------

def parse_vless_trojan_hysteria(link, scheme):
    rest = link[len(scheme) + 3:]
    if "#" in rest:
        body, frag = rest.rsplit("#", 1)
        name = urllib.parse.unquote(frag)
    else:
        body, name = rest, ""
    if "?" in body:
        auth_host, query = body.split("?", 1)
    else:
        auth_host, query = body, ""
    if "@" in auth_host:
        userinfo, hostport = auth_host.split("@", 1)
    else:
        userinfo, hostport = "", auth_host
    if ":" in hostport:
        host, port = hostport.rsplit(":", 1)
        try:
            port = int(port)
        except Exception:
            port = 443
    else:
        host, port = hostport, 443
    q = urllib.parse.parse_qs(query)
    g = lambda k: (q.get(k) or [""])[0]
    return name, userinfo, host, port, q, g


def to_clash(link):
    if link.startswith("vmess://"):
        try:
            j = json.loads(b64d(link[8:].split("#")[0]))
        except Exception:
            return None
        net = j.get("net", "tcp")
        node = {
            "name": j.get("ps", "vmess"),
            "type": "vmess",
            "server": j.get("add", ""),
            "port": parse_port(j.get("port", 443), 443) or 443,
            "uuid": j.get("id", ""),
            "alterId": int(j.get("aid", 0)),
            "cipher": j.get("scy", "auto") or "auto",
            "network": net,
            "tls": (j.get("tls", "") == "tls"),
        }
        if net == "ws":
            node["ws-opts"] = {"path": j.get("path", "/"),
                               "headers": {"Host": j.get("host", j.get("sni", ""))}}
        elif net == "grpc":
            node["grpc-opts"] = {"grpc-service-name": j.get("path", "")}
        return node
    if link.startswith("ss://"):
        b = link[5:]
        name = ""
        if "#" in b:
            b, frag = b.split("#", 1)
            name = urllib.parse.unquote(frag)
        if "?" in b:                      # strip query (some subs append ?plugin= etc.)
            b = b.split("?", 1)[0]
        if "@" in b:
            userinfo, hostport = b.split("@", 1)
        else:
            dec = b64d(b)
            if "@" in dec:
                userinfo, hostport = dec.split("@", 1)
            else:
                return None
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        else:
            dec = b64d(userinfo)
            if ":" in dec:
                method, password = dec.split(":", 1)
            else:
                return None
        if ":" in hostport:
            host, port = hostport.rsplit(":", 1)
            host = host.split("/")[0]
            port = parse_port(port)
            if port is None:
                return None
        else:
            host, port = hostport, 443
        # Normalize the cipher before it is written out: mihomo matches the name
        # exactly (lower case, hyphenated). Common short forms are repaired via
        # SS_ALIASES; genuinely unknown names are rejected by valid_node.
        method = (method or "").strip().lower()
        method = SS_ALIASES.get(method, method)
        # Skip SS 2022 ciphers entirely: free sources often have invalid base64
        # keys and Clash rejects them. The loss is tiny (~0.2% of nodes).
        if method.startswith("2022-"):
            return None
        return {"name": name or "SS", "type": "ss", "server": host, "port": port,
                "cipher": method, "password": password}
    for scheme in ("vless", "trojan", "hysteria2", "hy2"):
        if link.startswith(scheme + "://"):
            name, userinfo, host, port, q, g = parse_vless_trojan_hysteria(link, scheme)
            sec = g("security")
            fp = g("fp")
            net = g("type") or "tcp"
            if scheme in ("hysteria2", "hy2"):
                node = {"name": name or "hysteria2", "type": "hysteria2",
                        "server": host, "port": port, "password": userinfo}
                if g("sni"):
                    node["sni"] = g("sni")
                if g("insecure") == "1" or g("allowInsecure") == "1":
                    node["skip-cert-verify"] = True
                if g("alpn"):
                    node["alpn"] = g("alpn").split(",")
                return node
            if scheme == "trojan":
                node = {"name": name or "trojan", "type": "trojan",
                        "server": host, "port": port, "password": userinfo, "network": net}
                if sec == "tls" or sec == "reality":
                    node["tls"] = True
                sni = g("sni")
                if sni:
                    node["sni"] = sni
                if g("allowInsecure") == "1" or g("insecure") == "1":
                    node["skip-cert-verify"] = True
                if fp:
                    node["client-fingerprint"] = fp
                if net == "ws":
                    node["ws-opts"] = {"path": g("path") or "/",
                                      "headers": {"Host": g("host") or sni or host}}
                if g("alpn"):
                    node["alpn"] = g("alpn").split(",")
                return node
            if scheme == "vless":
                node = {"name": name or "vless", "type": "vless",
                        "server": host, "port": port, "uuid": userinfo, "network": net}
                flow = g("flow")
                if flow:
                    node["flow"] = flow
                if sec == "tls":
                    node["tls"] = True
                elif sec == "reality":
                    node["tls"] = True
                    node["reality-opts"] = {"public-key": g("pbk"), "sni": g("sni")}
                else:
                    node["tls"] = False
                sni = g("sni")
                if sni and sec != "reality":
                    node["sni"] = sni
                if fp:
                    node["client-fingerprint"] = fp
                if net == "ws":
                    node["ws-opts"] = {"path": g("path") or "/",
                                      "headers": {"Host": g("host") or sni or host}}
                if g("packetEncoding") == "xudp" or g("udp") == "1":
                    node["udp"] = True
                return node
    return None


# ---- source text -> list of clash nodes ---------------------------------------

def outbound_to_clash(o):
    """Best-effort conversion of a v2ray outbound JSON dict to a clash node."""
    try:
        proto = o.get("protocol", "")
        tag = o.get("tag", "")
        if proto == "vmess":
            s = o.get("settings", {}).get("vnext", [{}])[0]
            stream = o.get("streamSettings", {})
            net = stream.get("network", "tcp")
            node = {"name": tag or "vmess", "type": "vmess",
                    "server": s.get("address", ""), "port": int(s.get("port", 443)),
                    "uuid": s.get("users", [{}])[0].get("id", ""),
                    "alterId": int(s.get("users", [{}])[0].get("alterId", 0)),
                    "cipher": "auto", "network": net,
                    "tls": (stream.get("security") == "tls")}
            if net == "ws":
                ws = stream.get("wsSettings", {})
                node["ws-opts"] = {"path": ws.get("path", "/"),
                                  "headers": {"Host": ws.get("headers", {}).get("Host", "")}}
            return node
        if proto == "vless":
            s = o.get("settings", {}).get("vnext", [{}])[0]
            stream = o.get("streamSettings", {})
            node = {"name": tag or "vless", "type": "vless",
                    "server": s.get("address", ""), "port": int(s.get("port", 443)),
                    "uuid": s.get("users", [{}])[0].get("id", ""), "network": stream.get("network", "tcp")}
            node["tls"] = (stream.get("security") in ("tls", "reality"))
            return node
        if proto == "trojan":
            s = o.get("settings", {}).get("servers", [{}])[0]
            return {"name": tag or "trojan", "type": "trojan",
                    "server": s.get("address", ""), "port": int(s.get("port", 443)),
                    "password": s.get("password", ""), "network": o.get("streamSettings", {}).get("network", "tcp"),
                    "tls": (o.get("streamSettings", {}).get("security") == "tls")}
        if proto == "shadowsocks":
            s = o.get("settings", {}).get("servers", [{}])[0]
            return {"name": tag or "ss", "type": "ss",
                    "server": s.get("address", ""), "port": int(s.get("port", 443)),
                    "cipher": s.get("method", "aes-256-gcm"), "password": s.get("password", "")}
    except Exception:
        return None
    return None


def parse_source(text):
    text = text.strip()
    if not text:
        return []
    # 1) raw Clash YAML: we don't parse full YAML (no PyYAML); skip
    if re.search(r"(?m)^proxies\s*:", text):
        return []
    # 2) whole-blob base64 -> decode and recurse
    if looks_base64(text.replace("\n", "").replace(" ", "")):
        dec = b64d(text.replace("\n", "").replace(" ", ""))
        if dec:
            if any(p in dec for p in ("://", "vmess", "vless", "trojan", "hysteria", "shadowsocks")):
                return parse_source(dec)
            try:
                j = json.loads(dec)
                if isinstance(j, list):
                    return [n for n in (outbound_to_clash(o) for o in j) if n and valid_node(n)]
            except Exception:
                pass
    # 3) line based
    nodes = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # One malformed link must never abort the whole source. Free lists
        # routinely contain garbage (ports glued to paths/queries, double
        # schemes, truncated base64) -- skip the bad line, keep the rest.
        try:
            if line.startswith(PROTO_PREFIXES):
                n = to_clash(line)
                if n and valid_node(n):
                    nodes.append(n)
            elif looks_base64(line):
                dec = b64d(line)
                if dec:
                    if any(p in dec for p in ("://", "vmess", "vless", "trojan")):
                        nodes.extend(parse_source(dec))
                    else:
                        try:
                            j = json.loads(dec)
                            if isinstance(j, list):
                                nodes.extend(n for n in (outbound_to_clash(o) for o in j) if n and valid_node(n))
                            elif isinstance(j, dict) and "outbounds" in j:
                                nodes.extend(n for n in (outbound_to_clash(o) for o in j["outbounds"]) if n and valid_node(n))
                        except Exception:
                            pass
        except Exception:
            continue
    return nodes


# YAML forbids C0 controls (except tab/LF/CR) and C1 controls (U+007F-U+009F),
# plus BOM and U+FFFE/U+FFFF. Free-node sources occasionally inject them (seen:
# a ws `path` carrying U+0087/U+009F). Desktop Clash is lenient, but Clash for
# Android rejects the whole file with "yaml: control characters are not allowed".
_BAD_CHARS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ufeff\ufffe\uffff]")


def sanitize(s):
    return _BAD_CHARS.sub("", s)


def yaml_str(v):
    s = sanitize(str(v))
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


DROP = {}          # reason -> count; printed once at the end as build diagnostics


def _drop(reason):
    DROP[reason] = DROP.get(reason, 0) + 1
    return False


def bad_server(host):
    """True when `host` can never be a real proxy endpoint.

    Free lists pad themselves with placeholders rather than leaving a gap. Our
    17-source merge produced RFC5737 documentation addresses (192.0.2.1:1) and
    systemd-resolved stubs (127.0.0.53) dressed up as nodes; they can never
    connect, they only lengthen url-test rounds.
    """
    h = (host or "").strip()
    if not h or len(h) > 253 or " " in h or "\t" in h:
        return True
    try:
        ip = ipaddress.ip_address(h.strip("[]"))
    except ValueError:
        return False            # a domain name -- nothing to judge statically
    return (ip.is_private or ip.is_loopback or ip.is_reserved
            or ip.is_multicast or ip.is_link_local or ip.is_unspecified)


def valid_node(n):
    """Drop nodes that cannot connect or that a strict core would reject.

    Two classes, both observed in real free-list payloads:
      * placeholder / credential-less entries (see bad_server, port 0-1);
      * parameters mihomo refuses at parse time -- one unknown ss cipher name
        ("i5p", "chacha20-poly1305") makes Clash reject the WHOLE subscription
        with "initialize error: unknown method".
    """
    if bad_server(n.get("server")):
        return _drop("bad-server")
    p = n.get("port")
    if not isinstance(p, int) or not 2 <= p <= 65535:
        return _drop("bad-port")
    t = n.get("type")
    if t in ("vless", "vmess") and not n.get("uuid"):
        return _drop("no-uuid")
    if t in ("trojan", "hysteria2") and not n.get("password"):
        return _drop("no-password")
    if t == "ss":
        if not n.get("password"):
            return _drop("no-password")
        if n.get("cipher") not in SS_CIPHERS:
            return _drop("ss-unknown-cipher")
    return True


def node_key(n):
    return (n.get("type"), n.get("server"), n.get("port"),
            n.get("uuid") or n.get("password") or "")


# ---- lite build ---------------------------------------------------------------
# A 14k-node subscription is technically valid but unusable on a phone: the
# client allocates one proxy object per node, renders every one of them in the
# proxy picker, and a url-test group re-probes ALL of them on a timer (measured:
# 14,036 nodes sat on only 6,324 distinct /24 blocks -- one Cloudflare address
# alone carried 344). So the count is largely redundant, not extra reach.
#
# Lite keeps ~1 node per network block: an order of magnitude fewer objects for
# almost the same number of reachable networks.

LITE_TARGET = int(os.environ.get("SUPER_LITE_TARGET", "600"))
LITE_NET_CAP = int(os.environ.get("SUPER_LITE_NET_CAP", "3"))
LITE_ENABLE = os.environ.get("SUPER_LITE", "1").lower() not in ("0", "false", "no")


def net_key(n):
    """The network a node lives in: /24 for v4, /48 for v6, host for domains."""
    h = (n.get("server") or "").strip("[]")
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return "d:" + h.lower()
    return str(ipaddress.ip_network(f"{h}/{24 if ip.version == 4 else 48}",
                                    strict=False))


def make_lite(uniq, consensus):
    """Pick a diverse, budget-sized subset of `uniq`.

    Ranking first puts nodes advertised by several independent sources at the
    front: a node three lists agree on has a track record, and it survives
    re-ranking when any single source goes stale. The per-network cap then stops
    one operator from filling the budget with clones, and a uniform stride keeps
    the mix across protocols and source order.
    """
    order = sorted(range(len(uniq)), key=lambda i: (-consensus[i], i))
    capped, per_net = [], {}
    for i in order:
        k = net_key(uniq[i])
        if per_net.get(k, 0) >= LITE_NET_CAP:
            continue
        per_net[k] = per_net.get(k, 0) + 1
        capped.append(uniq[i])
    if LITE_TARGET and len(capped) > LITE_TARGET:
        step = len(capped) / LITE_TARGET
        capped = [capped[int(i * step)] for i in range(LITE_TARGET)]
    return capped


def assert_clean(text, path):
    """Sanitizing must leave zero illegal chars; fail loudly rather than ship."""
    leaked = _BAD_CHARS.findall(text)
    if leaked:
        print(f"[FATAL] {len(leaked)} illegal control char(s) survived sanitizing; "
              f"refusing to write {os.path.basename(path)}.")
        sys.exit(1)


def build_yaml(nodes, title, interval):
    out = io.StringIO()
    out.write(f"# {title}\n")
    out.write("# auto-generated - do not edit by hand\n")
    out.write("proxies:\n")
    for n in nodes:
        out.write("  - name: " + yaml_str(n["name"]) + "\n")
        out.write("    type: " + n["type"] + "\n")
        out.write("    server: " + yaml_str(n["server"]) + "\n")
        out.write("    port: " + str(n["port"]) + "\n")
        for k in ("uuid", "password", "cipher"):
            if k in n:
                out.write(f"    {k}: {yaml_str(n[k])}\n")
        if "alterId" in n:
            out.write(f"    alterId: {n['alterId']}\n")
        if "flow" in n:
            out.write("    flow: " + yaml_str(n["flow"]) + "\n")
        if "network" in n:
            out.write("    network: " + yaml_str(n["network"]) + "\n")
        if "tls" in n:
            out.write(f"    tls: {str(n['tls']).lower()}\n")
        if "udp" in n:
            out.write(f"    udp: {str(n['udp']).lower()}\n")
        if "sni" in n:
            out.write(f"    sni: {yaml_str(n['sni'])}\n")
        if "client-fingerprint" in n:
            out.write(f"    client-fingerprint: {yaml_str(n['client-fingerprint'])}\n")
        if "skip-cert-verify" in n:
            out.write(f"    skip-cert-verify: {str(n['skip-cert-verify']).lower()}\n")
        if "reality-opts" in n:
            ro = n["reality-opts"]
            out.write("    reality-opts:\n")
            out.write(f"      public-key: {yaml_str(ro.get('public-key', ''))}\n")
            out.write(f"      sni: {yaml_str(ro.get('sni', ''))}\n")
        if "ws-opts" in n:
            wo = n["ws-opts"]
            out.write("    ws-opts:\n")
            out.write(f"      path: {yaml_str(wo.get('path', '/'))}\n")
            out.write("      headers:\n")
            out.write(f"        Host: {yaml_str(wo.get('headers', {}).get('Host', ''))}\n")
        if "grpc-opts" in n:
            go = n["grpc-opts"]
            out.write("    grpc-opts:\n")
            out.write("      grpc-service-name: " + yaml_str(go.get("grpc-service-name", "")) + "\n")
        if "alpn" in n:
            out.write("    alpn:\n")
            for a in n["alpn"]:
                out.write(f"      - {yaml_str(a)}\n")

    names = [n["name"] for n in nodes]
    out.write("proxy-groups:\n")
    out.write("  - name: \U0001F680 NodeSelect\n")
    out.write("    type: select\n")
    out.write("    proxies:\n")
    out.write("      - \u267B\uFE0F AutoTest\n")
    out.write("      - DIRECT\n")
    for nm in names:
        out.write(f"      - {yaml_str(nm)}\n")
    out.write("  - name: \u267B\uFE0F AutoTest\n")
    out.write("    type: url-test\n")
    out.write("    url: https://www.gstatic.com/generate_204\n")
    out.write(f"    interval: {interval}\n")
    out.write("    proxies:\n")
    for nm in names:
        out.write(f"      - {yaml_str(nm)}\n")
    out.write("rules:\n")
    out.write("  - GEOIP,CN,DIRECT\n")
    out.write("  - MATCH,\U0001F680 NodeSelect\n")
    return out.getvalue()


def main():
    ctx = ssl_create()
    cache_dir = os.path.join(WS, "cache")
    os.makedirs(cache_dir, exist_ok=True)
    sources = []
    if os.path.exists(SOURCES_FILE):
        for ln in open(SOURCES_FILE, encoding="utf-8").read().splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            sources.append(ln)
    print(f"[info] {len(sources)} sources configured")
    all_nodes = []
    skipped = []
    # key -> set of source indexes that advertised it. Cross-source agreement is
    # the only free quality signal we have: a node three independent lists carry
    # is far likelier to still be alive than one that appeared once.
    key_sources = {}
    for i, url in enumerate(sources):
        ns = None
        try:
            txt = fetch(url, ctx)
            # persist successful fetch as offline cache for next run
            try:
                open(os.path.join(cache_dir, f"{i}.txt"), "w", encoding="utf-8").write(txt)
            except Exception:
                pass
            ns = parse_source(txt)
            print(f"[ok]   src#{i} {len(ns)} nodes <- {url.split('/')[-1]}")
        except Exception as e:
            # fall back to last successful cache if live fetch failed
            cf = os.path.join(cache_dir, f"{i}.txt")
            if os.path.exists(cf):
                try:
                    ns = parse_source(open(cf, encoding="utf-8").read())
                    print(f"[cache] src#{i} {len(ns)} nodes from offline cache")
                except Exception:
                    ns = None
            if ns is None:
                print(f"[FAIL] src#{i} {url.split('/')[-1]} : {e}")
                skipped.append(url)
                continue
        for n in ns:
            key_sources.setdefault(node_key(n), set()).add(i)
        all_nodes.extend(ns)

    # dedupe by (type, server, port, credential)
    seen = set()
    uniq = []
    consensus = []
    for n in all_nodes:
        k = node_key(n)
        if k in seen:
            continue
        seen.add(k)
        uniq.append(n)
        consensus.append(len(key_sources.get(k) or ()))

    # Hard guard: never publish an empty config (a build outage must fail loudly
    # instead of committing a node-less SuperMerge.yaml that overwrites a good one).
    if not uniq:
        print(f"[FATAL] 0 nodes parsed from {len(sources)} sources "
              f"({len(skipped)} fetch failures, no offline cache). "
              f"Aborting: existing {os.path.basename(OUT_FILE)} left untouched.")
        sys.exit(1)

    # Node names must be unique inside a file. Lite is a subset of `uniq`, so
    # de-duplicating once here covers both files -- and it has to happen before
    # the subset is taken, so the lite file never inherits a collision.
    name_count = {}
    for n in uniq:
        base = n.get("name") or "node"
        if base in name_count:
            name_count[base] += 1
            n["name"] = f"{base}-{name_count[base]}"
        else:
            name_count[base] = 0

    os.makedirs(OUT_DIR, exist_ok=True)

    def _dist(ns):
        d = {}
        for n in ns:
            d[n["type"]] = d.get(n["type"], 0) + 1
        return " ".join(f"{k}={v}" for k, v in sorted(d.items()))

    # interval 600s: at 14k nodes a 300s url-test means the core is basically
    # always probing. Halving the frequency is free and cuts battery/data use.
    text = build_yaml(uniq, "SuperMerge - aggregated free nodes (FULL)", 600)
    assert_clean(text, OUT_FILE)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"[done] full={len(uniq)} (deduped from {len(all_nodes)}) "
          f"failed_sources={len(skipped)} -> {OUT_FILE}")
    print("[dist]", _dist(uniq))

    if LITE_ENABLE:
        lite = make_lite(uniq, consensus)
        lite_file = os.path.join(OUT_DIR, "SuperMergeLite.yaml")
        n_nets = len({net_key(n) for n in lite})
        ltext = build_yaml(
            lite,
            f"SuperMergeLite - diverse subset of SuperMerge "
            f"({len(lite)} nodes covering {n_nets} networks)", 600)
        assert_clean(ltext, lite_file)
        with open(lite_file, "w", encoding="utf-8") as f:
            f.write(ltext)
        print(f"[lite] total={len(lite)} networks={n_nets} "
              f"target={LITE_TARGET} net_cap={LITE_NET_CAP} -> {lite_file}")
        print("[lite-dist]", _dist(lite))

    if DROP:
        print("[drop]", " ".join(f"{k}={v}" for k, v in sorted(DROP.items())))


if __name__ == "__main__":
    main()
