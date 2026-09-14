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
import os, sys, io, base64, ssl, json, re, urllib.parse, urllib.request

WS = os.path.dirname(os.path.abspath(__file__))
# In CI, github.workspace (repo root). Locally, beside this script.
OUT_DIR = os.environ.get("SUPER_OUT_DIR") or WS
OUT_FILE = os.path.join(OUT_DIR, "SuperMerge.yaml")
SOURCES_FILE = os.path.join(WS, "sources.txt")

PROTO_PREFIXES = ("vmess://", "vless://", "trojan://", "ss://", "ssr://",
                  "hysteria2://", "hy2://", "tuic://", "socks://", "socks5://")


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
    # 1) direct (env proxies ignored by design)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with direct_opener(ctx).open(req, timeout=25) as r:
            d = r.read().decode("utf-8", "ignore")
        if d.strip():
            return d
        last_err = "empty response body"
    except Exception as e:
        last_err = e
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
            "port": int(j.get("port", 443)),
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
            port = int(port)
        else:
            host, port = hostport, 443
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
                    return [n for n in (outbound_to_clash(o) for o in j) if n]
            except Exception:
                pass
    # 3) line based
    nodes = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(PROTO_PREFIXES):
            n = to_clash(line)
            if n:
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
                            nodes.extend(n for n in (outbound_to_clash(o) for o in j) if n)
                        elif isinstance(j, dict) and "outbounds" in j:
                            nodes.extend(n for n in (outbound_to_clash(o) for o in j["outbounds"]) if n)
                    except Exception:
                        pass
    return nodes


def yaml_str(v):
    s = str(v)
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def node_key(n):
    return (n.get("type"), n.get("server"), n.get("port"),
            n.get("uuid") or n.get("password") or "")


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
    for i, url in enumerate(sources):
        txt = None
        try:
            txt = fetch(url, ctx)
            # persist successful fetch as offline cache for next run
            try:
                open(os.path.join(cache_dir, f"{i}.txt"), "w", encoding="utf-8").write(txt)
            except Exception:
                pass
            ns = parse_source(txt)
            all_nodes.extend(ns)
            print(f"[ok]   src#{i} {len(ns)} nodes <- {url.split('/')[-1]}")
        except Exception as e:
            # fall back to last successful cache if live fetch failed
            cf = os.path.join(cache_dir, f"{i}.txt")
            if os.path.exists(cf):
                try:
                    txt = open(cf, encoding="utf-8").read()
                    ns = parse_source(txt)
                    all_nodes.extend(ns)
                    print(f"[cache] src#{i} {len(ns)} nodes from offline cache")
                except Exception:
                    txt = None
            if txt is None:
                print(f"[FAIL] src#{i} {url.split('/')[-1]} : {e}")
                skipped.append(url)

    # dedupe by (type, server, port, credential)
    seen = {}
    uniq = []
    for n in all_nodes:
        k = node_key(n)
        if k in seen:
            continue
        seen[k] = True
        uniq.append(n)

    # Hard guard: never publish an empty config (a build outage must fail loudly
    # instead of committing a node-less SuperMerge.yaml that overwrites a good one).
    if not uniq:
        print(f"[FATAL] 0 nodes parsed from {len(sources)} sources "
              f"({len(skipped)} fetch failures, no offline cache). "
              f"Aborting: existing {os.path.basename(OUT_FILE)} left untouched.")
        sys.exit(1)

    # dedupe names
    name_count = {}
    for n in uniq:
        base = n.get("name") or "node"
        if base in name_count:
            name_count[base] += 1
            n["name"] = f"{base}-{name_count[base]}"
        else:
            name_count[base] = 0

    out = io.StringIO()
    out.write("# SuperMerge - aggregated free nodes (auto-generated)\n")
    out.write("proxies:\n")
    for n in uniq:
        out.write("  - name: " + yaml_str(n["name"]) + "\n")
        out.write("    type: " + n["type"] + "\n")
        out.write("    server: " + str(n["server"]) + "\n")
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
            out.write(f"    client-fingerprint: {n['client-fingerprint']}\n")
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
                out.write(f"      - {a}\n")

    out.write("proxy-groups:\n")
    out.write("  - name: \U0001F680 NodeSelect\n")
    out.write("    type: select\n")
    out.write("    proxies:\n")
    out.write("      - \u267B\uFE0F AutoTest\n")
    out.write("      - DIRECT\n")
    for nm in [n["name"] for n in uniq]:
        out.write(f"      - {yaml_str(nm)}\n")
    out.write("  - name: \u267B\uFE0F AutoTest\n")
    out.write("    type: url-test\n")
    out.write("    url: https://www.gstatic.com/generate_204\n")
    out.write("    interval: 300\n")
    out.write("    proxies:\n")
    for nm in [n["name"] for n in uniq]:
        out.write(f"      - {yaml_str(nm)}\n")
    out.write("rules:\n")
    out.write("  - GEOIP,CN,DIRECT\n")
    out.write("  - MATCH,\U0001F680 NodeSelect\n")

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write(out.getvalue())

    # type distribution
    dist = {}
    for n in uniq:
        dist[n["type"]] = dist.get(n["type"], 0) + 1
    print(f"[done] total={len(uniq)} (deduped from {len(all_nodes)}) "
          f"failed_sources={len(skipped)} -> {OUT_FILE}")
    print("[dist]", " ".join(f"{k}={v}" for k, v in sorted(dist.items())))


if __name__ == "__main__":
    main()
