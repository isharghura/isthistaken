#!/usr/bin/env python3
"""namecheck: check a handle across domains, social platforms and package registries.

Run:  python3 app.py     then open http://localhost:8000
No dependencies, Python 3.8+.
"""
import json, re, socket, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

TLDS = ["com", "net", "org", "io", "ai", "co", "app", "dev", "xyz", "me", "gg", "tv", "fm", "so", "sh", "gg", "lol"]
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
TIMEOUT = 8


def fetch(url, method="GET", data=None, headers=None):
    """Return (status, body_text). Status 0 means network failure."""
    h = {"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read(400_000).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(50_000).decode("utf-8", "ignore")
        except Exception:
            body = ""
        return e.code, body
    except Exception:
        return 0, ""


# ---------- domains ----------
def check_domain(name, tld):
    domain = f"{name}.{tld}"
    status, body = fetch(f"https://rdap.org/domain/{domain}", headers={"Accept": "application/rdap+json"})
    if status == 200:
        state = "taken"
    elif status == 404:
        # rdap.org also returns 404 for TLDs with no RDAP server, so confirm with DNS.
        try:
            socket.getaddrinfo(domain, None)
            state = "taken"
        except socket.gaierror:
            state = "available"
    else:
        try:
            socket.getaddrinfo(domain, None)
            state = "taken"
        except socket.gaierror:
            state = "unknown"
    return {"label": domain, "state": state, "url": f"https://www.namecheap.com/domains/registration/results/?domain={domain}"}


# ---------- social / registries ----------
def by_status(available=(404,), taken=(200,)):
    def f(status, body):
        if status in available:
            return "available"
        if status in taken:
            return "taken"
        return "unknown"
    return f


def tiktok_rule(status, body):
    if status == 404 or '"statusCode":10221' in body or "Couldn't find this account" in body:
        return "available"
    if status == 200 and ("webapp.user-detail" in body and '"uniqueId"' in body):
        return "taken"
    return "unknown"


def discord_check(name):
    status, body = fetch(
        "https://discord.com/api/v9/unique-username/username-attempt-unauthed",
        method="POST", data=json.dumps({"username": name}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        taken = json.loads(body).get("taken")
    except Exception:
        return "unknown"
    return "taken" if taken else "available" if taken is False else "unknown"


def bluesky_rule(status, body):
    if status == 200:
        return "taken"
    if status == 400 and "unable to resolve handle" in body.lower():
        return "available"
    return "unknown"


def instagram_rule(status, body):
    # Same public endpoint the website calls for a profile page. Blocked or
    # rate-limited responses fall back to a manual check instead of guessing.
    if status == 404:
        return "available"
    if status == 200 and '"username"' in body:
        return "taken"
    return "manual"


EXTRA_HEADERS = {"Instagram": {"X-IG-App-ID": "936619743392459"}}


# name, profile URL, probe URL, rule. Rule None means manual check only.
SOCIAL = [
    ("Instagram", "https://www.instagram.com/{n}/",
     "https://www.instagram.com/api/v1/users/web_profile_info/?username={n}", instagram_rule),
    ("Gmail (@gmail.com)", "https://accounts.google.com/signup", None, None),
    ("TikTok", "https://www.tiktok.com/@{n}", "https://www.tiktok.com/@{n}", tiktok_rule),
    ("YouTube", "https://www.youtube.com/@{n}", "https://www.youtube.com/@{n}", lambda s, b: by_status()(s, b)),
    ("Discord", "https://discord.com/users/{n}", "discord", None),
    ("X / Twitter", "https://x.com/{n}", None, None),
    ("Reddit", "https://www.reddit.com/user/{n}", "https://www.reddit.com/user/{n}/about.json", by_status()),
    ("GitHub", "https://github.com/{n}", "https://github.com/{n}", by_status()),
    ("Bluesky", "https://bsky.app/profile/{n}.bsky.social",
     "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={n}.bsky.social", bluesky_rule),
    ("npm package", "https://www.npmjs.com/package/{n}", "https://registry.npmjs.org/{n}", by_status()),
    ("PyPI package", "https://pypi.org/project/{n}/", "https://pypi.org/pypi/{n}/json", by_status()),
]


def check_social(name, spec):
    label, profile, probe, rule = spec
    url = profile.format(n=name)
    if probe == "discord":
        state = discord_check(name)
    elif probe is None:
        state = "manual"
    else:
        status, body = fetch(probe.format(n=name), headers=EXTRA_HEADERS.get(label))
        state = rule(status, body)
    return {"label": label, "state": state, "url": url}


def variants(name):
    n = name
    return [f"get{n}", f"{n}hq", f"{n}app", f"the{n}", f"{n}official", f"{n}1", f"{n}_", f"real{n}", f"{n}tv"]


# ---------- server ----------
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, ctype, payload):
        b = payload if isinstance(payload, bytes) else payload.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            return self.send(200, "text/html; charset=utf-8", PAGE)
        if u.path == "/api/check":
            q = parse_qs(u.query)
            name = (q.get("name", [""])[0]).strip().lower().lstrip("@")
            kind = q.get("kind", ["domains"])[0]
            if not NAME_RE.match(name):
                return self.send(400, "application/json", json.dumps({"error": "Use letters, numbers, dots, dashes or underscores (max 63)."}))
            with ThreadPoolExecutor(max_workers=12) as ex:
                if kind == "domains":
                    dn = name.replace("_", "").replace(".", "")
                    res = list(ex.map(lambda t: check_domain(dn, t), dict.fromkeys(TLDS)))
                else:
                    res = list(ex.map(lambda s: check_social(name, s), SOCIAL))
            return self.send(200, "application/json", json.dumps({"name": name, "results": res, "variants": variants(name)}))
        self.send(404, "text/plain", "not found")


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>namecheck</title>
<style>
:root{--bg:#f6f7f9;--ink:#171b26;--mute:#6b7280;--line:#dfe2e8;--yes:#0b7a5a;--no:#8a90a0;--maybe:#b45309;--card:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#12141a;--ink:#e9ecf2;--mute:#9aa1b0;--line:#2a2e39;--yes:#3ccf9d;--no:#7c8394;--maybe:#e7a24a;--card:#1a1d25}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:760px;margin:0 auto;padding:40px 20px 80px}
h1{font-size:30px;margin:0 0 4px;letter-spacing:-.02em}p.sub{margin:0 0 24px;color:var(--mute)}
form{display:flex;gap:8px}input{flex:1;font:inherit;padding:12px 14px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink)}
button{font:inherit;padding:12px 20px;border:0;border-radius:8px;background:var(--ink);color:var(--bg);cursor:pointer}
:focus-visible{outline:2px solid var(--yes);outline-offset:2px}
h2{font-size:17px;margin:32px 0 8px;display:flex;justify-content:space-between;align-items:baseline}
h2 small{font-weight:400;color:var(--mute);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px}
a.row{display:flex;justify-content:space-between;gap:8px;padding:10px 12px;background:var(--card);border:1px solid var(--line);border-radius:8px;color:inherit;text-decoration:none}
a.row:hover{border-color:var(--ink)}a.row b{font-weight:500;overflow:hidden;text-overflow:ellipsis}
.available{color:var(--yes)}.taken{color:var(--no)}.unknown,.manual{color:var(--maybe)}.loading{color:var(--mute)}
.chips{display:flex;flex-wrap:wrap;gap:6px}.chips button{padding:5px 10px;font-size:14px;background:var(--card);color:var(--ink);border:1px solid var(--line)}
.err{color:var(--maybe);margin-top:12px}.note{color:var(--mute);font-size:13px;margin-top:28px}
</style></head><body><main>
<h1>namecheck</h1>
<p class="sub">One name, checked across domains, socials and package registries.</p>
<form id="f"><input id="q" placeholder="selfishidiot" autocomplete="off" autofocus aria-label="Name to check"><button>Check</button></form>
<div id="err" class="err"></div>
<div id="out" hidden>
 <h2>Domains <small id="dc"></small></h2><div id="domains" class="grid"></div>
 <h2>Socials and registries <small id="sc"></small></h2><div id="social" class="grid"></div>
 <h2>Variations <small>click to check</small></h2><div id="variants" class="chips"></div>
 <p class="note">Domain results come from RDAP with a DNS check, so "available" means likely available; confirm at a registrar.
 Instagram and X block automated checks, so those open the profile for a manual look. Handle checks can also return "unknown" when a site rate-limits you.</p>
</div>
<script>
const $=id=>document.getElementById(id);
const words={available:"available",taken:"taken",unknown:"unknown",manual:"check manually"};
function render(el,items){el.innerHTML=items.map(r=>`<a class="row" href="${r.url}" target="_blank" rel="noopener"><b>${r.label}</b><span class="${r.state}">${words[r.state]||r.state}</span></a>`).join("")}
function skeleton(el,n){el.innerHTML=Array(n).fill('<a class="row"><b>...</b><span class="loading">checking</span></a>').join("")}
async function run(name){
  $("err").textContent="";name=name.trim().replace(/^@/,"");if(!name)return;$("q").value=name;$("out").hidden=false;
  skeleton($("domains"),12);skeleton($("social"),10);$("dc").textContent=$("sc").textContent="";
  for(const [kind,el,cnt] of [["domains","domains","dc"],["social","social","sc"]]){
    fetch(`/api/check?name=${encodeURIComponent(name)}&kind=${kind}`).then(r=>r.json()).then(d=>{
      if(d.error){$("err").textContent=d.error;$("out").hidden=true;return}
      render($(el),d.results);$(cnt).textContent=`${d.results.filter(r=>r.state==="available").length} available`;
      if(kind==="social")$("variants").innerHTML=d.variants.map(v=>`<button type="button" data-v="${v}">${v}</button>`).join("");
    }).catch(()=>{$("err").textContent="Could not reach the local server."});
  }
}
$("f").addEventListener("submit",e=>{e.preventDefault();run($("q").value)});
$("variants").addEventListener("click",e=>{if(e.target.dataset.v)run(e.target.dataset.v)});
</script></main></body></html>
"""

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    host = "0.0.0.0" if "PORT" in os.environ else "127.0.0.1"  # public only when a host sets PORT
    print(f"namecheck running on {host}:{port}  (Ctrl+C to stop)")
    ThreadingHTTPServer((host, port), Handler).serve_forever()