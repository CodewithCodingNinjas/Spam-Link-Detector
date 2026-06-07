"""
Real-URL Dataset Builder
=========================
Fetches genuine phishing and legitimate URLs from public threat-intel feeds and
top-sites lists, extracts the structural feature vector using the SAME
URLFeatureExtractor used at inference time, and writes a labelled CSV.

This replaces the previous synthetic-distribution generator, whose perfectly
separable classes produced a meaningless AUC of 1.0.

Sources (all public, no API key required):
  * Phishing : OpenPhish community feed + mitchellkrogza/Phishing.Database (active)
  * Legit    : zer0h top-100k domains list (Tranco-style popularity ranking)

Usage:
    python build_dataset.py --phishing 4000 --legit 4000 --out data/urls_dataset.csv

Offline / air-gapped use:
    Place pre-downloaded url lists at data/phishing_raw.txt and data/legit_raw.txt
    and pass --offline to skip network fetches.
"""
import argparse
import os
import sys
import csv
import urllib.request
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.url_features import URLFeatureExtractor  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (research; phishing-detection-dataset)"}

PHISHING_SOURCES = [
    "https://openphish.com/feed.txt",
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
]
LEGIT_SOURCE = "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-100000-domains"

# Realistic paths grafted onto legit bare domains so the model cannot learn the
# trivial shortcuts "has a path => phishing" or "is long => phishing". These mix
# short and long paths, query strings, and digits so url_length / digit_ratio /
# path_depth distributions overlap with the phishing class.
LEGIT_PATHS = [
    "", "/", "/login", "/account/settings?ref=home",
    "/search?q=annual+report+2026&page=3",
    "/products/category/electronics?id=4821&sort=price",
    "/help/support/article/1029384", "/signin?next=/dashboard/overview",
    "/cart/checkout/step2?session=ab8821", "/user/profile/12839/edit",
    "/news/2026/06/finance-update-q2-earnings-call",
    "/orders/INV-2026-0098213/track", "/v2/api/docs/reference#section-4",
]

# Maximum fraction of phishing samples allowed to be bare IP-address hosts.
# The raw feeds are ~45% IP hosts; uncapped, the model learns the trivial
# shortcut "numeric host => phishing" (artificially inflating accuracy). Real
# phishing is overwhelmingly on look-alike DOMAINS, so we cap IP hosts low and
# force the model to learn lexical/structural signals instead.
MAX_IP_PHISHING_FRACTION = 0.15

# The free phishing feeds are stale and ~96% HTTP, while modern phishing widely
# adopts HTTPS (Let's Encrypt; ~80%+ per recent APWG reports). Left uncorrected,
# the model degenerates into an "is-HTTP" detector that fails on real HTTPS
# phishing. We deterministically upgrade ~80% of phishing URLs to HTTPS so the
# has_https feature stops being a free separator and the model must learn the
# lexical/host structure that actually distinguishes phishing.
PHISHING_HTTPS_FRACTION = 0.80
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def _fetch(url: str, timeout: int = 20) -> list:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "ignore").splitlines()


def _read_local(path: str) -> list:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read().splitlines()


def _is_ip_host(host: str) -> bool:
    parts = host.split(":")[0].split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def collect_phishing(n: int, offline: bool) -> list:
    raw = []
    if offline:
        raw = _read_local(os.path.join(DATA_DIR, "phishing_raw.txt"))
    else:
        for src in PHISHING_SOURCES:
            try:
                lines = _fetch(src)
                print(f"  [phishing] {src} -> {len(lines)} lines")
                raw.extend(lines)
            except Exception as e:
                print(f"  [phishing] WARN {src}: {e}")
            if len(raw) >= n * 6:
                break
    # Cap IP-host phishing to a realistic fraction so the model cannot win on the
    # trivial "numeric host => phishing" shortcut (see MAX_IP_PHISHING_FRACTION).
    ip_cap = int(n * MAX_IP_PHISHING_FRACTION)
    domain_urls, ip_urls, seen = [], [], set()
    for line in raw:
        line = line.strip()
        if not line.startswith(("http://", "https://")):
            continue
        host = urlparse(line).netloc.lower()
        if not host or host in seen:        # dedup by host -> avoids near-duplicate leakage
            continue
        seen.add(host)
        if _is_ip_host(host):
            if len(ip_urls) < ip_cap:
                ip_urls.append(line)
        else:
            domain_urls.append(line)
        if len(domain_urls) + len(ip_urls) >= n * 2:
            break
    urls = (domain_urls + ip_urls)[:n]
    # Deterministically upgrade ~PHISHING_HTTPS_FRACTION of http:// phishing URLs
    # to https:// to match modern phishing reality (see PHISHING_HTTPS_FRACTION).
    # keep_http_every = 1 in N kept as http; e.g. 0.80 -> keep 1 in 5 as http.
    keep_http_every = max(2, round(1 / max(1 - PHISHING_HTTPS_FRACTION, 1e-6)))
    for i, u in enumerate(urls):
        if u.startswith("http://") and (i % keep_http_every != 0):
            urls[i] = "https://" + u[len("http://"):]
    n_ip = sum(1 for u in urls if _is_ip_host(urlparse(u).netloc.lower()))
    n_https = sum(1 for u in urls if u.startswith("https://"))
    print(f"  [phishing] kept {len(urls)} urls ({n_ip} IP-host {100*n_ip/max(len(urls),1):.0f}%, "
          f"{n_https} https {100*n_https/max(len(urls),1):.0f}%)")
    return urls


def collect_legit(n: int, offline: bool) -> list:
    if offline:
        raw = _read_local(os.path.join(DATA_DIR, "legit_raw.txt"))
    else:
        try:
            raw = _fetch(LEGIT_SOURCE)
            print(f"  [legit] {LEGIT_SOURCE} -> {len(raw)} lines")
        except Exception as e:
            print(f"  [legit] ERROR {e}")
            raw = []
    urls, seen = [], set()
    for i, line in enumerate(raw):
        dom = line.strip().lower()
        # file may be "rank,domain" or bare "domain"
        if "," in dom:
            dom = dom.split(",")[-1]
        if not dom or "." not in dom or dom in seen:
            continue
        seen.add(dom)
        path = LEGIT_PATHS[i % len(LEGIT_PATHS)]
        scheme = "https://" if i % 10 else "http://"   # ~10% legit on http, realistic
        urls.append(f"{scheme}{dom}{path}")
        if len(urls) >= n:
            break
    return urls


def build(phishing_n: int, legit_n: int, out_path: str, offline: bool):
    extractor = URLFeatureExtractor()
    feature_names = URLFeatureExtractor.get_feature_names()

    print("Collecting phishing URLs...")
    phishing = collect_phishing(phishing_n, offline)
    print("Collecting legitimate URLs...")
    legit = collect_legit(legit_n, offline)

    print(f"Collected {len(phishing)} phishing + {len(legit)} legit URLs")
    if not phishing or not legit:
        print("ERROR: insufficient data fetched. Use --offline with local lists.")
        sys.exit(1)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    rows = 0
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(feature_names + ["label", "url"])
        for url, label in ([(u, 1) for u in phishing] + [(u, 0) for u in legit]):
            try:
                feats = extractor.extract_numeric_features(url)
            except Exception:
                continue
            w.writerow(list(feats) + [label, url])
            rows += 1

    print(f"Wrote {rows} rows ({len(feature_names)} features) -> {out_path}")
    return out_path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--phishing", type=int, default=4000)
    ap.add_argument("--legit", type=int, default=4000)
    ap.add_argument("--out", default=os.path.join(DATA_DIR, "urls_dataset.csv"))
    ap.add_argument("--offline", action="store_true")
    args = ap.parse_args()
    build(args.phishing, args.legit, args.out, args.offline)
