import requests
import csv
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse

# ------------ "Browser mode" defaults ------------
DEFAULT_TIMEOUT = 15
DEFAULT_MAX_WORKERS = 20
# Browsers let you proceed despite bad certs; do the same
DEFAULT_VERIFY_SSL = False

_thread_local = threading.local()


def get_session(verify_ssl: bool):
    if not hasattr(_thread_local, "session") or _thread_local.verify_ssl != verify_ssl:
        s = requests.Session()
        s.headers.update(
            {
                # Chrome-like UA
                "User-Agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/127.0.0.1 Safari/537.36"
                )
            }
        )
        _thread_local.session = s
        _thread_local.verify_ssl = verify_ssl
        if verify_ssl is False:
            try:
                from requests.packages.urllib3.exceptions import InsecureRequestWarning

                requests.packages.urllib3.disable_warnings(
                    category=InsecureRequestWarning
                )
            except Exception:
                pass
    return _thread_local.session


def http_get(url: str, timeout=DEFAULT_TIMEOUT, verify_ssl=DEFAULT_VERIFY_SSL):
    """GET with redirects; return (status_code:int|None, final_url:str|None, err:str|None)"""
    sess = get_session(verify_ssl)
    try:
        r = sess.get(
            url, allow_redirects=True, timeout=timeout, stream=True, verify=verify_ssl
        )
        code = int(r.status_code) if r.status_code is not None else None
        final_url = r.url
        r.close()
        return code, final_url, None
    except requests.exceptions.RequestException as e:
        # If server responded with a code, surface it anyway
        resp = getattr(e, "response", None)
        if resp is not None and resp.status_code is not None:
            return int(resp.status_code), getattr(resp, "url", url), None
        return None, None, type(e).__name__
    except Exception as e:
        return None, None, type(e).__name__


def is_good(code: int | None):
    # Browser-success = any 2xx or 3xx
    return code is not None and 200 <= code < 400


def ensure_candidates(raw: str):
    """
    Build the set of URLs a browser would effectively try:
      https://input, http://input, https://www.input, http://www.input
    (preserve path/query if user provided them; add scheme if missing)
    """
    raw = (raw or "").strip()
    if not raw:
        return []

    # If they gave a scheme, keep it as candidate(0); also build the alternates
    if raw.startswith(("http://", "https://")):
        p = urlparse(raw)
        host = p.netloc or p.path
        path = p.path if p.netloc else ""
        https_orig = urlunparse(("https", host, path, p.params, p.query, p.fragment))
    else:
        # treat like an address bar: try https first
        https_orig = "https://" + raw
        p = urlparse(https_orig)
        host = p.netloc or p.path
        path = p.path if p.netloc else ""

    http_orig = "http://" + host + (path or "")
    # www toggle (keep path/query)
    www_host = host if host.lower().startswith("www.") else f"www.{host}"
    https_www = urlunparse(("https", www_host, path, p.params, p.query, p.fragment))
    http_www = "http://" + www_host + (path or "")

    # Candidate priority mimics how users experience it (secure first, then www, then http)
    candidates = [https_orig, https_www, http_orig, http_www]

    # Ensure uniqueness while keeping order
    seen, out = set(), []
    for u in candidates:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


# --------- Cache so duplicates don't re-fetch ----------
_cache_lock = threading.Lock()
# base key = what user typed normalized to first https (like browser address bar)
_cache: dict[str, tuple[str, int | str, str, str]] = {}
# key -> (resolved_url, status_code, state, via)  where via describes which candidate worked


def classify_browser_style(
    raw_url: str, timeout=DEFAULT_TIMEOUT, verify_ssl=DEFAULT_VERIFY_SSL
):
    """
    Try candidates; return (resolved_url, status_code, state, via, tried_summary)
      - state = "good" if any 2xx/3xx, else "bad"
      - via = which candidate succeeded (e.g., 'https_www')
    """
    candidates = ensure_candidates(raw_url)
    tried = []
    mapping = {}

    for u in candidates:
        code, final_u, err = http_get(u, timeout=timeout, verify_ssl=verify_ssl)
        label = f"{code}" if code is not None else f"error:{err or 'unknown'}"
        tried.append(f"{u} -> {label}")
        mapping[u] = (code, final_u, err)
        if is_good(code):
            via = (
                "https_orig"
                if u == candidates[0]
                else (
                    "https_www"
                    if u == candidates[1]
                    else "http_orig" if u == candidates[2] else "http_www"
                )
            )
            return final_u or u, code, "good", via, " | ".join(tried)

    # none were good; pick the last attempt details to report code/error
    last_u = candidates[-1] if candidates else raw_url
    code, final_u, err = mapping.get(last_u, (None, None, "unknown"))
    status = code if code is not None else "error"
    return (final_u or last_u), status, "bad", "", " | ".join(tried)


def check_one(
    row, website_field="Website", timeout=DEFAULT_TIMEOUT, verify_ssl=DEFAULT_VERIFY_SSL
):
    row = dict(row)
    raw = (row.get(website_field, "") or "").strip()
    if not raw:
        row["final_url"] = ""
        row["status_code"] = "error"
        row["state"] = "bad"
        row["via"] = ""
        row["tried"] = "no_url"
        return row, f"{row.get('Company','')} -> (no url) -> error (bad)"

    # cache key: pretend address bar added https
    key = raw if raw.startswith(("http://", "https://")) else "https://" + raw

    with _cache_lock:
        cached = _cache.get(key)

    if cached is not None:
        final_url, status_code, state, via = cached
        tried_summary = "(cached)"
    else:
        final_url, status_code, state, via, tried_summary = classify_browser_style(
            raw, timeout=timeout, verify_ssl=verify_ssl
        )
        with _cache_lock:
            _cache[key] = (final_url, status_code, state, via)

    row["final_url"] = final_url
    row["status_code"] = status_code
    row["state"] = state
    row["via"] = via
    row["tried"] = tried_summary

    line = (
        f"{row.get('Company','')} -> {final_url} -> {status_code} ({state}) via={via}"
    )
    return row, line


def check_urls(
    file_path,
    max_workers=DEFAULT_MAX_WORKERS,
    timeout=DEFAULT_TIMEOUT,
    verify_ssl=DEFAULT_VERIFY_SSL,
):
    base, _ = os.path.splitext(file_path)
    output_csv = base + "_with_status.csv"

    with open(file_path, newline="", encoding="utf-8") as infile:
        reader = csv.DictReader(infile)
        fieldnames = list(reader.fieldnames)
        for extra in ["final_url", "status_code", "state", "via", "tried"]:
            if extra not in fieldnames:
                fieldnames.append(extra)
        rows = list(reader)

    total = len(rows)
    completed = 0
    results = []
    print(
        f"Starting checks on {total} URLs (browser-mode: 2xx/3xx=good, SSL ignored={not verify_ssl})...\n"
    )

    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {
            ex.submit(check_one, row, "Website", timeout, verify_ssl): idx
            for idx, row in enumerate(rows)
        }
        for fut in as_completed(futures):
            updated_row, line = fut.result()
            results.append(updated_row)
            with lock:
                completed += 1
                pct = completed / total if total else 1.0
                print(f"{completed}/{total} ({pct:.1%})  {line}")

    with open(output_csv, "w", newline="", encoding="utf-8") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nFinished! Results saved to {output_csv}")


if __name__ == "__main__":
    input_file = "./url-checker/Leads 9.17.25.bad.csv"
    check_urls(
        input_file,
        max_workers=20,
        timeout=15,
        verify_ssl=False,  # behave like a browser (don’t fail on cert issues)
    )
