import requests
import csv
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Per-thread requests.Session
_thread_local = threading.local()


def get_session():
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.headers.update({"User-Agent": "url-checker/1.0"})
        _thread_local.session = s
    return _thread_local.session


def quick_status(url: str, timeout=5):
    """Try HEAD, fallback to GET if needed."""
    sess = get_session()
    try:
        r = sess.head(url, allow_redirects=True, timeout=timeout)
        code = r.status_code
        if code in (403, 405) or code is None:
            r = sess.get(url, allow_redirects=True, timeout=timeout, stream=True)
            r.close()
            code = r.status_code
        return code
    except Exception:
        return None


def is_good(code):
    return code is not None and 200 <= code < 400


def normalize_url(raw: str):
    """Use the exact URL, only add https:// if no scheme given."""
    raw = (raw or "").strip()
    if not raw:
        return None
    if raw.startswith(("http://", "https://")):
        return raw
    return "https://" + raw


def with_http(url_https: str):
    """Convert https:// to http:// for fallback"""
    if url_https.startswith("https://"):
        return "http://" + url_https[len("https://") :]
    return url_https.replace("https://", "http://", 1)


def check_one(row, website_field="Website"):
    row = dict(row)
    raw = row.get(website_field, "").strip()
    if not raw:
        row["final_url"] = ""
        row["status_code"] = "error"
        row["state"] = "bad"
        return row, f"{row.get('Company','')} -> (no url) -> error (bad)"

    url_https = normalize_url(raw)
    final_url = url_https
    code = quick_status(url_https)

    if is_good(code):
        state = "good"
    else:
        url_http = with_http(url_https)
        code = quick_status(url_http)
        final_url = url_http
        state = "good" if is_good(code) else "bad"

    row["final_url"] = final_url
    row["status_code"] = code if code is not None else "error"
    row["state"] = state

    line = f"{row.get('Company','')} -> {final_url} -> {row['status_code']} ({state})"
    return row, line


def check_urls(file_path, max_workers=20):
    base, _ = os.path.splitext(file_path)
    output_csv = base + "_with_status.csv"

    with open(file_path, newline="", encoding="utf-8") as infile:
        reader = csv.DictReader(infile)
        fieldnames = list(reader.fieldnames)
        for extra in ["final_url", "status_code", "state"]:
            if extra not in fieldnames:
                fieldnames.append(extra)
        rows = list(reader)

    total = len(rows)
    completed = 0
    results = []
    print(f"Starting checks on {total} URLs...\n")

    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(check_one, row): idx for idx, row in enumerate(rows)}
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
    # Replace with your text file name, or take as input
    input_file = "/Users/edward/Documents/git/svitlana/url-checker/Leads 9.17.25.csv"
    check_urls(input_file)
