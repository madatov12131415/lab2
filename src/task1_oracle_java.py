import json
import re
from datetime import datetime

import requests
from bs4 import BeautifulSoup


HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.oracle.com/java/",
}

SESSION = requests.Session()
SESSION.headers.update(HEADERS)


def fetch(url: str) -> str:
    response = SESSION.get(url, timeout=30)
    response.raise_for_status()
    return response.text


def advisory_date_from_url(url: str) -> str:
    m = re.search(r"cpu([a-z]{3})(\d{4})(?:verbose)?\.html$", url, flags=re.IGNORECASE)
    if not m:
        raise ValueError(f"Cannot parse advisory date from URL: {url}")

    mon = m.group(1).title()
    year = int(m.group(2))
    month_num = datetime.strptime(mon, "%b").month
    return f"{year:04d}-{month_num:02d}-01"


def build_candidate_verbose_urls(start_year: int = 2014, end_year: int = 2026) -> list[str]:
    months = ["jan", "apr", "jul", "oct"]
    urls = []
    for year in range(start_year, end_year + 1):
        for mon in months:
            urls.append(f"https://www.oracle.com/security-alerts/cpu{mon}{year}verbose.html")
    return urls


def find_java_section_text(html: str) -> str:
    soup = BeautifulSoup(html, "lxml")
    text = soup.get_text("\n", strip=True)

    start_marker = "Text Form of Risk Matrix for Oracle Java SE"
    start = text.find(start_marker)
    if start == -1:
        return ""

    tail = text[start + len(start_marker):]
    next_section = re.search(r"\nText Form of Risk Matrix for Oracle .+", tail)
    if next_section:
        end = start + len(start_marker) + next_section.start()
        return text[start:end]

    return text[start:]


def extract_java_cves_from_verbose(html: str) -> list[str]:
    java_section = find_java_section_text(html)
    if not java_section:
        return []

    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", java_section)))


def verbose_to_advisory_url(verbose_url: str) -> str:
    return verbose_url.replace("verbose.html", ".html")


def collect_task1() -> list[dict]:
    results = []
    seen = set()

    for verbose_url in build_candidate_verbose_urls():
        try:
            html = fetch(verbose_url)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code in (403, 404):
                continue
            print(f"[WARN] {verbose_url}: {e}")
            continue
        except Exception as e:
            print(f"[WARN] {verbose_url}: {e}")
            continue

        cves = extract_java_cves_from_verbose(html)
        if not cves:
            continue

        advisory_url = verbose_to_advisory_url(verbose_url)
        vendor_release_date = advisory_date_from_url(advisory_url)

        for cve_id in cves:
            key = (cve_id, advisory_url)
            if key in seen:
                continue
            seen.add(key)
            results.append(
                {
                    "ID": cve_id,
                    "vendor_release_date": vendor_release_date,
                    "vendor_release_url": advisory_url,
                }
            )

    results.sort(key=lambda x: (x["vendor_release_date"], x["ID"]))
    return results


def main():
    data = collect_task1()
    with open("result_task_1.json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"Saved records: {len(data)}")
    print("Output: result_task_1.json")


if __name__ == "__main__":
    main()
