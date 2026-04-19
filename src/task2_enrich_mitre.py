import json
import re
import time
from typing import Any, Dict, List, Set

import requests
from bs4 import BeautifulSoup


HEADERS = {
    "User-Agent": "lab2-cve-enricher/1.0",
    "Accept": "application/json, text/html;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

SESSION = requests.Session()
SESSION.headers.update(HEADERS)

CVE_ORG_URL = "https://www.cve.org/CVERecord?id={}"
CWE_URL = "https://cwe.mitre.org/data/definitions/{}.html"
RAW_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"


def fetch_json(url: str) -> Dict[str, Any]:
    response = SESSION.get(url, timeout=20)
    response.raise_for_status()
    return response.json()


def fetch_text(url: str) -> str:
    response = SESSION.get(url, timeout=20)
    response.raise_for_status()
    return response.text


def load_task1(path: str = "result_task_1.json") -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_task2(data: List[Dict[str, Any]], path: str = "result_task_2.json") -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def build_candidate_cvelistv5_urls(cve_id: str) -> List[str]:
    m = re.fullmatch(r"CVE-(\d{4})-(\d+)", cve_id, flags=re.IGNORECASE)
    if not m:
        raise ValueError(f"Invalid CVE ID: {cve_id}")

    year = m.group(1)
    num_str = m.group(2)
    n = int(num_str)

    candidates = []
    seen = set()

    def add(folder: str):
        if folder not in seen:
            seen.add(folder)
            candidates.append(f"{RAW_BASE}/{year}/{folder}/{cve_id.upper()}.json")

    # Базовые варианты
    add("0xxx")
    add(f"{n // 1000}xxx")                 # 2397 -> 2xxx, 6629 -> 6xxx
    add(f"{(n // 1000) * 1000}xxx")        # 1876 -> 1000xxx, 6456 -> 6000xxx
    add(f"{n // 100}xx")                   # 2397 -> 23xx
    add(f"{n // 100}xxx")                  # 2397 -> 23xxx
    add(f"{n // 10}x")                     # 2397 -> 239x
    add(f"{n // 10}xx")                    # 2397 -> 239xx

    # Для 5-7 значных номеров пробуем префиксные диапазоны
    if len(num_str) >= 5:
        add(f"{num_str[:2]}xxx")           # 62543 -> 62xxx
        add(f"{num_str[:3]}xxx")           # 123456 -> 123xxx
    if len(num_str) >= 6:
        add(f"{num_str[:3]}xxx")           # 456789 -> 456xxx

    # Иногда полезно попробовать только первую цифру с xxx
    add(f"{num_str[0]}xxx")

    return candidates


def fetch_cve_record(cve_id: str) -> Dict[str, Any]:
    last_error = None

    for url in build_candidate_cvelistv5_urls(cve_id):
        try:
            return fetch_json(url)
        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                last_error = e
                continue
            raise

    if last_error:
        raise last_error
    raise FileNotFoundError(f"Could not find record for {cve_id}")


def get_first_english_description(containers: Dict[str, Any]) -> str:
    cna = containers.get("cna")
    if isinstance(cna, dict):
        for item in cna.get("descriptions", []):
            if item.get("lang") == "en" and item.get("value"):
                return item["value"]

    adp = containers.get("adp", [])
    if isinstance(adp, list):
        for adp_item in adp:
            if isinstance(adp_item, dict):
                for item in adp_item.get("descriptions", []):
                    if item.get("lang") == "en" and item.get("value"):
                        return item["value"]

    return ""


def collect_metrics_from_container(container: Dict[str, Any]) -> List[Dict[str, Any]]:
    result = []
    metrics = container.get("metrics", [])
    if not isinstance(metrics, list):
        return result

    for metric in metrics:
        if not isinstance(metric, dict):
            continue

        for metric_key, metric_value in metric.items():
            if metric_key.startswith("cvssV") and isinstance(metric_value, dict):
                version = metric_value.get("version", "")
                score = metric_value.get("baseScore")
                vector = metric_value.get("vectorString", "")
                severity = metric_value.get("baseSeverity", "")
                result.append(
                    {
                        "version": version.lower().replace(".", "") if version else metric_key.lower(),
                        "score": score,
                        "vector": vector,
                        "severity": severity,
                    }
                )
    return result


def dedupe_cvss(cvss_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    result = []

    for item in cvss_list:
        key = (
            item.get("version"),
            item.get("score"),
            item.get("vector"),
            item.get("severity"),
        )
        if key not in seen:
            seen.add(key)
            result.append(item)

    return result


def extract_cvss(containers: Dict[str, Any]) -> List[Dict[str, Any]]:
    all_metrics = []

    cna = containers.get("cna")
    if isinstance(cna, dict):
        all_metrics.extend(collect_metrics_from_container(cna))

    adp = containers.get("adp", [])
    if isinstance(adp, list):
        for adp_item in adp:
            if isinstance(adp_item, dict):
                all_metrics.extend(collect_metrics_from_container(adp_item))

    return dedupe_cvss(all_metrics)


def extract_cpes(containers: Dict[str, Any]) -> List[str]:
    cpes: Set[str] = set()

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == "criteria" and isinstance(value, str) and value.startswith("cpe:"):
                    cpes.add(value)
                else:
                    walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(containers)
    return sorted(cpes)


def extract_cwe_ids(containers: Dict[str, Any]) -> List[str]:
    cwe_ids = set()

    def from_problem_types(problem_types: List[Dict[str, Any]]) -> None:
        for problem_type in problem_types:
            if not isinstance(problem_type, dict):
                continue

            for desc in problem_type.get("descriptions", []):
                if not isinstance(desc, dict):
                    continue

                desc_id = desc.get("cweId") or desc.get("description") or ""
                if isinstance(desc_id, str):
                    match = re.search(r"CWE-(\d+)", desc_id, flags=re.IGNORECASE)
                    if match:
                        cwe_ids.add(match.group(1))

    cna = containers.get("cna")
    if isinstance(cna, dict):
        from_problem_types(cna.get("problemTypes", []))

    adp = containers.get("adp", [])
    if isinstance(adp, list):
        for adp_item in adp:
            if isinstance(adp_item, dict):
                from_problem_types(adp_item.get("problemTypes", []))

    return sorted(cwe_ids, key=lambda x: int(x))


def parse_cwe_page(cwe_id: str) -> Dict[str, str]:
    url = CWE_URL.format(cwe_id)

    try:
        html = fetch_text(url)
    except Exception:
        return {"name": "", "description": ""}

    soup = BeautifulSoup(html, "lxml")

    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    name = ""

    title_match = re.search(
        rf"CWE-{re.escape(cwe_id)}:\s*(.+?)(?:\s*\(|\s*-\s*CWE|\s*$)",
        title
    )
    if title_match:
        name = title_match.group(1).strip()

    description = ""
    page_text = soup.get_text("\n", strip=True)

    desc_match = re.search(
        r"\bDescription\b\s*(.+?)(?:\bExtended Description\b|\bAlternate Terms\b|\bModes Of Introduction\b|\bLikelihood Of Exploit\b)",
        page_text,
        flags=re.DOTALL,
    )
    if desc_match:
        description = " ".join(desc_match.group(1).split())

    return {
        "name": name,
        "description": description,
    }


def extract_dates(cve_record: Dict[str, Any]) -> Dict[str, str]:
    metadata = cve_record.get("cveMetadata", {})
    return {
        "published_date": metadata.get("datePublished", ""),
        "updated_date": metadata.get("dateUpdated", ""),
    }


def build_result_item(
    task1_item: Dict[str, Any],
    cve_record: Dict[str, Any],
    cwe_cache: Dict[str, Dict[str, str]]
) -> Dict[str, Any]:
    containers = cve_record.get("containers", {})
    dates = extract_dates(cve_record)
    cwe_ids = extract_cwe_ids(containers)

    cwe_obj = {}
    for cwe_id in cwe_ids:
        if cwe_id not in cwe_cache:
            cwe_cache[cwe_id] = parse_cwe_page(cwe_id)
            time.sleep(0.05)
        cwe_obj[f"CWE-{cwe_id}"] = cwe_cache[cwe_id]

    return {
        "ID": task1_item["ID"],
        "vendor_release_date": task1_item["vendor_release_date"],
        "vendor_release_url": task1_item["vendor_release_url"],
        "url": CVE_ORG_URL.format(task1_item["ID"]),
        "published_date": dates["published_date"],
        "updated_date": dates["updated_date"],
        "description": get_first_english_description(containers),
        "cvss_list": extract_cvss(containers),
        "cpe_list": extract_cpes(containers),
        "cwe": cwe_obj,
    }


def main():
    task1_data = load_task1()
    result = []
    cwe_cache: Dict[str, Dict[str, str]] = {}

    for idx, item in enumerate(task1_data, start=1):
        cve_id = item["ID"]
        try:
            cve_data = fetch_cve_record(cve_id)
            result.append(build_result_item(item, cve_data, cwe_cache))
            print(f"[{idx}/{len(task1_data)}] OK {cve_id}")
            time.sleep(0.05)
        except Exception as e:
            print(f"[{idx}/{len(task1_data)}] FAIL {cve_id}: {e}")

    save_task2(result)
    print(f"Saved records: {len(result)}")
    print("Output: result_task_2.json")


if __name__ == "__main__":
    main()
