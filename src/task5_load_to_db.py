import json
from datetime import datetime

import psycopg2


DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "lab2_db",
    "user": "lab2_user",
    "password": "lab2_pass",
}


def parse_ts(value: str):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_data(path: str = "result_task_2.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_or_create_vendor_release(cur, vendor_release_date, vendor_release_url):
    cur.execute(
        """
        INSERT INTO vendor_releases (vendor_release_date, vendor_release_url)
        VALUES (%s, %s)
        ON CONFLICT (vendor_release_url) DO UPDATE
        SET vendor_release_date = EXCLUDED.vendor_release_date
        RETURNING id
        """,
        (vendor_release_date, vendor_release_url),
    )
    return cur.fetchone()[0]


def get_or_create_cve(cur, item, vendor_release_id):
    cur.execute(
        """
        INSERT INTO cves (
            cve_id, vendor_release_id, url, published_date, updated_date, description
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (cve_id) DO UPDATE
        SET vendor_release_id = EXCLUDED.vendor_release_id,
            url = EXCLUDED.url,
            published_date = EXCLUDED.published_date,
            updated_date = EXCLUDED.updated_date,
            description = EXCLUDED.description
        RETURNING id
        """,
        (
            item["ID"],
            vendor_release_id,
            item["url"],
            parse_ts(item["published_date"]),
            parse_ts(item["updated_date"]),
            item.get("description", ""),
        ),
    )
    return cur.fetchone()[0]


def insert_cvss(cur, cve_db_id, cvss_list):
    for cvss in cvss_list:
        cur.execute(
            """
            INSERT INTO cvss_metrics (cve_id, version, score, vector, severity)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                cve_db_id,
                cvss.get("version", ""),
                cvss.get("score"),
                cvss.get("vector", ""),
                cvss.get("severity", ""),
            ),
        )


def get_or_create_cpe(cur, cpe_string):
    cur.execute(
        """
        INSERT INTO cpes (cpe_string)
        VALUES (%s)
        ON CONFLICT (cpe_string) DO UPDATE
        SET cpe_string = EXCLUDED.cpe_string
        RETURNING id
        """,
        (cpe_string,),
    )
    return cur.fetchone()[0]


def link_cve_cpe(cur, cve_db_id, cpe_db_id):
    cur.execute(
        """
        INSERT INTO cve_cpes (cve_id, cpe_id)
        VALUES (%s, %s)
        ON CONFLICT DO NOTHING
        """,
        (cve_db_id, cpe_db_id),
    )


def get_or_create_cwe(cur, cwe_code, cwe_data):
    cur.execute(
        """
        INSERT INTO cwes (cwe_code, name, description)
        VALUES (%s, %s, %s)
        ON CONFLICT (cwe_code) DO UPDATE
        SET name = EXCLUDED.name,
            description = EXCLUDED.description
        RETURNING id
        """,
        (
            cwe_code,
            cwe_data.get("name", ""),
            cwe_data.get("description", ""),
        ),
    )
    return cur.fetchone()[0]


def link_cve_cwe(cur, cve_db_id, cwe_db_id):
    cur.execute(
        """
        INSERT INTO cve_cwes (cve_id, cwe_id)
        VALUES (%s, %s)
        ON CONFLICT DO NOTHING
        """,
        (cve_db_id, cwe_db_id),
    )


def main():
    data = load_data()

    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False

    try:
        with conn.cursor() as cur:
            for item in data:
                vendor_release_id = get_or_create_vendor_release(
                    cur,
                    item["vendor_release_date"],
                    item["vendor_release_url"],
                )

                cve_db_id = get_or_create_cve(cur, item, vendor_release_id)

                insert_cvss(cur, cve_db_id, item.get("cvss_list", []))

                for cpe_string in item.get("cpe_list", []):
                    cpe_db_id = get_or_create_cpe(cur, cpe_string)
                    link_cve_cpe(cur, cve_db_id, cpe_db_id)

                for cwe_code, cwe_data in item.get("cwe", {}).items():
                    cwe_db_id = get_or_create_cwe(cur, cwe_code, cwe_data)
                    link_cve_cwe(cur, cve_db_id, cwe_db_id)

        conn.commit()
        print(f"Loaded CVE records: {len(data)}")
    except Exception as e:
        conn.rollback()
        print("Load failed:", e)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
