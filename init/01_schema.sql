CREATE TABLE vendor_releases (
    id SERIAL PRIMARY KEY,
    vendor_release_date DATE NOT NULL,
    vendor_release_url TEXT NOT NULL UNIQUE
);

CREATE TABLE cves (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(32) NOT NULL UNIQUE,
    vendor_release_id INT NOT NULL REFERENCES vendor_releases(id),
    url TEXT NOT NULL,
    published_date TIMESTAMP NULL,
    updated_date TIMESTAMP NULL,
    description TEXT
);

CREATE TABLE cvss_metrics (
    id SERIAL PRIMARY KEY,
    cve_id INT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    version VARCHAR(32),
    score NUMERIC(4,1),
    vector TEXT,
    severity VARCHAR(32)
);

CREATE TABLE cpes (
    id SERIAL PRIMARY KEY,
    cpe_string TEXT NOT NULL UNIQUE
);

CREATE TABLE cve_cpes (
    cve_id INT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    cpe_id INT NOT NULL REFERENCES cpes(id) ON DELETE CASCADE,
    PRIMARY KEY (cve_id, cpe_id)
);

CREATE TABLE cwes (
    id SERIAL PRIMARY KEY,
    cwe_code VARCHAR(32) NOT NULL UNIQUE,
    name TEXT,
    description TEXT
);

CREATE TABLE cve_cwes (
    cve_id INT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    cwe_id INT NOT NULL REFERENCES cwes(id) ON DELETE CASCADE,
    PRIMARY KEY (cve_id, cwe_id)
);
