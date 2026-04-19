Lab 2 — CVE Data Processing Pipeline

Описание проекта

В лабораторной работе реализован конвейер обработки данных об уязвимостях Oracle Java JDK: сбор CVE из Oracle CPU, обогащение данными из открытых источников, преобразование JSON в XML, валидация структуры через JSON Schema и загрузка результатов в PostgreSQL.

Используемые технологии

Python 3, requests, BeautifulSoup, jsonschema, psycopg2-binary, PostgreSQL, Docker Compose.

Структура проекта

lab2/
├── docker-compose.yml
├── requirements.txt
├── init/
│   └── 01_schema.sql
└── src/
    ├── task1_oracle_java.py
    ├── task2_enrich_mitre.py
    ├── task3_json_to_xml.py
    ├── task4_validate_json.py
    ├── json_schema.json
    └── task5_load_to_db.py

Установка

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

Выполнение заданий

1. Получение списка CVE

python src/task1_oracle_java.py

Результат: result_task_1.json

2. Обогащение данных

python src/task2_enrich_mitre.py

Результат: result_task_2.json

3. Конвертация JSON → XML

python src/task3_json_to_xml.py

Результат: result_task_3.xml

4. Валидация JSON Schema

python src/task4_validate_json.py

Ожидаемый результат:

Validation passed

5. PostgreSQL + Docker

Запуск контейнера:

docker compose up -d

Загрузка данных:

python src/task5_load_to_db.py

Проверка:

SELECT COUNT(*) FROM cves;
SELECT COUNT(*) FROM cwes;
SELECT COUNT(*) FROM cvss_metrics;

Структура базы данных

Используются таблицы:
	•	vendor_releases
	•	cves
	•	cvss_metrics
	•	cpes
	•	cve_cpes
	•	cwes
	•	cve_cwes
