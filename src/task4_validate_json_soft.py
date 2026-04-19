import json
from jsonschema import validate, ValidationError


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    data = load_json("result_task_2.json")
    schema = load_json("src/json_schema_soft.json")

    try:
        validate(instance=data, schema=schema)
        print("Validation passed")
    except ValidationError as e:
        print("Validation failed")
        print("Message:", e.message)
        print("Path:", list(e.absolute_path))


if __name__ == "__main__":
    main()
