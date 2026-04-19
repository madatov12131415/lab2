import json
import xml.etree.ElementTree as ET
from xml.dom import minidom


def load_task2(path: str = "result_task_2.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def prettify_xml(element: ET.Element) -> str:
    rough_string = ET.tostring(element, encoding="utf-8")
    parsed = minidom.parseString(rough_string)
    return parsed.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")


def build_xml(data):
    root = ET.Element("items")

    for item in data:
        item_el = ET.SubElement(root, "item")

        ET.SubElement(item_el, "ID").text = str(item.get("ID", ""))
        ET.SubElement(item_el, "vendor_release_date").text = str(item.get("vendor_release_date", ""))
        ET.SubElement(item_el, "vendor_release_url").text = str(item.get("vendor_release_url", ""))
        ET.SubElement(item_el, "url").text = str(item.get("url", ""))
        ET.SubElement(item_el, "published_date").text = str(item.get("published_date", ""))
        ET.SubElement(item_el, "updated_date").text = str(item.get("updated_date", ""))
        ET.SubElement(item_el, "description").text = str(item.get("description", ""))

        cvss_list_el = ET.SubElement(item_el, "cvss_list")
        for cvss in item.get("cvss_list", []):
            cvss_el = ET.SubElement(cvss_list_el, "cvss")
            cvss_el.set("version", str(cvss.get("version", "")))
            cvss_el.set("score", str(cvss.get("score", "")))
            cvss_el.set("severity", str(cvss.get("severity", "")))
            cvss_el.text = str(cvss.get("vector", ""))

        cpe_list_el = ET.SubElement(item_el, "cpe_list")
        for cpe in item.get("cpe_list", []):
            cpe_el = ET.SubElement(cpe_list_el, "cpe")
            cpe_el.text = str(cpe)

        cwe_list_el = ET.SubElement(item_el, "cwe_list")
        cwe_dict = item.get("cwe", {})
        for cwe_id, cwe_data in cwe_dict.items():
            cwe_el = ET.SubElement(cwe_list_el, "cwe")
            cwe_el.set("id", str(cwe_id))
            cwe_el.set("name", str(cwe_data.get("name", "")))
            cwe_el.text = str(cwe_data.get("description", ""))

    return root


def main():
    data = load_task2()
    root = build_xml(data)
    xml_string = prettify_xml(root)

    with open("result_task_3.xml", "w", encoding="utf-8") as f:
        f.write(xml_string)

    print(f"Saved records: {len(data)}")
    print("Output: result_task_3.xml")


if __name__ == "__main__":
    main()
