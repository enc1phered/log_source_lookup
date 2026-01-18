# Script to extract all Defender related log sources for all MITRE data components
import json

parsed_data_components = {}
parsed_output = []

with open("./data_components.json", "r") as f:
    data_components = json.load(f)

for component in data_components:
    if "x_mitre_log_sources" in component:
        for log_source in component["x_mitre_log_sources"]:
            if "defender" in (log_source["name"]).lower():
                parsed_data_components = {
                "id": component["id"],
                "dc_name": component["name"],
                "log_source_name": log_source["name"]
                }
                parsed_output.append(parsed_data_components)

print(json.dumps(parsed_output, indent=2))