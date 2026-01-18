from attackcti import attack_client
import json

lift = attack_client()

data_components = lift.get_data_components()

with open("./data_components.json", "w") as f:
    json.dump(data_components, f, indent=2)