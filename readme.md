# Signal Trace
**Tactical Log Mapper for Microsoft Defender XDR & Cloud Sources**

## 🎯 Concept & Mission
Signal Trace is designed to cut through the noise of security logging. It produces a clear, human-readable index that maps industry-standard data tables (MDE, Defender XDR, Azure, M365) directly to MITRE ATT&CK techniques, enabling analysts to rapidly identify the correct log sources for specific threats.

## 🚀 Key Objectives
* **Data Source Mapping:** Automatically map Microsoft Defender for Endpoint (MDE) and Defender XDR data tables to specific MITRE ATT&CK techniques.
* **Rapid Identification:** Provide a searchable, filterable index to help analysts quickly identify the tables of interest for a given attack vector.
* **Gap Prioritization (Roadmap):** Implement logic to highlight coverage gaps based on industry verticals (e.g., Finance, Defense, Hospitality), tying specific log gaps to sector-specific threat objectives.
* **Navigator Integration (Roadmap):** Overlay table coverage information directly onto MITRE ATT&CK Navigator layers.

## 📚 Data Sources & Credits
This project leverages the following community-driven data models for its logic:

* **[OTRF / OSSEM-DM](https://github.com/OTRF/OSSEM-DM)** * Used for the heavy lifting of mapping core Techniques to Event Logs.  
  * *Source:* [techniques_to_events_mapping.json](https://raw.githubusercontent.com/OTRF/OSSEM-DM/03404288803c743cd5254f8888d664a5a106ec89/use-cases/mitre_attack/techniques_to_events_mapping.json)

* **[Center for Threat-Informed Defense (CTID)](https://github.com/center-for-threat-informed-defense/mappings-explorer)** * Used for Cloud Source mappings.
  * *Azure:* [azure-04.26.2025_attack-16.1-enterprise.json](https://github.com/center-for-threat-informed-defense/mappings-explorer/blob/main/mappings/azure/attack-16.1/azure-04.26.2025/enterprise/azure-04.26.2025_attack-16.1-enterprise.json)
  * *M365:* [m365-07.18.2025_attack-16.1-enterprise.json](https://github.com/center-for-threat-informed-defense/mappings-explorer/blob/main/mappings/m365/attack-16.1/m365-07.18.2025/enterprise/m365-07.18.2025_attack-16.1-enterprise.json)

## 🛠️ Related Tools & References
* **[Sensor Mappings to ATT&CK (SMAP) Overview](https://center-for-threat-informed-defense.github.io/sensor-mappings-to-attack/overview/)**
* **[CTID Heatmap Creation Tool](https://github.com/center-for-threat-informed-defense/sensor-mappings-to-attack/blob/main/src/util/create_heatmaps.py)**

---
*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.*
