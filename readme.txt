## Concept
  *Produce mapping of MDE/DefenderXDR data sources (tables) to MITRE techniques
  *Produce human readible index to enable rapid identification of tables of interest
  *Produce logic to, based on industry, prioritize coverage gaps by accentuating the cells (I.E tying gaps to threat objectives for finance/defense/hospitality/etc)
  *Leverage OSSEM-DM for heavy lifting: 
    *https://raw.githubusercontent.com/OTRF/OSSEM-DM/03404288803c743cd5254f8888d664a5a106ec89/use-cases/mitre_attack/techniques_to_events_mapping.json
  *Leverage CTID mappings for Cloud Sources: 
    *Including Azure:
      *https://github.com/center-for-threat-informed-defense/mappings-explorer/blob/main/mappings/azure/attack-16.1/azure-04.26.2025/enterprise/azure-04.26.2025_attack-16.1-enterprise.json
    *And M365:
      *https://github.com/center-for-threat-informed-defense/mappings-explorer/blob/main/mappings/m365/attack-16.1/m365-07.18.2025/enterprise/m365-07.18.2025_attack-16.1-enterprise.json
  *Overlay table information atop attack navigator layer

## Potentially helpful tools:
  *https://github.com/center-for-threat-informed-defense/sensor-mappings-to-attack/blob/main/src/util/create_heatmaps.py
  *ATT&CKv13.1 SMAP:
    *https://center-for-threat-informed-defense.github.io/sensor-mappings-to-attack/overview/