import argparse
import json
import pandas as pd

# Add command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-p", "--Platform", help = "Use -p or --Platform to supply the platform (Windows, Linux, MacOS)")
args = parser.parse_args()

# Variables
parsed_techniques = {}
parsed_output = []
output_json = "output/attack_tables.json"

# Load attack techniques model (https://github.com/OTRF/OSSEM-DM/blob/main/use-cases/mitre_attack/techniques_to_events_mapping.json)
techniques_model_path = "source/techniques_to_events_mapping.json"
with open(techniques_model_path, "r") as f:
    techniques_model = json.load(f)

#print(json.dumps(techniques_model, indent = 2))
#print out data of interest (technique_id, technique, tactic[], platform[], event_id = table)
for technique in techniques_model:
    if technique["log_source"] == "Microsoft Defender for Endpoint":
        parsed_techniques = {
            "tactic": technique["tactic"],
            "technique_id": technique["technique_id"],
            "technique_name" : technique["technique"],
            "event_description" : technique["name"],
            "platform": technique["platform"], 
            "table_name": technique["event_id"], 
            "log_source": technique["log_source"],
            "table_filter": technique["filter_in"]
            }
        #print(parsed_techniques)
        parsed_output.append(parsed_techniques)
#print(parsed_output)
    #if args.Platform:
    
#print(json.dumps(parsed_output, indent=2))
with open(output_json, "w") as f:
    json.dump(parsed_output, f, indent=2)

df = pd.read_json(output_json)

df = df.explode(("tactic"))
df = df.explode(("platform"))

html = df.to_html(classes="display", table_id="jsonTable", index=False)    

# Write HTML page
with open("table.html", "w") as f:
    f.write(f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>MITRE ATT&CK Log Source Lookup</title>
            
    <!-- DataTables CSS --> 
    <link rel="stylesheet"
    href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
            
    <!-- jQuery + DataTables -->
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
            
    <style>
    h1 {{
        text-align: center;
    }}
            
    tfoot select {{
        width: 100%;
        padding: 4px;
    }}
    </style>
            
</head>
<body>

<h1>MITRE ATT&CK Log Source Lookup</h1>            

{html}

<script>
$(document).ready(function () {{
    var table = $('#jsonTable').DataTable({{
        paging: true,
        searching: true,
        ordering: true,
        pageLength: 25,
        order: [],
        initComplete: function () {{
            var api = this.api();

            // Create a dropdown filter for each column
            api.columns().every(function () {{
                var column = this;
                var footer = $('<th></th>').appendTo(
                    $('#jsonTable tfoot').length
                        ? $('#jsonTable tfoot tr')
                        : $('<tfoot><tr></tr></tfoot>').appendTo('#jsonTable').find('tr')
                );

                var select = $('<select><option value="">All</option></select>')
                    .appendTo(footer)
                    .on('change', function () {{
                        var val = $.fn.dataTable.util.escapeRegex($(this).val());
                        column
                            .search(val ? '^' + val + '$' : '', true, false)
                            .draw();
                    }});

                column.data().unique().sort().each(function (d) {{
                    select.append('<option value="' + d + '">' + d + '</option>');
                }});
            }});
        }}
    }});
}});
</script>
</body>
</html>
""")

