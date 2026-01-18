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

# parse data of interest
for technique in techniques_model:
    #if technique["log_source"] == "Microsoft Defender for Endpoint":
        parsed_techniques = {
            "tactic": technique["tactic"],
            "technique_id": technique["technique_id"],
            "technique_name" : technique["technique"],
            "event_description" : technique["name"],
            "platform": technique["platform"], 
            "table_name_or_eventID": technique["event_id"], 
            "log_source": technique["log_source"],
            "filter": technique["filter_in"]
            }
        parsed_output.append(parsed_techniques)

with open(output_json, "w") as f:
    json.dump(parsed_output, f, indent=2)

df = pd.read_json(output_json)

#df = df.explode(("tactic"))
#df = df.explode(("platform"))
df["tactic"] = df["tactic"].apply(
    lambda x: ", ".join(x)
)

df["platform"] = df["platform"].apply(
    lambda x: ", ".join(x)
)

html = df.to_html(classes="display stripe hover cell-border order-column", table_id="jsonTable", index=False)

# Write HTML page
with open("table.html", "w") as f:
    f.write(f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>MITRE ATT&CK Log Source Lookup</title>
            
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
            
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
            
    <style>
    /* 1. Basic Reset & Font */
    body {{
        margin: 0;
        padding: 0;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        color: #333;
        overflow-x: hidden; /* Prevent horizontal scroll from canvas */
    }}

    /* 2. The Matrix Canvas Background */
    #matrixCanvas {{
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: -1; /* Puts it behind everything */
        background: black;
    }}

    /* 3. Container for the content (centered and readable) */
    .content-wrapper {{
        position: relative;
        z-index: 1; /* Puts it above the canvas */
        width: 90%;
        max-width: 1400px;
        margin: 40px auto;
        background-color: rgba(255, 255, 255, 0.92); /* 92% opaque white so you can read text */
        padding: 30px;
        border-radius: 8px;
        box-shadow: 0 0 20px rgba(0, 255, 0, 0.2); /* Slight green glow */
    }}

    .header-container {{
        text-align: center;
        margin-bottom: 20px;
    }}

    .logo {{
        max-width: 300px;
        display: block;
        margin: 0 auto 10px auto;
    }}

    h1 {{
        color: #2c3e50;
        text-transform: uppercase;
        letter-spacing: 2px;
    }}

    /* Table Styling overrides */
    table.dataTable thead th {{
        background-color: #111; /* Almost black header */
        color: #0f0; /* Matrix Green text */
        border-bottom: 2px solid #0f0;
    }}
    
    /* Input/Select styling */
    tfoot select, tfoot input {{
        width: 100%;
        padding: 6px;
        border: 1px solid #ccc;
        border-radius: 4px;
    }}
    </style>
            
</head>
<body>

<canvas id="matrixCanvas"></canvas>

<div class="content-wrapper">
    <div class="header-container">
        <h1>Log Source Lookup</h1>
    </div>

    {html}
</div>

<script>
// --- MATRIX RAIN EFFECT SCRIPT ---
const canvas = document.getElementById('matrixCanvas');
const ctx = canvas.getContext('2d');

// Set canvas to full screen
function resizeCanvas() {{
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
}}
resizeCanvas();
window.addEventListener('resize', resizeCanvas);

// Matrix characters (Katakana + Numbers)
const chars = 'アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビピウゥクスツヌフムユュルグズブヅプエェケセテネヘメレヱゲゼデベペオォコソトノホモヨョロヲゴゾドボポヴッン0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const charArray = chars.split('');

const fontSize = 16;
const columns = canvas.width / fontSize;

// Array of drops - one per column
const drops = [];
for(let x = 0; x < columns; x++) {{
    drops[x] = 1; 
}}

function drawMatrix() {{
    // Translucent black background to create the fade effect
    ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = '#0F0'; // Green text
    ctx.font = fontSize + 'px monospace';

    for(let i = 0; i < drops.length; i++) {{
        const text = charArray[Math.floor(Math.random() * charArray.length)];
        ctx.fillText(text, i * fontSize, drops[i] * fontSize);

        // Reset drop to top randomly after it has crossed screen
        if(drops[i] * fontSize > canvas.height && Math.random() > 0.975) {{
            drops[i] = 0;
        }}

        drops[i]++;
    }}
}}

// Animate at 30fps
setInterval(drawMatrix, 33);


// --- DATATABLES SCRIPT (EXISTING) ---
$(document).ready(function () {{
    // Setup inputs
    $('#jsonTable tfoot th').each(function () {{
        var title = $(this).text();
        $(this).html('<input type="text" placeholder="Search ' + title + '" />');
    }});

    var table = $('#jsonTable').DataTable({{
        paging: true,
        searching: true,
        ordering: true,
        pageLength: 25,
        autoWidth: false,
        order: [],
        initComplete: function () {{
            var api = this.api();

            api.columns().every(function () {{
                var column = this;
                var footer = $('<th></th>').appendTo(
                    $('#jsonTable tfoot').length
                        ? $('#jsonTable tfoot tr')
                        : $('<tfoot><tr></tr></tfoot>').appendTo('#jsonTable').find('tr')
                );
                
                footer.empty(); 

                var select = $('<select><option value="">All</option></select>')
                    .appendTo(footer)
                    .on('change', function () {{
                        var val = $.fn.dataTable.util.escapeRegex($(this).val());
                        if (val == "") {{
                            column.search("").draw();
                        }}
                        else {{
                            column.search('(^|,)\\\\s*' + val + '\\\\s*(,|$)', true, false).draw();
                        }}
                    }});

                let uniqueValues = new Set();
                column.data().each(function (d) {{
                    if (!d) return;
                    d.split(',').forEach(function (item) {{
                        let cleanItem = item.trim();
                        if (cleanItem) uniqueValues.add(cleanItem);
                    }});
                }});

                Array.from(uniqueValues).sort().forEach(function (val) {{
                    select.append('<option value="' + val + '">' + val + '</option>');
                }});
            }});
        }}
    }});
}});
</script>
</body>
</html>
""")

