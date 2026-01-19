import argparse
import json
import pandas as pd
import html as html_lib

# Add command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-p", "--Platform", help = "Use -p or --Platform to supply the platform (Windows, Linux, MacOS)")
args = parser.parse_args()

# Variables
parsed_techniques = {}
parsed_output = []
output_json = "output/attack_tables.json"

# Load attack techniques model
techniques_model_path = "source/techniques_to_events_mapping.json"
with open(techniques_model_path, "r") as f:
    techniques_model = json.load(f)

# Parse data of interest
for technique in techniques_model:
    parsed_techniques = {
        "tactic": technique["tactic"],
        "technique_id": technique["technique_id"],
        "technique_name" : technique["technique"],
        "event_description" : technique["name"],
        "platform": technique["platform"], 
        "table_or_event_id": technique["event_id"], # <--- RENAMED
        "log_source": technique["log_source"],
        "table_filter": technique["filter_in"]
    }
    parsed_output.append(parsed_techniques)

with open(output_json, "w") as f:
    json.dump(parsed_output, f, indent=2)

# --- DATAFRAME PROCESSING ---
df = pd.read_json(output_json)

# 1. Clean up Lists
df["tactic"] = df["tactic"].apply(lambda x: ", ".join(x) if isinstance(x, list) else x)
df["platform"] = df["platform"].apply(lambda x: ", ".join(x) if isinstance(x, list) else x)

# 2. Format the Filter Column
def format_filter_data(cell_data):
    if not cell_data: return ""
    if isinstance(cell_data, list):
        items = []
        for entry in cell_data:
            if isinstance(entry, dict):
                dict_str = ", ".join([f"{key}: {value}" for key, value in entry.items()])
                items.append(dict_str)
            else:
                items.append(str(entry))
        return "; ".join(items)
    return str(cell_data)

df["table_filter"] = df["table_filter"].apply(format_filter_data)

# 3. Create the "Copy KQL" Button
def create_copy_button(row):
    # Updated to look for the new column name
    t_name = str(row['table_or_event_id']) 
    raw_filter = row['table_filter']
    
    # Check for empty filter
    if not raw_filter or raw_filter.lower() == 'nan' or raw_filter.strip() == "":
        return ('<button class="copy-btn disabled-btn" disabled>'
                '<i class="fa-solid fa-ban"></i> No Filter</button>')
    
    # Active Button
    safe_name = t_name.replace("'", "\\'")
    safe_filter = str(raw_filter).replace("'", "\\'")
    
    return (f'<button class="copy-btn active-btn" onclick="generateKQL(this, \'{safe_name}\', \'{safe_filter}\')">'
            f'<i class="fa-solid fa-terminal"></i> Copy KQL</button>')

df['Query'] = df.apply(create_copy_button, axis=1)

# 4. Sanitize other columns AND Add Tooltip
# We wrap the content in a <span> or just modify the string so DataTables renders it.
# However, pandas 'to_html' is rigid. The best way to add a tooltip to the TD is via JS later,
# OR we can wrap the inner text in a span with a title attribute now.
for col in df.columns:
    if col != 'Query':
        def add_tooltip(x):
            if not x: return ""
            safe_text = html_lib.escape(str(x))
            # Wrap text in a span that has a title attribute equal to the full text
            return f'<span title="{safe_text}">{safe_text}</span>'
        
        df[col] = df[col].apply(add_tooltip)

# 5. Generate HTML Table
# Note: We must use escape=False now because we added <span> tags to every cell
html = df.to_html(
    classes="display stripe hover cell-border order-column", 
    table_id="jsonTable", 
    index=False,
    escape=False 
)

# --- WRITE FINAL HTML FILE ---
with open("table.html", "w") as f:
    f.write(f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Signal Trace</title>
            
    <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
            
    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
            
    <style>
    /* 1. Basic Page Styling */
    body {{
        margin: 0;
        padding: 0;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background-color: #f4f6f9;
        color: #333;
    }}

    /* 2. Main Container */
    .content-wrapper {{
        width: 98%;
        margin: 20px auto;
        background-color: #ffffff;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        box-sizing: border-box;
    }}

    .header-container {{
        text-align: center;
        margin-bottom: 20px;
        border-bottom: 2px solid #ecf0f1;
        padding-bottom: 20px;
    }}

    .header-icon {{
        font-size: 3rem;
        color: #e74c3c;
        margin-bottom: 10px;
    }}

    h1 {{
        color: #2c3e50;
        font-size: 1.8rem;
        margin: 0;
    }}
    
    .subtitle {{
        color: #7f8c8d;
        font-size: 0.9rem;
        margin-top: 5px;
    }}

    /* 3. DataTables Styling */
    table.dataTable {{
        width: 100% !important;
    }}

    table.dataTable thead th {{
        background-color: #2c3e50;
        color: white;
        font-weight: 600;
        padding: 12px;
        white-space: nowrap; 
    }}
    
    table.dataTable tbody tr:hover {{
        background-color: #f1f1f1 !important;
    }}
    
    td {{
        vertical-align: middle !important;
        white-space: nowrap; 
        overflow: hidden;
        text-overflow: ellipsis;
        max-width: 400px;
        cursor: default;
    }}

    td:nth-child(4), td:nth-child(8) {{
        white-space: normal;
        word-wrap: break-word;
        min-width: 300px;
        max-width: 600px;
    }}

    /* 4. BUTTON STYLES */
    .copy-btn {{
        min-width: 110px;
        justify-content: center;
        padding: 6px 10px;
        border-radius: 4px;
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 0.8em;
        white-space: nowrap;
        display: inline-flex;
        align-items: center;
        gap: 6px;
        transition: all 0.2s ease;
    }}

    .active-btn {{
        background-color: #2d3436;
        color: #00b894;
        border: 1px solid #00b894;
        cursor: pointer;
    }}

    .active-btn:hover {{
        background-color: #00b894;
        color: #2d3436;
    }}

    .active-btn.copied {{
        background-color: #0984e3;
        color: white;
        border-color: #0984e3;
    }}

    .disabled-btn {{
        background-color: #dfe6e9;
        color: #b2bec3;
        border: 1px solid #d6d6d6;
        cursor: not-allowed;
        opacity: 0.7;
    }}
    
    tfoot select {{
        width: 100%;
        padding: 6px;
        border: 1px solid #dfe6e9;
        border-radius: 4px;
        background-color: #fdfdfd;
        box-sizing: border-box; 
    }}

    /* 5. NEW: TERMINAL CREDIT STYLING */
    .console-credit {{
        text-align: center;
        margin-top: 40px;
        font-family: 'Consolas', 'Monaco', monospace;
        background-color: #2d3436;
        color: #dfe6e9;
        padding: 12px 20px;
        border-radius: 6px;
        font-size: 0.9em;
        /* Center the box */
        display: table; 
        margin-left: auto;
        margin-right: auto;
        box-shadow: 0 4px 6px rgba(0,0,0,0.2);
    }}
    
    .prompt {{
        color: #00b894; /* Hacker Green */
        margin-right: 10px;
    }}

    .user-link {{
        color: #e74c3c; /* Red highlight */
        font-weight: bold;
        text-decoration: none;
        border-bottom: 1px dashed #e74c3c; /* Techy dashed underline */
        transition: all 0.3s;
    }}

    .user-link:hover {{
        color: #ffffff;
        border-bottom-style: solid;
        border-bottom-color: #ffffff;
        text-shadow: 0 0 8px rgba(255, 255, 255, 0.5);
    }}

    .legal-footer {{
        margin-top: 20px;
        text-align: center;
        font-size: 0.75rem;
        color: #95a5a6;
        border-top: 1px solid #eee;
        padding-top: 15px;
    }}
    </style>
            
</head>
<body>

<div class="content-wrapper">
    <div class="header-container">
        <div class="header-icon"><i class="fa-solid fa-shield-halved"></i></div>
        <h1>Signal Trace</h1>
        <div class="subtitle">Tactical Log Mapper for MITRE ATT&CK®</div>
    </div>

    {html}

    <div class="console-credit">
        <span class="prompt">root@soc:~$</span> echo "Created by <a href="https://www.linkedin.com/in/anthonyndutra/" target="_blank" class="user-link">Anthony Dutra</a>"
    </div>

    <div class="legal-footer">
        <p>© 2024 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.</p>
        <p>Comparison data provided by the OSSEM Project.</p>
    </div>
</div>

<script>
// --- KQL LOGIC ---
function generateKQL(btnElement, tableName, filterString) {{
    let query = tableName;
    if (filterString && filterString.trim() !== "") {{
        let conditions = [];
        if (filterString !== "None" && filterString !== "nan") {{
            let filters = filterString.split(';');
            filters.forEach(function(f) {{
                let parts = f.split(':');
                if (parts.length >= 2) {{
                    let key = parts[0].trim();
                    let value = parts.slice(1).join(':').trim();
                    conditions.push(key + " == '" + value + "'");
                }}
            }});
        }}
        
        if (conditions.length > 0) {{
            query += " | where " + conditions.join(" and ");
        }}
    }}

    navigator.clipboard.writeText(query).then(function() {{
        let originalHTML = btnElement.innerHTML;
        btnElement.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
        btnElement.classList.add('copied');
        setTimeout(function() {{
            btnElement.innerHTML = originalHTML;
            btnElement.classList.remove('copied');
        }}, 2000);
    }}, function(err) {{
        console.error('Copy failed: ', err);
    }});
}}

// --- DATATABLES CONFIGURATION ---
$(document).ready(function () {{
    var tableElement = $('#jsonTable');
    var tfoot = $('<tfoot></tfoot>');
    var headerRow = tableElement.find('thead tr').clone();
    
    headerRow.find('th').empty();
    tfoot.append(headerRow);
    tableElement.append(tfoot);

    var table = tableElement.DataTable({{
        paging: true,
        searching: true,
        ordering: true,
        pageLength: 25,
        autoWidth: false,
        scrollX: true, 
        order: [],
        initComplete: function () {{
            this.api().columns().every(function () {{
                var column = this;
                var headerText = $(column.header()).text().trim();

                if (headerText === "Query") return;

                var footerCell = $(column.footer());
                footerCell.empty(); 

                var select = $('<select><option value="">All</option></select>')
                    .appendTo(footerCell)
                    .on('change', function () {{
                        const rawInput = $(this).val();
                        const escapedTerm = $.fn.dataTable.util.escapeRegex(rawInput);
                        
                        if (rawInput === "") {{
                            column.search("").draw();
                        }}
                        else {{
                            column.search('(^|,)\\\\s*' + escapedTerm + '\\\\s*(,|$)', true, false).draw();
                        }}
                    }});

                let uniqueValues = new Set();
                column.data().each(function (d) {{
                    if (!d) return;
                    if (d.includes('<button')) return; 
                    
                    var tempDiv = document.createElement("div");
                    tempDiv.innerHTML = d;
                    var decoded = tempDiv.textContent || tempDiv.innerText || "";

                    decoded.split(',').forEach(function (item) {{
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