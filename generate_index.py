import os
from datetime import datetime

# Try reading the generation time
try:
    with open("generation_time.html", "r") as f:
        content = f.read().strip()
        gen_time = datetime.strptime(content, "%a %b %d %H:%M:%S %Z %Y")
except Exception as e:
    print(f"Error reading generation_time.html: {e}")
    gen_time = datetime.now()

# Collect file entries (excluding some files)
entries = []
for filename in sorted(os.listdir(".")):
    if filename in [".git", ".github", "generate_index.py", "index.html"]:
        continue
    if os.path.isdir(filename):
        continue
    size = os.path.getsize(filename)
    entries.append((filename, size))

# Get max width for filename
max_name_length = max(len(name) for name, _ in entries) if entries else 0

# Build tree lines with proper spacing
tree_lines = []
tree_lines.append(f"[{4096:>12} {gen_time.strftime('%d-%b-%Y %H:%M')}]    .")

for i, (filename, size) in enumerate(entries):
    prefix = "└──" if i == len(entries) - 1 else "├──"
    size_str = f"{size:>12}"
    date_str = gen_time.strftime("%d-%b-%Y %H:%M")
    file_str = f"{filename:<{max_name_length}}"
    line = f"{prefix} [{size_str} {date_str}]    <a href=\"./{filename}\">{file_str}</a>"
    tree_lines.append(line)

tree_output = "<br>\n".join(tree_lines)

# HTML template
html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Index of Files</title>
  <style>
    body {{
      font-family: monospace;
      background: #121212;
      color: #d0d0d0;
      padding: 2rem;
    }}
    a {{
      color: #79b8ff;
      text-decoration: none;
      display: inline-block;
      min-width: {max_name_length}ch;
    }}
    a:hover {{
      text-decoration: underline;
    }}
  </style>
</head>
<body>
  <h1>Index of Files</h1>
  <p>
{tree_output}
  </p>
</body>
</html>
"""

# Write to index.html
with open("index.html", "w") as f:
    f.write(html)
