import re
import sys

def sanitize_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Regex to remove trailing commas before } or ]
    content = re.sub(r',\s*([\]}])', r'\1', content)

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        sanitize_json(sys.argv[1])
    else:
        print("Usage: python fix_json.py <file>")
