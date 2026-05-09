import sys
import re

def fix_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Fix trailing commas
    content = re.sub(r',\s*([\]}])', r'\1', content)
    
    # Fix improperly escaped quotes (two backslashes and a quote) which breaks outer JSON
    # We replace \\" with \"
    content = content.replace(r'\\"', r'\"')

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

if __name__ == "__main__":
    fix_json(sys.argv[1])
