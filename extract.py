import json
import os

try:
    with open('.aistudio/artifacts/brain/ddf21ed8-bb7e-4da4-9c16-982e231d5034/.system_generated/logs/transcript.jsonl', 'r') as f:
        lines = f.readlines()
        for line in lines:
            data = json.loads(line)
            # Find the message with the original App.tsx
            print(data.keys())
except Exception as e:
    print(e)
