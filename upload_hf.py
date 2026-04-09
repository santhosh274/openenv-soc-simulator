#!/usr/bin/env python3
"""
Upload script using upload_large_folder with smaller batches.
"""

import os
import sys
from pathlib import Path

os.environ['PYTHONIOENCODING'] = 'utf-8'
os.environ['REQUESTS_CA_BUNDLE'] = r'C:\Users\santh\AppData\Roaming\Python\Python313\site-packages\certifi\cacert.pem'
os.environ['CURL_CA_BUNDLE'] = r'C:\Users\santh\AppData\Roaming\Python\Python313\site-packages\certifi\cacert.pem'

from huggingface_hub import HfApi

# Use the user's token from environment variable
token = os.getenv('HF_TOKEN')
if not token:
    print("Error: HF_TOKEN environment variable not set")
    sys.exit(1)

api = HfApi(token=token)
repo_id = "samxpwn/security-incident-soc"  # Your username

ignore_patterns = {'__pycache__', '.git', 'venv', '.venv', 'push_env.py', 'upload_hf.py', 
                   'output.txt', '.dockerignore', '.gitignore', 'uv.lock', 'security_incident_soc.egg-info'}

def get_files_to_upload(root_dir):
    files = []
    for root, dirs, filenames in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in ignore_patterns]
        for f in filenames:
            if f.startswith('.') or f.endswith('.pyc') or f in ignore_patterns:
                continue
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, root_dir)
            files.append((rel_path, full_path))
    return files

print(f"Creating/verifying Space: {repo_id}...")

try:
    api.create_repo(
        repo_id=repo_id,
        repo_type="space",
        space_sdk="docker",
        exist_ok=True
    )
    print("Space created/verified")
    
    files = get_files_to_upload(".")
    print(f"Found {len(files)} files to upload")
    
    batch_size = 10
    for i in range(0, len(files), batch_size):
        batch = files[i:i+batch_size]
        print(f"Uploading batch {i//batch_size + 1}/{(len(files)-1)//batch_size + 1} ({len(batch)} files)...")
        
        for rel_path, full_path in batch:
            try:
                api.upload_file(
                    path_or_fileobj=full_path,
                    path_in_repo=rel_path,
                    repo_id=repo_id,
                    repo_type="space",
                    commit_message=f"Upload {rel_path}"
                )
            except Exception as e:
                print(f"  Error: {rel_path} - {e}")
    
    print(f"Success! https://huggingface.co/spaces/{repo_id}")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)