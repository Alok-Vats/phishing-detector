import os
import hashlib
import json
from glob import glob

def compute_hash(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

models_dir = os.path.abspath("models")
trusted = {}
for pkl in glob(os.path.join(models_dir, "*.pkl")):
    basename = os.path.basename(pkl)
    trusted[basename] = compute_hash(pkl)

with open(os.path.join(models_dir, "trusted_hashes.json"), "w") as f:
    json.dump(trusted, f, indent=2)

print("Hashes computed.")
