import os
import sys

# Ensure the root of the project is in the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app

# Vercel sets FLASK_ENV or similar, we can explicitly set production
app = create_app('production')

# Optional: Add a simple health endpoint check directly if needed,
# but our app might already have one.
# temporaryly commenting this out to check vercel deployment issue
#@app.route('/health')
#def health_check():
#    return {"status": "ok", "environment": "production"}, 200

# Serverless execution point for Vercel
# Vercel automatically looks for `app` in `api/index.py`.
