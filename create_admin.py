"""
Run this script ONCE after setting up Supabase to create your admin account.
Usage: python create_admin.py

Make sure your environment variables are set:
  export SUPABASE_URL=https://your-project.supabase.co
  export SUPABASE_KEY=your-service-role-key
"""

import os
from werkzeug.security import generate_password_hash
from supabase import create_client

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("❌ Set SUPABASE_URL and SUPABASE_KEY environment variables first!")
    exit(1)

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- Customize your admin credentials ---
ADMIN_FULLNAME = "Admin"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"  # ⚠️ CHANGE THIS!

hashed = generate_password_hash(ADMIN_PASSWORD)

try:
    result = supabase.table("users").insert({
        "fullname": ADMIN_FULLNAME,
        "username": ADMIN_USERNAME,
        "password": hashed,
        "role": "admin",
        "status": "active"
    }).execute()
    print(f"✅ Admin user '{ADMIN_USERNAME}' created successfully!")
except Exception as e:
    print(f"❌ Error: {e}")
