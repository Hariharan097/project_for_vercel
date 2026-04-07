import pickle
import numpy as np
import os
import math

from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from feature_extraction import extract_features
from supabase import create_client, Client

# ---------------- APP CONFIG ----------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "super_secret_key_change_later")

# ---------------- SUPABASE CONFIG ----------------
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")  # Use the "service_role" key for full access

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("❌ Missing SUPABASE_URL or SUPABASE_KEY environment variables!")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------------- LOAD ML MODEL ----------------
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model", "phishing_model.pkl")
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# ============================================================
#                    AUTH ROUTES
# ============================================================

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        fullname = request.form["fullname"]
        username = request.form["username"]
        password = request.form["password"]

        hashed_pw = generate_password_hash(password)

        try:
            # Check if username already exists
            existing = supabase.table("users").select("id").eq("username", username).execute()
            if existing.data:
                return render_template("signup.html", error="Username already exists")

            # Insert new user
            supabase.table("users").insert({
                "fullname": fullname,
                "username": username,
                "password": hashed_pw,
                "role": "user",
                "status": "pending"
            }).execute()

            return redirect(url_for("login"))
        except Exception as e:
            return render_template("signup.html", error=f"Signup failed: {str(e)}")

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Fetch user from Supabase
        result = supabase.table("users").select("*").eq("username", username).execute()

        if not result.data:
            return render_template("login.html", error="Invalid username or password")

        user = result.data[0]

        # Check password
        if not check_password_hash(user["password"], password):
            return render_template("login.html", error="Invalid username or password")

        # Check status
        role = user["role"]
        status = user["status"]

        if status == "pending":
            return render_template("login.html", error="Waiting for admin approval")

        if status == "blocked":
            return render_template("login.html", error="Your account is blocked by admin")

        # Set session
        session["user"] = username
        session["role"] = role

        if role == "admin":
            return redirect(url_for("admin_dashboard"))
        else:
            return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("role", None)
    return redirect(url_for("login"))

# ============================================================
#                    PROTECTED HOME
# ============================================================

@app.route("/")
def home():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("index.html", user=session["user"])

# ============================================================
#                    PREDICTION
# ============================================================

@app.route("/predict", methods=["POST"])
def predict():
    if "user" not in session:
        return redirect(url_for("login"))

    try:
        url = request.form.get("url", "").strip()
        if not url:
            return render_template("index.html", error="Please enter a URL.", user=session["user"])

        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url

        features = extract_features(url)
        features_arr = np.array(features).reshape(1, -1)

        pred = model.predict(features_arr)[0]
        prob = model.predict_proba(features_arr)[0] if hasattr(model, "predict_proba") else None

        label_text = "Phishing Website — DO NOT TRUST" if pred == 1 else "Legitimate / Safe Website"

        confidence = None
        if prob is not None:
            confidence = round(float(prob[pred]) * 100, 2)

        # Save to Supabase history
        supabase.table("history").insert({
            "username": session["user"],
            "url": url,
            "prediction": label_text,
            "confidence": confidence
        }).execute()

        return render_template(
            "result.html",
            url=url,
            prediction=label_text,
            confidence=confidence,
            user=session["user"]
        )

    except Exception as e:
        return render_template("index.html", error=str(e), user=session["user"])

# ============================================================
#                    HISTORY PAGE
# ============================================================

@app.route('/history')
def history():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']
    page = request.args.get('page', 1, type=int)
    per_page = 5
    offset = (page - 1) * per_page

    # Get total count
    count_result = supabase.table("history").select("id", count="exact").eq("username", user).execute()
    total_records = count_result.count

    # Get paginated records
    result = supabase.table("history") \
        .select("url, prediction, confidence, timestamp") \
        .eq("username", user) \
        .order("timestamp", desc=True) \
        .range(offset, offset + per_page - 1) \
        .execute()

    # Convert to tuple format for template compatibility
    records = [(r["url"], r["prediction"], r["confidence"], r["timestamp"]) for r in result.data]

    total_pages = math.ceil(total_records / per_page) if total_records else 0

    return render_template(
        'history.html',
        records=records,
        user=user,
        page=page,
        total_pages=total_pages
    )

# ============================================================
#                    ADMIN ROUTES
# ============================================================

def admin_required():
    return ("role" in session) and (session["role"] == "admin")


@app.route("/admin")
def admin_dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    if not admin_required():
        return redirect(url_for("home"))

    # Fetch users
    users_result = supabase.table("users") \
        .select("id, fullname, username, role, status") \
        .order("id", desc=True) \
        .execute()
    # Convert to tuple format for template compatibility
    users = [(u["id"], u["fullname"], u["username"], u["role"], u["status"]) for u in users_result.data]

    # Fetch all history
    history_result = supabase.table("history") \
        .select("username, url, prediction, confidence, timestamp") \
        .order("timestamp", desc=True) \
        .execute()
    history = [(h["username"], h["url"], h["prediction"], h["confidence"], h["timestamp"]) for h in history_result.data]

    # Stats
    total_users = len(users_result.data)

    count_checks = supabase.table("history").select("id", count="exact").execute()
    total_checks = count_checks.count

    count_phishing = supabase.table("history") \
        .select("id", count="exact") \
        .like("prediction", "Phishing%") \
        .execute()
    phishing_count = count_phishing.count

    return render_template(
        "admin.html",
        users=users,
        history=history,
        total_users=total_users,
        total_checks=total_checks,
        phishing_count=phishing_count,
        user=session["user"]
    )


@app.route("/admin/approve/<int:user_id>")
def approve_user(user_id):
    if not admin_required():
        return redirect(url_for("home"))

    supabase.table("users").update({"status": "active"}).eq("id", user_id).execute()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/toggle_block/<int:user_id>")
def toggle_block(user_id):
    if not admin_required():
        return redirect(url_for("home"))

    result = supabase.table("users").select("status").eq("id", user_id).execute()
    if result.data:
        current_status = result.data[0]["status"]
        new_status = "blocked" if current_status != "blocked" else "active"
        supabase.table("users").update({"status": new_status}).eq("id", user_id).execute()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/toggle_role/<int:user_id>")
def toggle_role(user_id):
    if not admin_required():
        return redirect(url_for("home"))

    result = supabase.table("users").select("role").eq("id", user_id).execute()
    if result.data:
        current_role = result.data[0]["role"]
        new_role = "admin" if current_role == "user" else "user"
        supabase.table("users").update({"role": new_role}).eq("id", user_id).execute()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users")
def manage_users():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    result = supabase.table("users").select("id, fullname, username, role, status").execute()
    users = [(u["id"], u["fullname"], u["username"], u["role"], u["status"]) for u in result.data]

    return render_template("Manage_Users.html", users=users, user=session["user"])


@app.route("/admin/history")
def view_history():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    page = request.args.get("page", 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    count_result = supabase.table("history").select("id", count="exact").execute()
    total_records = count_result.count

    result = supabase.table("history") \
        .select("username, url, prediction, confidence, timestamp") \
        .order("timestamp", desc=True) \
        .range(offset, offset + per_page - 1) \
        .execute()

    history = [(h["username"], h["url"], h["prediction"], h["confidence"], h["timestamp"]) for h in result.data]

    total_pages = math.ceil(total_records / per_page) if total_records else 0

    return render_template(
        "view_history.html",
        history=history,
        user=session["user"],
        page=page,
        total_pages=total_pages
    )


@app.route("/charts")
def charts():
    if "user" not in session:
        return redirect(url_for("login"))

    count_phishing = supabase.table("history") \
        .select("id", count="exact") \
        .like("prediction", "Phishing%") \
        .execute()
    phishing_count = count_phishing.count

    count_safe = supabase.table("history") \
        .select("id", count="exact") \
        .like("prediction", "Legitimate%") \
        .execute()
    safe_count = count_safe.count

    return render_template(
        "charts.html",
        phishing_count=phishing_count,
        safe_count=safe_count,
        user=session["user"]
    )


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
