-- ============================================================
-- SUPABASE SQL SCHEMA FOR PHISHING DETECTION PROJECT
-- Run this in Supabase SQL Editor (Dashboard > SQL Editor > New Query)
-- ============================================================

-- 1️⃣ USERS TABLE
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    fullname TEXT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2️⃣ HISTORY TABLE
CREATE TABLE IF NOT EXISTS history (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    url TEXT NOT NULL,
    prediction TEXT,
    confidence REAL,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 3️⃣ INSERT DEFAULT ADMIN USER
-- Password: admin123 (hashed with werkzeug scrypt)
-- ⚠️ You should change this password after first login!
-- For now, register a new admin via signup, then manually update role in Supabase.
-- Or insert one here (you'll need to generate the hash from Python):

-- Example: INSERT INTO users (fullname, username, password, role, status)
-- VALUES ('Admin', 'admin', '<paste_hashed_password_here>', 'admin', 'active');

-- 4️⃣ CREATE INDEXES FOR PERFORMANCE
CREATE INDEX IF NOT EXISTS idx_history_username ON history(username);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
