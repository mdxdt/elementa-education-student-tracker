-- Elementa Education - D1 Database Schema
-- Run this to initialize your D1 database:
-- wrangler d1 execute elementa-db --file=schema.sql

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  subjects TEXT, -- comma-separated
  hourly_rate REAL DEFAULT 0,
  payment_plan TEXT DEFAULT 'per_session', -- per_session, monthly, weekly
  payment_method TEXT DEFAULT 'cash', -- cash, bank_transfer, payid
  bank_details TEXT, -- BSB/account or PayID details
  parent_name TEXT,
  parent_email TEXT,
  parent_phone TEXT,
  notes TEXT,
  active INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS class_slots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  day_of_week TEXT NOT NULL, -- Sunday, Monday, etc.
  start_time TEXT NOT NULL, -- HH:MM
  end_time TEXT NOT NULL,   -- HH:MM
  location TEXT NOT NULL,
  active INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS student_slots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL,
  slot_id INTEGER NOT NULL,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  FOREIGN KEY (slot_id) REFERENCES class_slots(id) ON DELETE CASCADE,
  UNIQUE(student_id, slot_id)
);

CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL,
  slot_id INTEGER,
  date TEXT NOT NULL, -- YYYY-MM-DD
  duration_hours REAL DEFAULT 1,
  subject TEXT,
  status TEXT DEFAULT 'present', -- present, absent, cancelled
  amount_billed REAL DEFAULT 0,
  notes TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  FOREIGN KEY (slot_id) REFERENCES class_slots(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  payment_method TEXT DEFAULT 'cash',
  date TEXT NOT NULL, -- YYYY-MM-DD
  notes TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS marks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL,
  subject TEXT NOT NULL,
  assessment_name TEXT NOT NULL,
  score REAL,
  max_score REAL DEFAULT 100,
  date TEXT NOT NULL, -- YYYY-MM-DD
  notes TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_attendance_student ON attendance(student_id);
CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(date);
CREATE INDEX IF NOT EXISTS idx_payments_student ON payments(student_id);
CREATE INDEX IF NOT EXISTS idx_marks_student ON marks(student_id);
CREATE INDEX IF NOT EXISTS idx_student_slots_student ON student_slots(student_id);
CREATE INDEX IF NOT EXISTS idx_student_slots_slot ON student_slots(slot_id);
