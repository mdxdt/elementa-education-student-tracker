# Elementa Education — Tutoring Management System

A full-stack tutoring centre management app built on **Cloudflare Workers + D1**.

## Features

- 🔐 **Password Protection** — PBKDF2 (200k iterations) + random salt, HMAC-signed tokens
- 👩‍🎓 **Student Database** — name, phone, email, subjects, rate, payment method, parent info, notes
- 📅 **Class Schedule** — recurring weekly slots with location & student assignments
- ✅ **Mark Attendance** — bulk mark sessions by day/slot, auto-calculates billing
- 📋 **Session Log** — full history with filters, export to CSV
- 📊 **Marks Tracker** — record assessment scores with percentage + visual bar
- 💳 **Payments** — track balances (billed vs paid), record cash/bank/PayID payments
- 📈 **Dashboard** — revenue chart, overdue students, monthly summary
- 📱 **Responsive** — works on phone (vertical), iPad, laptop
- 🔄 **Batch API** — bulk import students, attendance, payments, marks via JSON

---

## Quick Start

### 1. Install Wrangler
```bash
npm install
```

### 2. Create the D1 database
```bash
npx wrangler d1 create elementa-db
```
Copy the `database_id` from the output and paste it into `wrangler.toml`.

### 3. Initialize the schema
```bash
# Local dev
npm run db:init

# Production (remote)
npm run db:init:remote
```

### 4. Set a JWT secret (important for production!)
```bash
npx wrangler secret put JWT_SECRET
# Enter a long random string when prompted
```

### 5. Run locally
```bash
npm run dev
# Open http://localhost:8787
# On first visit, you'll be prompted to create an admin account
```

### 6. Deploy to Cloudflare
```bash
npm run deploy
```

---

## API Reference

All endpoints require `Authorization: Bearer <token>` except auth routes.

### Auth
| Method | Path | Body |
|--------|------|------|
| POST | `/api/auth/setup` | `{ username, password }` — first-time setup |
| POST | `/api/auth/login` | `{ username, password }` → `{ token }` |
| GET  | `/api/auth/check` | — |

### Students
| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/students` | All students with slot info |
| POST | `/api/students` | Create student |
| GET | `/api/students/:id` | Student + marks + attendance + payments |
| PUT | `/api/students/:id` | Update student |
| DELETE | `/api/students/:id` | Delete (cascades all records) |

### Schedule
| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/slots` | All class slots with student count |
| POST | `/api/slots` | `{ day_of_week, start_time, end_time, location }` |
| PUT | `/api/slots/:id` | Update slot |
| DELETE | `/api/slots/:id` | Delete slot |
| GET | `/api/slots/:id/students` | Students in slot |
| POST | `/api/slots/:id/students` | `{ student_id }` — assign |
| DELETE | `/api/slots/:id/students` | `{ student_id }` — remove |

### Attendance
| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/attendance` | `?student_id=&month=YYYY-MM` |
| POST | `/api/attendance` | Log single session |
| POST | `/api/attendance/bulk` | `{ date, records: [...] }` |
| PUT | `/api/attendance/:id` | Update session |
| DELETE | `/api/attendance/:id` | Delete session |

### Payments
| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/payments` | `?student_id=` |
| GET | `/api/payments/balances` | All students billed vs paid |
| POST | `/api/payments` | Record payment |
| DELETE | `/api/payments/:id` | Delete payment |

### Marks
| Method | Path | Notes |
|--------|------|-------|
| GET | `/api/marks` | `?student_id=` |
| POST | `/api/marks` | Create mark |
| PUT | `/api/marks/:id` | Update mark |
| DELETE | `/api/marks/:id` | Delete mark |

### Dashboard
| Method | Path |
|--------|------|
| GET | `/api/dashboard` |

### Batch Operations (bulk import)
| Method | Path | Body |
|--------|------|------|
| POST | `/api/batch/students` | `{ students: [...] }` |
| POST | `/api/batch/attendance` | `{ records: [...] }` |
| POST | `/api/batch/payments` | `{ payments: [...] }` |
| POST | `/api/batch/marks` | `{ marks: [...] }` |

### Exports (CSV)
| Method | Path |
|--------|------|
| GET | `/api/export/students` |
| GET | `/api/export/attendance?month=YYYY-MM` |

---

## Batch Import Examples

### Bulk add students
```bash
curl -X POST https://your-worker.workers.dev/api/batch/students \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "students": [
      {
        "name": "Alice Smith",
        "email": "alice@example.com",
        "phone": "0412345678",
        "subjects": "Math, Physics",
        "hourly_rate": 45,
        "payment_plan": "monthly",
        "payment_method": "bank_transfer",
        "parent_name": "Bob Smith",
        "parent_phone": "0498765432"
      }
    ]
  }'
```

### Bulk log attendance
```bash
curl -X POST https://your-worker.workers.dev/api/batch/attendance \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "records": [
      { "student_id": 1, "date": "2026-05-02", "duration_hours": 3, "subject": "Physics", "status": "present" },
      { "student_id": 2, "date": "2026-05-02", "duration_hours": 3, "subject": "Math", "status": "present" }
    ]
  }'
```

---

## Security Notes

- Passwords hashed with PBKDF2-SHA256, 200,000 iterations + unique random salt per user
- Auth tokens are HMAC-SHA256 signed, expire after 24 hours
- All string inputs sanitized (trimmed, `<>` stripped) before DB insertion
- Parameterized queries throughout (no SQL injection possible)
- Change `JWT_SECRET` before deploying to production!
