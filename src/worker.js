/**
 * Elementa Education - Cloudflare Worker Backend
 * 
 * Deploy: wrangler deploy
 * DB Init: wrangler d1 execute elementa-db --file=schema.sql
 * 
 * Batch API endpoints available at /api/batch/* for bulk operations
 */

import { handleAuth, requireAuth, hashPassword, verifyPassword } from './auth.js';
import { getHTML } from './frontend.js';

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// Input sanitization
function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str.trim().replace(/[<>]/g, '');
}

function sanitizeObj(obj, fields) {
  const result = { ...obj };
  for (const f of fields) {
    if (result[f] != null) result[f] = sanitize(String(result[f]));
  }
  return result;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    // Serve frontend
    if (path === '/' || path === '/index.html') {
      return new Response(getHTML(), {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' },
      });
    }

    // Auth endpoints (no token required)
    if (path === '/api/auth/setup' && method === 'POST') return handleSetup(request, env);
    if (path === '/api/auth/login' && method === 'POST') return handleLogin(request, env);
    if (path === '/api/auth/check' && method === 'GET') return handleAuthCheck(request, env);

    // All other API routes require auth
    const authResult = await requireAuth(request, env);
    if (!authResult.ok) return err('Unauthorized', 401);

    // ── STUDENTS ──────────────────────────────────────────────
    if (path === '/api/students') {
      if (method === 'GET') return getStudents(env);
      if (method === 'POST') return createStudent(request, env);
    }
    if (path.match(/^\/api\/students\/(\d+)$/)) {
      const id = path.split('/')[3];
      if (method === 'GET') return getStudent(id, env);
      if (method === 'PUT') return updateStudent(id, request, env);
      if (method === 'DELETE') return deleteStudent(id, env);
    }

    // ── SCHEDULE ──────────────────────────────────────────────
    if (path === '/api/slots') {
      if (method === 'GET') return getSlots(env);
      if (method === 'POST') return createSlot(request, env);
    }
    if (path.match(/^\/api\/slots\/(\d+)$/)) {
      const id = path.split('/')[3];
      if (method === 'PUT') return updateSlot(id, request, env);
      if (method === 'DELETE') return deleteSlot(id, env);
    }
    if (path.match(/^\/api\/slots\/(\d+)\/students$/)) {
      const id = path.split('/')[3];
      if (method === 'GET') return getSlotStudents(id, env);
      if (method === 'POST') return assignStudentToSlot(id, request, env);
      if (method === 'DELETE') return removeStudentFromSlot(id, request, env);
    }

    // ── ATTENDANCE ────────────────────────────────────────────
    if (path === '/api/attendance') {
      if (method === 'GET') return getAttendance(url, env);
      if (method === 'POST') return logAttendance(request, env);
    }
    if (path.match(/^\/api\/attendance\/(\d+)$/)) {
      const id = path.split('/')[3];
      if (method === 'PUT') return updateAttendance(id, request, env);
      if (method === 'DELETE') return deleteAttendance(id, env);
    }
    if (path === '/api/attendance/bulk' && method === 'POST') {
      return bulkLogAttendance(request, env);
    }

    // ── PAYMENTS ──────────────────────────────────────────────
    if (path === '/api/payments') {
      if (method === 'GET') return getPayments(url, env);
      if (method === 'POST') return recordPayment(request, env);
    }
    if (path.match(/^\/api\/payments\/(\d+)$/)) {
      const id = path.split('/')[3];
      if (method === 'DELETE') return deletePayment(id, env);
    }
    if (path === '/api/payments/balances' && method === 'GET') {
      return getBalances(env);
    }

    // ── MARKS ─────────────────────────────────────────────────
    if (path === '/api/marks') {
      if (method === 'GET') return getMarks(url, env);
      if (method === 'POST') return createMark(request, env);
    }
    if (path.match(/^\/api\/marks\/(\d+)$/)) {
      const id = path.split('/')[3];
      if (method === 'PUT') return updateMark(id, request, env);
      if (method === 'DELETE') return deleteMark(id, env);
    }

    // ── DASHBOARD ─────────────────────────────────────────────
    if (path === '/api/dashboard' && method === 'GET') return getDashboard(env);

    // ── BATCH OPERATIONS ──────────────────────────────────────
    if (path === '/api/batch/students' && method === 'POST') return batchCreateStudents(request, env);
    if (path === '/api/batch/attendance' && method === 'POST') return batchCreateAttendance(request, env);
    if (path === '/api/batch/payments' && method === 'POST') return batchCreatePayments(request, env);
    if (path === '/api/batch/marks' && method === 'POST') return batchCreateMarks(request, env);
    if (path === '/api/export/students' && method === 'GET') return exportStudents(env);
    if (path === '/api/export/attendance' && method === 'GET') return exportAttendance(url, env);

    return err('Not found', 404);
  },
};

// ── AUTH ────────────────────────────────────────────────────────────────────

async function handleSetup(request, env) {
  const existing = await env.DB.prepare('SELECT id FROM users LIMIT 1').first();
  if (existing) return err('Already set up', 409);
  const body = await request.json();
  if (!body.username || !body.password) return err('Missing credentials');
  const salt = crypto.randomUUID();
  const hash = await hashPassword(body.password, salt);
  await env.DB.prepare('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)')
    .bind(sanitize(body.username), hash, salt).run();
  return json({ ok: true });
}

async function handleLogin(request, env) {
  const body = await request.json();
  if (!body.username || !body.password) return err('Missing credentials');
  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?')
    .bind(sanitize(body.username)).first();
  if (!user) return err('Invalid credentials', 401);
  const valid = await verifyPassword(body.password, user.salt, user.password_hash);
  if (!valid) return err('Invalid credentials', 401);
  // Generate a simple session token (store in KV or just use JWT-like signing)
  const token = await generateToken(user.id, env);
  return json({ token, username: user.username });
}

async function handleAuthCheck(request, env) {
  const existing = await env.DB.prepare('SELECT id FROM users LIMIT 1').first();
  if (!existing) return json({ ok: false, setup_needed: true });
  const result = await requireAuth(request, env);
  return json({ ok: result.ok, setup_needed: false });
}

async function generateToken(userId, env) {
  const payload = `${userId}:${Date.now()}:${crypto.randomUUID()}`;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(env.JWT_SECRET || 'elementa-secret-change-me'),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const sigHex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  return btoa(`${payload}:${sigHex}`);
}

// ── STUDENTS ────────────────────────────────────────────────────────────────

async function getStudents(env) {
  const rows = await env.DB.prepare(`
    SELECT s.*, GROUP_CONCAT(cs.id || ':' || cs.day_of_week || ':' || cs.start_time || ':' || cs.end_time || ':' || cs.location, '|') as slots
    FROM students s
    LEFT JOIN student_slots ss ON ss.student_id = s.id
    LEFT JOIN class_slots cs ON cs.id = ss.slot_id
    GROUP BY s.id ORDER BY s.name
  `).all();
  return json(rows.results);
}

async function getStudent(id, env) {
  const student = await env.DB.prepare('SELECT * FROM students WHERE id = ?').bind(id).first();
  if (!student) return err('Not found', 404);
  const marks = await env.DB.prepare('SELECT * FROM marks WHERE student_id = ? ORDER BY date DESC').bind(id).all();
  const attendance = await env.DB.prepare('SELECT * FROM attendance WHERE student_id = ? ORDER BY date DESC LIMIT 50').bind(id).all();
  const payments = await env.DB.prepare('SELECT * FROM payments WHERE student_id = ? ORDER BY date DESC').bind(id).all();
  return json({ ...student, marks: marks.results, attendance: attendance.results, payments: payments.results });
}

async function createStudent(request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['name', 'email', 'phone', 'subjects', 'payment_plan', 'payment_method',
    'bank_details', 'parent_name', 'parent_email', 'parent_phone', 'notes']);
  if (!b.name) return err('Name required');
  const r = await env.DB.prepare(`
    INSERT INTO students (name, email, phone, subjects, hourly_rate, payment_plan, payment_method,
      bank_details, parent_name, parent_email, parent_phone, notes)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
  `).bind(b.name, b.email||null, b.phone||null, b.subjects||null, b.hourly_rate||0,
    b.payment_plan||'per_session', b.payment_method||'cash', b.bank_details||null,
    b.parent_name||null, b.parent_email||null, b.parent_phone||null, b.notes||null).run();
  return json({ id: r.meta.last_row_id }, 201);
}

async function updateStudent(id, request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['name', 'email', 'phone', 'subjects', 'payment_plan', 'payment_method',
    'bank_details', 'parent_name', 'parent_email', 'parent_phone', 'notes']);
  await env.DB.prepare(`
    UPDATE students SET name=?, email=?, phone=?, subjects=?, hourly_rate=?, payment_plan=?,
      payment_method=?, bank_details=?, parent_name=?, parent_email=?, parent_phone=?, notes=?,
      active=?, updated_at=CURRENT_TIMESTAMP WHERE id=?
  `).bind(b.name, b.email||null, b.phone||null, b.subjects||null, b.hourly_rate||0,
    b.payment_plan||'per_session', b.payment_method||'cash', b.bank_details||null,
    b.parent_name||null, b.parent_email||null, b.parent_phone||null, b.notes||null,
    b.active !== false ? 1 : 0, id).run();
  return json({ ok: true });
}

async function deleteStudent(id, env) {
  await env.DB.prepare('DELETE FROM students WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

// ── SLOTS ───────────────────────────────────────────────────────────────────

async function getSlots(env) {
  const rows = await env.DB.prepare(`
    SELECT cs.*, COUNT(ss.student_id) as student_count
    FROM class_slots cs
    LEFT JOIN student_slots ss ON ss.slot_id = cs.id
    GROUP BY cs.id
    ORDER BY CASE cs.day_of_week
      WHEN 'Sunday' THEN 0 WHEN 'Monday' THEN 1 WHEN 'Tuesday' THEN 2
      WHEN 'Wednesday' THEN 3 WHEN 'Thursday' THEN 4 WHEN 'Friday' THEN 5
      WHEN 'Saturday' THEN 6 END, cs.start_time
  `).all();
  return json(rows.results);
}

async function createSlot(request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['day_of_week', 'start_time', 'end_time', 'location']);
  if (!b.day_of_week || !b.start_time || !b.end_time || !b.location) return err('Missing fields');
  const r = await env.DB.prepare(
    'INSERT INTO class_slots (day_of_week, start_time, end_time, location) VALUES (?,?,?,?)'
  ).bind(b.day_of_week, b.start_time, b.end_time, b.location).run();
  return json({ id: r.meta.last_row_id }, 201);
}

async function updateSlot(id, request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['day_of_week', 'start_time', 'end_time', 'location']);
  await env.DB.prepare(
    'UPDATE class_slots SET day_of_week=?, start_time=?, end_time=?, location=?, active=? WHERE id=?'
  ).bind(b.day_of_week, b.start_time, b.end_time, b.location, b.active !== false ? 1 : 0, id).run();
  return json({ ok: true });
}

async function deleteSlot(id, env) {
  await env.DB.prepare('DELETE FROM class_slots WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function getSlotStudents(slotId, env) {
  const rows = await env.DB.prepare(`
    SELECT s.* FROM students s
    JOIN student_slots ss ON ss.student_id = s.id
    WHERE ss.slot_id = ?
  `).bind(slotId).all();
  return json(rows.results);
}

async function assignStudentToSlot(slotId, request, env) {
  const { student_id } = await request.json();
  if (!student_id) return err('student_id required');
  await env.DB.prepare(
    'INSERT OR IGNORE INTO student_slots (student_id, slot_id) VALUES (?, ?)'
  ).bind(student_id, slotId).run();
  return json({ ok: true });
}

async function removeStudentFromSlot(slotId, request, env) {
  const { student_id } = await request.json();
  await env.DB.prepare(
    'DELETE FROM student_slots WHERE student_id = ? AND slot_id = ?'
  ).bind(student_id, slotId).run();
  return json({ ok: true });
}

// ── ATTENDANCE ──────────────────────────────────────────────────────────────

async function getAttendance(url, env) {
  const studentId = url.searchParams.get('student_id');
  const month = url.searchParams.get('month'); // YYYY-MM
  let query = `SELECT a.*, s.name as student_name FROM attendance a JOIN students s ON s.id = a.student_id WHERE 1=1`;
  const params = [];
  if (studentId) { query += ' AND a.student_id = ?'; params.push(studentId); }
  if (month) { query += ' AND a.date LIKE ?'; params.push(`${month}%`); }
  query += ' ORDER BY a.date DESC LIMIT 200';
  const stmt = env.DB.prepare(query);
  const rows = await stmt.bind(...params).all();
  return json(rows.results);
}

async function logAttendance(request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['subject', 'status', 'notes']);
  if (!b.student_id || !b.date) return err('student_id and date required');
  const student = await env.DB.prepare('SELECT hourly_rate FROM students WHERE id = ?').bind(b.student_id).first();
  const billed = student ? (b.duration_hours || 1) * student.hourly_rate : 0;
  const r = await env.DB.prepare(`
    INSERT INTO attendance (student_id, slot_id, date, duration_hours, subject, status, amount_billed, notes)
    VALUES (?,?,?,?,?,?,?,?)
  `).bind(b.student_id, b.slot_id||null, b.date, b.duration_hours||1,
    b.subject||null, b.status||'present', b.amount_billed ?? billed, b.notes||null).run();
  return json({ id: r.meta.last_row_id }, 201);
}

async function updateAttendance(id, request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['subject', 'status', 'notes']);
  await env.DB.prepare(`
    UPDATE attendance SET date=?, duration_hours=?, subject=?, status=?, amount_billed=?, notes=? WHERE id=?
  `).bind(b.date, b.duration_hours||1, b.subject||null, b.status||'present',
    b.amount_billed||0, b.notes||null, id).run();
  return json({ ok: true });
}

async function deleteAttendance(id, env) {
  await env.DB.prepare('DELETE FROM attendance WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function bulkLogAttendance(request, env) {
  const { date, slot_id, student_ids, duration_hours, subject } = await request.json();
  if (!date || !student_ids?.length) return err('date and student_ids required');
  const results = [];
  for (const sid of student_ids) {
    const student = await env.DB.prepare('SELECT hourly_rate FROM students WHERE id = ?').bind(sid).first();
    const billed = student ? (duration_hours || 1) * student.hourly_rate : 0;
    const r = await env.DB.prepare(`
      INSERT INTO attendance (student_id, slot_id, date, duration_hours, subject, status, amount_billed)
      VALUES (?,?,?,?,?,?,?)
    `).bind(sid, slot_id||null, date, duration_hours||1, subject||null, 'present', billed).run();
    results.push(r.meta.last_row_id);
  }
  return json({ ids: results }, 201);
}

// ── PAYMENTS ────────────────────────────────────────────────────────────────

async function getPayments(url, env) {
  const studentId = url.searchParams.get('student_id');
  let query = 'SELECT p.*, s.name as student_name FROM payments p JOIN students s ON s.id = p.student_id WHERE 1=1';
  const params = [];
  if (studentId) { query += ' AND p.student_id = ?'; params.push(studentId); }
  query += ' ORDER BY p.date DESC LIMIT 200';
  const rows = await env.DB.prepare(query).bind(...params).all();
  return json(rows.results);
}

async function getBalances(env) {
  const rows = await env.DB.prepare(`
    SELECT 
      s.id, s.name, s.payment_method,
      COALESCE(SUM(CASE WHEN a.status = 'present' THEN a.amount_billed ELSE 0 END), 0) as total_billed,
      COALESCE((SELECT SUM(amount) FROM payments WHERE student_id = s.id), 0) as total_paid
    FROM students s
    LEFT JOIN attendance a ON a.student_id = s.id
    WHERE s.active = 1
    GROUP BY s.id
    ORDER BY s.name
  `).all();
  return json(rows.results.map(r => ({ ...r, balance: r.total_billed - r.total_paid })));
}

async function recordPayment(request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['payment_method', 'notes']);
  if (!b.student_id || !b.amount || !b.date) return err('student_id, amount, date required');
  const r = await env.DB.prepare(
    'INSERT INTO payments (student_id, amount, payment_method, date, notes) VALUES (?,?,?,?,?)'
  ).bind(b.student_id, b.amount, b.payment_method||'cash', b.date, b.notes||null).run();
  return json({ id: r.meta.last_row_id }, 201);
}

async function deletePayment(id, env) {
  await env.DB.prepare('DELETE FROM payments WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

// ── MARKS ───────────────────────────────────────────────────────────────────

async function getMarks(url, env) {
  const studentId = url.searchParams.get('student_id');
  let query = 'SELECT m.*, s.name as student_name FROM marks m JOIN students s ON s.id = m.student_id WHERE 1=1';
  const params = [];
  if (studentId) { query += ' AND m.student_id = ?'; params.push(studentId); }
  query += ' ORDER BY m.date DESC';
  const rows = await env.DB.prepare(query).bind(...params).all();
  return json(rows.results);
}

async function createMark(request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['subject', 'assessment_name', 'notes']);
  if (!b.student_id || !b.subject || !b.assessment_name || !b.date) return err('Missing required fields');
  const r = await env.DB.prepare(`
    INSERT INTO marks (student_id, subject, assessment_name, score, max_score, date, notes)
    VALUES (?,?,?,?,?,?,?)
  `).bind(b.student_id, b.subject, b.assessment_name, b.score ?? null,
    b.max_score || 100, b.date, b.notes||null).run();
  return json({ id: r.meta.last_row_id }, 201);
}

async function updateMark(id, request, env) {
  let b = await request.json();
  b = sanitizeObj(b, ['subject', 'assessment_name', 'notes']);
  await env.DB.prepare(`
    UPDATE marks SET subject=?, assessment_name=?, score=?, max_score=?, date=?, notes=? WHERE id=?
  `).bind(b.subject, b.assessment_name, b.score ?? null, b.max_score || 100,
    b.date, b.notes||null, id).run();
  return json({ ok: true });
}

async function deleteMark(id, env) {
  await env.DB.prepare('DELETE FROM marks WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

// ── DASHBOARD ───────────────────────────────────────────────────────────────

async function getDashboard(env) {
  const today = new Date();
  const monthStart = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-01`;
  const weekStart = new Date(today); weekStart.setDate(today.getDate() - 6);
  const weekStartStr = weekStart.toISOString().split('T')[0];

  const [activeStudents, monthRevenue, weekRevenue, overdue, recentAttendance] = await Promise.all([
    env.DB.prepare("SELECT COUNT(*) as c FROM students WHERE active = 1").first(),
    env.DB.prepare("SELECT COALESCE(SUM(amount_billed),0) as t FROM attendance WHERE status='present' AND date >= ?").bind(monthStart).first(),
    env.DB.prepare("SELECT COALESCE(SUM(amount_billed),0) as t FROM attendance WHERE status='present' AND date >= ?").bind(weekStartStr).first(),
    env.DB.prepare(`
      SELECT COUNT(*) as c FROM (
        SELECT s.id, COALESCE(SUM(a.amount_billed),0) - COALESCE((SELECT SUM(p.amount) FROM payments p WHERE p.student_id=s.id),0) as bal
        FROM students s LEFT JOIN attendance a ON a.student_id=s.id AND a.status='present'
        WHERE s.active=1 GROUP BY s.id HAVING bal > 0
      )
    `).first(),
    env.DB.prepare(`
      SELECT a.date, SUM(a.amount_billed) as revenue 
      FROM attendance a WHERE a.status='present' AND a.date >= ? 
      GROUP BY a.date ORDER BY a.date
    `).bind(weekStartStr).all(),
  ]);

  return json({
    active_students: activeStudents?.c || 0,
    monthly_revenue: monthRevenue?.t || 0,
    week_revenue: weekRevenue?.t || 0,
    overdue_students: overdue?.c || 0,
    revenue_chart: recentAttendance.results,
  });
}

// ── BATCH OPERATIONS ────────────────────────────────────────────────────────

async function batchCreateStudents(request, env) {
  const { students } = await request.json();
  if (!Array.isArray(students)) return err('students array required');
  const ids = [];
  for (const b of students) {
    const s = sanitizeObj(b, ['name', 'email', 'phone', 'subjects', 'payment_plan', 'payment_method', 'bank_details', 'parent_name', 'parent_email', 'parent_phone', 'notes']);
    if (!s.name) continue;
    const r = await env.DB.prepare(`
      INSERT INTO students (name, email, phone, subjects, hourly_rate, payment_plan, payment_method, bank_details, parent_name, parent_email, parent_phone, notes)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    `).bind(s.name, s.email||null, s.phone||null, s.subjects||null, s.hourly_rate||0,
      s.payment_plan||'per_session', s.payment_method||'cash', s.bank_details||null,
      s.parent_name||null, s.parent_email||null, s.parent_phone||null, s.notes||null).run();
    ids.push(r.meta.last_row_id);
  }
  return json({ created: ids.length, ids }, 201);
}

async function batchCreateAttendance(request, env) {
  const { records } = await request.json();
  if (!Array.isArray(records)) return err('records array required');
  let count = 0;
  for (const b of records) {
    if (!b.student_id || !b.date) continue;
    const student = await env.DB.prepare('SELECT hourly_rate FROM students WHERE id = ?').bind(b.student_id).first();
    const billed = student ? (b.duration_hours || 1) * student.hourly_rate : 0;
    await env.DB.prepare(`INSERT INTO attendance (student_id, slot_id, date, duration_hours, subject, status, amount_billed, notes) VALUES (?,?,?,?,?,?,?,?)`)
      .bind(b.student_id, b.slot_id||null, b.date, b.duration_hours||1, b.subject||null, b.status||'present', b.amount_billed ?? billed, b.notes||null).run();
    count++;
  }
  return json({ created: count }, 201);
}

async function batchCreatePayments(request, env) {
  const { payments } = await request.json();
  if (!Array.isArray(payments)) return err('payments array required');
  let count = 0;
  for (const b of payments) {
    if (!b.student_id || !b.amount || !b.date) continue;
    await env.DB.prepare('INSERT INTO payments (student_id, amount, payment_method, date, notes) VALUES (?,?,?,?,?)')
      .bind(b.student_id, b.amount, b.payment_method||'cash', b.date, b.notes||null).run();
    count++;
  }
  return json({ created: count }, 201);
}

async function batchCreateMarks(request, env) {
  const { marks } = await request.json();
  if (!Array.isArray(marks)) return err('marks array required');
  let count = 0;
  for (const b of marks) {
    if (!b.student_id || !b.subject || !b.assessment_name || !b.date) continue;
    await env.DB.prepare('INSERT INTO marks (student_id, subject, assessment_name, score, max_score, date, notes) VALUES (?,?,?,?,?,?,?)')
      .bind(b.student_id, b.subject, b.assessment_name, b.score ?? null, b.max_score || 100, b.date, b.notes||null).run();
    count++;
  }
  return json({ created: count }, 201);
}

async function exportStudents(env) {
  const rows = await env.DB.prepare('SELECT * FROM students ORDER BY name').all();
  const csv = toCSV(rows.results, ['id','name','email','phone','subjects','hourly_rate','payment_plan','payment_method','bank_details','parent_name','parent_email','parent_phone','notes','active','created_at']);
  return new Response(csv, { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="students.csv"', ...CORS } });
}

async function exportAttendance(url, env) {
  const month = url.searchParams.get('month');
  let query = 'SELECT a.*, s.name as student_name FROM attendance a JOIN students s ON s.id=a.student_id WHERE 1=1';
  const params = [];
  if (month) { query += ' AND a.date LIKE ?'; params.push(`${month}%`); }
  query += ' ORDER BY a.date DESC';
  const rows = await env.DB.prepare(query).bind(...params).all();
  const csv = toCSV(rows.results, ['id','student_name','date','duration_hours','subject','status','amount_billed','notes']);
  return new Response(csv, { headers: { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="attendance.csv"', ...CORS } });
}

function toCSV(rows, fields) {
  const header = fields.join(',');
  const lines = rows.map(r => fields.map(f => {
    const v = r[f] ?? '';
    return `"${String(v).replace(/"/g, '""')}"`;
  }).join(','));
  return [header, ...lines].join('\n');
}
