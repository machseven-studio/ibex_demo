# I.B.E.X. — Institutional Backbone EXecutive

Institutional Backbone EXecutive — clerical automation for education institutes.

## Demo build

This branch ships with a **demo seeder** that populates the database with a fully-fledged
imaginary institute on first boot (only if the demo account doesn't already exist — it is
idempotent and safe to redeploy).

**Demo login**

| Email                 | Password        | Role                |
|-----------------------|-----------------|---------------------|
| demo@ibex.in          | demo12345678    | Owner (full access) |
| principal@ibex.in     | demo12345678    | Principal (edit)    |
| accounts@ibex.in      | demo12345678    | Accountant (edit)   |
| teacher@ibex.in       | demo12345678    | Teacher (read-only) |

Demo institute: **Sunrise International Academy** with branches
*Main Campus — Andheri*, *North Campus — Borivali*, *South Campus — Bandra*.

The seeder creates:
- 3 branches
- 4 staff users (Owner / Principal / Accountant / Teacher)
- 22 classrooms across branches
- 8 teachers with subjects and contact numbers
- 30+ students split across 5 batches (JEE 2026 A/B, NEET 2026 A/B, Foundation X)
- 14 days of attendance for every student
- Timetables for 3 batches (Monday–Friday, 4 lectures per day) + saved configs
- 2 seating plans for two exam dates
- 5 invigilation duties
- 15 fee records (mixed Paid / Pending, with UTRs)
- 30 exam result records + 6 exam history records
- 3 Director's Journal entries
- 5 prospect inquiries
- 6 audit log entries

## Deploy on Render

1. Push this repo to GitHub.
2. Create a **Web Service** from the repo (Render reads `render.yaml` automatically).
3. Render provisions the Postgres database and wires `DATABASE_URL`.
4. First boot auto-creates every table and seeds the demo data — watch the logs for
   `[demo] Seeded 'Sunrise International Academy'`.
5. Log in with `demo@ibex.in` / `demo12345678`.

## Local development

```bash
pip install -r requirements.txt
export DATABASE_URL="postgresql://user:pass@localhost:5432/ibex"
uvicorn main:app --reload
