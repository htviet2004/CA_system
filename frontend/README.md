Frontend (Vite + React)

Quick start:

1. Install dependencies

```bash
cd frontend
npm install
```

2. Run dev server (proxy to Django at http://localhost:8000)

```bash
npm run dev
```

Open http://localhost:3000

Notes:
- The Vite dev server proxies `/api` and `/verifier` to the Django backend at port 8000 (see `vite.config.js`).
- Build artifact (`npm run build`) can be served as static files by Django if you copy `dist/` into Django's `static/` or configure `django.contrib.staticfiles` accordingly.
