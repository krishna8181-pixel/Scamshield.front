# ScamShield – AI-Powered Digital Fraud Detection Platform

Paste a suspicious SMS / WhatsApp message / email, check a link, or upload a screenshot. ScamShield shows an
explainable risk score (Low / Medium / High / Critical), the exact phrases that raised suspicion, and what to do next.
Privacy-first: nothing is stored and links are never opened.

## Project layout
    index.html               The whole website (one file: HTML + CSS + JS, includes the in-browser detection engine).
    backend/server.py        Flask REST API: serves the site, rule engine, OCR, optional AI second opinion.
    backend/engine.py        Python fraud-detection + URL-analysis engine.
    backend/rules.py         Detection rules, demo scenarios, quiz – single source of truth.
    backend/rules.json       Generated copy of the rules.
    backend/sync_rules.py    Re-embeds rules into index.html after you edit rules.py.
    backend/requirements.txt, backend/.env.example
    tests/test_engine.py     Unit tests.   README.md, .gitignore

## Pages
Home (intro + live scanner + 10 demo scenarios) · Message Analysis · URL Scanner · **QR Code Scanner** · **Number Fraud Check** · Screenshot Scanner · Cyber Awareness (scam types, how phishing works, checklist, genuine-vs-fake, quiz, tips) · **Helplines** · About Project.

## New in v7 – Scam Emergency Assistant (`#/emergency`)
- Already clicked, shared or paid? Tick what happened (shared an OTP or PIN, lost money, approved a UPI request, shared card details or a password, installed an APK, let someone control the screen, entered details on a link, shared Aadhaar/PAN) and when it happened.
- You get one ordered plan grouped into **Now**, **Within 1 hour** and **Within 24 hours**, with 1930, 112 and cybercrime.gov.in one tap away. Steps can be ticked off as you go (ticks are not saved).
- Urgent items, or a "within the last hour" report, make the plan **Act now**. Recovery-scam warnings are always included.
- Rules live in `backend/rules.py` (`EMERGENCY`). The plan logic is `build_emergency()` in `backend/engine.py`, mirrored in the browser. API: `POST /api/emergency {"incidents": ["otp","money"], "timing": "just"}`.

## New in v7 – Multilingual scam detection
- **Hindi (Devanagari), Bengali, Assamese and Hinglish** (Hindi written in Latin letters) are recognised. Scam phrases in these languages (OTP requests, fake KYC, prize fees, arrest threats, job fees, UPI collect tricks, \"sent by mistake\" stories) feed the same rules and score.
- Each report shows the detected language (for example a *Hindi* chip). Explanations stay in English.
- Language detection is script-based and dependency-free (`detect_language()` in `backend/engine.py`, mirrored in the browser engine).
- **Screenshots in other languages:** the server runs Tesseract with `eng+hin+ben+asm`. Set `OCR_LANGS` to change this. If a language pack is not installed, it falls back to English automatically. Install the packs with `tesseract-ocr-hin`, `tesseract-ocr-ben` and `tesseract-ocr-asm` (or the equivalents for your OS).
- New demos: OTP request in Hindi, lottery in Bengali, KYC scam in Assamese, Hinglish bank scam, and a genuine Hindi OTP notice that must stay Low.
- Indic patterns avoid `\b` on purpose (it is ASCII-only in both Python and JavaScript). The wording lists should be reviewed by a native speaker before production use.
- Tests extended (`python3 -m unittest discover -s tests`).

## New in v4
- **Cyber-warning redesign:** dark red theme with your two reference images as backgrounds (`assets/bg-hacker-warning.jpg`, `assets/bg-warning-triangle.jpg`), scan-line effects, hero banner and page banners.
- **QR Code Scanner (`#/qr`):** upload / drop / paste a QR image or use the camera. It decodes the code and analyses what is inside: UPI payee and amount, links (full URL engine), Wi-Fi, tel/SMS/email, app-install intents, crypto, plain text. Pick *why you have the QR* (e.g. "told it will send me money") to sharpen the score. Nothing is opened or paid. Decoding uses the browser's BarcodeDetector, falling back to jsQR from a CDN (internet needed).
- **Number Fraud Check (`#/number`):** checks format, country, number series (140 telemarketing, 160 service, toll-free, helplines, frequently reported foreign prefixes, odd digit patterns) and weighs what the caller said or asked (OTP, remote app, "police", money, secrecy…). Rules live in `backend/rules.py` (`NUMBER_*`); API: `POST /api/analyze/number`. It does not look numbers up in any database, so it cannot say who owns a number.
- Tests extended (`python3 -m unittest discover -s tests`).

## New in v3
- Your warning sound is in `assets/warning.mp3` (plays on every suspicious result, loops until dismissed; ).
- Cybersecurity background art in `assets/*.svg` (shield, padlock, phishing hook, network/code-rain) on the home page and page banners.
- Alarm fix: it now triggers for every suspicious result (score 20+), not only High/Critical, and the sound is no longer cancelled by the pop-up.

## New in v2
- **Fraud alarm:** when a message or link scores High/Critical, a flashing red full-screen warning appears, a siren + voice warning plays, and a red banner stays on the report. Mute/unmute with the speaker button in the header. To use your own sound, put a file next to `index.html` and set `ALARM_FILE='alarm.mp3'` in the script.
- **Screenshot upload everywhere:** every scanner has an *Upload screenshot* button; you can also drag-and-drop or paste (Ctrl/Cmd+V) an image straight into the message box.
- **Helplines page + floating 1930 button:** one-tap call/copy for India (1930, 112, 1915, 14567, 181, 1098), official reporting sites, other countries, a first-hour checklist.
- **Visual refresh:** animated aurora background, scan-line preview, live tips ticker, count-up stats, scroll reveals, glow hover effects.

## Option A – No server (GitHub Pages / just open the file)
Open `index.html`, or upload the repo and enable Pages (`main` / root). The same detection engine runs in your browser
(badge: "Browser engine"). Screenshot OCR in this mode uses Tesseract.js from a CDN, so it needs internet.

## Option B – With the Python backend (recommended for the demo)
    cd backend
    pip install -r requirements.txt
    cp .env.example .env          # optional: add OPENAI_API_KEY or ANTHROPIC_API_KEY
    python3 server.py             # http://localhost:8000
Install the Tesseract OCR program too (https://github.com/tesseract-ocr/tesseract) and make sure it is on PATH.
Without an AI key everything still works using the rule engine. With a key, an AI second opinion is blended in
(`0.65 × rules + 0.35 × AI`, and it can never lower a clear scam pattern below 70). Keys stay on the server.

To use a hosted backend from a static site: `https://<site>/?backend=https://your-server` (HTTPS; set `ALLOWED_ORIGIN`).

## API
    GET  /api/health          GET /api/demos
    POST /api/analyze/message {"text": "..."}
    POST /api/analyze/url     {"url": "..."}            (static analysis – URL is never fetched)
    POST /api/analyze/number  {"number": "...", "context": ["otp","money"]}
    POST /api/ocr/extract     multipart: image
    POST /api/analyze/screenshot  multipart: image      (OCR + analysis)

## How the score works
Each matched rule adds a weight; `score = 100 × (1 − e^(−weight/60))`. Genuine wording ("Do not share your OTP") earns a
credit, and dangerous combinations (asking for an OTP, "pay a fee to claim a prize", "digital arrest", remote-access apps)
set a minimum score. The report's "How this score was calculated" panel shows every contribution.
To add or tune rules: edit `backend/rules.py`, then run `python3 backend/sync_rules.py`.

## Tests
    python3 -m unittest discover -s tests

## Privacy & security
No database, no logs of message content, images processed in memory only, strict input limits, rate limiting
(`RATE_LIMIT_PER_MIN`), security headers, no API keys in frontend code.

## Notes
- The risk score is an estimate, not a guarantee. A low score does not prove a message is safe.
- Stack note: built as a dependency-free single-file frontend (vanilla JS/CSS) with a Flask backend, matching the layout
  of your SeeForMe project, so it runs with no build step. Supabase/Firebase are intentionally not used (nothing is stored).
- India-focused examples (UPI, KYC, 1930, cybercrime.gov.in, Sanchar Saathi); the approach generalises.
