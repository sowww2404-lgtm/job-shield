# JobShield — Setup & Your Part

## How to run it

**Backend:**
```
cd backend
pip install -r requirements.txt
python app.py
```
Runs at `http://localhost:5000`.

**Frontend:**
Just open `frontend/index.html` in a browser (double-click it, or right-click → Open with Browser). No build step needed.

## Your part of the work

1. **Get 2 free API keys** (optional, for stronger link checking — app works without them using rule-based checks only):
   - Google Safe Browsing API key → real-time malicious/phishing URL detection
   - A WHOIS API key (e.g. whoisxmlapi.com free tier) → flags domains registered in the last 30 days
   - Once you have them, paste them into `backend/scoring.py` where marked `# Placeholders for real-time API checks`, and I can wire them in.

2. **Grow the datasets** (both are in `backend/`, plain Python files, easy to edit):
   - `verified_companies.py` — currently ~20 companies. Add ones relevant to your college placements.
   - `scam_data.py` — currently ~25 scam phrases. Add real examples you or classmates have seen (great "real dataset" talking point for your PPT).

3. **Test with real offers** — paste 5-10 real (or reported-scam) offers you or friends have received, note anything the app misses, and tell me — I'll tune the weights.

4. **For your PPT**: the Dashboard tab numbers (Total/High/Medium/Low checks) will populate as you use it — screenshot it after a few test runs for a "real usage" slide.

## What I can extend later, on your word
- Plug in the two API keys once you have them
- Add more scam phrases / verified companies you collect
- Any UI tweaks (colors, wording, extra tips)
