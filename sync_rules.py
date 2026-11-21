"""Regenerate backend/rules.json and embed the rules into ../index.html.
Run after editing rules.py:   python3 backend/sync_rules.py
"""
import json
import re
from pathlib import Path

import rules as R

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DATA = {
    "CATEGORIES": R.CATEGORIES, "PROTECT": R.PROTECT, "PROTECT_WEIGHT": R.PROTECT_WEIGHT, "SIGNALS": R.SIGNALS,
    "FLOORS": R.FLOORS, "SHORTENERS": R.SHORTENERS, "SUSPICIOUS_TLDS": R.SUSPICIOUS_TLDS, "FREE_HOSTS": R.FREE_HOSTS,
    "SECOND_LEVEL": R.SECOND_LEVEL, "BRANDS": R.BRANDS, "URL_PATH_WORDS": R.URL_PATH_WORDS, "DOMAIN_WORDS": R.DOMAIN_WORDS,
    "BARE_TLDS": R.BARE_TLDS, "RECS": R.RECS, "DEMOS": R.DEMOS, "URL_EXAMPLES": R.URL_EXAMPLES, "QUIZ": R.QUIZ,
    "NUMBER_COUNTRIES": R.NUMBER_COUNTRIES, "NUMBER_WATCH_CC": R.NUMBER_WATCH_CC, "NUMBER_HELPLINES": R.NUMBER_HELPLINES,
    "NUMBER_CONTEXT": R.NUMBER_CONTEXT, "NUMBER_FLOORS": R.NUMBER_FLOORS, "NUMBER_RECS": R.NUMBER_RECS,
    "LANG_HINGLISH": R.LANG_HINGLISH, "EMERGENCY": R.EMERGENCY,
}
blob = json.dumps(DATA, ensure_ascii=False, separators=(",", ":"))
(HERE / "rules.json").write_text(json.dumps(DATA, ensure_ascii=False, indent=1), encoding="utf-8")

html_path = ROOT / "index.html"
if html_path.exists():
    html = html_path.read_text(encoding="utf-8")
    new = re.sub(r"(/\*RULES_START\*/).*?(/\*RULES_END\*/)",
                 lambda m: m.group(1) + "const RULES=" + blob.replace("</", "<\\/") + ";" + m.group(2), html, flags=re.S)
    if new == html and "/*RULES_START*/" not in html:
        raise SystemExit("index.html has no /*RULES_START*/ ... /*RULES_END*/ markers")
    html_path.write_text(new, encoding="utf-8")
    print("rules.json written and embedded into index.html")
else:
    print("rules.json written (index.html not found)")
