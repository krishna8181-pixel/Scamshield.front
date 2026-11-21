"""ScamShield detection engine (rule-based, explainable).

analyze_text(text)  -> full report for an SMS / WhatsApp / e-mail
analyze_url(url)    -> static analysis of a single URL. The URL is NEVER fetched or opened.

The same logic exists in JavaScript inside index.html so the site also works without a server.
Scores are estimates, not guarantees.
"""
import math
import re

import rules as R

MAX_TEXT = 5000


def _round(x):  # same rounding as JavaScript's Math.round for positive numbers
    return int(math.floor(x + 0.5))


def level_for(score):
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------- compile once
_SIGNALS = [dict(s, rx=[re.compile(p, re.I) for p in s["pats"]]) for s in R.SIGNALS]
_PROTECT = [re.compile(p, re.I) for p in R.PROTECT]
_CAT_LABEL = {c["id"]: c["label"] for c in R.CATEGORIES}
_TLDS = "|".join(sorted(R.BARE_TLDS, key=len, reverse=True))
URL_RX = re.compile(
    r"(?<![@\w.\-/])(?:(?:https?://|www\.)[^\s<>\"'\)\]]+|"
    r"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:shorturl\.at|" + _TLDS + r")(?![a-z0-9\-])(?::\d+)?(?:[/?#][^\s<>\"'\)\]]*)?)",
    re.I)
PHONE_RX = re.compile(r"(?<!\d)(?:\+?91[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}(?!\d)|(?<!\d)1800[\s\-]?\d{3}[\s\-]?\d{3,4}(?!\d)")
UPI_RX = re.compile(r"\b[\w.\-]{2,}@(?:ok(?:hdfc|sbi|icici|axis)bank|ybl|paytm|axl|ibl|upi|oksbi|apl|fbl)\b", re.I)
AMOUNT_RX = re.compile(r"(?:₹|rs\.?|inr)\s?\d[\d,]*(?:\.\d+)?", re.I)
EMOJI_RX = re.compile("[\U0001F300-\U0001FAFF☀-➿]")
URL_PARTS_RX = re.compile(r"^(?:([a-z][a-z0-9+.\-]*):\/\/)?(?:([^\/?#@]*)@)?(\[[^\]]*\]|[^\/?#:]*)(?::(\d+))?([^?#]*)(\?[^#]*)?(#.*)?$", re.I)
IPV4_RX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
LEET = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("4", "a"), ("@", "a")]


def _strip_url(u):
    return re.sub(r"[.,;:!?)\]}'\"]+$", "", u)


def find_urls(text):
    out = []
    for m in URL_RX.finditer(text):
        raw = _strip_url(m.group(0))
        if len(raw) < 4:
            continue
        out.append({"raw": raw, "start": m.start(), "end": m.start() + len(raw)})
    return out[:10]


# ---------------------------------------------------------------- URL analysis
def _registered(host):
    labels = host.split(".")
    if len(labels) <= 2:
        return host, ""
    last2 = ".".join(labels[-2:])
    n = 3 if last2 in R.SECOND_LEVEL else 2
    n = min(n, len(labels))
    return ".".join(labels[-n:]), ".".join(labels[:-n])


def _normalise_leet(s):
    for a, b in R.LEET if hasattr(R, "LEET") else LEET:
        s = s.replace(a, b)
    return s


def analyze_url(raw):
    raw = (raw or "").strip()
    out = {"url": raw, "valid": False, "score": 0, "level": "Low", "checks": [], "parts": {}, "verdict": ""}
    if not raw or len(raw) > 2048 or re.search(r"\s", raw):
        out["verdict"] = "Please enter a single URL without spaces."
        return out
    m = URL_PARTS_RX.match(raw)
    if not m or not m.group(3):
        out["verdict"] = "That doesn't look like a valid URL."
        return out
    scheme, userinfo, host, port, path, query, frag = m.groups()
    scheme = (scheme or "").lower()
    host = host.lower().rstrip(".")
    path, query = path or "", query or ""
    if scheme and scheme not in ("http", "https", "ftp"):
        out["verdict"] = "Only http(s) links can be analysed."
        return out
    if not host or (("." not in host) and not host.startswith("[")):
        out["verdict"] = "That doesn't look like a valid URL."
        return out
    out["valid"] = True
    is_ip = bool(IPV4_RX.match(host)) or host.startswith("[") or bool(re.match(r"^(?:0x[0-9a-f]+|\d{8,10})$", host))
    reg, sub = (host, "") if is_ip else _registered(host)
    tld = "" if is_ip else host.split(".")[-1]
    main_label = reg.split(".")[0] if not is_ip else host
    out["parts"] = {"scheme": scheme or "(none)", "subdomain": sub, "domain": main_label, "registered": reg, "tld": tld,
                    "port": port or "", "path": path + query, "userinfo": userinfo or ""}

    checks, total = [], 0

    def add(cid, w, status, title, detail):
        nonlocal total
        checks.append({"id": cid, "weight": w, "status": status, "title": title, "detail": detail})
        total += w

    # official domain?
    brand_official = next((b for b in R.BRANDS if reg in b["domains"]), None)

    if is_ip:
        add("ip", 35, "bad", "IP address instead of a domain name", "Legitimate services use names like sbi.co.in. A raw IP address hides who owns the site.")
    if reg in R.SHORTENERS:
        add("shortener", 28, "bad", "URL shortener", "Shorteners hide the real destination. You can't tell where the link leads until it's too late.")
    if userinfo is not None and userinfo != "":
        add("userinfo", 35, "bad", "Contains '@' before the real host", "In 'https://trusted.com@evil.com' the browser goes to evil.com. This trick disguises the true address.")
    if "xn--" in host:
        add("punycode", 30, "bad", "Punycode / look-alike international characters", "Characters from other alphabets can imitate Latin letters (e.g. a Cyrillic 'а').")

    if not brand_official and not is_ip:
        toks = [t for t in re.split(r"[.\-_]", host) if t]
        norm_host = _normalise_leet(host)
        norm_toks = [t for t in re.split(r"[.\-_]", norm_host) if t]
        hit = None
        for b in R.BRANDS:
            for tok in b["tokens"]:
                if b["exact"]:
                    raw_hit = tok in toks
                    norm_hit = tok in norm_toks
                else:
                    raw_hit = tok in host
                    norm_hit = tok in norm_host
                if raw_hit or norm_hit:
                    hit = (b, tok, (not raw_hit) and norm_hit)
                    break
            if hit:
                break
        if hit:
            b, tok, lookalike = hit
            if lookalike:
                add("brand", 40, "bad", f"Look-alike of {b['name']}", f"The domain spells '{tok}' using swapped characters (like 0 for o). The official site is {b['domains'][0]}.")
            else:
                add("brand", 38, "bad", f"Pretends to be {b['name']}", f"The name '{tok}' appears in the address, but the real owner of this domain is '{reg}'. The official site is {b['domains'][0]}.")
    if brand_official:
        add("official", -25, "good", f"Official {brand_official['name']} domain", f"'{reg}' is a known official domain for {brand_official['name']}.")

    if tld in R.SUSPICIOUS_TLDS:
        add("tld", 20, "bad", f"Risky domain ending (.{tld})", "Cheap or free domain endings like .xyz, .top or .click are heavily used for throw-away scam sites.")
    if reg in R.FREE_HOSTS:
        add("freehost", 18, "warn", "Free / temporary hosting service", f"Anyone can create a page on '{reg}' in minutes, so it says nothing about the brand it displays.")
    sub_labels = [x for x in sub.split(".") if x]
    if len(sub_labels) >= 3:
        add("subdomains", 15, "warn", "Long chain of subdomains", "Scammers stack subdomains like 'bank.secure.login.evil.com' to push the real domain out of sight.")
    if not is_ip:
        hy = main_label.count("-")
        if hy >= 2:
            add("hyphens", 12, "warn", "Many hyphens in the domain", "Names like 'sbi-kyc-update-now' are typical of fake sites. Real brands use short domains.")
        if sum(c.isdigit() for c in main_label) >= 3:
            add("digits", 8, "warn", "Lots of digits in the domain name", "Random numbers in a domain are common on auto-generated scam sites.")
        words = [w for w in R.DOMAIN_WORDS if w in main_label]
        if words and not brand_official:
            add("domainwords", 14, "warn", "Security-sounding words in the domain", f"Words like '{words[0]}' are added to look official ('{reg}').")
    if scheme == "http":
        add("http", 12, "warn", "Not encrypted (http://)", "The connection is not encrypted. Note that https alone does NOT prove a site is safe.")
    elif scheme == "https":
        add("https", 0, "info", "Uses https", "Encryption is on, but scam sites use https too – it does not prove the site is genuine.")
    elif not scheme:
        add("noscheme", 0, "info", "No scheme given", "Analysed as written. Treat it as unverified.")
    if len(raw) > 100:
        add("long", 8, "warn", "Very long URL", "Long addresses can bury the real destination or hide tracking and redirect data.")
    if port and port not in ("80", "443"):
        add("port", 10, "warn", f"Unusual port :{port}", "Normal websites rarely use custom ports. Often seen on temporary servers.")
    lp = (path + query).lower()
    pw = [w for w in R.URL_PATH_WORDS if w in lp]
    if pw:
        add("pathwords", min(20, 8 * len(pw)), "warn", "Credential / reward words in the path", "Found: " + ", ".join(pw[:5]) + ". Fake pages are often named /login, /verify, /claim.")
    if re.search(r"\.(?:apk|exe|scr|bat|msi|jar|dmg)(?:\?|$)", path.lower()):
        add("download", 35, "bad", "Direct app / program download", "The link downloads an installable file. Malicious apps are the main way banking trojans spread.")
    if len(re.findall(r"%[0-9a-f]{2}", raw, re.I)) >= 4:
        add("encoded", 8, "warn", "Heavily encoded characters", "Percent-encoding can disguise what the address really says.")
    if re.search(r"[?&](?:url|redirect|redir|next|goto|link|u|target)=https?", raw, re.I):
        add("redirect", 15, "warn", "Redirects to another address", "The link bounces you to a second site hidden in its parameters.")

    if not any(c["status"] in ("bad", "warn") for c in checks):
        add("clean", 0, "good", "No structural warning signs found", "That doesn't guarantee safety – only that the address itself looks ordinary.")

    score = _round(100 * (1 - math.exp(-max(0, total) / 50))) if total > 0 else 0
    out["checks"] = checks
    out["score"] = score
    out["level"] = level_for(score)
    out["verdict"] = {
        "Low": "No strong warning signs in the address itself.",
        "Medium": "Some warning signs. Don't open it unless you can verify the sender.",
        "High": "Likely a phishing or scam link. Do not open it.",
        "Critical": "Very likely malicious. Do not open it and report it.",
    }[out["level"]]
    return out


# ---------------------------------------------------------------- language detection (v7)
_HINGLISH = set(R.LANG_HINGLISH)
LANG_NAMES = {"en": "English", "hi": "Hindi", "bn": "Bengali", "as": "Assamese",
              "hi-Latn": "Hinglish (Hindi in Latin letters)", "und": "Unknown"}


def detect_language(text):
    """Rough, dependency-free script detection: Devanagari -> Hindi, Bengali script -> Bengali or Assamese
    (Assamese has the letters ৰ and ৱ), Latin text with several romanised Hindi words -> Hinglish, else English."""
    deva = beng = asm = latin = 0
    for ch in (text or "")[:MAX_TEXT]:
        o = ord(ch)
        if 0x0900 <= o <= 0x097F:
            deva += 1
        elif 0x0980 <= o <= 0x09FF:
            beng += 1
            if o in (0x09F0, 0x09F1):
                asm += 1
        elif ch.isascii() and ch.isalpha():
            latin += 1
    total = deva + beng + latin
    if not total:
        code, script, mixed = "und", "", False
    elif (deva + beng) / total >= 0.3:
        mixed = latin / total >= 0.2
        if deva >= beng:
            code, script = "hi", "Devanagari"
        elif asm:
            code, script = "as", "Bengali script"
        else:
            code, script = "bn", "Bengali script"
    else:
        mixed = False
        words = set(re.findall(r"[a-z]+", text.lower()))
        code, script = ("hi-Latn" if len(words & _HINGLISH) >= 3 else "en"), "Latin"
    return {"code": code, "name": LANG_NAMES[code], "script": script, "mixed": mixed}


# ---------------------------------------------------------------- text analysis
def analyze_text(text):
    text = (text or "")[:MAX_TEXT]
    out = {"ok": True, "length": len(text), "engine": "server-rules", "language": detect_language(text)}
    masked = text
    protect_hit = False
    for rx in _PROTECT:
        def blank(m):
            nonlocal protect_hit
            protect_hit = True
            return " " * len(m.group(0))
        masked = rx.sub(blank, masked)

    signals, highlights, keywords, seen_kw = [], [], [], set()
    matched_ids = set()
    for s in _SIGNALS:
        spans = []
        for rx in s["rx"]:
            for m in rx.finditer(masked):
                if m.end() > m.start():
                    spans.append((m.start(), m.end()))
        if not spans:
            continue
        matched_ids.add(s["id"])
        samples = []
        for a, b in spans[:6]:
            frag = text[a:b].strip()
            highlights.append({"start": a, "end": b, "cat": s["cat"], "sig": s["id"]})
            if len(frag) > 70:
                frag = frag[:67] + "…"
            if frag.lower() not in seen_kw and len(keywords) < 24:
                seen_kw.add(frag.lower())
                keywords.append({"word": frag, "cat": s["cat"]})
            if len(samples) < 2:
                samples.append(frag)
        signals.append({"id": s["id"], "cat": s["cat"], "weight": s["w"], "tactic": s["tactic"], "label": s["label"],
                        "why": s["why"], "matches": samples})

    # style signals
    letters = [c for c in text if c.isalpha() and c.isascii()]
    if len(letters) >= 25 and sum(c.isupper() for c in letters) / len(letters) > 0.55:
        signals.append({"id": "style.caps", "cat": "general", "weight": 6, "tactic": "Pressure", "label": "Mostly CAPITAL LETTERS",
                        "why": "Shouting in capitals is used to create alarm.", "matches": []})
    if text.count("!") >= 3:
        signals.append({"id": "style.exclaim", "cat": "general", "weight": 5, "tactic": "Pressure", "label": "Excessive exclamation marks",
                        "why": "Official notices are rarely written like adverts.", "matches": []})
    if len(EMOJI_RX.findall(text)) >= 3:
        signals.append({"id": "style.emoji", "cat": "general", "weight": 5, "tactic": "Pressure", "label": "Heavy emoji use",
                        "why": "Banks and government bodies don't write with strings of emoji.", "matches": []})

    # links
    links = []
    for u in find_urls(text):
        a = analyze_url(u["raw"])
        if not a["valid"]:
            continue
        a["start"], a["end"] = u["start"], u["end"]
        links.append(a)
        highlights.append({"start": u["start"], "end": u["end"], "cat": "phishing", "sig": "link"})
        if a["score"] >= 20:
            matched_ids.add("link")
            signals.append({"id": "link", "cat": "phishing", "weight": _round(a["score"] * 0.5), "tactic": "Link",
                            "label": f"Suspicious link ({a['parts']['registered']})", "why": a["verdict"],
                            "matches": [u["raw"][:70]]})
            if len(keywords) < 24:
                keywords.append({"word": u["raw"][:70], "cat": "phishing"})

    if protect_hit:
        signals.append({"id": "legit.protect", "cat": "general", "weight": R.PROTECT_WEIGHT, "tactic": "Genuine wording",
                        "label": "Contains genuine-style security wording",
                        "why": "Phrases such as 'Do not share this OTP' or 'valid for 10 minutes' are typical of real security messages and lower the score.",
                        "matches": []})

    # entities
    entities = {
        "phones": sorted(set(m.group(0).strip() for m in PHONE_RX.finditer(text)))[:5],
        "upi_ids": sorted(set(m.group(0) for m in UPI_RX.finditer(text)))[:5],
        "amounts": sorted(set(m.group(0) for m in AMOUNT_RX.finditer(text)))[:6],
        "urls": [l["url"] for l in links],
    }

    # score
    pos = sum(s["weight"] for s in signals if s["weight"] > 0)
    neg = sum(s["weight"] for s in signals if s["weight"] < 0)
    eff = max(0, pos + neg)
    raw_score = _round(100 * (1 - math.exp(-eff / 60)))
    score = raw_score
    floors = []
    for f in R.FLOORS:
        ok = all(i in matched_ids for i in f["all"]) if "all" in f else any(i in matched_ids for i in f["any"])
        if ok and f["min"] > score:
            score = f["min"]
            floors = [f["why"]]
        elif ok and f["min"] == score:
            floors.append(f["why"])
    score = max(2, min(100, score))
    level = level_for(score)

    # categories
    cat_sum = {}
    for s in signals:
        if s["cat"] != "general" and s["weight"] > 0:
            cat_sum[s["cat"]] = cat_sum.get(s["cat"], 0) + s["weight"]
    categories = []
    for c in R.CATEGORIES:
        v = cat_sum.get(c["id"], 0)
        categories.append({"id": c["id"], "label": c["label"], "icon": c["icon"], "score": _round(100 * (1 - math.exp(-v / 45))) if v else 0})
    categories.sort(key=lambda c: -c["score"])
    top = [c for c in categories if c["score"] >= 25][:3]

    tactics = []
    for s in sorted(signals, key=lambda s: -s["weight"]):
        if s["weight"] > 0 and s["tactic"] not in tactics:
            tactics.append(s["tactic"])

    if not signals or (not top and level == "Low"):
        summary = "No known scam patterns were found in this message."
    elif top:
        names = [c["label"].lower() for c in top]
        summary = "This message resembles a " + (names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]) + "."
        if tactics:
            summary += " Tactics detected: " + ", ".join(t.lower() for t in tactics[:4]) + "."
    else:
        summary = "Some general warning signs were found: " + ", ".join(t.lower() for t in tactics[:4]) + "."

    verdict = {
        "Low": "Low risk – no strong scam patterns detected",
        "Medium": "Medium risk – warning signs present, verify before acting",
        "High": "High risk – likely a scam attempt",
        "Critical": "Critical risk – matches known scam playbooks. Do not respond.",
    }[level]

    # recommendations
    recs, used = [], set()

    def push(r):
        if r["text"] not in used:
            used.add(r["text"])
            recs.append(r)
    if level in ("High", "Critical"):
        push({"icon": "ban", "text": "Do not reply, click, call back or pay. Block the sender and delete the message."})
    for c in top:
        for r in R.RECS.get(c["id"], []):
            push(r)
    if links and any(l["score"] >= 25 for l in links):
        for r in R.RECS["phishing"]:
            push(r)
    for r in R.RECS["base"]:
        push(r)
    if level in ("Medium", "High", "Critical"):
        for r in R.RECS["report"]:
            push(r)
    if level == "Low":
        for r in R.RECS["low"]:
            push(r)

    out.update({
        "score": score, "level": level, "verdict": verdict, "summary": summary,
        "categories": categories, "signals": sorted(signals, key=lambda s: -abs(s["weight"])),
        "keywords": keywords, "highlights": highlights, "links": links, "entities": entities,
        "tactics": tactics, "recommendations": recs,
        "breakdown": {"positive": pos, "negative": neg, "effective": eff, "raw_score": raw_score, "floors": floors},
        "disclaimer": "This risk score is an estimate based on known scam patterns, not a guarantee. A low score does not prove a message is safe.",
    })
    return out


# ---------------------------------------------------------------- phone-number analysis
_CC_KEYS = sorted(R.NUMBER_COUNTRIES, key=len, reverse=True)
_CTX = {c["id"]: c for c in R.NUMBER_CONTEXT}


def _fmt_national(cc, nat):
    if cc == "91" and len(nat) == 10:
        return f"+91 {nat[:5]} {nat[5:]}"
    return f"+{cc} {nat}" if cc else nat


def parse_number(raw):
    """Return dict(kind, cc, country, national, display) or dict(error=...). Never contacts anything."""
    s = (raw or "").strip()
    if not s:
        return {"error": "Please enter a phone number."}
    if len(s) > 40 or re.search(r"[^\d\s\-().+]", s):
        return {"error": "Use digits only (spaces, dashes and a leading + are fine)."}
    digits = re.sub(r"\D", "", s)
    plus = s.startswith("+") or s.startswith("00")
    if s.startswith("00"):
        digits = digits[2:]
    if len(digits) < 3 or len(digits) > 15:
        return {"error": "That doesn't look like a phone number (3–15 digits expected)."}
    if plus:
        cc = next((k for k in _CC_KEYS if digits.startswith(k)), "")
        if not cc:
            cc, nat = digits[:2], digits[2:]
            return {"kind": "intl", "cc": cc, "country": "Unknown country code", "national": nat, "display": f"+{cc} {nat}", "assumed": False}
        nat = digits[len(cc):]
        if cc == "91":
            if len(nat) != 10:
                return {"error": "Indian numbers have 10 digits after +91."}
            kind = "mobile" if nat[0] in "6789" else "invalid-in"
            return {"kind": kind, "cc": cc, "country": "India", "national": nat, "display": _fmt_national(cc, nat), "assumed": False}
        if len(nat) < 6:
            return {"error": "That number is too short for its country code."}
        return {"kind": "intl", "cc": cc, "country": R.NUMBER_COUNTRIES[cc], "national": nat, "display": f"+{cc} {nat}", "assumed": False}
    # no '+' – assume India, and say so
    if digits in R.NUMBER_HELPLINES:
        return {"kind": "helpline", "cc": "91", "country": "India", "national": digits, "display": digits, "assumed": True}
    if 3 <= len(digits) <= 6:
        return {"kind": "short", "cc": "91", "country": "India", "national": digits, "display": digits, "assumed": True}
    if len(digits) == 10:
        if digits.startswith("140"):
            return {"kind": "tm140", "cc": "91", "country": "India", "national": digits, "display": digits, "assumed": True}
        if digits.startswith("160"):
            return {"kind": "svc160", "cc": "91", "country": "India", "national": digits, "display": digits, "assumed": True}
        if digits[0] in "6789":
            return {"kind": "mobile", "cc": "91", "country": "India", "national": digits, "display": _fmt_national("91", digits), "assumed": True}
        return {"kind": "invalid-in", "cc": "91", "country": "India", "national": digits, "display": digits, "assumed": True}
    if re.match(r"^1800\d{6,7}$", digits) or re.match(r"^1860\d{6,7}$", digits):
        return {"kind": "tollfree", "cc": "91", "country": "India", "national": digits, "display": digits, "assumed": True}
    if len(digits) == 11 and digits[0] == "0":
        nat = digits[1:]
        if nat[0] in "6789":
            return {"kind": "mobile", "cc": "91", "country": "India", "national": nat, "display": _fmt_national("91", nat), "assumed": True}
        return {"kind": "landline", "cc": "91", "country": "India", "national": nat, "display": digits, "assumed": True}
    if len(digits) == 12 and digits.startswith("91") and digits[2] in "6789":
        nat = digits[2:]
        return {"kind": "mobile", "cc": "91", "country": "India", "national": nat, "display": _fmt_national("91", nat), "assumed": True}
    return {"error": "Couldn't recognise that number's format. Add the country code with + if it is from abroad."}


def _pattern_checks(nat):
    out = []
    if re.search(r"(\d)\1{6,}", nat):
        out.append(("pattern", 10, "warn", "Repetitive digit pattern",
                    "Long runs of the same digit (like 99999 99999) are typical of throw-away or spoofed numbers."))
    else:
        asc = "0123456789"
        for i in range(len(nat) - 5):
            seg = nat[i:i + 6]
            if seg in asc or seg in asc[::-1]:
                out.append(("pattern", 8, "warn", "Sequential digit pattern",
                            "Easy-to-remember sequences (like 123456) are common on throw-away numbers."))
                break
    return out


def analyze_number(raw, context=None):
    context = [c for c in (context or []) if c in _CTX]
    context = list(dict.fromkeys(context))
    p = parse_number(raw)
    out = {"input": (raw or "").strip(), "valid": False, "score": 0, "level": "Low", "checks": [], "context": context,
           "verdict": "", "display": "", "country": "", "type": ""}
    if "error" in p:
        out["verdict"] = p["error"]
        return out
    out.update(valid=True, display=p["display"], country=p["country"], cc=p["cc"], assumed=p["assumed"])
    kind, cc, nat = p["kind"], p["cc"], p["national"]
    type_label = {"mobile": "Mobile number", "intl": "International number", "invalid-in": "Invalid Indian mobile format",
                  "helpline": "Short helpline code", "short": "Short code", "tm140": "Telemarketing series (140)",
                  "svc160": "Service / transactional series (160)", "tollfree": "Toll-free number", "landline": "Landline (STD)"}[kind]
    out["type"] = type_label
    checks, total = [], 0

    def add(cid, w, status, title, detail):
        nonlocal total
        checks.append({"id": cid, "weight": w, "status": status, "title": title, "detail": detail})
        total += w

    if p["assumed"] and kind in ("mobile", "invalid-in", "tm140", "svc160", "landline"):
        add("assume", 0, "info", "Treated as an Indian number", "No country code was given, so this was read as an Indian number. Add + and the code if it came from abroad.")
    if kind == "mobile":
        add("type", 0, "info", "Valid Indian mobile format", "Starts with 6–9 and has 10 digits. A valid format does not mean the person is who they claim to be – caller names and numbers can be faked (spoofed).")
    if kind == "invalid-in":
        add("invalid", 25, "bad", "Not a valid Indian mobile number", "Indian mobile numbers start with 6, 7, 8 or 9. A call showing this number is either spoofed, internet-generated or from a different country.")
    if kind == "intl":
        add("foreign", 12, "warn", f"International number ({'+' + cc} {p['country']})", "If you weren't expecting a call or message from abroad, treat it with caution. Many scam calls and WhatsApp messages come from overseas numbers.")
        if cc in R.NUMBER_WATCH_CC:
            add("watch", 14, "warn", f"+{cc} is a frequently reported prefix", "Indian users and the Department of Telecommunications have warned about missed calls and WhatsApp 'job' messages from this country code. A prefix alone doesn't prove fraud.")
    if kind == "tm140":
        add("tm140", 12, "warn", "140-series (telemarketing) number", "Numbers starting 140 are allotted for promotional calls. They are widely abused for unsolicited sales and sometimes fraud. Genuine service calls use the 160 series.")
    if kind == "svc160":
        add("svc160", 0, "info", "160-series (service / transactional) number", "Banks and other regulated firms use this series for genuine service calls – but numbers can be spoofed, so never share OTPs or PINs even if it looks official.")
    if kind == "tollfree":
        add("tollfree", 0, "info", "Toll-free number", "Real companies use toll-free numbers, but scammers copy them. Check the number on the company's own website before calling back.")
    if kind == "landline":
        add("landline", 0, "info", "Landline (STD) number", "Landlines are hard to fake but not impossible. Police, banks and courts do not make threats or demand money by phone.")
    if kind == "helpline":
        add("helpline", -20, "good", f"Matches a national helpline: {R.NUMBER_HELPLINES[nat]}", "This is a genuine public service number. If someone calls you *from* it demanding money or codes, it is spoofed – hang up and dial it yourself.")
    if kind == "short":
        add("short", 8, "warn", "Short code that can't be verified", "Short codes belong to businesses or networks. This one isn't a known public helpline, so check the sender's official website.")
    if kind in ("mobile", "intl", "invalid-in", "tm140"):
        for c in _pattern_checks(nat):
            add(*c)

    # what the caller said / asked
    for cid in context:
        c = _CTX[cid]
        add("ctx." + cid, c["w"], "bad" if c["w"] >= 30 else "warn", c["label"], c["why"])
    if p["cc"] == "91" and kind in ("mobile", "tm140", "invalid-in") and any(i in context for i in ("authority", "bank", "threat")):
        add("official-mobile", 20, "bad", "Officials don't use personal mobile numbers for this",
            "Police, courts, tax and bank officers do not phone from ordinary mobile numbers to demand money, codes or secrecy.")

    if not any(c["status"] in ("bad", "warn") for c in checks):
        add("clean", 0, "good", "No warning signs in the number itself",
            "That doesn't prove the caller is genuine. Tick what they asked for below to get a better assessment.")

    score = _round(100 * (1 - math.exp(-max(0, total) / 50))) if total > 0 else 0
    floors = []
    for f in R.NUMBER_FLOORS:
        if all(i in context for i in f["all"]) and f["min"] > score:
            score = f["min"]
            floors = [f["why"]]
    score = max(0, min(100, score))
    level = level_for(score)
    out.update(checks=checks, score=score, level=level, floors=floors)
    out["verdict"] = {
        "Low": "No strong warning signs. Stay alert and verify before sharing anything.",
        "Medium": "Some warning signs. Verify through an official channel before acting.",
        "High": "Likely a scam call or message. Don't engage, share codes or send money.",
        "Critical": "Very likely fraud. Hang up, don't pay or share anything, and report it.",
    }[level]

    recs, used = [], set()

    def push(r):
        if r["text"] not in used:
            used.add(r["text"])
            recs.append(r)
    if level in ("High", "Critical"):
        push({"icon": "ban", "text": "Hang up or stop replying. Do not call back, share codes, install anything or pay. Block the number."})
    for cid in context:
        if cid in R.NUMBER_RECS:
            push(R.NUMBER_RECS[cid])
    for r in R.RECS["base"][:1] + R.RECS["base"][2:]:
        push(r)
    if level in ("Medium", "High", "Critical"):
        for r in R.RECS["report"]:
            push(r)
    out["recommendations"] = recs
    return out


# ---------------------------------------------------------------- scam emergency assistant (v7)
_EM = {i["id"]: i for i in R.EMERGENCY["incidents"]}
EM_PRIORITY = ["Now", "Within 1 hour", "Within 24 hours"]


def build_emergency(incidents, timing="today"):
    """Ordered recovery plan for what the person says happened. Unknown ids are ignored; nothing is stored."""
    ids = [i for i in dict.fromkeys(incidents or []) if isinstance(i, str) and i in _EM]
    if not ids:
        return {"valid": False, "error": "Tell us what happened so we can give you the right steps."}
    if timing not in R.EMERGENCY["timing"]:
        timing = "today"
    seen, steps = set(), []

    def add(pri, txt):
        if txt not in seen:
            seen.add(txt)
            steps.append({"priority": pri, "text": txt})

    for i in ids:
        for pri, txt in _EM[i]["steps"]:
            add(pri, txt)
    for pri, txt in R.EMERGENCY["always"]:
        add(pri, txt)
    steps.sort(key=lambda s: EM_PRIORITY.index(s["priority"]))  # stable: keeps incident order inside each band
    urgent = any(_EM[i]["urgent"] for i in ids)
    return {
        "valid": True, "ok": True,
        "urgency": "Act now" if (urgent or timing == "just") else "Act soon",
        "timing": timing, "timing_note": R.EMERGENCY["timing"][timing],
        "incidents": [{"id": i, "label": _EM[i]["label"]} for i in ids],
        "steps": steps, "helplines": R.EMERGENCY["helplines"], "disclaimer": R.EMERGENCY["disclaimer"],
    }
