"""ScamShield detection rules – the single source of truth.

Both the Python engine (engine.py) and the in-browser engine (index.html) read these rules.
After editing this file run:   python3 backend/sync_rules.py
which regenerates backend/rules.json and re-embeds the rules into index.html.

All regular expressions are case-insensitive and written to work in both Python `re` and JavaScript.
"""

# ---------------------------------------------------------------- categories
CATEGORIES = [
    {"id": "bank",     "label": "Fake bank alert",         "icon": "bank"},
    {"id": "kyc",      "label": "KYC update scam",         "icon": "id"},
    {"id": "otp",      "label": "OTP theft attempt",       "icon": "key"},
    {"id": "delivery", "label": "Fake delivery notice",    "icon": "box"},
    {"id": "lottery",  "label": "Lottery / prize scam",    "icon": "gift"},
    {"id": "gov",      "label": "Government impersonation","icon": "landmark"},
    {"id": "phishing", "label": "Phishing link",           "icon": "link"},
    {"id": "job",      "label": "Fake job offer",          "icon": "briefcase"},
    {"id": "upi",      "label": "UPI payment scam",        "icon": "wallet"},
]

# Phrases that signal a *genuine* security notice. They are masked out before scam rules run
# (so "Do not share your OTP" is never read as "share your OTP") and earn a small score reduction.
PROTECT = [
    r"\b(?:do not|don'?t|never|dont|please do not|kindly do not)\s+(?:share|disclose|give|reveal|tell|forward)[^.\n]{0,40}?\b(?:otp|pin|mpin|password|cvv|code|passcode)\b[^.\n]{0,25}",
    r"\bvalid for\s+\d+\s*(?:min(?:ute)?s?|mins)\b",
    r"\b(?:bank|we|sbi|hdfc|icici|axis)\s+(?:will\s+)?never\s+ask\b[^.\n]{0,40}",
]
PROTECT_WEIGHT = -25

# ---------------------------------------------------------------- signals
# id, cat, w (weight), tactic, label, why, pats
SIGNALS = [
    # ---- pressure / threat / generic
    {"id": "gen.urgency", "cat": "general", "w": 10, "tactic": "Pressure", "label": "Artificial urgency",
     "why": "Scammers create time pressure so you act before you think. Genuine organisations rarely demand action within hours.",
     "pats": [r"\b(?:urgent(?:ly)?|immediate(?:ly)?|right now|act now|asap|last (?:chance|warning|reminder)|expires? (?:today|soon|in)|within \d+ ?(?:hours?|hrs?|minutes?|mins?)|within (?:one|two|24|48) ?(?:hours?|hrs?)|today only|hurry|before midnight|final notice|without delay)\b"]},
    {"id": "gen.threat", "cat": "general", "w": 14, "tactic": "Threat", "label": "Threat of blocking, penalty or legal action",
     "why": "Fear is the scammer's main lever: 'your account will be blocked' or 'legal action' pushes you to comply.",
     "pats": [r"\b(?:account|card|sim|number|service|connection|upi|wallet|net ?banking|a/c)\s+(?:will be|has been|is|are|got)\s+(?:temporarily\s+|permanently\s+)?(?:blocked|suspended|frozen|closed|deactivated|disabled|locked|limited|disconnected|cancelled|barred)\b",
              r"\b(?:legal action|penalty|prosecut\w+|permanent(?:ly)? (?:closure|blocked|suspended)|will be (?:blocked|suspended|deactivated|terminated|returned))\b"]},
    {"id": "gen.greeting", "cat": "general", "w": 6, "tactic": "Impersonation", "label": "Generic greeting",
     "why": "Real banks and couriers usually address you by name. 'Dear customer' suggests a mass-sent message.",
     "pats": [r"\b(?:dear (?:customer|user|sir|madam|sir/madam|valued|account ?holder|client|beneficiary|winner|member)|valued customer|hello (?:customer|user|dear))\b"]},
    {"id": "gen.money", "cat": "general", "w": 12, "tactic": "Payment", "label": "Asks you to pay or transfer money",
     "why": "Unexpected requests to pay, transfer or deposit money are the end goal of most scams.",
     "pats": [r"\b(?:pay|transfer|deposit|send|remit)\b[^.\n]{0,25}?(?:₹|rs\.?|inr|\$|usd)\s?\d[\d,]*"]},
    {"id": "gen.callback", "cat": "general", "w": 8, "tactic": "Off-platform", "label": "Pushes you to call or message a number",
     "why": "Scammers move you to a phone call or chat where they can pressure you without any filters.",
     "pats": [r"\b(?:call|contact|whatsapp|dial|reach|text)\b[^.\n]{0,30}?(?:\+?\d[\d \-]{8,14}\d)"]},
    {"id": "gen.remote", "cat": "general", "w": 35, "tactic": "Data request", "label": "Asks you to install a remote-access app",
     "why": "Apps like AnyDesk or TeamViewer let a stranger see and control your phone, including your banking apps. No genuine bank asks for this.",
     "pats": [r"\b(?:anydesk|any desk|teamviewer|team viewer|quick ?support|rustdesk|airdroid|ultraviewer|screen ?sharing?|share (?:your )?screen|remote (?:access|support|control))\b"]},
    {"id": "gen.apk", "cat": "general", "w": 30, "tactic": "Data request", "label": "Asks you to install an app / APK file",
     "why": "Apps installed outside the official Play Store or App Store can steal SMS, OTPs and banking data.",
     "pats": [r"\b[\w\-.]+\.apk\b", r"\b(?:install|download)\s+(?:this|the|our)\s+(?:app|apk|application)\b"]},
    {"id": "gen.newnumber", "cat": "general", "w": 18, "tactic": "Impersonation", "label": "'This is my new number' family impersonation",
     "why": "Scammers pretend to be a relative on a new number and then ask for urgent money. Call the person on their old number to check.",
     "pats": [r"\b(?:this is my new number|my new number|new number|lost my phone|phone (?:broke|is broken|got stolen|fell))\b", r"\b(?:hi|hello|hey) (?:mum|mom|mummy|dad|papa|bhaiya|didi)\b"]},
    {"id": "gen.sensitive", "cat": "bank", "w": 20, "tactic": "Data request", "label": "Asks for card, password or ID details",
     "why": "Banks never ask you to type card numbers, CVV, passwords or ID numbers into a message or a link.",
     "pats": [r"\b(?:enter|share|send|provide|submit|confirm|update|verify|reply with)\b[^.\n]{0,40}?\b(?:card (?:number|details)|cvv|expiry|password|net ?banking (?:id|password|details)|login (?:id|details)|aadhaar|aadhar|pan (?:card )?(?:number|details))\b"]},

    # ---- bank
    {"id": "bank.mention", "cat": "bank", "w": 6, "tactic": "Impersonation", "label": "Mentions a bank",
     "why": "Bank names are borrowed to look trustworthy. A bank name alone proves nothing.",
     "pats": [r"\b(?:sbi|hdfc|icici|axis bank|kotak|pnb|punjab national|bank of baroda|canara|union bank|yes bank|idfc|indusind|yono|netbanking|net banking)\b"]},
    {"id": "bank.verify", "cat": "bank", "w": 16, "tactic": "Data request", "label": "Asks you to verify / reactivate your account",
     "why": "Genuine banks don't ask you to verify or reactivate accounts through links in SMS or WhatsApp.",
     "pats": [r"\b(?:verify|update|reactivate|re-?activate|unlock|restore|secure|confirm|validate)\b[^.\n]{0,30}?\b(?:account|card|net ?banking|wallet|details|identity)\b"]},
    {"id": "bank.unusual", "cat": "bank", "w": 12, "tactic": "Threat", "label": "Claims of unusual or unauthorised activity",
     "why": "'Suspicious activity' alerts are a common bait to make you panic and click.",
     "pats": [r"\b(?:unusual|suspicious|unauthori[sz]ed|fraudulent)\s+(?:activity|login|transaction|access|attempt|sign-?in)\b"]},
    {"id": "bank.points", "cat": "bank", "w": 18, "tactic": "Pressure", "label": "Expiring reward points",
     "why": "'Your reward points expire today – redeem now' is a classic credit-card phishing lure.",
     "pats": [r"\b(?:reward|credit card|loyalty)\s+points?\b[^.\n]{0,40}?\b(?:expire[sd]?|redeem|lapse)\b"]},

    # ---- kyc
    {"id": "kyc.update", "cat": "kyc", "w": 28, "tactic": "Data request", "label": "KYC update / expiry demand",
     "why": "KYC scams claim your account will be blocked unless you 'update KYC' through a link. Banks complete KYC at a branch or in their official app.",
     "pats": [r"\bkyc\b[^.\n]{0,50}?\b(?:expire[sd]?|pending|update[sd]?|incomplete|verif\w+|suspend\w*|block\w*|invalid|failed|mandatory)\b",
              r"\b(?:update|complete|verify|renew|submit)\b[^.\n]{0,20}?\bkyc\b", r"\bre-?kyc\b"]},
    {"id": "kyc.docs", "cat": "kyc", "w": 10, "tactic": "Data request", "label": "PAN / Aadhaar linking or verification",
     "why": "Messages saying your PAN or Aadhaar is 'inactive' or 'needs linking' via a link are a common data-theft trick.",
     "pats": [r"\b(?:pan|aadhaar|aadhar)\b[^.\n]{0,30}?\b(?:link\w*|update[sd]?|verif\w+|expire[sd]?|invalid|inactive|blocked)\b"]},

    # ---- otp
    {"id": "otp.request", "cat": "otp", "w": 32, "tactic": "Data request", "label": "Asks you to share an OTP / PIN / code",
     "why": "An OTP is a key to your money. Nobody genuine – not a bank, courier or friend – needs you to read it out or send it back.",
     "pats": [r"\b(?:share|send|tell|give|read(?: out)?|forward|reply(?: with)?|provide)\b[^.\n]{0,30}?\b(?:otp|one[- ]time (?:password|pin|code)|verification code|security code|upi pin|mpin|atm pin|cvv|the code|6[- ]digit code|\d[- ]digit code)\b",
              r"\b(?:otp|code)\b[^.\n]{0,25}?\b(?:send(?: it)? (?:back|me)|share (?:it )?with (?:me|us))\b"]},
    {"id": "otp.mistake", "cat": "otp", "w": 28, "tactic": "Pretext", "label": "'Sent my code to you by mistake' pretext",
     "why": "The 'I sent my OTP to your number by mistake' story tricks you into forwarding a code that actually belongs to YOUR account.",
     "pats": [r"\b(?:sent|received|came|went)\b[^.\n]{0,40}?\b(?:by mistake|wrongly|accidentally|to (?:the )?wrong number)\b[^.\n]{0,60}?\b(?:code|otp)\b",
              r"\b(?:code|otp)\b[^.\n]{0,50}?\b(?:by mistake|accidentally|wrongly)\b"]},

    # ---- delivery
    {"id": "delivery.fail", "cat": "delivery", "w": 22, "tactic": "Pretext", "label": "Delivery problem notice",
     "why": "Fake 'delivery failed / incomplete address' notices lure you to a link that asks for card details.",
     "pats": [r"\b(?:parcel|package|shipment|consignment|courier|order|delivery)\b[^.\n]{0,60}?\b(?:held|on hold|failed|undelivered|could not be delivered|unable to (?:deliver|be delivered)|pending|returned|stuck|customs|incomplete address|address (?:is )?(?:incomplete|invalid|issue)|not delivered)\b",
              r"\bincomplete address\b"]},
    {"id": "delivery.fee", "cat": "delivery", "w": 26, "tactic": "Payment", "label": "Small 'redelivery' or 'customs' fee",
     "why": "A tiny fee is the hook – the payment page captures your card or UPI PIN. Couriers don't collect fees through SMS links.",
     "pats": [r"\b(?:redelivery|re-delivery|customs|clearance|delivery|shipping|handling|storage|reschedul\w+)\s+(?:fee|fees|charge|charges|duty|payment)\b",
              r"\bpay\b[^.\n]{0,25}?(?:₹|rs\.?|inr|\$)\s?\d[\d,]*[^.\n]{0,40}?\b(?:delivery|parcel|package|shipment)\b"]},
    {"id": "delivery.brand", "cat": "delivery", "w": 6, "tactic": "Impersonation", "label": "Mentions a courier or postal service",
     "why": "Courier brand names are commonly forged.",
     "pats": [r"\b(?:india post|indiapost|speed post|fedex|dhl|bluedart|blue dart|delhivery|ecom express|dtdc|ups|royal mail|usps|xpressbees)\b"]},

    # ---- lottery
    {"id": "lottery.win", "cat": "lottery", "w": 28, "tactic": "Reward", "label": "'You have won' prize claim",
     "why": "You can't win a contest you never entered. Unexpected prize messages are bait for fees and personal data.",
     "pats": [r"\b(?:you (?:have |'ve )?(?:won|been selected|are (?:the )?(?:lucky )?winner)|lucky (?:draw|winner|customer)|jackpot|lottery|kbc|bumper (?:prize|draw)|prize money|won (?:a|an|₹|rs\.?|\$))\b"]},
    {"id": "lottery.generic", "cat": "lottery", "w": 10, "tactic": "Reward", "label": "Prize / free-gift language",
     "why": "Over-the-top rewards ('free iPhone', gift vouchers) are used to lower your guard.",
     "pats": [r"\b(?:congratulations?|congrats|free (?:iphone|gift|recharge|data)|gift (?:card|voucher)|cash ?back (?:offer|reward)|lucky)\b"]},
    {"id": "lottery.fee", "cat": "lottery", "w": 30, "tactic": "Payment", "label": "Fee required to claim a prize",
     "why": "Real prizes never need an upfront 'processing fee' or 'tax'. This is the core of an advance-fee scam.",
     "pats": [r"\b(?:processing|claim|tax|release|clearing|gst|insurance)\s+(?:fee|fees|charge|charges|amount|tax)\b",
              r"\b(?:claim|collect|receive|get)\b[^.\n]{0,30}?\b(?:prize|reward|gift|winning|lottery)\b"]},

    # ---- government
    {"id": "gov.impersonation", "cat": "gov", "w": 18, "tactic": "Impersonation", "label": "Claims to be a government or law-enforcement body",
     "why": "Scammers pose as police, tax, customs or telecom authorities to scare you into obeying.",
     "pats": [r"\b(?:income tax|it department|itr|rbi|reserve bank|cbi|enforcement directorate|cyber ?crime|narcotics|customs (?:department|officer)|police|inspector|trai|uidai|epfo|pm[- ]kisan|ministry|supreme court|high court|court notice|traffic (?:police|challan)|e-?challan|rto|electricity (?:board|department)|government of india|govt\.? of india)\b"]},
    {"id": "gov.threat", "cat": "gov", "w": 32, "tactic": "Threat", "label": "Arrest / 'digital arrest' / case-registered threat",
     "why": "'Digital arrest' is not a legal concept in India. Police and agencies never arrest anyone over a video call or demand money to 'clear' a case.",
     "pats": [r"\b(?:digital arrest|arrest warrant|(?:you )?(?:will|are going to) be arrested|money laundering|illegal (?:parcel|items|goods|drugs)|drugs? (?:found|in (?:your )?(?:parcel|package))|(?:your )?(?:sim|mobile number|aadhaar) (?:is|has been|will be) (?:linked|used|involved|blocked)|case (?:against you|has been registered|is registered)|stay on (?:the )?(?:video )?call|do not (?:disconnect|tell anyone)|don'?t tell anyone|safe account)\b"]},
    {"id": "gov.refund", "cat": "gov", "w": 24, "tactic": "Reward", "label": "Refund / subsidy / pending fine bait",
     "why": "Fake tax refunds, subsidies and 'pending challan' notices are used to harvest bank logins or payments.",
     "pats": [r"\b(?:tax|income tax|gst|pm[- ]kisan|subsidy|govt\.?|government)\s+(?:refund|rebate|benefit|subsidy)\b[^.\n]{0,50}?\b(?:claim|credit\w*|pending|approved|click|apply)\b",
              r"\brefund\b[^.\n]{0,30}?\b(?:approved|pending|credited)\b",
              r"\b(?:pending|unpaid|overdue)\s+(?:e-?challan|fine|traffic fine|electricity bill|bill)\b"]},

    # ---- job
    {"id": "job.offer", "cat": "job", "w": 24, "tactic": "Reward", "label": "Too-good-to-be-true job offer",
     "why": "High pay for simple tasks and 'no experience needed' is the signature of task and job scams.",
     "pats": [r"\b(?:work from home|part[- ]time (?:job|work)|online (?:job|work)|earn (?:up to |upto )?(?:₹|rs\.?|inr|\$)?\s?\d[\d,]*\s*(?:/|per|a)?\s*(?:day|daily|week|month|hour)|daily (?:income|payout|payment|salary)|no experience (?:needed|required)|data entry job|hiring urgently|simple tasks?|(?:liking|like) (?:and )?(?:subscrib\w+|videos?|youtube)|review(?:ing)? (?:products|hotels)|task[- ]based)\b"]},
    {"id": "job.fee", "cat": "job", "w": 30, "tactic": "Payment", "label": "Fee or deposit to get the job",
     "why": "Genuine employers never charge for registration, training or 'security deposits'.",
     "pats": [r"\b(?:registration|training|security|joining|kit|refundable|verification|activation)\s+(?:fee|fees|charge|charges|deposit|amount)\b",
              r"\bpay\b[^.\n]{0,30}?\bto (?:join|register|start|activate)\b",
              r"\b(?:deposit|invest)\b[^.\n]{0,40}?\bto (?:start|unlock|activate|receive|earn)\b"]},
    {"id": "job.channel", "cat": "job", "w": 14, "tactic": "Off-platform", "label": "Recruiter only reachable on WhatsApp / Telegram",
     "why": "Recruiting through private chat apps hides the scammer and lets them avoid platform checks.",
     "pats": [r"\b(?:whatsapp|telegram|dm)\b[^.\n]{0,30}?\b(?:hr|recruiter|manager|agent|admin)\b", r"\bt\.me/\S+", r"\bwa\.me/\S+", r"\bjoin (?:our )?(?:telegram|whatsapp) (?:group|channel)\b"]},

    # ---- upi
    {"id": "upi.collect", "cat": "upi", "w": 32, "tactic": "Data request", "label": "Tricks you into approving a payment / entering UPI PIN to 'receive' money",
     "why": "You never need a PIN, QR scan or 'approval' to RECEIVE money. These steps only ever send money out of your account.",
     "pats": [r"\b(?:collect|payment) request\b[^.\n]{0,50}?\b(?:approve|accept|enter)\b",
              r"\b(?:approve|accept)\b[^.\n]{0,25}?\b(?:collect|payment) request\b",
              r"\b(?:enter|share)\b[^.\n]{0,20}?\b(?:upi )?pin\b[^.\n]{0,40}?\b(?:receive|refund|credit|get (?:the )?money|cashback)\b",
              r"\bscan\b[^.\n]{0,20}?\b(?:qr|code)\b[^.\n]{0,40}?\b(?:receive|refund|get|credit|claim)\b",
              r"\bto receive (?:money|payment|refund|cashback)\b[^.\n]{0,40}?\b(?:pin|scan|qr)\b"]},
    {"id": "upi.mistake", "cat": "upi", "w": 26, "tactic": "Pretext", "label": "'Paid by mistake, please return' story",
     "why": "Fraudsters claim a wrong transfer, then ask for money back – sometimes after a fake or reversible credit.",
     "pats": [r"\b(?:sent|transferred|paid|credited)\b[^.\n]{0,25}?\b(?:by mistake|wrongly|accidentally|to (?:the )?wrong (?:number|account))\b[^.\n]{0,60}?\b(?:return|refund|send(?: it)? back|back)\b",
              r"\b(?:return|send back|refund)\b[^.\n]{0,20}?\b(?:my|the) (?:money|amount|payment)\b"]},
    {"id": "upi.app", "cat": "upi", "w": 5, "tactic": "Impersonation", "label": "Mentions a UPI / wallet app",
     "why": "Payment app names are used to sound credible.",
     "pats": [r"\b(?:upi|phonepe|gpay|google pay|paytm|bhim|vpa)\b"]},
    {"id": "upi.id", "cat": "upi", "w": 10, "tactic": "Payment", "label": "Contains a UPI ID",
     "why": "A UPI ID inside an unsolicited message is a payment destination. Verify who owns it before sending anything.",
     "pats": [r"\b[\w.\-]{2,}@(?:ok(?:hdfc|sbi|icici|axis)bank|ybl|paytm|axl|ibl|upi|oksbi|apl|fbl)\b"]},
]

# ---------------------------------------------------------------- hard floors
# (all ids must be matched)  ->  minimum score and reason
FLOORS = [
    {"any": ["otp.request"],                         "min": 70, "why": "Asking you to hand over an OTP/PIN/CVV is never legitimate."},
    {"any": ["otp.mistake"],                         "min": 65, "why": "The 'sent my code by mistake' story is a known OTP-theft trick."},
    {"all": ["lottery.win", "lottery.fee"],          "min": 85, "why": "A prize that requires a fee is an advance-fee scam."},
    {"any": ["gov.threat"],                          "min": 80, "why": "Threats of arrest or 'digital arrest' are a known extortion script."},
    {"any": ["gen.remote"],                          "min": 70, "why": "Remote-access apps give a stranger control of your phone."},
    {"any": ["gen.apk"],                             "min": 70, "why": "Installing apps from messages is how banking malware spreads."},
    {"any": ["upi.collect"],                         "min": 70, "why": "Approving a collect request or entering a PIN sends money out."},
    {"any": ["job.fee"],                             "min": 75, "why": "A job that charges a fee is not a job."},
    {"all": ["delivery.fee", "link"],                "min": 75, "why": "A delivery 'fee' paid through a link is a classic card-theft page."},
]

# ---------------------------------------------------------------- URL analysis data
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "ow.ly",
              "bl.ink", "rebrand.ly", "buff.ly", "s.id", "t.ly", "v.gd", "shorte.st", "lnkd.in", "adf.ly", "qr.ae", "l.ead.me", "urlz.fr"]
SUSPICIOUS_TLDS = ["xyz", "top", "click", "live", "icu", "cfd", "sbs", "buzz", "vip", "work", "support", "rest", "tk", "ml", "ga",
                   "cf", "gq", "zip", "mov", "monster", "cyou", "fun", "life", "today", "world", "pw", "ru", "loan", "men", "download",
                   "country", "stream", "gdn", "bid", "win", "review", "party", "trade", "accountant", "racing", "date", "faith", "science"]
FREE_HOSTS = ["blogspot.com", "weebly.com", "wixsite.com", "netlify.app", "vercel.app", "github.io", "web.app", "firebaseapp.com",
              "pages.dev", "glitch.me", "herokuapp.com", "ngrok.io", "ngrok-free.app", "workers.dev", "000webhostapp.com",
              "duckdns.org", "onrender.com", "webflow.io", "carrd.co", "sites.google.com"]
SECOND_LEVEL = ["co.in", "gov.in", "nic.in", "org.in", "net.in", "ac.in", "res.in", "edu.in", "co.uk", "org.uk", "gov.uk",
                "com.au", "co.za", "com.br", "co.jp", "com.sg", "com.pk", "com.bd", "co.nz"]
# token -> brand. exact=True means the token must be a whole hyphen/dot-separated label (avoids false hits like "taxis")
BRANDS = [
    {"name": "SBI",            "tokens": ["sbi", "onlinesbi", "yono"],    "exact": True,  "domains": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "bank.sbi", "yonosbi.com"]},
    {"name": "HDFC Bank",      "tokens": ["hdfc", "hdfcbank"],            "exact": False, "domains": ["hdfcbank.com", "hdfc.com", "hdfclife.com", "hdfcergo.com"]},
    {"name": "ICICI Bank",     "tokens": ["icici", "icicibank"],          "exact": False, "domains": ["icicibank.com", "icicilombard.com", "iciciprulife.com"]},
    {"name": "Axis Bank",      "tokens": ["axisbank", "axis"],            "exact": True,  "domains": ["axisbank.com", "axis.bank.in"]},
    {"name": "Kotak",          "tokens": ["kotak"],                       "exact": False, "domains": ["kotak.com", "kotakbank.com"]},
    {"name": "PNB",            "tokens": ["pnb", "pnbindia"],             "exact": True,  "domains": ["pnbindia.in", "netpnb.com"]},
    {"name": "Paytm",          "tokens": ["paytm"],                       "exact": False, "domains": ["paytm.com", "paytmbank.com"]},
    {"name": "PhonePe",        "tokens": ["phonepe"],                     "exact": False, "domains": ["phonepe.com"]},
    {"name": "Google Pay",     "tokens": ["gpay", "googlepay"],           "exact": False, "domains": ["pay.google.com", "google.com"]},
    {"name": "Amazon",         "tokens": ["amazon", "amzn"],              "exact": False, "domains": ["amazon.in", "amazon.com", "amazon.co.uk", "amzn.in", "amzn.to", "amazon.jobs"]},
    {"name": "Flipkart",       "tokens": ["flipkart"],                    "exact": False, "domains": ["flipkart.com", "fkrt.it"]},
    {"name": "India Post",     "tokens": ["indiapost", "indiaspeedpost"], "exact": False, "domains": ["indiapost.gov.in"]},
    {"name": "Income Tax India","tokens": ["incometax", "incometaxindia"],"exact": False, "domains": ["incometax.gov.in", "incometaxindia.gov.in"]},
    {"name": "UIDAI / Aadhaar","tokens": ["uidai", "aadhaar", "aadhar"],  "exact": False, "domains": ["uidai.gov.in", "myaadhaar.uidai.gov.in"]},
    {"name": "IRCTC",          "tokens": ["irctc"],                       "exact": False, "domains": ["irctc.co.in", "irctc.com"]},
    {"name": "EPFO",           "tokens": ["epfo", "epfindia"],            "exact": False, "domains": ["epfindia.gov.in", "epfindia.com"]},
    {"name": "FedEx",          "tokens": ["fedex"],                       "exact": False, "domains": ["fedex.com"]},
    {"name": "DHL",            "tokens": ["dhl"],                         "exact": True,  "domains": ["dhl.com", "dhl.de"]},
    {"name": "Blue Dart",      "tokens": ["bluedart"],                    "exact": False, "domains": ["bluedart.com"]},
    {"name": "Delhivery",      "tokens": ["delhivery"],                   "exact": False, "domains": ["delhivery.com"]},
    {"name": "Google",         "tokens": ["google", "gmail"],             "exact": False, "domains": ["google.com", "google.co.in", "gmail.com", "googleusercontent.com"]},
    {"name": "Microsoft",      "tokens": ["microsoft", "office365", "outlook"], "exact": False, "domains": ["microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com"]},
    {"name": "Apple",          "tokens": ["apple", "icloud"],             "exact": True,  "domains": ["apple.com", "icloud.com"]},
    {"name": "Netflix",        "tokens": ["netflix"],                     "exact": False, "domains": ["netflix.com"]},
    {"name": "WhatsApp",       "tokens": ["whatsapp"],                    "exact": False, "domains": ["whatsapp.com", "wa.me"]},
    {"name": "Facebook / Instagram", "tokens": ["facebook", "instagram"], "exact": False, "domains": ["facebook.com", "instagram.com", "fb.com", "meta.com"]},
    {"name": "PayPal",         "tokens": ["paypal"],                      "exact": False, "domains": ["paypal.com", "paypal.me"]},
    {"name": "Jio / Airtel",   "tokens": ["jio", "airtel"],               "exact": True,  "domains": ["jio.com", "airtel.in", "airtel.com"]},
]
URL_PATH_WORDS = ["login", "signin", "verify", "secure", "update", "kyc", "otp", "claim", "reward", "prize", "account",
                  "confirm", "wallet", "refund", "bonus", "free", "gift", "payment", "track", "redeliver", "customs", "invoice", "password"]
DOMAIN_WORDS = ["secure", "login", "verify", "kyc", "update", "support", "helpdesk", "alert", "care", "official", "online", "service", "account", "refund", "reward", "claim"]
BARE_TLDS = ["com", "net", "org", "in", "info", "biz", "xyz", "top", "click", "live", "icu", "cfd", "sbs", "buzz", "vip", "work",
             "support", "rest", "tk", "ml", "ga", "cf", "gq", "site", "online", "shop", "store", "link", "cc", "ly", "gl", "gd",
             "me", "io", "app", "page", "fun", "club", "cyou", "monster", "today", "life", "world", "pw", "gy", "co", "gov"]

# ---------------------------------------------------------------- recommendations
RECS = {
    "base": [
        {"icon": "key",   "text": "Never share OTPs, PINs, CVV or passwords with anyone – no genuine bank, courier or officer will ask for them."},
        {"icon": "link",  "text": "Avoid clicking links in unexpected messages. Type the official website or open the official app yourself."},
        {"icon": "phone", "text": "Verify the sender through official channels – use the phone number printed on your card, statement or the company's real website."},
    ],
    "bank":     [{"icon": "bank", "text": "Banks do not 'block' accounts over SMS. Open your bank's official app or call the number on the back of your card to check."}],
    "kyc":      [{"icon": "id", "text": "Complete KYC only at a branch or inside your bank's official app. Never upload PAN/Aadhaar through a message link."}],
    "otp":      [{"icon": "key", "text": "If you already shared an OTP, call your bank immediately to block cards/UPI and change your passwords."}],
    "delivery": [{"icon": "box", "text": "Track parcels only on the courier's official site or the shopping app you ordered from. Real couriers don't charge fees by SMS link."}],
    "lottery":  [{"icon": "gift", "text": "You cannot win a contest you did not enter, and real prizes never need an upfront fee. Do not pay anything to claim a reward."}],
    "gov":      [{"icon": "landmark", "text": "Police, CBI, RBI or tax officers never arrest or settle cases over video call or WhatsApp. 'Digital arrest' is a scam – hang up and call 1930."}],
    "phishing": [{"icon": "link", "text": "Don't open the link. If you did, don't enter any details; close the page and run a security scan on your phone."}],
    "job":      [{"icon": "briefcase", "text": "Genuine employers never charge registration or training fees, and never pay for 'liking videos'. Research the company independently."}],
    "upi":      [{"icon": "wallet", "text": "You never need to enter your UPI PIN or scan a QR code to RECEIVE money. Decline unknown collect requests."}],
    "report": [
        {"icon": "flag", "text": "Report financial fraud on the National Cyber Crime Reporting Portal (cybercrime.gov.in) or call the helpline 1930 – act fast if money is lost."},
        {"icon": "flag", "text": "Report suspicious calls/SMS/WhatsApp on Sanchar Saathi's Chakshu facility (sancharsaathi.gov.in) and block the sender."},
    ],
    "low": [{"icon": "shield", "text": "No strong scam pattern found, but stay alert: if the message asks for money, codes or urgent action, verify it independently."}],
}

# ---------------------------------------------------------------- demo scenarios
DEMOS = [
    {"id": "bank", "title": "Fake bank alert", "channel": "SMS", "tag": "Phishing link",
     "text": "HDFC Bank Alert: Dear Customer, your account has been temporarily blocked due to unusual activity. Verify your details within 24 hours to avoid permanent closure: http://hdfc-secure-verify.top/login"},
    {"id": "kyc", "title": "KYC expiry scare", "channel": "SMS", "tag": "KYC scam",
     "text": "Dear SBI user, your YONO account will be BLOCKED today as KYC has expired. Update PAN & Aadhaar immediately: https://bit.ly/3xKyc-SBI - SBI Team"},
    {"id": "otp", "title": "'Sent my OTP by mistake'", "channel": "WhatsApp", "tag": "OTP theft",
     "text": "Hi, I accidentally sent my OTP to your number while doing a transaction. Please send me back the 6 digit code you got, it's urgent. I'll send you Rs 500 for the help 🙏"},
    {"id": "delivery", "title": "Redelivery fee", "channel": "SMS", "tag": "Fake delivery",
     "text": "India Post: Your parcel #IP884201 could not be delivered due to incomplete address. Pay redelivery fee Rs 25 within 12 hours or the package will be returned: http://indiapost-redelivery.click/track"},
    {"id": "lottery", "title": "KBC lottery win", "channel": "WhatsApp", "tag": "Prize scam",
     "text": "🎉 CONGRATULATIONS!! You have been selected as the lucky winner of KBC Lottery Rs 25,00,000! To claim your prize, pay the processing fee of Rs 4,999 and WhatsApp your Aadhaar to +91 98765 43210"},
    {"id": "gov", "title": "'Digital arrest' call script", "channel": "WhatsApp", "tag": "Govt impersonation",
     "text": "This is Inspector Rao from Mumbai Cyber Crime. A parcel in your name with illegal drugs was intercepted by Customs. A case has been registered and an arrest warrant is issued. Stay on the video call and do not tell anyone. Transfer Rs 80,000 to the RBI safe account to verify your funds."},
    {"id": "job", "title": "Work-from-home task job", "channel": "WhatsApp", "tag": "Fake job",
     "text": "Part time job offer! Work from home and earn Rs 5,000 daily by liking YouTube videos. No experience needed. Pay a one-time registration fee of Rs 999 (refundable). Message our HR on Telegram t.me/easyjobs_hr"},
    {"id": "upi", "title": "Wrong UPI transfer", "channel": "SMS", "tag": "UPI scam",
     "text": "Hello, I have sent Rs 2,000 to your PhonePe by mistake. Please return it. Also you will receive a collect request – approve it and enter your UPI PIN to receive your refund."},
    {"id": "genuine-otp", "title": "Genuine OTP message", "channel": "SMS", "tag": "Looks genuine",
     "text": "123456 is your OTP for login to HDFC Bank NetBanking. Valid for 10 minutes. Do not share this OTP with anyone. - HDFC Bank"},
    {"id": "genuine-appt", "title": "Appointment reminder", "channel": "SMS", "tag": "Looks genuine",
     "text": "Hi Priya, your appointment at Smile Care Dental is confirmed for Tuesday 25 Nov at 4:30 PM. Reply C to confirm or call the clinic if you need to reschedule. See you soon!"},
]

URL_EXAMPLES = [
    {"label": "Fake bank login", "url": "http://hdfc-secure-verify.top/login?session=482"},
    {"label": "Shortened link", "url": "https://bit.ly/3xKyc-SBI"},
    {"label": "IP address link", "url": "http://192.168.45.12:8080/paytm/refund/claim"},
    {"label": "Look-alike domain", "url": "https://www.amaz0n-gift-rewards.xyz/claim"},
    {"label": "Genuine site", "url": "https://www.sbi.co.in/"},
]

QUIZ = [
    {"text": "Your SBI account is blocked. Update KYC now: http://sbi-kyc-update.top", "scam": True,
     "why": "Banks don't block accounts by SMS, and the link is not sbi.co.in – it's a look-alike on a .top domain."},
    {"text": "482910 is your OTP for Amazon login. Valid for 10 mins. Do not share it with anyone.", "scam": False,
     "why": "It only delivers a code you requested and warns you not to share it. No link, no pressure."},
    {"text": "Hi mum, I lost my phone. This is my new number. Can you send Rs 15,000 to this UPI ID urgently?", "scam": True,
     "why": "The 'new number' impersonation scam. Call your relative on their old number or video-call before paying."},
    {"text": "Your order #4521 has shipped and will arrive Thursday. Track it in the Flipkart app under 'My Orders'.", "scam": False,
     "why": "It points you to the official app instead of a link, asks for no money and no details."},
    {"text": "You have won a Rs 12 lakh lucky draw! Pay Rs 3,500 GST today to release your prize.", "scam": True,
     "why": "You can't win a contest you never entered, and real prizes never require a fee."},
]


# ---------------------------------------------------------------- phone-number fraud check
# Country calling codes (a practical subset – enough to name the country for most numbers).
NUMBER_COUNTRIES = {
    "1": "United States / Canada", "7": "Russia / Kazakhstan", "20": "Egypt", "27": "South Africa", "31": "Netherlands",
    "33": "France", "34": "Spain", "39": "Italy", "44": "United Kingdom", "49": "Germany", "52": "Mexico", "55": "Brazil",
    "60": "Malaysia", "61": "Australia", "62": "Indonesia", "63": "Philippines", "64": "New Zealand", "65": "Singapore",
    "66": "Thailand", "81": "Japan", "82": "South Korea", "84": "Vietnam", "86": "China", "90": "Turkey", "91": "India",
    "92": "Pakistan", "93": "Afghanistan", "94": "Sri Lanka", "95": "Myanmar", "98": "Iran", "212": "Morocco",
    "225": "Cote d'Ivoire", "234": "Nigeria", "251": "Ethiopia", "254": "Kenya", "255": "Tanzania", "256": "Uganda",
    "351": "Portugal", "353": "Ireland", "380": "Ukraine", "855": "Cambodia", "856": "Laos", "880": "Bangladesh",
    "886": "Taiwan", "960": "Maldives", "962": "Jordan", "966": "Saudi Arabia", "971": "United Arab Emirates",
    "972": "Israel", "977": "Nepal",
}
# Prefixes Indian users most often report for missed-call, WhatsApp "job/task" and investment scams.
# A foreign prefix alone never proves fraud – it only adds a little weight.
NUMBER_WATCH_CC = ["84", "62", "60", "254", "251", "92", "855", "234", "63"]
NUMBER_HELPLINES = {
    "1930": "National Cyber Crime Helpline", "112": "National Emergency Number", "100": "Police", "101": "Fire",
    "102": "Ambulance", "108": "Emergency ambulance", "181": "Women Helpline", "1091": "Women Helpline (police)",
    "1098": "Childline", "1915": "National Consumer Helpline", "14567": "Elderline",
}
# What the caller said or asked. Ticked by the person; each adds weight.
NUMBER_CONTEXT = [
    {"id": "otp", "w": 45, "label": "Asked for an OTP, PIN, CVV or password",
     "why": "No bank, courier, officer or company ever needs your OTP or PIN. Anyone who asks is trying to take over your account."},
    {"id": "remote", "w": 45, "label": "Asked me to install an app or share my screen (AnyDesk, TeamViewer, APK…)",
     "why": "Remote-access apps let the caller see and control your phone, including your banking apps and incoming OTPs."},
    {"id": "money", "w": 35, "label": "Asked me to send money, pay a fee or accept a UPI request",
     "why": "Upfront fees to 'release' a parcel, prize, refund or loan are the core step of most scams."},
    {"id": "authority", "w": 35, "label": "Said they are police, CBI, customs, a court, TRAI or another authority",
     "why": "Agencies do not investigate, arrest or settle cases over a phone, WhatsApp or video call. 'Digital arrest' does not exist."},
    {"id": "bank", "w": 25, "label": "Said they are from my bank / KYC / card / account block",
     "why": "Banks do not phone from mobile numbers to demand a 'KYC update' or to 'unblock' an account."},
    {"id": "threat", "w": 30, "label": "Threatened arrest, SIM / account blocking or legal action",
     "why": "Fear is the scammer's main tool – real notices arrive in writing through official channels."},
    {"id": "prize", "w": 30, "label": "Said I won a prize, lottery, gift or refund",
     "why": "You cannot win a contest you never entered, and genuine prizes never need an upfront payment."},
    {"id": "job", "w": 30, "label": "Offered a job, part-time task, 'like & earn' or an investment",
     "why": "Paid-to-like-videos and guaranteed-return schemes are the most reported WhatsApp frauds."},
    {"id": "secret", "w": 35, "label": "Told me not to tell anyone or to stay on the line",
     "why": "Isolation stops you from checking with family or the bank. Genuine callers never demand secrecy."},
    {"id": "urgent", "w": 15, "label": "Pressed me to act immediately",
     "why": "Artificial urgency is designed to stop you thinking."},
    {"id": "link", "w": 15, "label": "Sent a link, QR code or file",
     "why": "Links and APK files sent by unknown numbers are the main way phones get infected."},
    {"id": "moveapp", "w": 15, "label": "Asked me to move to WhatsApp or Telegram",
     "why": "Scammers move victims to chat apps where calls and messages are harder to trace."},
    {"id": "callback", "w": 20, "label": "It was a missed call and they want me to call back",
     "why": "'Wangiri' scams ring once and hope you call back – especially numbers from abroad."},
]
# Dangerous combinations set a minimum score (same idea as FLOORS for messages).
NUMBER_FLOORS = [
    {"all": ["remote"], "min": 80, "why": "Remote-access requests are how accounts are emptied."},
    {"all": ["otp"], "min": 75, "why": "Asking for an OTP/PIN is never legitimate."},
    {"all": ["authority", "money"], "min": 85, "why": "An 'official' demanding money matches the digital-arrest scam playbook."},
    {"all": ["authority", "secret"], "min": 85, "why": "An 'official' demanding secrecy matches the digital-arrest scam playbook."},
    {"all": ["authority", "threat"], "min": 80, "why": "Authority plus threats is the standard intimidation script."},
    {"all": ["prize", "money"], "min": 80, "why": "A prize that needs a fee is a scam."},
    {"all": ["job", "money"], "min": 75, "why": "A job or investment that needs money upfront is a scam."},
    {"all": ["bank", "urgent"], "min": 60, "why": "Urgent 'bank' calls from unknown numbers are almost always phishing."},
]
NUMBER_RECS = {
    "otp": {"icon": "key", "text": "If you already shared an OTP or PIN, call your bank now to block cards and UPI, then change your passwords."},
    "remote": {"icon": "ban", "text": "If you installed an app, uninstall it, switch on airplane mode, and call your bank and 1930 immediately."},
    "authority": {"icon": "landmark", "text": "Hang up. Police, CBI or customs never arrest or 'verify' anyone over a call – 'digital arrest' is a scam."},
    "bank": {"icon": "bank", "text": "Call your bank back only on the number printed on your card or on its official website."},
    "money": {"icon": "wallet", "text": "If you already paid, call 1930 within the first hour – that is when money can most often be frozen."},
    "prize": {"icon": "gift", "text": "Do not pay anything to 'claim' a prize or refund."},
    "job": {"icon": "briefcase", "text": "Genuine employers never take fees or pay for liking videos. Research the company independently."},
}


# ---------------------------------------------------------------- v7: multilingual (Hindi, Bengali, Assamese, Hinglish)
# Indic-script patterns deliberately avoid \b: in both Python and JavaScript \b is ASCII-only and
# misbehaves around Devanagari / Bengali vowel signs. They use plain alternation and [^।.\n] windows.
# Native-speaker review of the wording lists is recommended before production use.
_ML_PROTECT = [
    r"(?:ओटीपी|OTP|ওটিপি)[^।.\n]{0,60}?(?:न करें|করবেন না|নকৰিব)",          # Hindi / Bengali / Assamese "do not share"
]

_ML_EXTRA = {
    "gen.urgency": [
        r"(?:तुरंत|तुरन्त|फौरन|अभी ही|जल्दी करें|জলদি|তৎক্ষণাৎ|এখনই|তাড়াতাড়ি|অবিলম্বে)",
    ],
    "gen.threat": [
        r"(?:बंद हो जाएगा|बंद हो जाएगी|ब्लॉक हो जाएगा|ब्लॉक हो जाएगी|बंद कर दिया जाएगा)",
        r"(?:ব্লক হয়ে যাবে|বন্ধ হয়ে যাবে|বন্ধ হ'ব|বন্ধ হ’ব|বন্ধ হবে|ব্লক হবে|স্থগিত হবে)",
        r"\b(?:account|khata)\s+(?:band|block)\s+ho\s+(?:jayega|jayegi|jaega|jaayega)\b",
    ],
    "gen.greeting": [
        r"(?:प्रिय (?:ग्राहक|उपयोगकर्ता|सदस्य)|प्रिय यूज़र)",
        r"(?:প্রিয় গ্রাহক|প্রিয় ব্যবহারকারী)",
    ],
    "gen.money": [
        r"(?:पैसे|रुपये|रुपए|₹)\s?[\d०-९,]+[^।.\n]{0,25}?(?:भेजें|भेजो|जमा करें|ट्रांसफर करें|दें|दो)",
        r"[\d০-৯,]+\s?(?:টাকা|রুপি)[^।\n]{0,25}?(?:পাঠান|পাঠাও|জমা|দিন|ট্রান্সফার)",
    ],
    "gen.remote": [
        r"(?:स्क्रीन शेयर|स्क्रीन साझा|फोन का कंट्रोल|স্ক্রিন শেয়ার|ফোন কন্ট্রোল)",
    ],
    "gen.apk": [
        r"(?:इंस्टॉल)[^।.\n]{0,25}?(?:ऐप|एप्लिकेशन|एप)",
        r"(?:ऐप|एप्लिकेशन|एप)[^।.\n]{0,25}?(?:इंस्टॉल)",
        r"(?:ইনস্টল)[^।\n]{0,25}?(?:অ্যাপ|এপ)",
        r"(?:অ্যাপ|এপ)[^।\n]{0,25}?(?:ইনস্টল)",
    ],
    "gen.sensitive": [
        r"(?:कार्ड नंबर|कार्ड नम्बर|सीवीवी|पासवर्ड|आधार नंबर|आधार नम्बर|पैन नंबर)[^।.\n]{0,30}?(?:भेजें|भरें|डालें|बताएं|दर्ज करें|अपडेट करें)",
        r"(?:কার্ড নম্বর|সিভিভি|পাসওয়ার্ড|আধার নম্বর)[^।\n]{0,30}?(?:পাঠান|দিন|লিখুন|শেয়ার|আপডেট)",
    ],
    "gen.newnumber": [
        r"(?:यह मेरा नया नंबर|मेरा नया नंबर|नया नंबर|फोन खो गया|फोन टूट गया)",
        r"(?:আমার নতুন নম্বর|নতুন নম্বর|ফোন হারিয়ে)",
        r"(?:नमस्ते|हाय)\s?(?:मम्मी|मम्मा|पापा|दीदी|भैया)",
    ],
    "bank.mention": [
        r"(?:बैंक|बेंक|ব্যাংক|ব্যাঙ্ক|বেংক|এসবিআই|এছবিআই|এইচডিএফসি)",
    ],
    "bank.verify": [
        r"(?:अपडेट|वेरिफाई|सत्यापित|सक्रिय करें|चालू करें|अनब्लॉक)[^।.\n]{0,30}?(?:खाता|खाते|अकाउंट|कार्ड|नेट ?बैंकिंग)",
        r"(?:আপডেট|ভেরিফাই|যাচাই|সক্রিয়|চালু)[^।\n]{0,30}?(?:অ্যাকাউন্ট|একাউন্ট|একাউণ্ট|কার্ড|নেট ?ব্যাংকিং)",
    ],
    "bank.unusual": [
        r"(?:संदिग्ध|अनधिकृत|असामान्य)[^।.\n]{0,25}?(?:गतिविधि|लेनदेन|लॉगिन|ट्रांजैक्शन)",
        r"(?:সন্দেহজনক|অননুমোদিত|অস্বাভাবিক)[^।\n]{0,25}?(?:লেনদেন|কার্যকলাপ|লগইন)",
    ],
    "kyc.update": [
        r"(?:केवाईसी|केवाइसी|KYC)[^।.\n]{0,50}?(?:अपडेट|समाप्त|बंद|ब्लॉक|एक्सपायर|लंबित|पूरा करें)",
        r"(?:অপডেট|কেওয়াইসি|কেৱাইচি|KYC)[^।\n]{0,50}?(?:আপডেট|মেয়াদ|বন্ধ|ব্লক|হ'ব|হ’ব|হবে|শেষ)",
        r"(?:अपडेट|पूरा करें|वेरिफाई)[^।.\n]{0,20}?(?:केवाईसी|केवाइसी|KYC)",
    ],
    "kyc.docs": [
        r"(?:पैन|आधार)[^।.\n]{0,30}?(?:लिंक|अपडेट|वेरिफाई|बंद|ब्लॉक|निष्क्रिय)",
        r"(?:প্যান|আধার)[^।\n]{0,30}?(?:লিংক|আপডেট|যাচাই|বন্ধ|ব্লক|নিষ্ক্রিয়)",
    ],
    "otp.request": [
        r"(?:ओटीपी|ओ टी पी|कोड|पिन|OTP)[^।.\n]{0,60}?(?:भेजें|भेजो|बताएं|बताइए|बताओ|शेयर करें|साझा करें|साझा कीजिए|दें|दो)",
        r"(?:ওটিপি|ও টি পি|কোড|পিন|OTP)[^।\n]{0,60}?(?:পাঠান|পাঠাও|পাঠিয়ে|জানান|জানাও|বলুন|শেয়ার|দিন)",
        r"(?:ওটিপি|OTP)[^।\n]{0,60}?(?:পঠাওক|জনাওক)",
        r"\b(?:otp|code|pin)\b[^.\n]{0,25}?\b(?:bhejo|bhejiye|batao|bata do|share karo|share kar do|de\s?do|bolo)\b",
        r"\b(?:bhejo|bhejiye|batao|share karo|share kar do|bolo)\b[^.\n]{0,25}?\b(?:otp|code|pin)\b",
    ],
    "otp.mistake": [
        r"(?:ओटीपी|कोड|OTP)[^।.\n]{0,60}?(?:गलती से|भूल से)",
        r"(?:गलती से|भूल से)[^।.\n]{0,60}?(?:ओटीपी|कोड|OTP)",
        r"(?:ওটিপি|কোড|OTP)[^।\n]{0,60}?(?:ভুলে|ভুল করে|ভুলক্রমে|ভুলবশত)",
        r"(?:ভুলে|ভুল করে|ভুলক্রমে|ভুলবশত)[^।\n]{0,60}?(?:ওটিপি|কোড|OTP)",
    ],
    "delivery.fail": [
        r"(?:पार्सल|पैकेज|कूरियर|डिलीवरी|शिपमेंट)[^।.\n]{0,60}?(?:रुका|वापस|नहीं पहुंच|डिलीवर नहीं|पता अधूरा|अधूरा पता|होल्ड)",
        r"(?:পার্সেল|প্যাকেজ|কুরিয়ার|ডেলিভারি)[^।\n]{0,60}?(?:আটকে|ফেরত|পৌঁছায়নি|ঠিকানা অসম্পূর্ণ|অসম্পূর্ণ ঠিকানা)",
    ],
    "delivery.fee": [
        r"(?:रीडिलीवरी|री-डिलीवरी|डिलीवरी|कस्टम्स|कस्टम|शिपिंग)\s*(?:फीस|फ़ीस|शुल्क|चार्ज|ड्यूटी)",
        r"(?:রিডেলিভারি|ডেলিভারি|কাস্টমস|শিপিং)\s*(?:ফি|চার্জ|শুল্ক)",
    ],
    "lottery.win": [
        r"(?:इनाम|पुरस्कार|लॉटरी|लकी ड्रॉ|लकी ड्रा)[^।.\n]{0,30}?(?:जीते|जीता|जीत लिया|विजेता|मिला है)",
        r"(?:आप|आपने|आपको)[^।.\n]{0,20}?(?:जीते|जीता|जीत लिया|विजेता चुना)",
        r"(?:লটারি|লটারী|লটাৰী|পুরস্কার|লাকি ড্র)[^।\n]{0,30}?(?:জিতেছেন|জিতেছ|জিতেছে|জয়ী)",
        r"(?:আপনি|আপনার)[^।\n]{0,20}?(?:জিতেছেন|জয়ী|নির্বাচিত)",
    ],
    "lottery.generic": [
        r"(?:बधाई हो|অভিনন্দন)",
    ],
    "lottery.fee": [
        r"(?:प्रोसेसिंग|प्रक्रिया|टैक्स|जीएसटी|इनाम|पुरस्कार)\s*(?:फीस|फ़ीस|शुल्क|चार्ज|टैक्स)",
        r"(?:প্রসেসিং|প্রক্রিয়াকরণ|ট্যাক্স|জিএসটি)\s*(?:ফি|চার্জ|কর)",
        r"(?:इनाम|पुरस्कार|लॉटरी)[^।.\n]{0,40}?(?:पाने|क्लेम)[^।.\n]{0,40}?(?:शुल्क|फीस|पैसे|रुपये)",
        r"(?:পুরস্কার|লটারি)[^।\n]{0,40}?(?:পেতে|দাবি)[^।\n]{0,40}?(?:ফি|টাকা|চার্জ)",
    ],
    "gov.impersonation": [
        r"(?:पुलिस|सीबीआई|ईडी|आरबीआई|कस्टम्स|साइबर क्राइम|कोर्ट|न्यायालय|ट्राई|इनकम टैक्स)",
        r"(?:পুলিশ|সিবিআই|আরবিআই|কাস্টমস|সাইবার ক্রাইম|আদালত|আয়কর)",
    ],
    "gov.threat": [
        r"(?:गिरफ्तार|गिरफ़्तार|गिरफ्तारी|गिरफ़्तारी|डिजिटल अरेस्ट|केस दर्ज|मनी लॉन्ड्रिंग|वारंट)",
        r"(?:গ্রেপ্তার|গ্রেফতার|গ্ৰেপ্তাৰ|ডিজিটাল অ্যারেস্ট|মামলা দায়ের|মানি লন্ডারিং|ওয়ারেন্ট)",
    ],
    "job.offer": [
        r"(?:घर बैठे|वर्क फ्रॉम होम|पार्ट टाइम|रोज़ाना कमाएं|रोजाना कमाएं|बिना अनुभव|लाइक करें|यूट्यूब वीडियो)",
        r"(?:ঘরে বসে|বাড়ি বসে|পার্ট টাইম|প্রতিদিন আয়|অভিজ্ঞতা ছাড়াই|লাইক করুন|ইউটিউব ভিডিও)",
    ],
    "job.fee": [
        r"(?:रजिस्ट्रेशन|पंजीकरण|ट्रेनिंग|सिक्योरिटी डिपॉजिट|सिक्योरिटी)\s*(?:फीस|शुल्क|राशि|जमा)",
        r"(?:রেজিস্ট্রেশন|নিবন্ধন|ট্রেনিং|সিকিউরিটি)\s*(?:ফি|চার্জ|জমা)",
    ],
    "job.channel": [
        r"(?:व्हाट्सऐप|टेलीग्राम)[^।.\n]{0,30}?(?:एचआर|भर्ती|मैनेजर|एजेंट)",
    ],
    "upi.collect": [
        r"(?:कलेक्ट रिक्वेस्ट|पेमेंट रिक्वेस्ट)[^।.\n]{0,50}?(?:स्वीकार|मंजूर|अप्रूव|पिन)",
        r"(?:কালেক্ট রিকোয়েস্ট|পেমেন্ট রিকোয়েস্ট)[^।\n]{0,50}?(?:গ্রহণ|অনুমোদন|পিন|মেনে)",
        r"(?:यूपीआई|UPI)\s*पिन[^।.\n]{0,40}?(?:पैसे|रिफंड|कैशबैक|प्राप्त|मिलेंगे)",
        r"(?:ইউপিআই|UPI)\s*পিন[^।\n]{0,40}?(?:টাকা|রিফান্ড|ক্যাশব্যাক|পাবেন)",
    ],
    "upi.mistake": [
        r"(?:गलती से|भूल से)[^।.\n]{0,40}?(?:भेजे|भेजा|ट्रांसफर)[^।.\n]{0,60}?(?:वापस|लौटा)",
        r"(?:ভুলে|ভুল করে)[^।\n]{0,40}?(?:পাঠিয়েছেন|পাঠিয়েছি|পাঠিয়েছ|ট্রান্সফার)[^।\n]{0,60}?(?:ফেরত)",
    ],
}

# Fail loudly if an extension targets a signal id that does not exist (it would otherwise be silently ignored).
assert not (set(_ML_EXTRA) - {s["id"] for s in SIGNALS}), "unknown signal id in _ML_EXTRA"
PROTECT = PROTECT + _ML_PROTECT
for _s in SIGNALS:
    _s["pats"] = _s["pats"] + _ML_EXTRA.get(_s["id"], [])

# Romanised Hindi words used to recognise Hinglish (Hindi written in Latin letters).
LANG_HINGLISH = ["hai", "hain", "karo", "karein", "bhejo", "bhejiye", "aap", "aapka", "aapke", "kar", "nahi", "paise",
                 "turant", "jaldi", "bhai", "ji", "mera", "meri", "khata", "band", "jayega", "jaayega", "inaam",
                 "dijiye", "kijiye", "batao", "bata", "lena", "dena", "hoga", "ho"]

# Multilingual demo scenarios (the genuine one must stay Low – see tests).
DEMOS += [
    {"id": "ml-hi-otp", "title": "OTP request in Hindi", "channel": "WhatsApp", "tag": "OTP theft",
     "text": "नमस्ते, मेरा ओटीपी गलती से आपके नंबर पर आ गया है, कृपया वो 6 अंकों वाला कोड तुरंत भेजें, मैं आपको ₹500 दूंगा"},
    {"id": "ml-bn-lottery", "title": "Lottery prize in Bengali", "channel": "SMS", "tag": "Prize scam",
     "text": "অভিনন্দন! আপনি ১০ লক্ষ টাকার লটারি জিতেছেন। পুরস্কার পেতে প্রসেসিং ফি ৪৯৯৯ টাকা পাঠান এবং আধার নম্বর শেয়ার করুন"},
    {"id": "ml-as-kyc", "title": "Bank KYC scam in Assamese", "channel": "SMS", "tag": "KYC scam",
     "text": "আপোনাৰ SBI একাউণ্ট আজি বন্ধ হ'ব। KYC আপডেট কৰিবলৈ এই লিংকত ক্লিক কৰক: https://sbi-kyc-update.top/login"},
    {"id": "ml-hinglish-bank", "title": "Bank scam in Hinglish", "channel": "WhatsApp", "tag": "KYC scam",
     "text": "Aapka SBI account band ho jayega! Turant KYC update karein aur OTP bhejo. Abhi link par click karein: http://sbi-kyc-verify.xyz/login"},
    {"id": "genuine-hi", "title": "Genuine OTP message in Hindi", "channel": "SMS", "tag": "Looks genuine",
     "text": "आपका HDFC बैंक ओटीपी 123456 है। यह 10 मिनट के लिए वैध है। कृपया ओटीपी किसी के साथ साझा न करें। - HDFC Bank"},
]


# ---------------------------------------------------------------- v7: scam emergency assistant
# "What happened?" -> an ordered recovery plan. Steps are [priority, text]; priority is one of
# "Now", "Within 1 hour", "Within 24 hours". Incidents marked urgent make the plan "Act now".
EMERGENCY = {
    "incidents": [
        {"id": "otp", "label": "I shared an OTP or PIN", "icon": "key", "urgent": True, "steps": [
            ["Now", "Call your bank on the number printed on your card or in its official app – not a number from the message. Ask them to block your cards, UPI and net banking."],
            ["Now", "If you see any transaction you did not make, tell the bank and call 1930 straight away."],
            ["Within 1 hour", "Change your net banking, UPI and email passwords from a device you trust."],
            ["Within 24 hours", "Check recent statements and point out any unfamiliar debit when you speak to the bank."],
        ]},
        {"id": "money", "label": "I lost money or paid someone", "icon": "wallet", "urgent": True, "steps": [
            ["Now", "Call 1930 immediately. Money can often be frozen when the report is made within the first hour."],
            ["Now", "Call your bank on its official number and ask them to flag the transaction and the receiving account."],
            ["Within 1 hour", "Write down the transaction ID, date, time, amount and the receiver's UPI ID or account number."],
            ["Within 24 hours", "File a complaint at cybercrime.gov.in and keep the complaint number safe."],
        ]},
        {"id": "upi", "label": "I approved a UPI request or entered my UPI PIN", "icon": "wallet", "urgent": True, "steps": [
            ["Now", "Decline or ignore further collect requests. Never enter your UPI PIN to receive money."],
            ["Now", "Call your bank and 1930. Ask them to block UPI on the account until you have checked it."],
            ["Within 1 hour", "Go through the payment history in your UPI app and report every payment you did not authorise."],
        ]},
        {"id": "card", "label": "I shared my card number, CVV or expiry", "icon": "bank", "urgent": True, "steps": [
            ["Now", "Call your bank now and ask them to block the card. Don't wait for the next statement."],
            ["Within 1 hour", "Turn on transaction alerts and ask for a new card number and a lower online spending limit."],
            ["Within 24 hours", "Check the card statement and report any charge you do not recognise."],
        ]},
        {"id": "passwords", "label": "I shared a password or login", "icon": "lock", "urgent": False, "steps": [
            ["Within 1 hour", "Change the password for that account, then for every other account where you used the same password."],
            ["Within 1 hour", "Turn on two-factor authentication, preferably with an authenticator app rather than SMS."],
            ["Within 1 hour", "Sign out of all other devices and sessions from the account's security settings."],
            ["Within 24 hours", "If the login was for banking, UPI or email, tell your bank as well."],
        ]},
        {"id": "apk", "label": "I installed an app or APK from a message or link", "icon": "box", "urgent": True, "steps": [
            ["Now", "Turn on airplane mode so the app cannot send data or receive commands."],
            ["Now", "Do not open banking, UPI or email apps until the suspicious app is removed."],
            ["Within 1 hour", "Uninstall the app from Settings > Apps. If you cannot, restart the phone in Safe Mode and try again."],
            ["Within 1 hour", "Run a scan with Google Play Protect (Play Store > profile icon > Play Protect > Scan)."],
            ["Within 24 hours", "Call your bank: some malicious apps read SMS and OTPs, so ask them to review recent logins and payments."],
        ]},
        {"id": "remote", "label": "I let someone see or control my screen", "icon": "phone", "urgent": True, "steps": [
            ["Now", "Turn on airplane mode, then end the remote session from the app."],
            ["Now", "Uninstall the remote-access app (AnyDesk, TeamViewer, QuickSupport or similar)."],
            ["Now", "Call your bank and 1930 and say that someone had remote access to your phone."],
            ["Within 1 hour", "Change your banking, UPI and email passwords from a different, trusted device."],
        ]},
        {"id": "link", "label": "I opened a link and entered my details", "icon": "link", "urgent": False, "steps": [
            ["Now", "Close the page. Do not enter anything more and do not download anything it offered."],
            ["Within 1 hour", "If you typed a password, card number or OTP, follow the matching steps in this plan."],
            ["Within 1 hour", "Run a security scan on your phone and update your browser and operating system."],
            ["Within 24 hours", "Report the link on Sanchar Saathi's Chakshu facility (sancharsaathi.gov.in)."],
        ]},
        {"id": "id", "label": "I shared my Aadhaar or PAN details", "icon": "id", "urgent": False, "steps": [
            ["Within 1 hour", "If your Aadhaar was shared, lock your biometrics on the official myAadhaar portal (uidai.gov.in)."],
            ["Within 24 hours", "Watch for loans, SIMs or cards you did not apply for, and check your credit report for new accounts."],
        ]},
    ],
    "always": [
        ["Within 24 hours", "Save evidence before you delete anything: screenshots of the messages, the phone number or link, and any payment receipts."],
        ["Within 24 hours", "Tell family members, especially older relatives, that this scam is going around."],
        ["Within 24 hours", "Never pay anyone who offers to 'recover' your money. Recovery callers are a common second wave of the same fraud."],
        ["Within 24 hours", "Block the sender and report the number on Sanchar Saathi's Chakshu facility."],
    ],
    "timing": {
        "just": "You are inside the golden hour. Speed matters most, so start with the 'Now' steps.",
        "today": "It happened today. Start with the 'Now' steps, then work through the rest – banks can still act.",
        "earlier": "It happened earlier. Still call your bank and report: banks and 1930 can still block accounts and record the fraud.",
    },
    "helplines": [
        {"name": "National Cyber Crime Helpline", "number": "1930", "note": "Report financial fraud. Call in the first hour if money has left your account."},
        {"name": "Emergency (police / danger)", "number": "112", "note": "Call if you feel threatened or are in danger."},
        {"name": "Cybercrime portal", "number": "cybercrime.gov.in", "note": "File a complaint online and keep the complaint number."},
    ],
    "disclaimer": "ScamShield gives general guidance and is not an official service. Verify numbers and websites through official sources.",
}
