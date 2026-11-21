"""Run:  python3 -m unittest discover -s tests   (from the project root)"""
import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))
import engine, rules


class EngineTests(unittest.TestCase):
    def test_scam_demos_are_high_or_critical(self):
        for d in rules.DEMOS:
            if not d["id"].startswith("genuine"):
                self.assertGreaterEqual(engine.analyze_text(d["text"])["score"], 50, d["id"])

    def test_genuine_demos_are_low(self):
        for d in rules.DEMOS:
            if d["id"].startswith("genuine"):
                self.assertEqual(engine.analyze_text(d["text"])["level"], "Low", d["id"])

    def test_do_not_share_otp_is_not_an_otp_request(self):
        r = engine.analyze_text("Your OTP is 1234. Do not share this OTP with anyone.")
        self.assertNotIn("otp.request", [s["id"] for s in r["signals"]])

    def test_urls(self):
        self.assertEqual(engine.analyze_url("https://www.sbi.co.in/")["level"], "Low")
        self.assertGreaterEqual(engine.analyze_url("http://192.168.1.5/login")["score"], 50)
        self.assertGreaterEqual(engine.analyze_url("https://amaz0n-gift.xyz/claim")["score"], 70)
        self.assertFalse(engine.analyze_url("not a url")["valid"])

    def test_number_basics(self):
        self.assertTrue(engine.analyze_number("98765 43210")["valid"])
        self.assertFalse(engine.analyze_number("hello")["valid"])
        self.assertFalse(engine.analyze_number("+91 12345")["valid"])
        self.assertEqual(engine.analyze_number("1930")["level"], "Low")
        self.assertGreaterEqual(engine.analyze_number("5123456789")["score"], 25)
        self.assertGreaterEqual(engine.analyze_number("+84 912 345 678")["score"], 25)

    def test_number_context_raises_score(self):
        base = engine.analyze_number("+91 98111 22334")["score"]
        self.assertGreaterEqual(engine.analyze_number("+91 98111 22334", ["otp"])["score"], 75)
        self.assertGreaterEqual(engine.analyze_number("+91 98111 22334", ["authority", "money"])["score"], 85)
        self.assertGreater(engine.analyze_number("+91 98111 22334", ["urgent"])["score"], base)
        self.assertEqual(engine.analyze_number("+91 98111 22334", ["bogus"])["context"], [])

    def test_language_detection(self):
        self.assertEqual(engine.detect_language("नमस्ते आपका ओटीपी भेजें")["code"], "hi")
        self.assertEqual(engine.detect_language("আপনি লটারি জিতেছেন")["code"], "bn")
        self.assertEqual(engine.detect_language("আপোনাৰ একাউণ্ট বন্ধ হ'ব, এই ৰ অক্ষৰটো")["code"], "as")
        self.assertEqual(engine.detect_language("Your OTP is 1234. Do not share it.")["code"], "en")
        self.assertEqual(engine.detect_language("aapka account band ho jayega, turant OTP bhejo")["code"], "hi-Latn")
        self.assertEqual(engine.detect_language("12345 !!!")["code"], "und")

    def test_report_carries_language(self):
        self.assertEqual(engine.analyze_text("नमस्ते")["language"]["code"], "hi")
        self.assertEqual(engine.analyze_text("Hello there")["language"]["code"], "en")

    def test_hindi_otp_request_is_flagged(self):
        r = engine.analyze_text("मेरा ओटीपी आपके नंबर पर आ गया, कृपया कोड तुरंत भेजें")
        self.assertIn("otp.request", [s["id"] for s in r["signals"]])
        self.assertGreaterEqual(r["score"], 70)

    def test_hinglish_otp_request_is_not_masked_as_genuine(self):
        r = engine.analyze_text("turant OTP bhejo, kisi ko mat batao")
        self.assertIn("otp.request", [s["id"] for s in r["signals"]])
        self.assertNotIn("legit.protect", [s["id"] for s in r["signals"]])

    def test_genuine_hindi_otp_notice_is_low(self):
        r = engine.analyze_text("आपका बैंक ओटीपी 123456 है। कृपया ओटीपी किसी के साथ साझा न करें।")
        self.assertEqual(r["level"], "Low")

    def test_emergency_plan_orders_steps_and_flags_urgency(self):
        order = ["Now", "Within 1 hour", "Within 24 hours"]
        p = engine.build_emergency(["otp", "money"], "just")
        self.assertTrue(p["valid"])
        self.assertEqual(p["urgency"], "Act now")
        pri = [s["priority"] for s in p["steps"]]
        self.assertEqual(pri, sorted(pri, key=order.index))
        self.assertEqual(pri[0], "Now")
        self.assertTrue(any("1930" in s["text"] for s in p["steps"]))

    def test_emergency_ignores_unknown_ids_and_requires_input(self):
        self.assertFalse(engine.build_emergency([], "today")["valid"])
        self.assertFalse(engine.build_emergency(["nonsense"], "today")["valid"])
        p = engine.build_emergency(["passwords", "bogus", "passwords"], "bogus")
        self.assertEqual([i["id"] for i in p["incidents"]], ["passwords"])
        self.assertEqual(p["timing"], "today")
        self.assertEqual(p["urgency"], "Act soon")

    def test_emergency_steps_are_unique_and_include_always_steps(self):
        p = engine.build_emergency([i["id"] for i in rules.EMERGENCY["incidents"]], "today")
        texts = [s["text"] for s in p["steps"]]
        self.assertEqual(len(texts), len(set(texts)))
        self.assertTrue(any("Chakshu" in x for x in texts))

    def test_emergency_rules_use_known_priorities(self):
        for inc in rules.EMERGENCY["incidents"]:
            for pri, _txt in inc["steps"]:
                self.assertIn(pri, ["Now", "Within 1 hour", "Within 24 hours"], inc["id"])

    def test_empty(self):
        self.assertEqual(engine.analyze_text("")["level"], "Low")


if __name__ == "__main__":
    unittest.main()
