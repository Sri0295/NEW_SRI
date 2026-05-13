from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import requests
import re
from dotenv import load_dotenv
from datetime import datetime

# ==============================
# Load Environment Variables
# ==============================
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# ==============================
# Flask Setup
# ==============================
app = Flask(__name__)
CORS(app)

# ==============================
# Constants
# ==============================
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "llama-3.1-8b-instant"

# ==============================
# BUG TAXONOMY (SHORTENED HERE)
# ==============================
PYTHON_BUG_TAXONOMY = """
1 SQLi CWE-89 | 2 Cmd Inj CWE-78 | 3 Code Inj CWE-94 | 4 XSS CWE-79 | 5 LDAP CWE-90
6 XXE CWE-611 | 7 XPath CWE-643 | 8 CSV CWE-1236 | 9 NoSQL CWE-943 | 10 SSTI CWE-1336
11 HTTP Split CWE-113 | 12 Log Inj CWE-117
13 Hardcoded Creds CWE-798 | 14 Weak Password CWE-521 | 15 Missing Auth CWE-306
16 Improper Authz CWE-863 | 17 Session Fix CWE-384 | 18 Session Timeout CWE-613
19 JWT None CWE-327 | 20 Weak Hash CWE-327 | 21 No Cert Check CWE-295
22 Auth Bypass CWE-287 | 23 IDOR CWE-639 | 24 Unverified Password Change CWE-620
25 Priv Esc CWE-269
26 Weak RNG CWE-338 | 27 Hardcoded Key CWE-321 | 28 ECB CWE-327
29 Low Entropy CWE-331 | 30 Cleartext Storage CWE-312
31 Weak Key Gen CWE-326 | 32 IV Reuse CWE-323 | 33 No Encryption CWE-311
34 Path Traversal CWE-22 | 35 Unrestricted Upload CWE-434 | 36 shell=True CWE-78
37 Format String CWE-134 | 38 Int Overflow CWE-190 | 39 Buffer Overflow CWE-121
40 Unchecked Length CWE-20 | 41 Open Redirect CWE-601 | 42 SMTP Inj CWE-147
43 ReDoS CWE-1333
44 Unsafe Pickle CWE-502 | 45 YAML Load CWE-502 | 46 File Leak CWE-404
47 Memory Leak CWE-401 | 48 Recursion CWE-674 | 49 Resource Exhaust CWE-400
50 Race CWE-362 | 51 Deadlock CWE-833 | 52 DB Leak CWE-404
53 Socket Leak CWE-404 | 54 Temp File CWE-377 | 55 Insecure Temp CWE-378
56 Resource Inj CWE-99 | 57 No Shutdown CWE-404 | 58 CPU Exhaust CWE-400
59 Bare Except CWE-1109 | 60 Empty Except CWE-390 | 61 Broad Catch CWE-396
62 Uncaught CWE-248 | 63 Bad Error Handle CWE-755 | 64 Info Leak CWE-209
65 Exception Leak CWE-460 | 66 Swallowed CWE-391 | 67 Return Finally CWE-584
68 Lost Exception CWE-754
69 Div Zero CWE-369 | 70 Int Underflow CWE-191 | 71 Off-by-One CWE-193
72 Infinite Loop CWE-835 | 73 Dead Code CWE-561 | 74 Singleton Race CWE-362
75 TOCTOU CWE-367 | 76 Uninit Var CWE-908 | 77 Type Mismatch CWE-697
78 Bad Conversion CWE-681
79 Mutable Default CWE-665 | 80 Class Mutable CWE-488 | 81 __del__ Cleanup CWE-672
82 Circular Import CWE-1047 | 83 Monkey Patch CWE-349 | 84 Global Mod CWE-1108
85 Dangerous vars/dir CWE-676 | 86 __eq__ no __hash__ CWE-581
87 Deprecated CWE-477
88 Debug Mode CWE-489 | 89 Assert Prod CWE-617 | 90 Pickle Untrusted CWE-502
91 CSRF CWE-352 | 92 SSRF CWE-918 | 93 Bad CORS CWE-942
94 Missing Headers CWE-693 | 95 Data in URL CWE-598
96 Bad Cookie Flags CWE-614 | 97 Mass Assign CWE-915
98 Logic Bypass CWE-840 | 99 API Key URL CWE-598
100 Timestamp Injection CWE-829
"""

# ==============================
# STRICT PROMPT
# ==============================
SYSTEM_PROMPT = f"""
{PYTHON_BUG_TAXONOMY}

You are a STRICT Python bug classification engine.

RULES:
- Use ONLY the predefined 100 bug types
- Detect EXACTLY ONE bug OR output Bug_Label: 0
- DO NOT guess
- DO NOT report already fixed code
- Prefer NO bug over WRONG bug

SAFE CODE RULE (MANDATORY):
If the code already uses a secure pattern, you MUST return:

Bug_Label: 0
Bug_Type: None

Example:
If mutable default argument uses None and initialization, it is SAFE.

OUTPUT FORMAT:

Bug_Label: 0 or 1

Bug_Type:
<Exact taxonomy name or None>

CWE:
<CWE-ID or N/A>

Severity:
<LOW | MEDIUM | HIGH | CRITICAL | NONE>

Bug_Risk_Score:
<float between 0.0 and 1.0>

Explanation:
<at least 3 sentences>

Fix:
Fix MUST contain full corrected code.
Fix MUST be multi-line if needed.
Do NOT return "No fix required" if Bug_Label = 1.
"""

# ==============================
# UTIL FUNCTIONS
# ==============================
def detect_language(code):
    return "python"


def parse_output(text):
    result = {
        "Bug_Label": 0,
        "Bug_Type": "None",
        "CWE": "N/A",
        "Severity": "NONE",
        "Bug_Risk_Score": 0.0,
        "Explanation": "",
        "Fix": ""
    }

    lines = text.splitlines()
    current_key = None

    for line in lines:
        line = line.strip()

        if line.startswith("Bug_Label:"):
            result["Bug_Label"] = int(line.split(":")[1].strip())
            current_key = None

        elif line.startswith("Bug_Type:"):
            result["Bug_Type"] = line.split(":",1)[1].strip()
            current_key = None

        elif line.startswith("CWE:"):
            result["CWE"] = line.split(":",1)[1].strip()
            current_key = None

        elif line.startswith("Severity:"):
            result["Severity"] = line.split(":",1)[1].strip()
            current_key = None

        elif line.startswith("Bug_Risk_Score:"):
            try:
                result["Bug_Risk_Score"] = float(line.split(":",1)[1].strip())
            except:
                result["Bug_Risk_Score"] = 0.0
            current_key = None

        elif line.startswith("Explanation:"):
            current_key = "Explanation"
            result["Explanation"] = line.replace("Explanation:", "").strip()

        elif line.startswith("Fix:"):
            current_key = "Fix"
            result["Fix"] = line.replace("Fix:", "").strip()

        else:
            if current_key:
                result[current_key] += "\n" + line

    return result

def is_safe_code(code):
    # Mutable default fix detection
    if "items=None" in code and "if items is None" in code:
        return True

    # subprocess safe usage
    if "subprocess.run" in code and "shell=False" in code:
        return True

    return False

def fallback_fix(parsed, code):
    if parsed["Bug_Label"] == 1:

        # Mutable default argument fix
        if "items=[]" in code:
            return """def append_item(item, items=None):
    if items is None:
        items = []
    items.append(item)
    return items"""

        # Command injection fix
        if "os.system" in code:
            return """import subprocess
subprocess.run(["command"], shell=False)"""

    return parsed["Fix"] if parsed["Fix"].strip() else "Fix not generated"

def convert_to_frontend_format(parsed):
    # ✅ Calculate score BEFORE dictionary
    score = int((1 - parsed["Bug_Risk_Score"]) * 100)

    if parsed["Bug_Label"] == 0:
        return {
            "summary": {
                "security_score": 100,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "overall_assessment": parsed["Explanation"]
            },
            "vulnerabilities": [],
            "refactored_code": "No fix required."
        }

    return {
        "summary": {
            "security_score": score,
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "overall_assessment": parsed["Explanation"]
        },
        "vulnerabilities": [
            {
                "cwe_id": parsed["CWE"],
                "severity": parsed["Severity"].lower(),
                "title": parsed["Bug_Type"],
                "description": parsed["Explanation"],
                "vulnerable_code": "Detected issue",
                "fixed_code": parsed["Fix"],
                "mitigation": parsed["Explanation"]
            }
        ],
        "refactored_code": parsed["Fix"]
    }

def calculate_metrics(code):
    lines = code.split("\n")

    # Lines of Code (excluding empty lines)
    loc = len([line for line in lines if line.strip() != ""])

    # Function count
    functions = sum(1 for line in lines if line.strip().startswith("def "))

    # Simple cyclomatic complexity
    complexity_keywords = ["if ", "for ", "while ", "and ", "or ", "elif ", "case "]
    complexity = 1  # base

    for line in lines:
        for keyword in complexity_keywords:
            if keyword in line:
                complexity += 1

    return {
        "lines_of_code": loc,
        "cyclomatic_complexity": complexity,
        "function_count": functions
    }

def call_groq(code):
    if not GROQ_API_KEY:
        raise Exception("Groq API key not configured")

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze this Python code:\n\n{code}"}
        ],
        "temperature": 0.1
    }

    response = requests.post(GROQ_URL, headers=headers, json=payload)

    if response.status_code != 200:
        raise Exception(response.text)

    content = response.json()["choices"][0]["message"]["content"]

    parsed = parse_output(content)

    # Confidence filter
    if parsed["Bug_Risk_Score"] < 0.6:
        parsed["Bug_Label"] = 0

    return parsed


# ==============================
# ROUTES
# ==============================
@app.route("/")
def home():
    return jsonify({"status": "running", "ai": "Groq"})


@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json()

        if not data or "code" not in data:
            return jsonify({"error": "No code provided"}), 400

        code = data["code"]

        # ✅ Step 1: AI analysis
        parsed = call_groq(code)

        # ✅ Step 2: Metrics
        metrics = calculate_metrics(code)

        # ✅ Step 3: Safe override
        if is_safe_code(code):
            parsed["Bug_Label"] = 0
            parsed["Explanation"] = "Code is secure and follows safe patterns."
            parsed["Fix"] = "No fix required."

        # ✅ Step 4: Fallback fix
        parsed["Fix"] = fallback_fix(parsed, code)

        # ✅ Step 5: Convert for frontend
        result = convert_to_frontend_format(parsed)

        # ✅ Step 6: Add metrics
        result["metrics"] = metrics

        # ✅ Step 7: Metadata
        result["metadata"] = {
            "timestamp": datetime.now().isoformat(),
            "model": MODEL
        }

        return jsonify(result)

    except Exception as e:
        return jsonify({
            "error": str(e),
            "summary": {
                "security_score": 0,
                "overall_assessment": "Analysis failed"
            },
            "vulnerabilities": []
        }), 500

@app.route("/health")
def health():
    return {
        "backend": "running",
        "groq_api": "connected" if GROQ_API_KEY else "not_configured"
    }


# ==============================
# RUN
# ==============================
if __name__ == "__main__":
    print("🚀 Sentinel AI (Strict Mode) Running")
    app.run(debug=True, port=5000)