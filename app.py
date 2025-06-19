import os
import re
import requests
import time
import traceback
from datetime import datetime, timedelta
from collections import Counter
import pytz
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv
from models import URLCheck  
from flask_login import LoginManager
from werkzeug.security import generate_password_hash, check_password_hash
import tldextract
import json
import rules_engine.rules as rules
import joblib
import numpy as np
from feature_extraction import main
import base64
import random
import feedparser
import socket
import email.utils

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")


LOCAL_TIMEZONE = pytz.timezone("Asia/Kolkata")

# Initialize Flask app
app = Flask(__name__)
CORS(app)  
MODEL_PATH = os.path.join(os.path.dirname(__file__), "ml_model", "rf_model.pkl")
rf = joblib.load(MODEL_PATH)

def combined_classification(url):
    # Trusted domains (add more as needed)
    trusted_domains = {
        "google.com", "microsoft.com", "github.com", "wikipedia.org", "amazon.com", "apple.com",
        "facebook.com", "twitter.com", "linkedin.com", "youtube.com", "instagram.com", "reddit.com",
        "stackoverflow.com", "bing.com", "yahoo.com", "cnn.com", "bbc.com", "nytimes.com","portswigger.net",
        "mozilla.org", "adobe.com", "paypal.com", "bankofamerica.com", "chase.com", "wellsfargo.com","whatsapp.com",
        "telegram.org", "signal.org", "slack.com", "zoom.us", "dropbox.com", "onedrive.com","webwhatsapp.com",
        "googleusercontent.com", "cloudflare.com", "akamai.com", "verizon.com", "comcast.net","udemy.com",
        "coursera.org", "edx.org", "khanacademy.org", "udacity.com", "githubusercontent.com","kaggle.com",
        "bitbucket.org", "gitlab.com", "codepen.io", "jsfiddle.net", "codesandbox.io","stackoverflowusercontent.com","medium.com",
        "dev.to", "hashnode.com", "blogger.com", "wordpress.com", "tumblr.com", "livejournal.com","sbi.co.in",
        "icicibank.com", "hdfcbank.com", "axisbank.com", "pnbindia.in", "bankofbaroda.in","paytm.com","pwnedlabs.io",
        "pwnedpasswords.com", "haveibeenpwned.com", "cyber.gov.au", "us-cert.cisa.gov", "nvd.nist.gov","apisecuniversity.com",
        "owasp.org", "cve.mitre.org", "cvedetails.com", "phishtank.com", "securityfocus.com", "exploit-db.com","shodan.io","virustotal.com","notion.so",
        "chatgpt.com", "openai.com", "bing.com/chat", "google.com/search","bing.com/search","quora.com","reddit.com/r/AskReddit",
        "stackoverflow.com/questions", "github.com/issues", "gitlab.com/issues", "bitbucket.org/issues",
    }
    # Extract domain from URL
    domain_info = tldextract.extract(url)
    domain = f"{domain_info.domain}.{domain_info.suffix}"

    # OVERRIDE: If domain is trusted, always return safe/benign/low
    if domain in trusted_domains:
        return {
            "ml_result": "benign",
            "rule_score": 0,
            "reasons": ["Trusted domain"],
            "risk_level": "Low"
        }

    # WHOIS data for domain age
    whois_info = get_whois_data(domain)
    domain_age_months = None
    if whois_info and isinstance(whois_info, dict):
        creation_date = whois_info.get("creation_date")
        if creation_date:
            # Handle if creation_date is a list (sometimes returned by python-whois)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            try:
                if isinstance(creation_date, str):
                    creation_date = datetime.fromisoformat(creation_date)
                domain_age_months = (datetime.now() - creation_date).days // 30
            except Exception:
                pass

    # Rule-based logic
    rule_result = rules.check_url_rules(url)
    rule_score = rule_result.get("rule_score", 0)
    rule_reasons = rule_result.get("reasons", [])

    # Increase risk if domain is new (< 6 months)
    if domain_age_months is not None and domain_age_months < 6:
        rule_score += 1
        rule_reasons.append("Domain is newly registered (less than 6 months old)")

    # ML model prediction
    features = main(url)
    features = np.array(features).reshape(1, -1)
    ml_prediction = rf.predict(features)[0]

    # VirusTotal and Google Safe Browsing checks
    vt_stats = check_virustotal(VT_API_KEY, url)
    google_sb = check_google_safe_browsing(GOOGLE_API_KEY, url)

    # Determine if VirusTotal or GSB flagged as unsafe/malicious
    vt_malicious = False
    if isinstance(vt_stats, dict):
        vt_malicious = vt_stats.get("malicious", 0) > 0 or vt_stats.get("suspicious", 0) > 0

    gsb_unsafe = google_sb and google_sb.lower() == "unsafe"

    # --- OVERRIDE ML if trusted or both VT+GSB say safe ---
    if domain in trusted_domains or (not vt_malicious and not gsb_unsafe):
        if ml_prediction != "benign":
            ml_prediction = "benign"
            rule_reasons.append("AI model detected phishing traits, but verified sources marked it safe.")

    # Combine results and assign risk level
    high_risk_votes = 0
    if ml_prediction in ['malware', 'phishing', 'defacement']:
        high_risk_votes += 1
    if vt_malicious:
        high_risk_votes += 1
    if gsb_unsafe:
        high_risk_votes += 1
    if rule_score >= 3:
        high_risk_votes += 1

    if high_risk_votes >= 2:
        risk_level = "High"
    elif high_risk_votes == 1 or rule_score >= 1.5:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Combine reasons: ML + rule-based + VT + GSB
    combined_reasons = list(rule_reasons)
    if ml_prediction != 'benign':
        combined_reasons.append(f"ML model prediction: {ml_prediction}")
    if vt_malicious:
        combined_reasons.append("VirusTotal flagged as malicious/suspicious")
    if gsb_unsafe:
        combined_reasons.append("Google Safe Browsing flagged as unsafe")

    return {
        "ml_result": ml_prediction,
        "rule_score": rule_score,
        "reasons": combined_reasons,
        "risk_level": risk_level
    }
def check_virustotal(api_key, url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": api_key}
    try:
        requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=5)
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return stats
        return {"error": resp.text}
    except Exception as e:
        return {"error": str(e)}
    # Google Safe Browsing Check
def check_google_safe_browsing(api_key, url):
    safe_browsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "suspicious-url-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(safe_browsing_url, json=payload, params={"key": api_key}, timeout=5)
        response.raise_for_status()
        return "unsafe" if "matches" in response.json() else "safe"  # <-- lowercase
    except requests.exceptions.Timeout:
        print("GSB timeout")
        return "unknown"
    except requests.exceptions.RequestException as e:
        print("GSB error:", e)
        return "unknown"
# WHOIS API Function
def get_whois_data(domain):
    try:
        import whois
        w = whois.whois(domain)
        # Convert to dict and filter out empty/null fields for clarity
        if isinstance(w, dict):
            return {k: v for k, v in w.items() if v}
        else:
            return dict(w)
    except Exception as e:
        return {"error": str(e)}
    
@app.route("/whois", methods=["POST"])
def get_whois_info():
    data = request.json
    domain = data.get("domain")

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    whois_data = get_whois_data(domain)  

    if "error" in whois_data:
        return jsonify({"error": whois_data["error"]}), 500

    return jsonify(whois_data)

# Check SSL Status
def check_ssl(url):
    if not url or not isinstance(url, str):
        return "Unknown"
    return "Valid" if url.startswith("https://") else "Invalid"
# URL Format Validation
def is_valid_url(url):
    url_regex = re.compile(r"^(https?://)?([\w.-]+\.[a-zA-Z]{2,10})(/[^\s]*)?$", re.IGNORECASE)
    return bool(re.match(url_regex, url))

# URL Classification
def classify_url(url):
    # Google Safe Browsing check
    google_result = check_google_safe_browsing(GOOGLE_API_KEY, url)  # Corrected
    if google_result == "malicious":
        print(f"URL classified as malicious by Google Safe Browsing: {url}")
        return "malicious"

    # Rule-based scoring (from rules.py)
    rule_result = rules.check_url_rules(url)
    rule_score = rule_result.get("rule_score", 0)
    reasons = rule_result.get("reasons", [])

    # Use rule_score to determine risk
    if rule_score >= 3:
        print(f"URL classified as malicious by rules: {url} | Reasons: {reasons}")
        return "malicious"
    elif rule_score >= 1.5:
        print(f"URL classified as suspicious by rules: {url} | Reasons: {reasons}")
        return "suspicious"

    # Optionally, keep URL shortener check
    domain_info = tldextract.extract(url)
    domain = f"{domain_info.domain}.{domain_info.suffix}"
    url_shorteners = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
    if domain in url_shorteners:
        print(f"URL classified as suspicious due to URL shortener: {url}")
        return "suspicious"

    print(f"URL classified as safe: {url}")
    return "safe"
# Routes
@app.route('/')
def home():
    whois_data = {} 
    return render_template('index.html',whois_data=whois_data)

@app.route('/about')
def about():
    return render_template('about.html')

# API for Chrome Extension
@app.route('/check_url', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        user_input = data.get("url", "").strip()
        # Run ML + rule-based classification
        classification = combined_classification(user_input)
        google_sb = check_google_safe_browsing(GOOGLE_API_KEY, user_input)
        domain_info = tldextract.extract(user_input)
        domain = f"{domain_info.domain}.{domain_info.suffix}"
        whois_info = get_whois_data(domain)
        vt_stats = check_virustotal(VT_API_KEY, user_input)
        key_fields = ["domain_name", "registrar", "creation_date", "expiration_date", "name_servers", "country"]
        filtered_whois = {k: whois_info.get(k) for k in key_fields if whois_info and isinstance(whois_info, dict) and whois_info.get(k)}
        return jsonify({
            "input_type": "domain",
            "message": f"Risk Level: {classification.get('risk_level', 'Unknown')}",
            "ml_result": classification.get("ml_result"),
            "risk_level": classification.get("risk_level"),
            "google_safe_browsing": google_sb,
            "whois": filtered_whois if filtered_whois else "No WHOIS info found or domain is new.",
            "virustotal": vt_stats
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route('/useredu')
def useredu():
    return render_template('safedu.html')   
FEED_URLS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://krebsonsecurity.com/feed/",
    "https://threatpost.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://blog.talosintelligence.com/atom.xml",
    "https://www.us-cert.gov/ncas/alerts.xml",
    "https://symantec-blogs.broadcom.com/feed/",
    "https://blog.malwarebytes.com/feed/"
]

RSS_CACHE = {"articles": [], "timestamp": 0}
RSS_CACHE_TTL = 300  # cache for 5 minutes

@app.route('/rss_feed')
def rss_feed():
    now = time.time()
    if RSS_CACHE["articles"] and now - RSS_CACHE["timestamp"] < RSS_CACHE_TTL:
        return jsonify({"articles": RSS_CACHE["articles"]})
    articles = []
    for feed_url in FEED_URLS:
        feed = feedparser.parse(feed_url)
        for entry in feed.entries:
            published = getattr(entry, "published", "") or getattr(entry, "updated", "")
            # Parse published date to timestamp for sorting
            try:
                published_parsed = email.utils.parsedate_to_datetime(published).timestamp() if published else 0
            except Exception:
                published_parsed = 0
            articles.append({
                "title": entry.title,
                "link": entry.link,
                "summary": getattr(entry, "summary", ""),
                "published": published,
                "published_parsed": published_parsed
            })
    # Sort articles by published timestamp (descending)
    articles = [a for a in articles if a["published"]]
    articles.sort(key=lambda x: x["published_parsed"], reverse=True)
    RSS_CACHE["articles"] = articles[:8]
    RSS_CACHE["timestamp"] = now
    return jsonify({"articles": RSS_CACHE["articles"]})
# Flask app for phishing detection
import difflib
from urllib.parse import urlparse

def has_fuzzy_phishing_keyword(text, keywords, threshold=0.85):
    text_lower = text.lower()
    for keyword in keywords:
        for word in text_lower.split():
            ratio = difflib.SequenceMatcher(None, word, keyword).ratio()
            if ratio >= threshold:
                return True, f'The message contains language similar to known phishing keywords'
    return False, None

def get_domain(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return url

def is_obfuscated_url(url):
    # Example: flag URLs with lots of %-encoding or suspicious patterns
    return '%' in url or '..' in url or '@' in url
PHISHING_KEYWORDS = [
    "verify now", "your account is suspended", "click here", "urgent",
    "unauthorized login", "update your information", "reset your password",
    "limited time", "act now"
]

def extract_links(text):
    # Match http(s) URLs and bare domains (e.g., example.com)
    url_regex = r'https?://[^\s]+|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
    return re.findall(url_regex, text)

def is_suspicious_message(text, bad_domains):
    # Expanded phishing/social engineering keywords and phrases
    phishing_keywords = [
        "password", "urgent", "verify", "account", "login", "click here", "update", "security",
        "free", "coupon", "claim", "win", "prize", "congratulations", "limited time", "offer",
        "bonus voucher", "gift card", "rewarded", "confidential", "surprise", "discreet",
        "token of appreciation", "help with something important", "keep this confidential",
        "employee bonus", "voucher card", "reward card", "secret", "do not share", "do not tell",
        "urgent request", "favor", "wire transfer", "bank details", "amazon gift card", "itunes card",
        "google play card", "steam card", "crypto", "bitcoin", "ethereum", "prepaid card"
    ]
    # For phrase matching, check for presence of both words in the message
    phrase_pairs = [
        ("bonus", "voucher"),
        ("gift", "card"),
        ("reward", "employee"),
        ("keep", "confidential"),
        ("help", "important"),
        ("wire", "transfer"),
        ("bank", "details"),
        ("urgent", "request"),
        ("do not", "share"),
        ("do not", "tell"),
    ]

    links = extract_links(text)
    text_lower = text.lower()

    # 1. Fuzzy keyword match
    is_fuzzy, reason = has_fuzzy_phishing_keyword(text, phishing_keywords)
    if is_fuzzy:
        return True, reason

    # 2. Exact keyword/phrase check
    for keyword in phishing_keywords:
        if keyword in text_lower:
            return True, f"Contains phishing/social engineering keywords'{keyword}'"

    # 3. Phrase pair check (both words must be present)
    for word1, word2 in phrase_pairs:
        if word1 in text_lower and word2 in text_lower:
            return True, f"Contains suspicious phrase: '{word1} ... {word2}'"

    # 4. Promotional language + links
    if links and any(word in text_lower for word in ["free", "coupon", "claim", "win", "prize", "bonus", "gift", "reward"]):
        return True, "Contains suspicious link with promotional language"

    # 5. Bad domain check (robust)
    for link in links:
        ext = tldextract.extract(link)
        root_domain = f"{ext.domain}.{ext.suffix}"
        if root_domain in bad_domains:
            return True, f"Contains known bad domain: {root_domain}"
        if is_obfuscated_url(link):
            return True, f"Obfuscated or suspicious URL format: {link}"

    # 6. Suspicious if message asks for secrecy or urgent help, even without links
    secrecy_triggers = [
        "keep this confidential", "do not share", "do not tell", "secret", "discreet", "urgent request", "favor"
    ]
    for trigger in secrecy_triggers:
        if trigger in text_lower:
            return True, f"Contains secrecy/urgency phrase: '{trigger}'"

    # 7. Suspicious if message mentions rewards, bonuses, or gift cards
    reward_triggers = [
        "bonus", "reward", "gift card", "voucher", "token of appreciation"
    ]
    if any(trigger in text_lower for trigger in reward_triggers):
        return True, "Mentions rewards, bonuses, or gift cards (common in phishing)"

    return False, None

@app.route('/check_message', methods=['POST'])
def check_message():
    bad_domains = ["malicious.com", "phishing.com"]
    if request.is_json:
        message = request.json.get('message', '')
    else:
        message = request.form.get('message', '')
    links = extract_links(message)
    is_suspicious, found_keyword = is_suspicious_message(message, bad_domains)

    result = {
        "links": links,
        "suspicious": is_suspicious,
        "reason": found_keyword if found_keyword else "No phishing signs found"
    }
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=False)