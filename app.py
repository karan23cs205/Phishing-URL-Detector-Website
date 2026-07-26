import re
import urllib.parse
import tldextract
import whois
from datetime import datetime
import joblib
from flask import Flask, render_template, request, jsonify
import numpy as np

app = Flask(__name__)

# Load your original trained model (or train a simple replacement if needed)
# Ensure 'phishing_model.pkl' exists in the main directory.
# This model needs to accept a feature array of size 5: 
# [url_len, has_at, dot_count, has_hyphen, has_ip]
try:
    model = joblib.load('phishing_model.pkl')
except FileNotFoundError:
    print("Warning: phishing_model.pkl not found. Random predictions will be used.")
    model = None

# Verified Domain Whitelist to prevent false positives on major sites
TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 
    'wikipedia.org', 'github.com', 'linkedin.com', 'microsoft.com', 
    'apple.com', 'twitter.com', 'paypal.com', 'netflix.com', 'adobe.com'
]

# Suspected Brand Keywords often spoofed in phishing
BRAND_KEYWORDS = ['paypal', 'login', 'secure', 'bank', 'account', 'update', 'verify', 'signin', 'support', 'billing']

# --- Helper Functions ---

def extract_lexical_features(url):
    """
    Extracts the basic 5 features needed for the trained model.
    Format: [url_len, has_at, dot_count, has_hyphen, has_ip]
    """
    ext = tldextract.extract(url)
    domain_part = ext.domain + '.' + ext.suffix
    
    url_len = len(url)
    has_at = 1 if '@' in url else 0
    dot_count = domain_part.count('.')
    has_hyphen = 1 if '-' in domain_part else 0
    
    # Simple IP check
    ip_pattern = r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])"
    has_ip = 1 if re.search(ip_pattern, domain_part) else 0

    return [url_len, has_at, dot_count, has_hyphen, has_ip]

def perform_whois_lookup(domain_name):
    """
    Attempts to fetch live WHOIS data and calculate domain age in days.
    """
    try:
        w = whois.whois(domain_name)
        creation_date = w.creation_date
        
        # Creation date can be a single datetime object or a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            today = datetime.now()
            age_delta = today - creation_date
            return age_delta.days
        else:
            return None # Creation date not available
            
    except Exception as e:
        print(f"WHOIS Lookup failed for {domain_name}: {e}")
        return -1 # Lookup Error

# --- Web Routes ---

# @app.route('/')
# def home():
#     return render_template('index.html')

# --- Page Navigation Routes ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analytics')
def analytics():
    return render_template('analytics.html')

@app.route('/batch-scan')
def batch_scan():
    return render_template('batch_scan.html')

@app.route('/docs')
def docs():
    # Placeholder so server doesn't crash before we create docs.html
    return render_template('docs.html')

@app.route('/api/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    url_input = data.get('url', '').strip()

    if not url_input:
        return jsonify({"error": "Please provide a valid URL"}), 400

    # Ensure URL has scheme for proper parsing
    if not url_input.startswith(('http://', 'https://')):
        url_input = 'http://' + url_input

    # Parse URL Structure
    try:
        parsed_url = urllib.parse.urlparse(url_input)
        ext = tldextract.extract(url_input)
        
        root_domain = ext.registered_domain
        domain_name = ext.domain + '.' + ext.suffix
        subdomain = ext.subdomain
        
        if not root_domain: # e.g., if only 'localhost' or an IP was entered
             root_domain = domain_name = parsed_url.netloc
    except Exception:
        return jsonify({"error": "Failed to parse URL structure"}), 400

    # -- Intelligence Check 1: Domain Whitelist --
    is_trusted = root_domain.lower() in TRUSTED_DOMAINS
    if is_trusted:
        # Predefined 'Safe' response for known authentic domains
        return jsonify({
            "url": url_input,
            "domain": root_domain,
            "status": "Safe",
            "risk_level": "LOW RISK",
            "risk_score": 5.0,
            "indicators": {
                "trusted_domain": True,
                "domain_age_days": 3650,  # Whitelisted domains default to old/established
                "https": parsed_url.scheme == 'https',
                "has_ip_host": False
            },
            "lexical_details": extract_lexical_features(url_input),
            "summary": "This domain is part of our Verified Whitelist and is confirmed to be legitimate. Low probability of phishing."
        })

    # -- Intelligence Check 2: Live WHOIS & Domain Age --
    # Whitelisted domains don't need WHOIS lookup (speeds up response)
    domain_age_days = perform_whois_lookup(root_domain)
    
    # -- Intelligence Check 3: Advanced Heuristics --
    https_status = parsed_url.scheme == 'https'
    
    # Check for brand spoofing/typosquatting keywords in the whole URL
    url_lower = url_input.lower()
    keyword_matches = [kw for kw in BRAND_KEYWORDS if kw in url_lower]
    keyword_count = len(keyword_matches)
    
    # Check for deceptive Subdomain/Path matching (e.g., paypal.support-update.com)
    deceptive_keywords = ['support', 'update', 'billing', 'security']
    deceptive_spoof = any(kw in subdomain.lower() for kw in deceptive_keywords)

    # -- ML Model Inference (5 Lexical Features) --
    ml_features = extract_lexical_features(url_input)
    # features: [url_len, has_at, dot_count, has_hyphen, has_ip]
    
    if model:
        # Predict probability of being phishing (index 1)
        # Random Forest proba returns [prob_safe, prob_phishing]
        probabilities = model.predict_proba([ml_features])[0]
        ml_phishing_prob = probabilities[1] * 100
    else:
        # Placeholder probability if model fails to load
        ml_phishing_prob = np.random.uniform(20.0, 80.0)

    # -- Final Risk Score Composite Calculation (Weighted Heuristics + ML) --
    # Higher Score = Higher Risk (0 to 100)
    risk_score = (ml_phishing_prob * 0.40) # ML model holds 40% weight

    # Penalty 1: Young Domain Age (CRITICAL)
    if domain_age_days is not None:
        if domain_age_days == -1: # Lookup failed/Error
            risk_score += 15
        elif domain_age_days < 90: # Very young (under 3 months)
            risk_score += 35
        elif domain_age_days < 365: # Under a year old
            risk_score += 15

    # Penalty 2: Insecure Connection
    if not https_status:
        risk_score += 10

    # Penalty 3: Brand Impersonation/Keyword Triggers
    if keyword_count > 1:
        risk_score += (keyword_count * 5)
        
    # Penalty 4: Deceptive Subdomain spoofing
    if deceptive_spoof:
        risk_score += 10
        
    # Cap Risk Score at 100
    risk_score = min(100.0, max(0.0, risk_score))

    # -- Status Classification --
    if risk_score >= 60:
        status = "Phishing"
        risk_level = "HIGH RISK"
    elif risk_score >= 35:
        status = "Suspicious"
        risk_level = "MEDIUM RISK"
    else:
        status = "Safe"
        risk_level = "LOW RISK"

    # -- Summary Generation --
    if status == "Phishing":
        summary = "CRITICAL: Our hybrid AI engine detected multiple high-risk indicators, likely brand spoofing, or deceptive domain registration. Extreme caution advised."
    elif status == "Suspicious":
        summary = "ALERT: This URL displays moderate risk behavior. It contains suspicious lexical structures and possibly a newer domain registration. Verification is strongly recommended."
    else:
        summary = "URL appears relatively secure based on available lexical features and domain reputational data. Basic security practices still apply."

    return jsonify({
        "url": url_input,
        "domain": root_domain,
        "status": status,
        "risk_level": risk_level,
        "risk_score": round(risk_score, 1),
        "indicators": {
            "trusted_domain": False,
            "domain_age_days": domain_age_days,
            "https": https_status,
            "has_ip_host": bool(ml_features[4]), # has_ip lexical check
            "keyword_matches": keyword_matches,
            "deceptive_spoof": deceptive_spoof
        },
        "lexical_details": ml_features,
        "summary": summary
    })

if __name__ == '__main__':
    # You MUST have 'phishing_model.pkl' in the directory before running this.
    # It also requires installing new packages: pip install tldextract python-whois
    app.run(debug=True, port=5000)
