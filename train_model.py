import re
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# Feature Extractor Function
def extract_features(url):
    # 1. URL Length (> 54 chars is often suspicious)
    url_len = len(url)
    
    # 2. Presence of '@' symbol
    has_at = 1 if '@' in url else 0
    
    # 3. Count of dots '.'
    dot_count = url.count('.')
    
    # 4. Presence of hyphen '-'
    has_hyphen = 1 if '-' in url else 0
    
    # 5. Presence of raw IP Address instead of domain name
    ip_pattern = r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])"
    has_ip = 1 if re.search(ip_pattern, url) else 0

    return [url_len, has_at, dot_count, has_hyphen, has_ip]

# Training Sample Data (Lexical Features)
# Features: [url_len, has_at, dot_count, has_hyphen, has_ip] | Label: 1 (Phishing), 0 (Safe)
X_train = np.array([
    # Safe URLs
    [19, 0, 1, 0, 0], [22, 0, 2, 0, 0], [25, 0, 1, 0, 0], [30, 0, 2, 1, 0], [15, 0, 1, 0, 0],
    # Phishing URLs
    [85, 1, 4, 3, 0], [110, 0, 5, 2, 1], [65, 1, 3, 2, 0], [95, 0, 4, 4, 0], [120, 1, 6, 1, 1]
])
y_train = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])

# Train Random Forest Model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save Trained Model to File
joblib.dump(model, 'phishing_model.pkl')
print("✅ Machine Learning model successfully trained and saved as 'phishing_model.pkl'!")