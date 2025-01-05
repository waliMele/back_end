from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import re

app = Flask(__name__)
CORS(app)

# ✅ Load the trained model
try:
    model = joblib.load('optimized_random_forest_model.pkl')
    print("✅ Model loaded successfully")
except Exception as e:
    print(f"❌ Failed to load the model: {e}")


# ✅ Explicit Conditional Rules for Scam Detection
def is_suspicious(url):
    """Check for explicit scam patterns in the URL."""
    HIGH_RISK_KEYWORDS = [
        'offer', 'free', 'win', 'bonus', 'gift', 'exclusive',
        'hurry', 'prize', 'jackpot', 'lottery', 'reward', 'deal'
    ]
    SUSPICIOUS_TLDS = ['tk', 'ru', 'biz', 'cf', 'xyz']
    TYPOSQUATTING_PATTERNS = [
        'login-', 'verify-', 'update-', 'secure-', 'account-', 'signin-', 'auth-'
    ]
    LOOKALIKE_PATTERNS = [r'0', r'1', r'5', r'3', r'7', r'@']
    SUSPICIOUS_SPECIAL_CHARS = ['$', '%', '&', '?', '-', '_', '!', '=', '@']

    # ✅ Check TLDs
    if url.split('.')[-1] in SUSPICIOUS_TLDS:
        print("❌ Rule Matched: Suspicious TLD detected")
        return True, "Suspicious TLD detected"

    # ✅ Check Hyphenated Keywords
    if any(keyword in url.lower() and '-' in url for keyword in HIGH_RISK_KEYWORDS):
        print("❌ Rule Matched: High-risk keyword with hyphen detected")
        return True, "High-risk keyword with hyphen detected"

    # ✅ Check Typosquatting Patterns
    if any(pattern in url.lower() for pattern in TYPOSQUATTING_PATTERNS):
        print("❌ Rule Matched: Typosquatting pattern detected")
        return True, "Typosquatting pattern detected"

    # ✅ Check Lookalike Characters
    if any(re.search(pattern, url.lower()) for pattern in LOOKALIKE_PATTERNS):
        print("❌ Rule Matched: Lookalike character pattern detected")
        return True, "Lookalike character pattern detected"

    # ✅ Check Suspicious Special Characters
    if sum(c in SUSPICIOUS_SPECIAL_CHARS for c in url) > 3:
        print("❌ Rule Matched: Excessive suspicious special characters detected")
        return True, "Excessive suspicious special characters detected"

    print("✅ Rule Check: No explicit scam patterns detected")
    return False, "No explicit scam patterns detected"


# ✅ Advanced Feature Extraction
def extract_features(url):
    """Extract advanced features from the URL."""
    HIGH_RISK_KEYWORDS = [
        'offer', 'free', 'win', 'bonus', 'gift', 'exclusive',
        'hurry', 'prize', 'jackpot', 'lottery', 'reward', 'deal'
    ]
    SUSPICIOUS_TLDS = ['tk', 'ru', 'biz', 'cf', 'xyz']
    SPECIAL_CHARS = ['$', '%', '&', '?', '-', '_', '!', '=', '@']

    scam_score = 0
    for word in HIGH_RISK_KEYWORDS:
        if re.search(rf'\b{word}\b', url.lower()):
            scam_score += 3

    unusual_tlds = 1 if url.split('.')[-1] in SUSPICIOUS_TLDS else 0
    special_chars = sum(c in SPECIAL_CHARS for c in url)
    subdomain_count = url.count('.') - 1
    length_of_url = len(url)

    return {
        'https': 1 if url.startswith('https') else 0,
        'length_of_url': length_of_url,
        'scam_score': scam_score,
        'unusual_tlds': unusual_tlds,
        'special_chars': special_chars,
        'subdomain_count': subdomain_count
    }


# ✅ Root Route
@app.route('/')
def home():
    return jsonify({
        "message": "URL Scam Detector Backend is running successfully.",
        "usage": "Send a POST request to /predict with a JSON payload containing 'url'."
    })


# ✅ Prediction Route
@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        print("✅ Received data:", data)

        if not data or not isinstance(data, list) or 'url' not in data[0]:
            print("❌ Invalid input format")
            return jsonify({"error": "Invalid input format. Expected JSON array with 'url' key."}), 400

        urls = [entry['url'] for entry in data]
        print("✅ Extracted URLs:", urls)

        results = []
        for url in urls:
            # Step 1: Run explicit rules
            suspicious, reason = is_suspicious(url)
            if suspicious:
                results.append({
                    "url": url,
                    "prediction": "Scam",
                    "reason": reason
                })
                continue

            # Step 2: Extract Features for ML Model
            features = extract_features(url)
            features_df = pd.DataFrame([features])
            features_df = features_df.reindex(columns=model.feature_names_in_, fill_value=0)
            print("✅ Features DataFrame (Reindexed):", features_df)

            # Step 3: Machine Learning Prediction
            prediction = model.predict(features_df)[0]
            prediction_label = "Scam" if prediction == 1 else "Legitimate"
            results.append({
                "url": url,
                "prediction": prediction_label,
                "reason": "Predicted by machine learning model"
            })

        return jsonify({"results": results})

    except Exception as e:
        print("❌ Error:", str(e))
        return jsonify({"error": str(e)}), 500


# ✅ Run the Flask App
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
