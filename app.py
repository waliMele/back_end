from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import joblib
import pandas as pd
import re
import stripe
import os
import logging

# ✅ Initialize Flask App
app = Flask(__name__)
CORS(app)

# ✅ Logging Configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.info("🚀 Starting the URL Scam Detector Backend...")

# ✅ Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ✅ Stripe Configuration
stripe.api_key = os.getenv('STRIPE_SECRET_KEY', 'your_stripe_secret_key')

# ✅ Load the Trained Model
model = None
try:
    model_path = os.path.expanduser('~/Desktop/back_end/optimized_random_forest_model.pkl')
    model = joblib.load(model_path)
    if hasattr(model, 'predict'):
        logger.info("✅ Machine Learning model loaded successfully.")
    else:
        raise ValueError("Loaded object is not a valid model.")
except FileNotFoundError:
    logger.error("❌ optimized_random_forest_model.pkl not found. Ensure the file exists.")
except Exception as e:
    logger.error(f"❌ Error loading model: {str(e)}")

# ✅ User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_premium = db.Column(db.Boolean, default=False)
    api_key = db.Column(db.String(100), unique=True)

# ✅ Initialize the Database
with app.app_context():
    db.create_all()
    logger.info("✅ Database initialized.")

# ✅ Explicit Conditional Rules for Scam Detection
def is_suspicious(url):
    HIGH_RISK_KEYWORDS = ['offer', 'free', 'win', 'bonus', 'gift']
    SUSPICIOUS_TLDS = ['tk', 'ru', 'biz', 'cf', 'xyz']
    SPECIAL_CHARS = ['$', '%', '&', '?', '-', '_', '!', '=', '@']

    if url.split('.')[-1] in SUSPICIOUS_TLDS:
        return True, "Suspicious TLD detected"
    if any(keyword in url.lower() for keyword in HIGH_RISK_KEYWORDS):
        return True, "High-risk keyword detected"
    if sum(c in SPECIAL_CHARS for c in url) > 3:
        return True, "Excessive special characters detected"
    return False, "No explicit scam patterns detected"

# ✅ Feature Extraction
def extract_features(url):
    HIGH_RISK_KEYWORDS = ['offer', 'free', 'win', 'bonus', 'gift']
    SUSPICIOUS_TLDS = ['tk', 'ru', 'biz', 'cf', 'xyz']
    SPECIAL_CHARS = ['$', '%', '&', '?', '-', '_', '!', '=', '@']

    scam_keywords = sum(word in url.lower() for word in HIGH_RISK_KEYWORDS)
    unusual_tlds = 1 if url.split('.')[-1] in SUSPICIOUS_TLDS else 0
    special_chars = sum(c in SPECIAL_CHARS for c in url)
    length_of_url = len(url)
    web_traffic = 0

    return {
        'web_traffic': web_traffic,
        'https': 1 if url.startswith('https') else 0,
        'length_of_url': length_of_url,
        'scam_keywords': scam_keywords,
        'unusual_tlds': unusual_tlds,
        'special_chars': special_chars
    }

# ✅ Predict Endpoint
@app.route('/predict', methods=['POST'])
def predict():
    try:
        api_key = request.headers.get('Authorization')
        user = User.query.filter_by(api_key=api_key).first()
        
        if not user:
            logger.warning("❌ Unauthorized access attempt detected.")
            return jsonify({"error": "Unauthorized"}), 401
        
        if not user.is_premium:
            logger.warning("🔒 Non-premium user attempted advanced features.")
            return jsonify({"error": "Upgrade to Premium for advanced features."}), 402

        data = request.get_json()
        url = data[0]['url']

        suspicious, reason = is_suspicious(url)
        if suspicious:
            return jsonify({"results": [{"url": url, "prediction": "Scam", "reason": reason}]})

        features = extract_features(url)
        features_df = pd.DataFrame([features])
        prediction = model.predict(features_df)[0]
        prediction_label = "Scam" if prediction == 1 else "Legitimate"
        
        return jsonify({"results": [{"url": url, "prediction": prediction_label, "reason": "Predicted by ML model"}]})
    except Exception as e:
        logger.error(f"❌ Error in /predict: {str(e)}")
        return jsonify({"error": str(e)}), 500

# ✅ Health Check Endpoint
@app.route('/health', methods=['GET'])
def health_check():
    logger.info("✅ Health check endpoint accessed.")
    return jsonify({
        "message": "Server is running successfully.",
        "usage": "Send a POST request to /predict with a JSON payload containing 'url'."
    })

# ✅ Root Route
@app.route('/', methods=['GET'])
def root():
    logger.info("✅ Root route accessed.")
    return jsonify({
        "message": "Welcome to URL Scam Detector Backend!",
        "health_check": "/health"
    })
# ✅ Run the Server
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
