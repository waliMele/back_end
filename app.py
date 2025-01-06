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
logger.info("Starting the URL Scam Detector Backend...")

# ✅ Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ✅ Stripe Configuration
stripe.api_key = os.getenv('STRIPE_SECRET_KEY', 'your_stripe_secret_key')

# ✅ Load the trained ML model
try:
    model = joblib.load('optimized_random_forest_model.pkl')
    logger.info("Machine learning model loaded successfully.")
except FileNotFoundError:
    logger.error("optimized_random_forest_model.pkl not found. Ensure the file exists.")
    model = None

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
    logger.info("Database initialized.")

# ✅ Explicit Conditional Rules for Scam Detection
def is_suspicious(url):
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

    if url.split('.')[-1] in SUSPICIOUS_TLDS:
        return True, "Suspicious TLD detected"
    if any(keyword in url.lower() and '-' in url for keyword in HIGH_RISK_KEYWORDS):
        return True, "High-risk keyword with hyphen detected"
    if any(pattern in url.lower() for pattern in TYPOSQUATTING_PATTERNS):
        return True, "Typosquatting pattern detected"
    if any(re.search(pattern, url.lower()) for pattern in LOOKALIKE_PATTERNS):
        return True, "Lookalike character pattern detected"
    if sum(c in SUSPICIOUS_SPECIAL_CHARS for c in url) > 3:
        return True, "Excessive suspicious special characters detected"
    return False, "No explicit scam patterns detected"

# ✅ Feature Extraction
def extract_features(url):
    HIGH_RISK_KEYWORDS = ['offer', 'free', 'win', 'bonus', 'gift']
    SUSPICIOUS_TLDS = ['tk', 'ru', 'biz', 'cf', 'xyz']
    SPECIAL_CHARS = ['$', '%', '&', '?', '-', '_', '!', '=', '@']

    scam_score = sum(word in url.lower() for word in HIGH_RISK_KEYWORDS)
    unusual_tlds = 1 if url.split('.')[-1] in SUSPICIOUS_TLDS else 0
    special_chars = sum(c in SPECIAL_CHARS for c in url)
    length_of_url = len(url)

    return {
        'https': 1 if url.startswith('https') else 0,
        'length_of_url': length_of_url,
        'scam_score': scam_score,
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
            logger.warning("Unauthorized access attempt detected.")
            return jsonify({"error": "Unauthorized"}), 401
        
        if not user.is_premium:
            logger.warning("Non-premium user attempted advanced features.")
            return jsonify({"error": "Upgrade to Premium for advanced features."}), 402

        data = request.get_json()
        if not data or 'url' not in data[0]:
            logger.error("Invalid input format received.")
            return jsonify({"error": "Invalid input format"}), 400

        url = data[0]['url']
        suspicious, reason = is_suspicious(url)
        if suspicious:
            logger.info(f"Explicit scam detected for URL: {url}")
            return jsonify({"results": [{"url": url, "prediction": "Scam", "reason": reason}]})

        features = extract_features(url)
        features_df = pd.DataFrame([features])
        prediction = model.predict(features_df)[0]
        prediction_label = "Scam" if prediction == 1 else "Legitimate"
        logger.info(f"Prediction for {url}: {prediction_label}")
        
        return jsonify({"results": [{"url": url, "prediction": prediction_label, "reason": "Predicted by machine learning model"}]})
    
    except Exception as e:
        logger.error(f"Error in /predict: {str(e)}")
        return jsonify({"error": str(e)}), 500

# ✅ Stripe Checkout Session
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {'name': 'Premium Membership'},
                    'unit_amount': 500,
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url='https://yourdomain.com/success',
            cancel_url='https://yourdomain.com/cancel',
        )
        logger.info("Stripe checkout session created successfully.")
        return jsonify({'id': session.id})
    except Exception as e:
        logger.error(f"Stripe checkout error: {str(e)}")
        return jsonify(error=str(e)), 403

# ✅ Health Check Endpoint
@app.route('/')
def health_check():
    logger.info("Health check endpoint accessed.")
    return jsonify({
        "message": "URL Scam Detector Backend is running successfully.",
        "usage": "Send a POST request to /predict with a JSON payload containing 'url'."
    })

# ✅ Run the Server
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
