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
# Allow CORS for your Netlify domain
CORS(app, resources={r"/*": {"origins": ["https://radiant-selkie-120b55.netlify.app", "http://127.0.0.1:8080"]}})

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
publishable_key = os.getenv('STRIPE_PUBLISHABLE_KEY')
print("STRIPE_SECRET_KEY:", stripe.api_key)
print("STRIPE_PUBLISHABLE_KEY:", os.getenv('STRIPE_PUBLISHABLE_KEY'))
# ✅ Load the Trained Model
model_path = os.path.join(os.path.dirname(__file__), 'optimized_random_forest_model.pkl')

try:
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

# Trusted Domains List
TRUSTED_DOMAINS = [
    'outlook.office.com', 'mail.google.com', 'yahoo.com', 'hotmail.com', 'icloud.com',
    'queensu.ca', 'harvard.edu', 'stanford.edu', 'mit.edu', 'ox.ac.uk',
    'paypal.com', 'stripe.com', 'bankofamerica.com', 'chase.com', 'wellsfargo.com',
    '.gov', '.gov.uk', 'canada.ca',
    'aws.amazon.com', 'cloudflare.com', 'azure.microsoft.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
    'amazon.com', 'ebay.com', 'shopify.com', '.ca' , '.et', '.org', '.edu'
]

# Update is_suspicious function
def is_suspicious(url):
    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Check against trusted domains
    if any(domain.endswith(trusted) for trusted in TRUSTED_DOMAINS):
        return False, "Trusted domain detected"
    
    # Continue with existing checks
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
        # ✅ Validate API Key
        api_key = request.headers.get('Authorization')
        if not api_key:
            logger.warning("❌ Missing API Key in Authorization header.")
            return jsonify({"error": "Missing API Key in Authorization header."}), 401

        user = User.query.filter_by(api_key=api_key).first()
        if not user:
            logger.warning("❌ Unauthorized access attempt detected with API Key: %s", api_key)
            return jsonify({"error": "Unauthorized: Invalid API Key."}), 401

        # ✅ Check Premium Status
        if not user.is_premium:
            logger.warning("🔒 Non-premium user attempted advanced features. User ID: %s", user.id)
            return jsonify({"error": "Upgrade to Premium for advanced features."}), 402

        # ✅ Validate Input Data
        data = request.get_json()
        if not data or 'url' not in data[0]:
            logger.warning("❌ Invalid JSON payload: Missing 'url' field.")
            return jsonify({"error": "Invalid payload. Ensure 'url' is provided in the request body."}), 400

        url = data[0]['url']

        # ✅ Check for Suspicious Patterns
        suspicious, reason = is_suspicious(url)
        if suspicious:
            logger.info("⚠️ Suspicious URL detected: %s | Reason: %s", url, reason)
            return jsonify({"results": [{"url": url, "prediction": "Scam", "reason": reason}]})

        # ✅ Feature Extraction & Model Prediction
        features = extract_features(url)
        features_df = pd.DataFrame([features])

        prediction = model.predict(features_df)[0]
        prediction_label = "Scam" if prediction == 1 else "Legitimate"

        logger.info("✅ Prediction complete: %s | Result: %s", url, prediction_label)

        return jsonify({
            "results": [{"url": url, "prediction": prediction_label, "reason": "Predicted by ML model"}]
        })

    except KeyError as e:
        logger.error("❌ KeyError in /predict: Missing key - %s", str(e))
        return jsonify({"error": f"KeyError: {str(e)}"}), 400

    except pd.errors.EmptyDataError as e:
        logger.error("❌ Pandas Error: %s", str(e))
        return jsonify({"error": "Error processing the data. Ensure valid input."}), 400

    except Exception as e:
        logger.error("❌ Unexpected Error in /predict: %s", str(e))
        return jsonify({"error": "An unexpected error occurred. Please try again later."}), 500

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
# ✅ Create Checkout Session Endpoint
@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': 'Premium Plan',
                        'description': 'Unlock advanced scam detection features.'
                    },
                    'unit_amount': 500
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url='https://radiant-selkie-120b55.netlify.app//success',
            cancel_url='https://radiant-selkie-120b55.netlify.app//cancel',
        )
        return jsonify({'checkout_url': session.url})
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error: {e}")
        return jsonify({'error': str(e)}), 500
@app.route('/debug-api-keys', methods=['GET'])
def debug_api_keys():
    try:
        users = User.query.all()
        users_data = [{"username": user.username, "api_key": user.api_key, "is_premium": user.is_premium} for user in users]
        return jsonify({"users": users_data})
    except Exception as e:
        logger.error(f"❌ Error in /debug-api-keys: {str(e)}")
        return jsonify({"error": str(e)}), 500
    @app.route('/add-api-key', methods=['POST'])
def add_api_key():
    try:
        with app.app_context():
            new_user = User(username='admin', password='securepassword', api_key='test_api_key', is_premium=True)
            db.session.add(new_user)
            db.session.commit()
        return jsonify({"message": "API key added successfully."})
    except Exception as e:
        logger.error(f"❌ Error in /add-api-key: {str(e)}")
        return jsonify({"error": str(e)}), 500
# ✅ Run the Server
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)