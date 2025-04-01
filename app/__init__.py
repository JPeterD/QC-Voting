"""
Secure Voting Application using TFHE Encryption

This Flask application provides a web interface for a secure voting system
backed by the TFHE homomorphic encryption scheme.
"""

from flask import Flask
import os
from tfhe_lib import TFHEContext

# Initialize a global encryption context
# Note: In a real application, you would need to securely manage keys
encryption_context = TFHEContext(polynomial_size=32).generate_keys()

# Create and configure the app
def create_app():
    app = Flask(__name__, template_folder='../templates')
    app.secret_key = os.urandom(24)
    
    # Directory for storing encrypted votes
    app.config['VOTES_DIR'] = "votes"
    app.config['RESULTS_DIR'] = "results"
    app.config['ELECTIONS_FILE'] = "elections.json"
    app.config['ADMIN_FILE'] = "admins.json"
    
    # reCAPTCHA Configuration
    app.config['RECAPTCHA_SITE_KEY'] = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"  # Test key, replace with actual key in production
    app.config['RECAPTCHA_SECRET_KEY'] = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"  # Test key, replace with actual key in production
    
    # Ensure directories exist
    os.makedirs(app.config['VOTES_DIR'], exist_ok=True)
    os.makedirs(app.config['RESULTS_DIR'], exist_ok=True)
    
    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.elections import elections_bp
    from app.routes.main import main_bp
    from app.routes.votes import votes_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(elections_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(votes_bp)
    
    return app