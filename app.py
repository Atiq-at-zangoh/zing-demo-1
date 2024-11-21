from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from oauthlib.oauth2 import WebApplicationClient
import os, json
import requests
from constants import *
# Flask app initialization
app = Flask(__name__)
app.secret_key = os.urandom(24)

# SQLite database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
client = WebApplicationClient(GOOGLE_CLIENT_ID)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Database model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150))

# Create the database
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    if 'user_email' in session:
        return render_template('dashboard.html', email=session['user_email'])
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash("Email not found. Please sign up first.", "warning")
            return redirect(url_for('signup'))  # Redirect to signup page
        if user.password == password:
            session['user_email'] = user.email
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        flash("Invalid password. Please try again.", "danger")
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash("Email already registered. Please log in.", "warning")
            return redirect(url_for('login'))
        new_user = User(email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/google-login')
def google_login():
    # Get Google's provider configuration
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    
    # Build the authorization URL
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route('/google-login/callback')
def google_callback():
    # Get Google's provider configuration
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Get the authorization code from the request
    code = request.args.get("code")

    # Exchange the authorization code for a token
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
        client_secret=GOOGLE_CLIENT_SECRET,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    ).json()

    # Parse the tokens
    client.parse_request_body_response(json.dumps(token_response))

    # Get user information from Google
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body).json()

    # Check if the user is already in the database
    email = userinfo_response["email"]
    user = User.query.filter_by(email=email).first()
    if not user:
        # Add new user to the database
        new_user = User(email=email)
        db.session.add(new_user)
        db.session.commit()

    # Log the user in
    session['user_email'] = email
    flash("Login successful!", "success")
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))

@app.route('/connect/gmail')
def connect_gmail():
    # Implement Gmail OAuth flow here
    return "Redirecting to Gmail OAuth..."

@app.route('/connect/github')
def connect_github():
    # Implement GitHub OAuth flow here
    return "Redirecting to GitHub OAuth..."

@app.route('/connect/slack')
def connect_slack():
    # Implement Slack OAuth flow here
    return "Redirecting to Slack OAuth..."


if __name__ == '__main__':
    app.run(debug=True)
