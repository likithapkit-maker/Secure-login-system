# Secure Login System

Features:
- User registration and login
- Password hashing using Werkzeug (PBKDF2-based password hashing)
- Parameterized SQLite queries to reduce SQL injection risk
- Basic input validation
- Session management and logout

## Run locally
```bash
pip install -r requirements.txt
python app.py
```
Then open http://127.0.0.1:8501

## Deployment
This project can be deployed on a Python hosting service such as Render. Set the start command to:
`python app.py`

For production, replace the Flask secret key with a strong environment variable and use HTTPS.
