"""Entry point for the deliberately-vulnerable Flask demo app.

    python -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    python run.py

Then open http://127.0.0.1:5000/ for an index of every vulnerable endpoint.

WARNING: This application contains intentional security vulnerabilities for
education and tooling demonstrations. Never expose it to an untrusted network.
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # debug=True is itself a (minor) misconfiguration for a "prod" app: it
    # exposes the Werkzeug debugger/PIN. Handy for the demo, dangerous in prod.
    app.run(host="127.0.0.1", port=5000, debug=True)
