"""Flask application factory.

Vulnerability modules live in ``app/vulns/`` and are auto-discovered: any
module that defines a module-level ``bp`` (a Flask ``Blueprint``) is registered
automatically. This lets each OWASP category live in its own self-contained
file with no central wiring to edit.
"""
import importlib
import pkgutil

from flask import Flask, render_template

from . import db, vulns


def create_app():
    app = Flask(__name__)

    # ---------------------------------------------------------------------
    # VULNERABILITY (Cryptographic Failures): a hard-coded secret key checked
    # into source control. Anyone with the repo can forge session cookies.
    # OWASP 2021 A02 | OWASP 2025 A04 | CWE-798 Use of Hard-coded Credentials
    # ---------------------------------------------------------------------
    app.config["SECRET_KEY"] = "super-secret-demo-key-please-change-1234567890"

    db.init_app(app)

    # Auto-register every blueprint found in the vulns package.
    for _, name, _ in pkgutil.iter_modules(vulns.__path__):
        module = importlib.import_module(f"{vulns.__name__}.{name}")
        if hasattr(module, "bp"):
            app.register_blueprint(module.bp)

    @app.route("/")
    def index():
        routes = []
        for rule in app.url_map.iter_rules():
            if rule.endpoint == "static" or rule.rule == "/":
                continue
            methods = sorted(
                m for m in rule.methods if m in {"GET", "POST", "PUT", "DELETE"}
            )
            routes.append(
                {
                    "rule": rule.rule,
                    "methods": ", ".join(methods),
                    "endpoint": rule.endpoint,
                }
            )
        routes.sort(key=lambda r: r["rule"])
        return render_template("index.html", routes=routes)

    return app
