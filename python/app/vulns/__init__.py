"""Vulnerability modules.

Each module in this package defines a module-level ``bp`` (Flask Blueprint) and
is auto-registered by the application factory. One module per OWASP category;
multiple annotated *permutations* of the vulnerability live inside each module.
"""
