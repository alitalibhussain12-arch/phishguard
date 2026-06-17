"""
PhishGuard AI - WSGI Entry Point
Used by Gunicorn in production: gunicorn wsgi:application
"""

from app import create_app

application = create_app()

if __name__ == "__main__":
    application.run()
