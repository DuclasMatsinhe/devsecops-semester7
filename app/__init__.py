from flask import Flask

def create_app():
    app = Flask(__name__)

    @app.get("/")
    def index():
        return {
            "application": "Semester 7 DevSecOps Security Validation Prototype",
            "status": "running"
        }

    @app.get("/health")
    def health():
        return {"status": "healthy"}

    return app
