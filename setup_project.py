import os

project_name = "SRI"

structure = {
    "backend": [
        "app.py",
        "requirements.txt",
        ".env",
        ".gitignore",
        "render.yaml"
    ],
    "backend/templates": [
        "index.html"
    ]
}

# Create main folder
os.makedirs(project_name, exist_ok=True)

# Create subfolders and files
for folder, files in structure.items():
    folder_path = os.path.join(project_name, folder)
    os.makedirs(folder_path, exist_ok=True)

    for file in files:
        file_path = os.path.join(folder_path, file)

        with open(file_path, "w", encoding="utf-8") as f:

            # ==============================
            # Environment Variables
            # ==============================
            if file == ".env":
                f.write("GROQ_API_KEY=\n")

            # ==============================
            # Requirements
            # ==============================
            elif file == "requirements.txt":
                f.write(
                    "Flask==3.0.3\n"
                    "Flask-CORS==4.0.1\n"
                    "requests==2.31.0\n"
                    "python-dotenv==1.0.1\n"
                    "gunicorn==22.0.0\n"
                )

            # ==============================
            # Git Ignore
            # ==============================
            elif file == ".gitignore":
                f.write(
                    "# Python virtual environments\n"
                    "venv/\n"
                    ".venv/\n\n"
                    "# Python cache files\n"
                    "__pycache__/\n"
                    "*.pyc\n"
                    "*.pyo\n"
                    "*.pyd\n\n"
                    "# Environment variables\n"
                    ".env\n\n"
                    "# IDE settings\n"
                    ".vscode/\n"
                    ".idea/\n\n"
                    "# OS files\n"
                    ".DS_Store\n"
                    "Thumbs.db\n\n"
                    "# Log files\n"
                    "*.log\n"
                )

            # ==============================
            # Render Configuration
            # ==============================
            elif file == "render.yaml":
                f.write(
                    "services:\n"
                    "  - type: web\n"
                    "    name: sentinel-ai\n"
                    "    env: python\n"
                    "    rootDir: backend\n"
                    "    buildCommand: pip install -r requirements.txt\n"
                    "    startCommand: gunicorn app:app\n"
                    "    plan: free\n"
                )

            # ==============================
            # Basic Flask App Template
            # ==============================
            elif file == "app.py":
                f.write("""from flask import Flask, render_template, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
CORS(app)

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/health")
def health():
    return {
        "backend": "running",
        "groq_api": "connected" if GROQ_API_KEY else "not_configured"
    }

if __name__ == "__main__":
    app.run(debug=True)
""")

            # ==============================
            # Basic HTML Template
            # ==============================
            elif file == "index.html":
                f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINEL AI</title>
</head>
<body>
    <h1>SENTINEL AI</h1>
    <p>Frontend is working successfully.</p>

    <script>
        // For Render deployment, use same domain
        const BACKEND_URL = '';

        async function checkHealth() {
            const response = await fetch(`${BACKEND_URL}/health`);
            const data = await response.json();
            console.log(data);
        }

        checkHealth();
    </script>
</body>
</html>
""")

print("✅ Project structure created successfully!")
print("📁 Render-ready Flask project has been generated.")
print("🚀 You can now replace app.py and index.html with your actual project files.")