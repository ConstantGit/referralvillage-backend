#!/bin/bash

echo "🚀 ReferralVillage Backend Migration Script"
echo "=========================================="
echo ""

echo "🧹 Cleaning out Node.js files..."
# Remove Node.js files and folders
rm -rf node_modules/ 2>/dev/null || true
rm -f package.json package-lock.json 2>/dev/null || true
rm -f server.js 2>/dev/null || true
rm -rf routes/ middleware/ 2>/dev/null || true
rm -rf .devcontainer/ 2>/dev/null || true
rm -rf prisma/ 2>/dev/null || true
rm -f *.js 2>/dev/null || true

echo "📁 Creating Python/FastAPI directory structure..."
# Create directory structure
mkdir -p app/{api/api_v1/endpoints,core,db,models,schemas,services,workers}
mkdir -p alembic/versions
mkdir -p tests/api
mkdir -p scripts
mkdir -p .github/workflows

# Create __init__.py files
touch app/__init__.py
touch app/api/__init__.py
touch app/api/api_v1/__init__.py
touch app/api/api_v1/endpoints/__init__.py
touch app/core/__init__.py
touch app/db/__init__.py
touch app/models/__init__.py
touch app/schemas/__init__.py
touch app/services/__init__.py
touch app/workers/__init__.py
touch tests/__init__.py
touch tests/api/__init__.py

echo "📝 Creating configuration files..."

# Create requirements.txt
cat > requirements.txt << 'EOF'
# Core
fastapi==0.110.0
uvicorn[standard]==0.27.0
gunicorn==21.2.0

# Database
sqlalchemy==2.0.25
alembic==1.13.1
psycopg2-binary==2.9.9

# Auth & Security
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6
email-validator==2.1.0

# Integrations
stripe==7.12.0
openai==1.10.0
httpx==0.26.0

# Redis & Background Tasks
redis==5.0.1
celery==5.3.4

# Utils
pydantic==2.5.3
pydantic-settings==2.1.0
python-dotenv==1.0.0

# Monitoring
sentry-sdk[fastapi]==1.40.0
psutil==5.9.8

# Development
pytest==7.4.4
pytest-asyncio==0.23.3
EOF

# Create .gitignore
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
ENV/

# Environment
.env
.env.local
.env.*.local

# Database
*.db
*.sqlite3

# Logs
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo

# Railway
.railway/

# Testing
.coverage
htmlcov/
.pytest_cache/

# OS
.DS_Store
Thumbs.db
EOF

# Create railway.json
cat > railway.json << 'EOF'
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "NIXPACKS"
  },
  "deploy": {
    "startCommand": "uvicorn app.main:app --host 0.0.0.0 --port $PORT",
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 10
  }
}
EOF

# Create .env.example
cat > .env.example << 'EOF'
# Railway provides these automatically
# DATABASE_URL=postgresql://...
# REDIS_URL=redis://...
# PORT=...

# Add these in Railway dashboard
SECRET_KEY=your-secret-key-here
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
OPENAI_API_KEY=sk-...
SENTRY_DSN=https://...
EOF

echo ""
echo "✅ Migration structure created!"
echo ""
echo "Now creating the Python setup script..."

# Create the Python setup script
cat > complete_setup.py << 'EOF'
#!/usr/bin/env python3
print("Starting Python files creation...")
print("Copy the content from Claude's artifact #9")
print("(Complete Python Setup Script - Part 2)")
EOF

chmod +x complete_setup.py

echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Copy the content from artifact #9 into complete_setup.py"
echo "2. Run: python3 complete_setup.py"
echo "3. Commit and push your changes"
