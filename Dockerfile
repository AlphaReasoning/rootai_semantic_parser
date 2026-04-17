# Use the official slim Python image
FROM python:3.11-slim

# 1. System-level Firewall & Build Tools
# Installing build-essential is critical for tree-sitter C-extensions
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# 2. Hugging Face "User Space" Permissions
# HF requires UID 1000 to prevent permission-denied errors on local mounts
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR $HOME/app

# 3. Dependency Logic
COPY --chown=user requirements.txt .
RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install --no-cache-dir -r requirements.txt

# 4. Install the RootAI Package 
# This makes the 'semantic-parser' command available globally in the container
COPY --chown=user . .
RUN python3 -m pip install --editable .

# 5. Network & Execution Logic
# Hugging Face proxies to port 7860
EXPOSE 7860

# --- THE SOVEREIGN PROXY FIX ---
# 1. 'python3 -m' bypasses binary pathing issues.
# 2. 'enableCORS false' and 'enableXsrfProtection false' allow the HF iframe to talk to your app.
CMD ["python3", "-m", "streamlit", "run", "app.py", \
     "--server.port", "7860", \
     "--server.address", "0.0.0.0", \
     "--server.enableCORS", "false", \
     "--server.enableXsrfProtection", "false"]
