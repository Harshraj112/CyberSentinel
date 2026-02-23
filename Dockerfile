FROM python:3.10-slim

WORKDIR /app

# Env vars
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# System dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy all project files (including final_model/)
COPY . .

# Install the cybersentinel package
RUN pip install -e .

# Create necessary runtime directories
RUN mkdir -p logs prediction_output templates

# Expose port (Render sets $PORT dynamically, default 10000)
EXPOSE 10000

# Start FastAPI with Render's dynamic $PORT
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-10000}"]
