# Use Python 3.10 slim image as base for smaller size
FROM python:3.10-slim

# Set working directory in container
WORKDIR /app

# Set environment variables
# Prevents Python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
# Prevents Python from buffering stdout and stderr
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the entire project to the container
COPY . .

# Create necessary directories
RUN mkdir -p logs final_model prediction_output templates

# Install the cybersentinel package in editable mode
RUN pip install -e .

# Expose port 8000 for FastAPI application
EXPOSE 8000

# Command to run the FastAPI application
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
