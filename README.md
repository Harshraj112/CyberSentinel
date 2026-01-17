# Network Security ML Pipeline

A comprehensive end-to-end machine learning pipeline for network security and phishing detection, implementing modular components for data processing, model training, evaluation, and deployment.

![ML Pipeline Workflow](ml_pipeline_workflow.png)

## 📋 Table of Contents

- [Overview](#overview)
- [Pipeline Architecture](#pipeline-architecture)
- [Components](#components)
- [Configuration Files](#configuration-files)
- [Installation](#installation)
- [Usage](#usage)
- [Deployment](#deployment)
- [Project Structure](#project-structure)

## 🎯 Overview

This project implements a production-ready machine learning pipeline for network security analysis. The system automatically processes network data, trains models, evaluates performance, and deploys the best-performing models to cloud storage (AWS/Azure).

**Key Features:**
- Modular component-based architecture
- Automated data validation and transformation
- Model evaluation with acceptance criteria
- Cloud deployment integration
- Comprehensive logging and artifact management
- MongoDB integration for data storage

## 🏗️ Pipeline Architecture

The ML pipeline consists of six main components that work sequentially:

### 1. **Data Ingestion Component**
- **Configuration**: `Data Ingestion Config`
- **Purpose**: Fetches network security data from MongoDB database
- **Outputs**: `Data Ingestion Artifacts` containing raw data for processing

### 2. **Data Validation Component**
- **Configuration**: `Data Validation Config`
- **Purpose**: Validates data quality, schema, and integrity
- **Checks**: Missing values, data drift, schema compliance
- **Outputs**: `Data Validation Artifacts` with validation reports

### 3. **Data Transformation Component**
- **Configuration**: `Data Transformation Config`
- **Purpose**: Preprocesses and transforms data for model training
- **Operations**: Feature engineering, encoding, scaling, splitting
- **Outputs**: `Data Transformation Artifacts` with processed datasets

### 4. **Model Trainer Component**
- **Configuration**: `Model Trainer Config`
- **Purpose**: Trains machine learning models on processed data
- **Outputs**: `Model Trainer Artifacts` containing trained models and metrics

### 5. **Model Evaluation Component**
- **Configuration**: `Model Evaluation Config`
- **Purpose**: Evaluates model performance against acceptance criteria
- **Decision Point**: Determines if model is accepted or rejected
- **Outputs**: `Model Evaluation Artifacts` with performance metrics

### 6. **Model Pusher Component**
- **Configuration**: `Model Pusher Config`
- **Purpose**: Deploys accepted models to cloud storage
- **Deployment**: Pushes models to AWS S3 or Azure Blob Storage
- **Outputs**: Deployed model accessible for inference

## 🔧 Components

### Data Ingestion
```python
from networksecurity.components.data_ingestion import DataIngestion
```
- Connects to MongoDB database
- Extracts network security dataset
- Stores raw data for validation

### Data Validation
```python
from networksecurity.components.data_validation import DataValidation
```
- Validates data schema
- Checks for missing values
- Detects data drift
- Generates validation reports

### Data Transformation
```python
from networksecurity.components.data_transformation import DataTransformation
```
- Feature engineering
- Categorical encoding
- Feature scaling
- Train-test splitting

### Model Trainer
```python
from networksecurity.components.model_trainer import ModelTrainer
```
- Trains ML models
- Performs hyperparameter tuning
- Generates training metrics
- Saves trained models

### Model Evaluation
```python
from networksecurity.components.model_evaluation import ModelEvaluation
```
- Evaluates model performance
- Compares against baseline
- Applies acceptance criteria
- Determines deployment eligibility

### Model Pusher
```python
from networksecurity.components.model_pusher import ModelPusher
```
- Deploys accepted models
- Uploads to cloud storage
- Manages model versioning

## ⚙️ Configuration Files

Each component is configured through dedicated configuration files:

- 📄 `Data Ingestion Config` - Database connection, collection settings
- 📄 `Data Validation Config` - Validation rules, drift thresholds
- 📄 `Data Transformation Config` - Preprocessing parameters
- 📄 `Model Trainer Config` - Model hyperparameters, algorithms
- 📄 `Model Evaluation Config` - Acceptance criteria, metrics
- 📄 `Model Pusher Config` - Cloud credentials, deployment settings

## 📦 Installation

### Prerequisites
- Python 3.8+
- MongoDB
- AWS/Azure account (for deployment)

### Setup

1. **Clone the repository**
```bash
git clone <repository-url>
cd networksecurity
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Install the package**
```bash
pip install -e .
```

4. **Configure environment variables**
```bash
# MongoDB
MONGO_DB_URL=<your-mongodb-url>

# AWS (Optional)
AWS_ACCESS_KEY_ID=<your-access-key>
AWS_SECRET_ACCESS_KEY=<your-secret-key>
AWS_REGION=us-east-1
AWS_ECR_LOGIN_URI=<your-ecr-uri>
ECR_REPOSITORY_NAME=networkssecurity
```

## 🚀 Usage

### Running the Complete Pipeline

Execute the entire ML pipeline from data ingestion to model deployment:

```bash
python main.py
```

### Running Individual Components

```python
from networksecurity.pipeline.training_pipeline import TrainingPipeline

# Initialize and run pipeline
pipeline = TrainingPipeline()
pipeline.run_pipeline()
```

### Making Predictions

```bash
python app.py
```

### Pushing Data to MongoDB

```bash
python push_data.py
```

## 🌐 Deployment

### Docker Setup

**Build Docker image:**
```bash
docker build -t networksecurity .
```

**Run container:**
```bash
docker run -p 8080:8080 networksecurity
```

### EC2 Deployment

**Setup Docker on EC2:**
```bash
# Update system
sudo apt-get update -y
sudo apt-get upgrade

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker ubuntu
newgrp docker
```

### GitHub Secrets Configuration

Set up the following secrets in your GitHub repository:

- `AWS_ACCESS_KEY_ID` - Your AWS access key
- `AWS_SECRET_ACCESS_KEY` - Your AWS secret key
- `AWS_REGION` - AWS region (e.g., us-east-1)
- `AWS_ECR_LOGIN_URI` - ECR login URI
- `ECR_REPOSITORY_NAME` - ECR repository name

## 📁 Project Structure

```
networksecurity/
├── networksecurity/               # Main package
│   ├── components/               # Pipeline components
│   │   ├── data_ingestion.py
│   │   ├── data_validation.py
│   │   ├── data_transformation.py
│   │   ├── model_trainer.py
│   │   ├── model_evaluation.py
│   │   └── model_pusher.py
│   ├── entity/                   # Configuration entities
│   │   ├── config_entity.py
│   │   └── artifact_entity.py
│   ├── pipeline/                 # Pipeline orchestration
│   │   └── training_pipeline.py
│   ├── exception/                # Custom exceptions
│   ├── logging/                  # Logging utilities
│   ├── constant/                 # Constants
│   ├── utils/                    # Utility functions
│   └── cloud/                    # Cloud integration
├── Artifacts/                    # Generated artifacts
├── logs/                         # Application logs
├── final_model/                  # Deployed models
├── templates/                    # Web UI templates
├── main.py                       # Pipeline execution
├── app.py                        # Flask application
├── push_data.py                  # Data upload script
├── setup.py                      # Package setup
├── requirements.txt              # Dependencies
├── Dockerfile                    # Docker configuration
└── README.md                     # Documentation
```

## 🔄 Workflow

1. **Data Ingestion**: Fetch data from MongoDB
2. **Data Validation**: Validate data quality and schema
3. **Data Transformation**: Preprocess and transform features
4. **Model Training**: Train ML models with hyperparameter tuning
5. **Model Evaluation**: Evaluate and validate model performance
6. **Decision**: Accept or reject model based on criteria
7. **Model Deployment**: Push accepted models to cloud (AWS/Azure)

## 📊 Artifacts

All components generate artifacts stored in the `Artifacts/` directory:
- Raw data files
- Validation reports
- Transformed datasets
- Trained models
- Evaluation metrics
- Deployment logs

## 🛠️ Technologies Used

- **Python 3.8+** - Core programming language
- **MongoDB** - Data storage
- **Scikit-learn** - Machine learning
- **Pandas** - Data manipulation
- **Flask** - Web application
- **Docker** - Containerization
- **AWS/Azure** - Cloud deployment
- **GitHub Actions** - CI/CD

## 📝 Logging

Comprehensive logging is implemented throughout the pipeline:
- Component-level logs
- Error tracking
- Artifact generation logs
- All logs stored in `logs/` directory

## 🤝 Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is part of a network security ML initiative.

## 👤 Author

**Harsh Raj**
- Email: harshraj250106@gmail.com

---

**Note**: Ensure all cloud credentials and database connections are properly configured before running the pipeline. The model pusher component will only deploy models that pass the evaluation criteria.