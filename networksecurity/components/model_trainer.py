from networksecurity.logging.logger import logging
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.entity.artifact_entity import ModelTrainerArtifact, ClassificationMetricArtifact
import sys
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, precision_score, recall_score
import pickle


class ModelTrainer:
    def __init__(self, model_trainer_config, data_transformation_artifact):
        self.model_trainer_config = model_trainer_config
        self.data_transformation_artifact = data_transformation_artifact

    def initiate_model_trainer(self):
        try:
            logging.info("Starting Model Training")
            
            # Create directories
            os.makedirs(os.path.dirname(self.model_trainer_config.trained_model_file_path), exist_ok=True)
            
            # Load transformed data
            X_train = np.load(self.data_transformation_artifact.transformed_train_file_path)
            X_test = np.load(self.data_transformation_artifact.transformed_test_file_path)
            
            # Separate features and target (assuming last column is target)
            X_train_features = X_train[:, :-1]
            y_train = X_train[:, -1]
            X_test_features = X_test[:, :-1]
            y_test = X_test[:, -1]
            
            # Train model
            model = RandomForestClassifier(n_estimators=100, random_state=42)
            model.fit(X_train_features, y_train)
            
            # Make predictions
            y_train_pred = model.predict(X_train_features)
            y_test_pred = model.predict(X_test_features)
            
            # Calculate metrics
            train_f1 = f1_score(y_train, y_train_pred, average='weighted', zero_division=0)
            train_precision = precision_score(y_train, y_train_pred, average='weighted', zero_division=0)
            train_recall = recall_score(y_train, y_train_pred, average='weighted', zero_division=0)
            
            test_f1 = f1_score(y_test, y_test_pred, average='weighted', zero_division=0)
            test_precision = precision_score(y_test, y_test_pred, average='weighted', zero_division=0)
            test_recall = recall_score(y_test, y_test_pred, average='weighted', zero_division=0)
            
            # Save model
            with open(self.model_trainer_config.trained_model_file_path, 'wb') as f:
                pickle.dump(model, f)
            
            train_metric = ClassificationMetricArtifact(
                f1_score=train_f1,
                precision_score=train_precision,
                recall_score=train_recall
            )
            
            test_metric = ClassificationMetricArtifact(
                f1_score=test_f1,
                precision_score=test_precision,
                recall_score=test_recall
            )
            
            artifact = ModelTrainerArtifact(
                trained_model_file_path=self.model_trainer_config.trained_model_file_path,
                train_metric_artifact=train_metric,
                test_metric_artifact=test_metric
            )
            
            logging.info("Model Training completed")
            return artifact
        except Exception as e:
            raise NetworkSecurityException(e, sys)
