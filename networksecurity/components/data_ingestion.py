from networksecurity.logging.logger import logging
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.entity.artifact_entity import DataIngestionArtifact
import sys
import os
from sklearn.model_selection import train_test_split
import pandas as pd


class DataIngestion:
    def __init__(self, data_ingestion_config):
        self.data_ingestion_config = data_ingestion_config

    def initiate_data_ingestion(self):
        try:
            logging.info("Starting Data Ingestion")
            
            # Create directories
            os.makedirs(self.data_ingestion_config.data_ingestion_dir, exist_ok=True)
            os.makedirs(os.path.dirname(self.data_ingestion_config.feature_store_file_path), exist_ok=True)
            
            # Copy raw data from Network_Data to feature store
            source_file = os.path.join(os.getcwd(), "Network_Data", "phisingData.csv")
            if not os.path.exists(source_file):
                raise FileNotFoundError(f"Source data file not found: {source_file}")
            
            import shutil
            shutil.copy(source_file, self.data_ingestion_config.feature_store_file_path)
            
            # Read raw data
            df = pd.read_csv(self.data_ingestion_config.feature_store_file_path)
            logging.info(f"Raw data shape: {df.shape}")
            
            # Split data
            train_data, test_data = train_test_split(
                df,
                test_size=1 - self.data_ingestion_config.train_test_split_ratio,
                random_state=42
            )
            
            # Log split details
            logging.info(f"Train-Test Split Ratio: {self.data_ingestion_config.train_test_split_ratio}")
            logging.info(f"Train data shape: {train_data.shape}")
            logging.info(f"Test data shape: {test_data.shape}")
            logging.info(f"Train samples: {len(train_data)}, Test samples: {len(test_data)}")
            
            # Save train and test files
            os.makedirs(os.path.dirname(self.data_ingestion_config.training_file_path), exist_ok=True)
            train_data.to_csv(self.data_ingestion_config.training_file_path, index=False)
            test_data.to_csv(self.data_ingestion_config.testing_file_path, index=False)
            logging.info(f"Train data saved at: {self.data_ingestion_config.training_file_path}")
            logging.info(f"Test data saved at: {self.data_ingestion_config.testing_file_path}")
            
            artifact = DataIngestionArtifact(
                trained_file_path=self.data_ingestion_config.training_file_path,
                test_file_path=self.data_ingestion_config.testing_file_path
            )
            
            logging.info("Data Ingestion completed")
            return artifact
        except Exception as e:
            raise NetworkSecurityException(e, sys)
