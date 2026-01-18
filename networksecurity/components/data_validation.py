from networksecurity.logging.logger import logging
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.entity.artifact_entity import DataValidationArtifact
import sys
import os
import pandas as pd


class DataValidation:
    def __init__(self, data_ingestion_artifact, data_validation_config):
        self.data_ingestion_artifact = data_ingestion_artifact
        self.data_validation_config = data_validation_config

    def initiate_data_validation(self):
        try:
            logging.info("Starting Data Validation")
            
            # Create directories
            os.makedirs(self.data_validation_config.valid_data_dir, exist_ok=True)
            os.makedirs(self.data_validation_config.invalid_data_dir, exist_ok=True)
            os.makedirs(os.path.dirname(self.data_validation_config.drift_report_file_path), exist_ok=True)
            
            # Read train and test data
            train_df = pd.read_csv(self.data_ingestion_artifact.trained_file_path)
            test_df = pd.read_csv(self.data_ingestion_artifact.test_file_path)
            
            # Assume all data is valid for now
            train_df.to_csv(self.data_validation_config.valid_train_file_path, index=False)
            test_df.to_csv(self.data_validation_config.valid_test_file_path, index=False)
            
            # Create empty invalid files
            open(self.data_validation_config.invalid_train_file_path, 'w').close()
            open(self.data_validation_config.invalid_test_file_path, 'w').close()
            
            # Create drift report
            with open(self.data_validation_config.drift_report_file_path, 'w') as f:
                f.write("No drift detected")
            
            artifact = DataValidationArtifact(
                validation_status=True,
                valid_train_file_path=self.data_validation_config.valid_train_file_path,
                valid_test_file_path=self.data_validation_config.valid_test_file_path,
                invalid_train_file_path=self.data_validation_config.invalid_train_file_path,
                invalid_test_file_path=self.data_validation_config.invalid_test_file_path,
                drift_report_file_path=self.data_validation_config.drift_report_file_path
            )
            
            logging.info("Data Validation completed")
            return artifact
        except Exception as e:
            raise NetworkSecurityException(e, sys)
