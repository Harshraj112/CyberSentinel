from networksecurity.logging.logger import logging
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.entity.artifact_entity import DataTransformationArtifact
import sys
import os
import pandas as pd
import numpy as np


class DataTransformation:
    def __init__(self, data_validation_artifact, data_transformation_config):
        self.data_validation_artifact = data_validation_artifact
        self.data_transformation_config = data_transformation_config

    def initiate_data_transformation(self):
        try:
            logging.info("Starting Data Transformation")
            
            # Create directories
            os.makedirs(os.path.dirname(self.data_transformation_config.transformed_train_file_path), exist_ok=True)
            os.makedirs(os.path.dirname(self.data_transformation_config.transformed_object_file_path), exist_ok=True)
            
            # Read validated data
            train_df = pd.read_csv(self.data_validation_artifact.valid_train_file_path)
            test_df = pd.read_csv(self.data_validation_artifact.valid_test_file_path)
            
            # Simple transformation: convert to numpy arrays
            train_arr = train_df.values
            test_arr = test_df.values
            
            # Save transformed data as .npy files
            np.save(self.data_transformation_config.transformed_train_file_path, train_arr)
            np.save(self.data_transformation_config.transformed_test_file_path, test_arr)
            
            # Save preprocessing object (dummy)
            with open(self.data_transformation_config.transformed_object_file_path, 'w') as f:
                f.write("Preprocessing object")
            
            artifact = DataTransformationArtifact(
                transformed_object_file_path=self.data_transformation_config.transformed_object_file_path,
                transformed_train_file_path=self.data_transformation_config.transformed_train_file_path,
                transformed_test_file_path=self.data_transformation_config.transformed_test_file_path
            )
            
            logging.info("Data Transformation completed")
            return artifact
        except Exception as e:
            raise NetworkSecurityException(e, sys)
