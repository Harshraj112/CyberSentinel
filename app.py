import sys
import os

import certifi
ca = certifi.where()

from dotenv import load_dotenv
load_dotenv()
mongo_db_url = os.getenv("MONGODB_URL_KEY")
print(mongo_db_url)
import pymongo
from cybersentinel.exception.exception import NetworkSecurityException
from cybersentinel.logging.logger import logging
from cybersentinel.pipeline.training_pipeline import TrainingPipeline

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, File, UploadFile,Request
from uvicorn import run as app_run
from fastapi.responses import Response
from starlette.responses import RedirectResponse
import pandas as pd

from cybersentinel.utils.main_utils.utils import load_object

from cybersentinel.utils.ml_utils.model.estimator import NetworkModel
from url_feature_extractor import URLFeatureExtractor
from pydantic import BaseModel

# Request model for URL analysis
class URLRequest(BaseModel):
    url: str

client = pymongo.MongoClient(mongo_db_url, tlsCAFile=ca)

from cybersentinel.constant.training_pipeline import DATA_INGESTION_COLLECTION_NAME
from cybersentinel.constant.training_pipeline import DATA_INGESTION_DATABASE_NAME

database = client[DATA_INGESTION_DATABASE_NAME]
collection = database[DATA_INGESTION_COLLECTION_NAME]

app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="./templates")

@app.get("/", tags=["authentication"])
async def index():
    return RedirectResponse(url="/docs")

@app.get("/train")
async def train_route():
    try:
        train_pipeline=TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response("Training is successful")
    except Exception as e:
        raise NetworkSecurityException(e,sys)
    
@app.post("/predict")
async def predict_route(request: Request,file: UploadFile = File(...)):
    try:
        df=pd.read_csv(file.file)
        #print(df)
        
        # Drop the target column 'Result' if it exists in the uploaded CSV
        # The model expects only feature columns for prediction
        if 'Result' in df.columns:
            df = df.drop(columns=['Result'])
        
        preprocesor=load_object("final_model/preprocessor.pkl")
        final_model=load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocesor,model=final_model)
        print(df.iloc[0])
        y_pred = network_model.predict(df)
        print(y_pred)
        df['predicted_column'] = y_pred
        print(df['predicted_column'])
        #df['predicted_column'].replace(-1, 0)
        #return df.to_json()
        df.to_csv('prediction_output/output.csv')
        table_html = df.to_html(classes='table table-striped')
        #print(table_html)
        return templates.TemplateResponse("table.html", {"request": request, "table": table_html})
        
    except Exception as e:
            raise NetworkSecurityException(e,sys)

@app.post("/analyze-url")
async def analyze_url(url_request: URLRequest):
    """
    Analyze a URL for phishing detection
    Accepts: {"url": "https://example.com"}
    Returns: Prediction result with confidence
    """
    try:
        # Extract features from URL
        extractor = URLFeatureExtractor(url_request.url)
        features = extractor.extract_all_features()
        
        # Convert features to DataFrame
        df = pd.DataFrame([features])
        
        # Load model and preprocessor
        preprocessor = load_object("final_model/preprocessor.pkl")
        final_model = load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocessor, model=final_model)
        
        # Make prediction
        prediction = network_model.predict(df)
        
        # Interpret result
        is_safe = int(prediction[0]) == 1
        result = {
            "url": url_request.url,
            "is_safe": is_safe,
            "prediction": "Safe" if is_safe else "Phishing/Malicious",
            "risk_level": "Low" if is_safe else "High",
            "features_extracted": features,
            "recommendation": "This URL appears to be safe." if is_safe else "⚠️ WARNING: This URL shows signs of phishing or malicious activity. Do not proceed!"
        }
        
        return result
        
    except Exception as e:
        raise NetworkSecurityException(e, sys)

    
if __name__=="__main__":
    # Get port from environment variable (Render sets this) or default to 8000
    port = int(os.getenv("PORT", 8000))
    app_run(app, host="0.0.0.0", port=port)
