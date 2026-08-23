from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import pandas as pd
import shap
import numpy as np

app = FastAPI(title="Network Intrusion Detection API")

# Load model and encoders once when the server starts
model = joblib.load("model/intrusion_model.pkl")
label_encoders = joblib.load("model/label_encoders.pkl")
target_encoder = joblib.load("model/target_encoder.pkl")

explainer = shap.TreeExplainer(model)

FEATURE_COLUMNS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds","is_host_login",
    "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
    "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

class ConnectionInput(BaseModel):
    duration: float
    protocol_type: str
    service: str
    flag: str
    src_bytes: float
    dst_bytes: float
    land: int
    wrong_fragment: int
    urgent: int
    hot: int
    num_failed_logins: int
    logged_in: int
    num_compromised: int
    root_shell: int
    su_attempted: int
    num_root: int
    num_file_creations: int
    num_shells: int
    num_access_files: int
    num_outbound_cmds: int
    is_host_login: int
    is_guest_login: int
    count: int
    srv_count: int
    serror_rate: float
    srv_serror_rate: float
    rerror_rate: float
    srv_rerror_rate: float
    same_srv_rate: float
    diff_srv_rate: float
    srv_diff_host_rate: float
    dst_host_count: int
    dst_host_srv_count: int
    dst_host_same_srv_rate: float
    dst_host_diff_srv_rate: float
    dst_host_same_src_port_rate: float
    dst_host_srv_diff_host_rate: float
    dst_host_serror_rate: float
    dst_host_srv_serror_rate: float
    dst_host_rerror_rate: float
    dst_host_srv_rerror_rate: float


@app.get("/")
def root():
    return {"message": "Intrusion Detection API is running"}


@app.post("/predict")
def predict(input_data: ConnectionInput):
    data = pd.DataFrame([input_data.dict()], columns=FEATURE_COLUMNS)

    # Encode categorical columns using saved encoders
    for col in ["protocol_type", "service", "flag"]:
        le = label_encoders[col]
        data[col] = data[col].map(lambda x: le.transform([x])[0] if x in le.classes_ else -1)

    # Predict
    pred_class = model.predict(data)[0]
    pred_label = target_encoder.inverse_transform([pred_class])[0]
    pred_proba = model.predict_proba(data)[0]

    # SHAP explanation for this prediction
    shap_vals = explainer.shap_values(data)
    row_shap = shap_vals[0, :, pred_class]
    top_features = pd.Series(row_shap, index=FEATURE_COLUMNS).sort_values(key=abs, ascending=False).head(5)

    return {
        "prediction": pred_label,
        "confidence": float(pred_proba[pred_class]),
        "top_contributing_factors": {k: float(v) for k, v in top_features.items()}
    }