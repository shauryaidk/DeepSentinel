import os
import xgboost as xgb
import pandas as pd
import shap
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "saved_models", "ja4_xgboost.json")
feature_names = ['bytes_in', 'bytes_out', 'byte_ratio', 'duration_ms', 'packet_count', 'is_known_browser', 'inter_arrival_variance']

model = xgb.XGBClassifier()
explainer = None

if os.path.exists(MODEL_PATH):
    model.load_model(MODEL_PATH)
    # v3: fail loudly at start-up if the saved model does not match the features
    # predict_session sends (v2 shipped a 6-feature model -> HTTP 500 on every call).
    saved = list(model.get_booster().feature_names or [])
    if saved != feature_names:
        raise RuntimeError(f"{MODEL_PATH} expects {saved}, predict_session sends {feature_names}; "
                           "retrain with python -m threat_d_ja4.train")
    explainer = shap.TreeExplainer(model)

def classify_ja4_browser(ja4_string: str) -> int:
    known_browsers = ["t13d1516h2_", "t13d1716h2_", "t13d1517h2_"]
    return 1 if any(ja4_string.startswith(b) for b in known_browsers) else 0

def predict_session(bytes_in: float, bytes_out: float, duration_ms: float, packet_count: int, ja4_fingerprint: str, inter_arrival_variance: float = 10.0):
    byte_ratio = bytes_out / (bytes_in + 1)
    is_known_browser = classify_ja4_browser(ja4_fingerprint)
    
    input_df = pd.DataFrame([[
        bytes_in, bytes_out, byte_ratio, duration_ms, packet_count, is_known_browser, inter_arrival_variance
    ]], columns=feature_names)
    
    prob = float(model.predict_proba(input_df)[0][1])
    is_malicious = prob >= 0.5
    
    explanation = "Traffic matches baseline norms."
    if is_malicious and explainer is not None:
        shap_values = explainer.shap_values(input_df)
        top_feature_idx = np.argmax(np.abs(shap_values[0]))
        explanation = f"Flagged primarily due to abnormal {feature_names[top_feature_idx]}"
    
    return {
        "is_malicious": is_malicious,
        "malicious_probability": round(prob, 4),
        "explanation": explanation
    }