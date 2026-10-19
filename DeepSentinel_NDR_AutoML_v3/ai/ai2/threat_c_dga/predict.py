import os
import onnxruntime as ort
import numpy as np
from threat_c_dga.tokenizer import domain_to_tensor

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ONNX_MODEL_PATH = os.path.join(BASE_DIR, "saved_models", "dga_lstm.onnx")

# Initialize ONNX runtime session
if os.path.exists(ONNX_MODEL_PATH):
    ort_session = ort.InferenceSession(ONNX_MODEL_PATH)
else:
    ort_session = None
    print(f"Warning: ONNX model not found at {ONNX_MODEL_PATH}. Run export_onnx.py first.")

def predict_domain(domain_string: str, threshold: float = 0.5):
    if ort_session is None:
        return {"error": "Model not loaded"}

    # Prepare tensor and convert to numpy array for ONNX
    tensor_input = domain_to_tensor(domain_string).unsqueeze(0).numpy()
    
    # Run bare-metal inference
    ort_inputs = {ort_session.get_inputs()[0].name: tensor_input}
    score = ort_session.run(None, ort_inputs)[0][0][0]
        
    is_dga = bool(score >= threshold)
    
    return {
        "domain": domain_string,
        "is_dga": is_dga,
        "dga_probability": round(float(score), 4),
        "threat_level": "HIGH" if is_dga else "LOW"
    }

if __name__ == "__main__":
    test_domains = ["google.com", "x9k2js9283nz.biz"]
    print("\n--- Live ONNX Inference Test ---")
    for d in test_domains:
        res = predict_domain(d)
        print(f"Domain: {res['domain']:<20} | Is DGA: {str(res['is_dga']):<5} | Score: {res.get('dga_probability')}")