import torch
from threat_c_dga.model import DGALSTM
from threat_c_dga.tokenizer import MAX_LEN
import os

def export_to_onnx():
    model_path = os.path.join("saved_models", "dga_lstm.pth")
    onnx_path = os.path.join("saved_models", "dga_lstm.onnx")
    
    if not os.path.exists(model_path):
        print(f"Error: Train the model first. {model_path} not found.")
        return

    model = DGALSTM()
    model.load_state_dict(torch.load(model_path, map_location="cpu", weights_only=True))
    model.eval()

    dummy_input = torch.zeros(1, MAX_LEN, dtype=torch.long)
    
    print("Exporting model to ONNX for low-latency inference...")
    torch.onnx.export(
        model, 
        dummy_input, 
        onnx_path, 
        export_params=True,
        opset_version=18,
        dynamo=False,
        input_names=['sequence_input'],
        output_names=['threat_score'],
        dynamic_axes={'sequence_input': {0: 'batch_size'}, 'threat_score': {0: 'batch_size'}}
    )
    print(f"ONNX Model exported successfully to {onnx_path}")

if __name__ == "__main__":
    export_to_onnx()