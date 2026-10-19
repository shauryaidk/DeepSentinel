from pathlib import Path
import subprocess
import sys

from generate_data import generate


def main():
    Path("data").mkdir(exist_ok=True)
    Path("models").mkdir(exist_ok=True)

    print("[1/4] Generating synthetic host windows...")
    generate(windows=30000, seed=42).to_csv("data/windows.csv", index=False)

    print("[2/4] Training benign-only deep autoencoder...")
    subprocess.run([sys.executable, "train_autoencoder.py", "--input", "data/windows.csv",
                    "--model", "models/autoencoder.joblib"], check=True)

    print("[3/4] Detecting anomalies on a fresh sample...")
    generate(windows=10000, seed=7).to_csv("data/windows_test.csv", index=False)
    subprocess.run([sys.executable, "detect.py", "--input", "data/windows_test.csv",
                    "--model", "models/autoencoder.joblib", "--output", "data/detections.csv"], check=True)

    print("[4/4] Evaluating...")
    subprocess.run([sys.executable, "evaluate.py", "--detections", "data/detections.csv"], check=True)
    print("\nDemo complete. Main output: data/detections.csv")


if __name__ == "__main__":
    main()
