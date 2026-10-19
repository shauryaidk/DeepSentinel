import argparse

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

MAP = {"possible_volumetric_ddos": "ddos", "possible_exfiltration": "exfil", "benign": "benign"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--detections", default="data/detections.csv")
    args = ap.parse_args()
    d = pd.read_csv(args.detections)
    if "true_label" not in d:
        print("No true_label column. Showing prediction counts only:")
        print(d["predicted_threat"].value_counts())
        return
    y_true = d["true_label"]; y_pred = d["predicted_threat"].map(MAP)
    labels = ["benign", "ddos", "exfil"]
    print("Confusion matrix [benign, ddos, exfil]:")
    print(confusion_matrix(y_true, y_pred, labels=labels))
    print()
    print(classification_report(y_true, y_pred, labels=labels, digits=4, zero_division=0))


if __name__ == "__main__":
    main()
