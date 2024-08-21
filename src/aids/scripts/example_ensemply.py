# example script of applying mutual application of supervised and unsupervised models in packet classification
import joblib
import numpy as np
from sklearn.discriminant_analysis import StandardScaler

# Load the saved ensemble model
ensemble_model = joblib.load("model.pkl")
oc_svm = joblib.load("one_class_svm_model.joblib")


# Example function to classify a new packet
def classify_packet(packet_features):
    # Standardize the packet features (assuming the scaler is available)
    scaler = StandardScaler()
    packet_features_scaled = scaler.transform([packet_features])

    # Predict using the ensemble model
    ensemble_prediction = ensemble_model.predict(packet_features_scaled)[0]

    # Predict using the One-Class SVM
    oc_svm_prediction = oc_svm.predict(packet_features_scaled)[0]
    oc_svm_prediction = (
        0 if oc_svm_prediction == 1 else 1
    )  # Adjust prediction: +1 -> 0 (normal), -1 -> 1 (anomaly)

    # Determine final prediction
    if ensemble_prediction == 1 or oc_svm_prediction == 1:
        return "Attack"
    else:
        return "Normal"


# Example usage
new_packet_features = (
    []
)  # Replace value1, value2, value3, ... with actual feature values
result = classify_packet(new_packet_features)
print(f"The packet is classified as: {result}")
