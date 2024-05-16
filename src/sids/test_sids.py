import pandas as pd
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)
import joblib
from ..utils.data_preprocessing import load_data, preprocess_test_data


def inverse_transform_label(label, encoder):
    if label == -1:
        return "unknown"
    return encoder.categories_[0][int(label)]


def test_model(filepath):
    model_data = joblib.load("src/sids/sids_rules/ruleset_1.pkl")
    classifier = model_data["model"]
    encoders = model_data["encoders"]
    scaler = model_data["scaler"]

    data = load_data(filepath)
    print("Loaded test data with shape:", data.shape)

    X_test, y_test = preprocess_test_data(data, encoders, scaler)
    print("Preprocessed test data with shape:", X_test.shape)

    print("First 10 y_test before prediction:", y_test[:10])
    print(f"Total 'unknown' labels in y_test: {list(y_test).count(-1)}")

    y_pred_probs = classifier.predict_proba(X_test)
    y_pred = []
    threshold = 0.5  # less that 0.5 is too suspicious

    for probs in y_pred_probs:
        max_prob = max(probs)
        if max_prob < threshold:
            y_pred.append(-1)
        else:
            y_pred.append(probs.argmax())

    print("First 10 predictions:", y_pred[:10])

    attack_encoder = encoders["attack"]

    y_pred_labels = [inverse_transform_label(label, attack_encoder) for label in y_pred]
    y_test_labels = [inverse_transform_label(label, attack_encoder) for label in y_test]

    # Count the number of unknowns in the predictions
    unknown_count = y_pred_labels.count("unknown")
    print(f"Number of unknown predictions: {unknown_count}")

    print("First 10 y_pred_labels:", y_pred_labels[:10])
    print("First 10 y_test_labels:", y_test_labels[:10])

    # Print a summary of "unknown" predictions
    unknown_indices = [i for i, label in enumerate(y_pred_labels) if label == "unknown"]
    print(
        f"Indices of unknown predictions: {unknown_indices[:10]}"
    )  # Print first 10 indices for brevity

    # Detailed analysis of unknown predictions
    unknown_details = [(i, y_test_labels[i], y_pred_labels[i]) for i in unknown_indices]
    print(f"Details of first 10 unknown predictions: {unknown_details[:10]}")

    # Evaluate the model
    report = classification_report(y_test_labels, y_pred_labels, zero_division=0)
    accuracy = accuracy_score(y_test_labels, y_pred_labels)
    precision = precision_score(
        y_test_labels, y_pred_labels, average="weighted", zero_division=0
    )
    recall = recall_score(
        y_test_labels, y_pred_labels, average="weighted", zero_division=0
    )
    f1 = f1_score(y_test_labels, y_pred_labels, average="weighted", zero_division=0)

    print("Classification Report:\n", report)
    print("Accuracy:", accuracy)
    print("Precision:", precision)
    print("Recall:", recall)
    print("F1 Score:", f1)


if __name__ == "__main__":
    test_model("data/raw/KDDTest+.txt")
