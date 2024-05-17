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


def inverse_transform_label(label, encoder, classes):
    if label == -1:
        return "unknown"
    return classes[int(label)]


def evaluate_model(classifier, X_test, y_test, encoder, classes):
    y_pred_probs = classifier.predict_proba(X_test)
    y_pred = []
    threshold = 0.5

    for probs in y_pred_probs:
        max_prob = max(probs)
        if max_prob < threshold:
            y_pred.append(-1)
        else:
            y_pred.append(probs.argmax())

    y_pred_labels = [
        inverse_transform_label(label, encoder, classes) for label in y_pred
    ]
    y_test_labels = [
        inverse_transform_label(label, encoder, classes) for label in y_test
    ]

    unknown_count = y_pred_labels.count("unknown")
    print(f"Number of unknown predictions: {unknown_count}")

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


def test_models(filepath):
    model_data = joblib.load("src/sids/sids_rules/models.pkl")
    encoders = model_data["encoders"]
    scaler = model_data["scaler"]

    data = load_data(filepath)
    print("Loaded test data with shape:", data.shape)

    X_test, y_test = preprocess_test_data(data, encoders, scaler)
    print("Preprocessed test data with shape:", X_test.shape)

    attack_encoder = encoders["attack"]
    classes = attack_encoder.categories_[0]

    for model_name in ["DecisionTree", "RandomForest", "ExtraTrees", "XGBoost"]:
        print(f"\nEvaluating {model_name}...")
        classifier = model_data[model_name]
        evaluate_model(classifier, X_test, y_test, attack_encoder, classes)


if __name__ == "__main__":
    test_models("data/raw/KDDTest+.txt")
