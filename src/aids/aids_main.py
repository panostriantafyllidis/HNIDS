import joblib
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from xgboost import XGBClassifier
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)
from ..utils.data_preprocessing import preprocess_data, preprocess_test_data


class AIDS:
    def __init__(self):
        self.classifiers = {
            "DecisionTree": DecisionTreeClassifier(random_state=42),
            "RandomForest": RandomForestClassifier(random_state=42),
            "ExtraTrees": ExtraTreesClassifier(random_state=42),
            "XGBoost": XGBClassifier(random_state=42),
        }
        self.model_data = {}

    def train(self, train_filepath):
        X, y, encoders, scaler, attack_encoder, all_classes = preprocess_data(
            train_filepath
        )

        # Compute class weights
        class_weights = compute_class_weight("balanced", classes=all_classes, y=y)
        class_weight_dict = {i: weight for i, weight in enumerate(class_weights)}

        self.model_data = {
            "encoders": encoders,
            "scaler": scaler,
            "attack_encoder": attack_encoder,
        }

        for name, clf in self.classifiers.items():
            print(f"Training {name}...")
            clf.set_params(class_weight=class_weight_dict)
            clf.fit(X, y)
            self.model_data[name] = clf
            print(f"{name} training complete.")

    def save_models(self, model_output_filepath):
        joblib.dump(self.model_data, model_output_filepath)
        print(f"All models saved to '{model_output_filepath}'")

    def load_models(self, model_input_filepath):
        self.model_data = joblib.load(model_input_filepath)

    def test(self, test_filepath):
        X_test, y_test = preprocess_test_data(
            test_filepath, self.model_data["encoders"], self.model_data["scaler"]
        )
        print("Preprocessed test data with shape:", X_test.shape)

        for model_name in self.classifiers.keys():
            print(f"\nEvaluating {model_name}...")
            classifier = self.model_data[model_name]
            self.evaluate_model(
                classifier, X_test, y_test, self.model_data["attack_encoder"]
            )

    def evaluate_model(self, classifier, X_test, y_test, encoder):
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
            self.inverse_transform_label(label, encoder) for label in y_pred
        ]
        y_test_labels = [
            self.inverse_transform_label(label, encoder) for label in y_test
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

        print("Classification Report:")
        print(report)
        print(f"Accuracy: {accuracy}")
        print(f"Precision: {precision}")
        print(f"Recall: {recall}")
        print(f"F1 Score: {f1}")

    def inverse_transform_label(self, label, encoder):
        if label == -1:
            return "unknown"
        return encoder.categories_[0][label]


aids = AIDS()
