import joblib
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.class_weight import compute_class_weight
from xgboost import XGBClassifier

from src.utils.data_preprocessing import preprocess_data, preprocess_test_data
from src.utils.feature_engineering import (
    extract_features_kpca,
    optimize_hyperparameters,
    select_features_ig_fcbf,
)


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
        X, y, encoders, scaler, label_encoder, all_classes = preprocess_data(
            train_filepath
        )

        # Feature Extraction
        X_extracted = extract_features_kpca(X)

        # Feature Selection
        X_selected = select_features_ig_fcbf(X_extracted, y)

        # Compute class weights
        class_weights = compute_class_weight("balanced", classes=all_classes, y=y)
        class_weight_dict = {i: weight for i, weight in enumerate(class_weights)}

        self.model_data = {
            "encoders": encoders,
            "scaler": scaler,
            "label_encoder": label_encoder,
        }

        for name, clf in self.classifiers.items():
            print(f"Training {name}...")
            if hasattr(clf, "class_weight"):
                clf.set_params(class_weight=class_weight_dict)

            # Hyperparameter Optimization
            param_space = self.get_param_space(name)
            optimized_clf = optimize_hyperparameters(clf, param_space, X_selected, y)

            optimized_clf.fit(X_selected, y)
            self.model_data[name] = optimized_clf
            print(f"{name} training complete.")

    def save_models(self, model_output_filepath):
        joblib.dump(self.model_data, model_output_filepath)
        print(f"All models saved to '{model_output_filepath}'")

    def load_models(self, model_input_filepath):
        self.model_data = joblib.load(model_input_filepath)

    def test(self, test_filepath):
        X_test, y_test = preprocess_test_data(
            test_filepath,
            self.model_data["encoders"],
            self.model_data["scaler"],
            self.model_data["label_encoder"],
        )
        X_test_extracted = extract_features_kpca(X_test)
        X_test_selected = select_features_ig_fcbf(X_test_extracted, y_test)
        print("Preprocessed test data with shape:", X_test_selected.shape)

        for model_name in self.classifiers.keys():
            print(f"\nEvaluating {model_name}...")
            classifier = self.model_data[model_name]
            self.evaluate_model(
                classifier, X_test_selected, y_test, self.model_data["label_encoder"]
            )

    def evaluate_model(self, classifier, X_test, y_test, label_encoder):
        y_pred = classifier.predict(X_test)
        y_pred_labels = label_encoder.inverse_transform(y_pred)
        y_test_labels = label_encoder.inverse_transform(y_test)

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

    def get_param_space(self, model_name):
        if model_name == "DecisionTree":
            return {"max_depth": (3, 30), "min_samples_split": (2, 20)}
        elif model_name == "RandomForest":
            return {"n_estimators": (10, 100), "max_depth": (3, 30)}
        elif model_name == "ExtraTrees":
            return {"n_estimators": (10, 100), "max_depth": (3, 30)}
        elif model_name == "XGBoost":
            return {
                "n_estimators": (10, 100),
                "max_depth": (3, 30),
                "learning_rate": (0.01, 0.2),
            }

    def inverse_transform_label(self, label, encoder):
        if label == -1:
            return "unknown"
        return encoder.inverse_transform([[label]])[0][0]


aids = AIDS()
