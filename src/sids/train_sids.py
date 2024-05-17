import joblib
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from ..utils.data_preprocessing import load_data, preprocess_data
import numpy as np


def train_model(train_filepath, model_output_filepath):
    data = load_data(train_filepath)
    X, y, encoders, scaler = preprocess_data(data)

    # Split data into training and validation sets
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Compute class weights for other classifiers
    class_weights = compute_class_weight(
        "balanced", classes=np.unique(y_train), y=y_train
    )
    class_weight_dict = dict(zip(np.unique(y_train), class_weights))

    classifiers = {
        "DecisionTree": DecisionTreeClassifier(
            random_state=42, class_weight=class_weight_dict
        ),
        "RandomForest": RandomForestClassifier(
            random_state=42, class_weight=class_weight_dict
        ),
        "ExtraTrees": ExtraTreesClassifier(
            random_state=42, class_weight=class_weight_dict
        ),
        "XGBoost": XGBClassifier(random_state=42),
    }

    model_data = {"encoders": encoders, "scaler": scaler}

    for name, clf in classifiers.items():
        print(f"Training {name}...")
        clf.fit(X_train, y_train)
        model_data[name] = clf
        print(f"{name} training complete.")

    joblib.dump(model_data, model_output_filepath)
    print(f"All models saved to '{model_output_filepath}'")


if __name__ == "__main__":
    train_model("data/raw/KDDTrain+.txt", "src/sids/sids_rules/models.pkl")
