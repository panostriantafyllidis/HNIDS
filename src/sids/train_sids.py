import joblib
from sklearn.ensemble import RandomForestClassifier
from ..utils.data_preprocessing import load_data, preprocess_data


def train_model(train_filepath, model_output_filepath):
    data = load_data(train_filepath)
    X, y, encoders, scaler = preprocess_data(data)
    # Train the model
    model = RandomForestClassifier(random_state=42)
    model.fit(X, y)
    # Save the model, encoders, and scaler
    model_data = {"model": model, "encoders": encoders, "scaler": scaler}
    joblib.dump(model_data, model_output_filepath)


print("Model training complete and saved to 'src/sids/sids_rules/ruleset_1.pkl'")
if __name__ == "__main__":
    train_model("data/raw/KDDTrain+.txt", "src/sids/sids_rules/ruleset_1.pkl")
