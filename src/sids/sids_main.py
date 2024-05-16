from flask import Flask, request, jsonify
from .sids_model import SIDSModel
from ..utils.data_preprocessing import load_data, preprocess_data
import pandas as pd

app = Flask(__name__)
model = SIDSModel()

# Load the trained model
model.load_model("src/sids/sids_rules/ruleset_1.pkl")


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    df = pd.DataFrame(data, index=[0])
    prediction = model.predict(df)
    return jsonify({"prediction": prediction[0]})


@app.route("/train", methods=["POST"])
def train():
    data = request.get_json()  # Receive training data in JSON format
    df = pd.DataFrame(data)  # Convert JSON data to pandas DataFrame
    X_train, X_test, y_train, y_test = preprocess_data(
        df, dataset_type="nsl_kdd"
    )  # Preprocess data
    model.train(X_train, y_train)  # Train the model
    model.save_model("src/sids/sids_rules/ruleset_1.pkl")  # Save the trained model
    return jsonify({"status": "model trained and saved"})  # Return a success message


if __name__ == "__main__":
    app.run(debug=True)
