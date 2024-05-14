from flask import Flask, request, jsonify
from .sids_model import SIDSModel
from ..utils.data_preprocessing import preprocess_data
import pandas as pd
import json

app = Flask(__name__)
model = SIDSModel()
model.load_model("src/sids/sids_rules/ruleset_1.pkl")


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    df = pd.DataFrame(data, index=[0])
    prediction = model.predict(df)
    return jsonify({"prediction": prediction[0]})


@app.route("/train", methods=["POST"])
def train():
    data = request.get_json()
    df = pd.DataFrame(data)
    X_train, X_test, y_train, y_test = preprocess_data(df)
    model.train(X_train, y_train)
    model.save_model("src/sids/sids_rules/ruleset_1.pkl")
    return jsonify({"status": "model trained and saved"})


if __name__ == "__main__":
    app.run(debug=True)
