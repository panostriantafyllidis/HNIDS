import joblib
from sklearn.tree import DecisionTreeClassifier


class SIDSModel:
    def __init__(self):
        self.model = DecisionTreeClassifier()

    def train(self, X, y):
        self.model.fit(X, y)

    def predict(self, X):
        return self.model.predict(X)

    def save_model(self, filepath):
        joblib.dump(self.model, filepath)

    def load_model(self, filepath):
        self.model = joblib.load(filepath)

    def handle_unknown(self, X, threshold=0.6):
        probabilities = self.model.predict_proba(X)
        predictions = self.model.predict(X)
        unknown = [
            "unknown" if max(prob) < threshold else pred
            for prob, pred in zip(probabilities, predictions)
        ]
        return unknown
