import pandas as pd
from sklearn.model_selection import train_test_split


def load_data(filepath):
    data = pd.read_csv(filepath)
    return data


def preprocess_data(data):
    X = data.drop("label", axis=1)
    y = data["label"]
    return train_test_split(X, y, test_size=0.2, random_state=42)
