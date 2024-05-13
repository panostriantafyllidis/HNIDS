from sklearn.tree import DecisionTreeClassifier


def preprocess_data(data):
    """
    Preprocesses the given data by separating features and labels.

    Args:
        data: The input data.

    Returns:
        x: The features.
        y: The labels.
    """
    # Your preprocessing code here
    # Assuming x contains features and y contains labels
    x = data.drop(columns=["label"])
    y = data["label"]
    return x, y


def train_model(x, y):
    # Initialize decision tree classifier
    model = DecisionTreeClassifier()

    # Train the model
    model.fit(x, y)
    return model
