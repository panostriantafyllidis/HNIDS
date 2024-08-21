import logging
import os
import pickle

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

from src.aids.preprocessing import *


def train_aids():
    # Paths to the training and testing datasets
    training_file_path = "C:/Users/takis/OneDrive - The University of Manchester/MSc-Hybrid-IDS/datasets/UNSW-NB15/UNSW_NB15_training-set.csv"
    testing_file_path = "C:/Users/takis/OneDrive - The University of Manchester/MSc-Hybrid-IDS/datasets/UNSW-NB15/UNSW_NB15_testing-set.csv"
    train_df = "C:/Users/takis/OneDrive - The University of Manchester/MSc-Hybrid-IDS/datasets/UNSW-NB15/dataset.csv"

    # Create logs directory if it doesn't exist
    log_directory = "src/aids/logs"
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)

    # Set up logging
    log_file_path = os.path.join(log_directory, "train_test_run.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file_path, mode="w"),  # Log to file
            logging.StreamHandler(),  # Log to console
        ],
    )

    logging.info("Starting training process...")

    # Load the datasets
    train_df = pd.read_csv(training_file_path)
    test_df = pd.read_csv(testing_file_path)

    # Log column names
    logging.info(f"Training dataset columns: {train_df.columns}")
    logging.info(f"Testing dataset columns: {test_df.columns}")

    # Drop unnecessary columns
    if "Unnamed: 0" in train_df.columns:
        train_df = train_df.drop(["Unnamed: 0"], axis=1)
    if "id" in train_df.columns:
        train_df = train_df.drop(["id"], axis=1)
    if "id" in test_df.columns:
        test_df = test_df.drop(["id"], axis=1)
    if "attack_cat" in train_df.columns:
        train_df = train_df.drop(["attack_cat"], axis=1)
    if "attack_cat" in test_df.columns:
        test_df = test_df.drop(["attack_cat"], axis=1)

    # Select the necessary features
    train_df = train_df[selected_features]
    test_df = test_df[selected_features]

    # Apply preprocessing (encoding and normalization)
    train_df = preprocess_data(train_df)
    test_df = preprocess_data(test_df)

    # Separate features and labels
    X_train = train_df.drop("label", axis=1)
    y_train = train_df["label"]
    X_test = test_df.drop("label", axis=1)
    y_test = test_df["label"]

    # Train the SVM model
    svm_model = SVC(kernel="linear")
    svm_model.fit(X_train, y_train)

    # Save the model
    model_directory = "models"
    if not os.path.exists(model_directory):
        os.makedirs(model_directory)
    model_path = os.path.join(model_directory, "svm_model.pkl")
    with open(model_path, "wb") as file:
        pickle.dump(svm_model, file)

    # Predict labels for the test data
    y_pred_train = svm_model.predict(X_train)
    y_pred_test = svm_model.predict(X_test)

    # Log classification metrics
    logging.info("Classification Report for training data:")
    logging.info("\n" + classification_report(y_train, y_pred_train))

    logging.info("Classification Report for testing data:")
    logging.info("\n" + classification_report(y_test, y_pred_test))

    # Convert confusion matrix to string and log it
    logging.info("Confusion Matrix for training data:")
    logging.info("\n" + str(confusion_matrix(y_train, y_pred_train)))

    logging.info("Confusion Matrix for testing data:")
    logging.info("\n" + str(confusion_matrix(y_test, y_pred_test)))

    logging.info("Training process finished.")


if __name__ == "__main__":
    train_aids()
