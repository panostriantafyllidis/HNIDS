# This code represents a sample ~mock version~ of the origina processing code as shown in the supporting file named 'HNIDS_with_unsw-nb15.ipynb', specifically the Preprocessing Seaction.

import logging
import os
import pickle
import time

import joblib
import numpy as np
import pandas as pd
import statsmodels.api as sm
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline
from imblearn.under_sampling import RandomUnderSampler
from sklearn.calibration import LinearSVC
from sklearn.decomposition import PCA
from sklearn.feature_selection import mutual_info_regression
from sklearn.metrics import accuracy_score  # will plot the confusion matrix
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    mean_absolute_error,
    precision_score,
    recall_score,
)
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler
from sklearn.svm import SVC
from statsmodels.stats.outliers_influence import variance_inflation_factor


def train_aids():
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
    train_df = pd.read_csv(
        "C:/Users/takis/OneDrive - The University of Manchester/MSc-Hybrid-IDS/datasets/UNSW-NB15/rawdataset.csv"
    )

    list_drop = ["attack_cat", "srcip", "dstip"]
    train_df.drop(list_drop, axis=1, inplace=True)
    train_df = train_df.drop_duplicates()

    # missing values imply that there were no flows with HTTP methods in certain instances so we will replace the NAN with 0
    train_df["ct_flw_http_mthd"].fillna(0, inplace=True)

    # is_ftp_login is of type binary that mean it takes 1(user has loged in) or 0 (or not) so the best approch is to replace nan with 0
    train_df["is_ftp_login"].fillna(0, inplace=True)

    # Function to clean and convert to numeric
    def clean_and_convert_ct_ftp_cmd(df, column):
        df[column] = df[column].astype("str").replace(" ", "0")
        df[column] = (
            pd.to_numeric(df[column], errors="coerce").fillna(0).astype("int64")
        )
        return df

    # Apply to 'ct_ftp_cmd'
    train_df = clean_and_convert_ct_ftp_cmd(train_df, "ct_ftp_cmd")

    # Function to ensure binary column
    def convert_to_binary(df, column):
        df[column] = (
            pd.to_numeric(df[column], errors="coerce").fillna(0).astype("int64")
        )
        df[column] = (df[column] > 0).astype("int64")
        return df

    # Apply to 'is_ftp_login'
    train_df = convert_to_binary(train_df, "is_ftp_login")

    # Function to convert to numeric and handle NaNs
    def convert_sport_dsport(df, column):
        df[column] = df[column].astype("str")
        df[column] = (
            pd.to_numeric(df[column], errors="coerce").fillna(0).astype("int64")
        )
        return df

    # Apply to 'sport' and 'dsport'
    train_df = convert_sport_dsport(train_df, "sport")
    train_df = convert_sport_dsport(train_df, "dsport")

    numerical_columns = train_df.select_dtypes(
        include=["float64", "int64"]
    ).columns.tolist()

    # Columns to exclude
    exclude_columns = [
        "sport",
        "swim",
        "dwim",
        "stcpb",
        "dtcpb",
        "Stime",
        "Ltime",
        "Label",
    ]

    # Filter out the columns to exclude
    numerical_columns = [col for col in numerical_columns if col not in exclude_columns]

    def generate_features(df):
        # Duration
        df["duration"] = df["Ltime"] - df["Stime"]

        # Ratios
        df["byte_ratio"] = df["sbytes"] / (df["dbytes"] + 1)
        df["pkt_ratio"] = df["Spkts"] / (df["Dpkts"] + 1)
        df["load_ratio"] = df["Sload"] / (df["Dload"] + 1)
        df["jit_ratio"] = df["Sjit"] / (df["Djit"] + 1)
        df["inter_pkt_ratio"] = df["Sintpkt"] / (df["Dintpkt"] + 1)
        df["tcp_setup_ratio"] = df["tcprtt"] / (df["synack"] + df["ackdat"] + 1)

        # Aggregate Features
        df["total_bytes"] = df["sbytes"] + df["dbytes"]
        df["total_pkts"] = df["Spkts"] + df["Dpkts"]
        df["total_load"] = df["Sload"] + df["Dload"]
        df["total_jitter"] = df["Sjit"] + df["Djit"]
        df["total_inter_pkt"] = df["Sintpkt"] + df["Dintpkt"]
        df["total_tcp_setup"] = df["tcprtt"] + df["synack"] + df["ackdat"]

        # Interaction Features
        df["byte_pkt_interaction_src"] = df["sbytes"] * df["Spkts"]
        df["byte_pkt_interaction_dst"] = df["dbytes"] * df["Dpkts"]
        df["load_jit_interaction_src"] = df["Sload"] * df["Sjit"]
        df["load_jit_interaction_dst"] = df["Dload"] * df["Djit"]
        df["pkt_jit_interaction_src"] = df["Spkts"] * df["Sjit"]
        df["pkt_jit_interaction_dst"] = df["Dpkts"] * df["Djit"]

        # Statistical Features
        df["mean_pkt_size"] = df["smeansz"] + df["dmeansz"]
        df["tcp_seq_diff"] = df["stcpb"] - df["dtcpb"]

        return df

    generate_features(train_df)

    cat_columns = train_df.select_dtypes(include=["O"]).columns.tolist()
    logging.info(f"Categorical columns: {cat_columns}")

    # Initialize LabelEncoder
    # label_encoder = LabelEncoder()
    label_encoder_proto = LabelEncoder()
    label_encoder_state = LabelEncoder()
    label_encoder_service = LabelEncoder()

    # Apply LabelEncoder to each categorical feature
    # train_df['Label'] = label_encoder.fit_transform(train_df['Label'])
    train_df["proto"] = label_encoder_proto.fit_transform(train_df["proto"])
    train_df["state"] = label_encoder_state.fit_transform(train_df["state"])
    train_df["service"] = label_encoder_service.fit_transform(train_df["service"])

    # Create the label mapping
    # label_mapping = dict(zip(label_encoder.classes_, label_encoder.transform(label_encoder.classes_)))
    proto_mapping = dict(
        zip(
            label_encoder_proto.classes_,
            label_encoder_proto.transform(label_encoder_proto.classes_),
        )
    )
    state_mapping = dict(
        zip(
            label_encoder_state.classes_,
            label_encoder_state.transform(label_encoder_state.classes_),
        )
    )
    service_mapping = dict(
        zip(
            label_encoder_service.classes_,
            label_encoder_service.transform(label_encoder_service.classes_),
        )
    )

    # print("Label Mapping:")
    # print(label_mapping)

    logging.info("Proto Mapping:")
    logging.info(proto_mapping)

    logging.info("State Mapping:")
    logging.info(state_mapping)

    logging.info("Service Mapping:")
    logging.info(service_mapping)

    cat_columns = train_df.select_dtypes(include=["O"]).columns.tolist()
    logging.info(f"Categorical columns: {cat_columns}")

    # Calculate the correlation matrix
    correlation_matrix = train_df.corr()

    # Set the correlation threshold (adjust if necessary)
    correlation_threshold = 0.8

    # Identify highly correlated features
    highly_correlated_features = set()

    for i in range(len(correlation_matrix.columns)):
        for j in range(i):
            if abs(correlation_matrix.iloc[i, j]) >= correlation_threshold:
                feature1 = correlation_matrix.columns[i]
                feature2 = correlation_matrix.columns[j]
                highly_correlated_features.add((feature1, feature2))

    # Create a set of features to drop
    features_to_drop = set()

    # Ensure required features are preserved
    required_features = {"dport", "sport", "state", "proto", "service", "Label"}

    # Drop the least important feature from each correlated pair
    for feature1, feature2 in highly_correlated_features:
        if feature1 not in required_features and feature2 not in required_features:
            # Choose the feature with higher correlation to the label for retention
            if abs(correlation_matrix.loc[feature1, "Label"]) > abs(
                correlation_matrix.loc[feature2, "Label"]
            ):
                features_to_drop.add(feature2)
            else:
                features_to_drop.add(feature1)

    # Drop the features from the DataFrame
    train_df = train_df.drop(columns=list(features_to_drop))

    # Print the remaining features
    logging.info(
        f"Remaining features after dropping highly correlated ones:{train_df.columns}"
    )

    x = train_df.drop(["Label"], axis=1)
    y = train_df[["Label"]]

    # Define the desired number of samples for each class
    desired_count = 88000

    # oversample_strategy = {key: desired_count for key in y.value_counts().index if y.value_counts()[key] < desired_count}
    # undersample_strategy = {key: desired_count for key in y.value_counts().index if y.value_counts()[key] > desired_count}

    # Define the oversampling strategy for SMOTE
    oversample_strategy = {
        i: desired_count
        for i in range(len(y.value_counts()))
        if y.value_counts()[i] < desired_count
    }

    # Define the undersampling strategy for RandomUnderSampler
    undersample_strategy = {
        i: desired_count
        for i in range(len(y.value_counts()))
        if y.value_counts()[i] > desired_count
    }

    # Create the SMOTE and RandomUnderSampler objects
    smote = SMOTE(sampling_strategy=oversample_strategy)
    undersample = RandomUnderSampler(sampling_strategy=undersample_strategy)

    # Combine SMOTE and RandomUnderSampler in a pipeline
    pipeline = Pipeline(steps=[("smote", smote), ("undersample", undersample)])

    # Print class distribution before resampling
    logging.info(f"Before resampling:{y.value_counts()}")

    # Apply the pipeline to resample the dataset
    x_resampled, y_resampled = pipeline.fit_resample(x, y)

    # Print class distribution after resampling
    logging.info(f"After resampling:{y_resampled.value_counts()}")

    x = x_resampled
    y = y_resampled

    # Determine which features are discrete
    from sklearn.feature_selection import mutual_info_classif

    discrete_features = x.dtypes == int

    # Function to calculate mutual information scores for feature selection
    def mi_score_maker(x, y, discrete_features):
        """
        This function calculates mutual information scores for each feature in the dataset
        relative to the target variable. It helps in identifying the importance of each feature
        in predicting the target.

        Parameters:
        x (DataFrame): The feature matrix.
        y (Series): The target variable.
        discrete_features (Series): Boolean series indicating which features are discrete.

        Returns:
        DataFrame: A DataFrame containing features and their corresponding mutual information scores,
                sorted in descending order of the scores.
        """
        # Calculate mutual information scores for each feature
        scores = mutual_info_classif(x, y, discrete_features=discrete_features)

        # Create a DataFrame to hold the feature names and their scores
        df = pd.DataFrame({"Features": x.columns, "Scores": scores})

        # Sort the DataFrame by scores in descending order and reset the index
        df = df.sort_values("Scores", ascending=False).reset_index(drop=True)

        return df

    # Calculate mutual information scores
    mi_scores = mi_score_maker(x, y, discrete_features)

    # Drop low-score features based on mutual information threshold
    mi_threshold = 0.1
    low_score_features = mi_scores[mi_scores["Scores"] < mi_threshold]

    # Extract the feature names
    low_score_feature_names = low_score_features["Features"].tolist()

    x.drop(low_score_feature_names, axis=1, inplace=True)
    remaining_features = x.columns
    logging.info(
        f"First Stage - Remaining features after dropping the ones with low mi-score:{remaining_features}"
    )

    # Adding a constant term for the intercept in the regression model
    x = sm.add_constant(x)

    # Function to calculate p-values
    def calculate_p_values(x, y):
        model = sm.OLS(y, x).fit()
        return model.pvalues

    # Function to calculate VIF
    def calculate_vif(x):
        vif_data = pd.DataFrame()
        vif_data["feature"] = x.columns
        vif_data["VIF"] = [
            variance_inflation_factor(x.values, i) for i in range(x.shape[1])
        ]
        return vif_data

    # Initial calculation of p-values and VIF
    p_values = calculate_p_values(x, y)
    vif_data = calculate_vif(x)

    # Combine p-values and VIF into a single DataFrame with rounding
    feature_stats = pd.DataFrame(
        {
            "feature": p_values.index,
            "p_value": np.round(p_values.values, 2),
            "VIF": np.round(vif_data["VIF"], 2),
        }
    )

    # Sort by p_value first, then by VIF in descending order
    feature_stats = feature_stats[feature_stats["feature"] != "const"]

    # Define thresholds
    p_value_threshold = 0.05
    vif_threshold = 10

    # Iterative process
    while True:
        # Step 1: Identify features with high p-value (regardless of VIF)
        high_p_features = feature_stats[feature_stats["p_value"] > p_value_threshold]

        # Step 2: Drop these features from the dataset
        if not high_p_features.empty:
            x.drop(columns=high_p_features["feature"], axis=1, inplace=True)
        else:
            # No more features with high p-value, now check VIF
            high_vif_features = feature_stats[feature_stats["VIF"] > vif_threshold]

            if not high_vif_features.empty:
                x.drop(columns=high_vif_features["feature"], axis=1, inplace=True)
            else:
                # If there are no features to drop, break the loop
                break

        # Recalculate p-values and VIF for the reduced feature set
        p_values = calculate_p_values(x, y)
        vif_data = calculate_vif(x)

        # Update the combined feature statistics
        feature_stats = pd.DataFrame(
            {
                "feature": p_values.index,
                "p_value": np.round(p_values.values, 2),
                "VIF": np.round(vif_data["VIF"], 2),
            }
        )

        # Remove 'const' if added
        feature_stats = feature_stats[feature_stats["feature"] != "const"]

    # Final selected features
    final_selected_features = feature_stats[
        (feature_stats["p_value"] <= p_value_threshold)
        & (feature_stats["VIF"] <= vif_threshold)
    ]["feature"].tolist()

    logging.info(
        f"Secnd Stage - Selected features post p-value/VIF: {final_selected_features}"
    )

    x = x.drop(columns=["const"])

    from sklearn.feature_selection import RFE
    from sklearn.linear_model import LogisticRegression

    # Initialize the model (Logistic Regression is used as a baseline)
    model = LogisticRegression(max_iter=1000)

    # Initialize RFE with the model and select the top 'n' features
    rfe = RFE(
        estimator=model, n_features_to_select=20
    )  # Adjust 'n_features_to_select' as needed
    rfe.fit(x, y)

    # Get the ranking of the features
    rfe_ranking = rfe.ranking_

    # Filter out features that were not selected by RFE (ranking > 1)
    x = x.loc[:, rfe.support_]

    # Print the selected features
    logging.info(f"Final Stage - Selected features after RFE: {x.columns}")

    # Separate features and labels
    x_train, x_val, y_train, y_val = train_test_split(
        x, y, test_size=0.2, random_state=42
    )

    # Standardize the features
    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_val_scaled = scaler.transform(x_val)

    pca = PCA()
    pca.fit(x_train_scaled)

    model_performance = pd.DataFrame(
        columns=[
            "Accuracy",
            "Recall",
            "Precision",
            "F1-Score",
            "Mean Absolute Error",
            "time to train",
            "time to predict",
            "total time",
        ]
    )

    def train_evaluate_model(model, x_train_scaled, y_train, x_val_scaled, y_val):
        start = time.time()
        model.fit(x_train_scaled, y_train)
        end_train = time.time()

        preds = model.predict(x_val_scaled)
        end_predict = time.time()

        accuracy = accuracy_score(y_val, preds)
        recall = recall_score(y_val, preds)
        precision = precision_score(y_val, preds)
        f1s = f1_score(y_val, preds)
        mae = mean_absolute_error(y_val, preds)

        logging.info(f"Accuracy: {accuracy:.2%}")
        logging.info(f"Recall: {recall:.2%}")
        logging.info(f"Precision: {precision:.2%}")
        logging.info(f"F1-Score: {f1s:.2%}")
        logging.info(f"Mean Absolute Error: {mae:.2%}")
        logging.info(f"time to train: {end_train-start:.2f} s")
        logging.info(f"time to predict: {end_predict-end_train:.2f} s")
        logging.info(f"total: {end_predict-start:.2f} s")

        model_performance.loc[type(model).__name__] = [
            accuracy,
            recall,
            precision,
            f1s,
            mae,
            end_train - start,
            end_predict - end_train,
            end_predict - start,
        ]

        logging.info(f"Classification Report:\n{classification_report(y_val, preds)}")
        cm = confusion_matrix(y_val, preds)
        logging.info(f"Confusion Matrix:\n{cm}")

    # Train and evaluate SVM with SVC Classifier
    svc_svm = LinearSVC()
    train_evaluate_model(svc_svm, x_train_scaled, y_train, x_val_scaled, y_val)

    # Check if the directory exists, if not, create it
    model_dir = "src/aids/models"
    if not os.path.exists(model_dir):
        os.makedirs(model_dir)
    joblib.dump(svc_svm, os.path.join(model_dir, "svc_svm_model.joblib"))
    logging.info("SVC model saved in ..src/aids/models")

    logging.info("Training process finished.")


if __name__ == "__main__":
    train_aids()
