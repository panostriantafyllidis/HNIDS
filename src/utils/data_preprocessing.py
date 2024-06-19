import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OrdinalEncoder
from sklearn.cluster import KMeans
from imblearn.over_sampling import SMOTE
from collections import Counter


# Load the dataset
def load_data(filepath):
    columns = [
        "duration",
        "protocol_type",
        "service",
        "flag",
        "src_bytes",
        "dst_bytes",
        "land",
        "wrong_fragment",
        "urgent",
        "hot",
        "num_failed_logins",
        "logged_in",
        "num_compromised",
        "root_shell",
        "su_attempted",
        "num_root",
        "num_file_creations",
        "num_shells",
        "num_access_files",
        "num_outbound_cmds",
        "is_host_login",
        "is_guest_login",
        "count",
        "srv_count",
        "serror_rate",
        "srv_serror_rate",
        "rerror_rate",
        "srv_rerror_rate",
        "same_srv_rate",
        "diff_srv_rate",
        "srv_diff_host_rate",
        "dst_host_count",
        "dst_host_srv_count",
        "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate",
        "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate",
        "dst_host_serror_rate",
        "dst_host_srv_serror_rate",
        "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate",
        "attack",
        "level",
    ]
    data = pd.read_csv(filepath, names=columns)
    return data


# Encode categorical features
def encode_categorical(data):
    encoders = {}
    categorical_columns = data.select_dtypes(include=[object]).columns
    for column in categorical_columns:
        encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
        data[[column]] = encoder.fit_transform(data[[column]])
        encoders[column] = encoder
    return data, encoders


# Sample the data using KMeans
def sample_data_kmeans(data, n_clusters=5):
    kmeans = KMeans(n_clusters=n_clusters, random_state=42)
    data["cluster"] = kmeans.fit_predict(data)
    sampled_data = (
        data.groupby("cluster")
        .apply(lambda x: x.sample(frac=0.1))
        .reset_index(drop=True)
    )
    return sampled_data.drop(columns=["cluster"])


# Normalize the data using Z-score normalization
def normalize_data(data):
    scaler = StandardScaler()
    numeric_columns = data.select_dtypes(include=[np.number]).columns
    data[numeric_columns] = scaler.fit_transform(data[numeric_columns])
    return data, scaler


# Handle class imbalance using SMOTE
def handle_class_imbalance(data):
    X = data.drop(columns=["attack", "level"])
    y = data["attack"]
    smote = SMOTE(random_state=42)

    unique_classes = y.unique()
    X_resampled, y_resampled = pd.DataFrame(), pd.Series(dtype="float64")

    for cls in unique_classes:
        X_cls = X[y == cls]
        y_cls = y[y == cls]
        if len(X_cls) > 1:  # Ensuring there are at least 2 instances to apply SMOTE
            y_cls = y_cls.astype(str)  # Convert to string to ensure discrete classes
            X_smote, y_smote = smote.fit_resample(X_cls, y_cls)
            X_resampled = pd.concat(
                [X_resampled, pd.DataFrame(X_smote, columns=X.columns)]
            )
            y_resampled = pd.concat([y_resampled, pd.Series(y_smote)])
        else:
            print(f"Skipping class {cls} with {len(X_cls)} instances.")

    if X_resampled.empty or y_resampled.empty:
        raise ValueError("After SMOTE, no data left for training.")

    balanced_data = pd.concat([X_resampled, y_resampled], axis=1)
    balanced_data.columns = list(X.columns) + ["attack"]
    return balanced_data


# Preprocess the training data
def preprocess_data(filepath):
    data = load_data(filepath)
    data, encoders = encode_categorical(data)  # Encode categorical features first
    sampled_data = sample_data_kmeans(data)  # Then sample the data using KMeans
    normalized_data, scaler = normalize_data(sampled_data)  # Normalize the data
    balanced_data = handle_class_imbalance(normalized_data)  # Handle class imbalance

    X = balanced_data.drop(columns=["attack"])
    y = balanced_data["attack"]
    attack_encoder = encoders["attack"]

    return X, y, encoders, scaler, attack_encoder


# Preprocess the test data
def preprocess_test_data(filepath, encoders, scaler):
    data = load_data(filepath)
    for column in data.select_dtypes(include=[object]).columns:
        if column in encoders:
            data[[column]] = encoders[column].transform(data[[column]])
    numeric_columns = data.select_dtypes(include=[np.number]).columns
    data[numeric_columns] = scaler.transform(data[numeric_columns])
    X_test = data.drop(columns=["attack"])
    y_test = data["attack"]
    return X_test, y_test
