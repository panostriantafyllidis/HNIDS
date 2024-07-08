import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.preprocessing import LabelEncoder  # Add this import
from sklearn.preprocessing import OrdinalEncoder, StandardScaler


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


def encode_categorical(data):
    encoders = {}
    categorical_columns = data.select_dtypes(include=[object]).columns
    for column in categorical_columns:
        encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
        data[[column]] = encoder.fit_transform(data[[column]])
        encoders[column] = encoder
    return data, encoders


def normalize_data(data):
    scaler = StandardScaler()
    numeric_columns = data.select_dtypes(include=[np.number]).columns
    data[numeric_columns] = scaler.fit_transform(data[numeric_columns])
    return data, scaler


def handle_class_imbalance(data):
    X = data.drop(columns=["attack", "level"])
    y = data["attack"]

    # Encode attack labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    smote = SMOTE(random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X, y_encoded)

    y_resampled = label_encoder.inverse_transform(
        y_resampled
    )  # Inverse transform for consistency

    balanced_data = pd.concat(
        [
            pd.DataFrame(X_resampled, columns=X.columns),
            pd.Series(y_resampled, name="attack"),
        ],
        axis=1,
    )
    return balanced_data


def preprocess_data(filepath):
    data = load_data(filepath)
    data, encoders = encode_categorical(data)
    normalized_data, scaler = normalize_data(data)
    balanced_data = handle_class_imbalance(normalized_data)
    X = balanced_data.drop(columns=["attack"])
    y = balanced_data["attack"]

    # Encode attack labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    return X, y_encoded, encoders, scaler, label_encoder, label_encoder.classes_


def preprocess_test_data(filepath, encoders, scaler, label_encoder):
    data = load_data(filepath)
    for column in data.select_dtypes(include=[object]).columns:
        if column in encoders:
            data[[column]] = encoders[column].transform(data[[column]])
    numeric_columns = data.select_dtypes(include=[np.number]).columns
    data[numeric_columns] = scaler.transform(data[numeric_columns])
    X_test = data.drop(columns=["attack"])
    y_test = data["attack"]

    # Encode attack labels
    y_test_encoded = label_encoder.transform(y_test)

    return X_test, y_test_encoded
