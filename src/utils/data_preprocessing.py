import pandas as pd
from sklearn.preprocessing import StandardScaler, OrdinalEncoder


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
    data = pd.read_csv(filepath, header=None, names=columns)
    return data


def preprocess_data(data):
    categorical_columns = ["protocol_type", "service", "flag", "attack"]
    encoders = {}
    for col in categorical_columns:
        oe = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
        data[col] = oe.fit_transform(data[[col]])
        encoders[col] = oe

    X = data.drop(columns=["attack"])
    y = data["attack"]

    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    return X, y, encoders, scaler


def preprocess_test_data(data, encoders, scaler):
    categorical_columns = ["protocol_type", "service", "flag", "attack"]
    for col in categorical_columns:
        oe = encoders[col]
        data[col] = oe.transform(data[[col]])

    X = data.drop(columns=["attack"])
    y = data["attack"]

    X = scaler.transform(X)

    return X, y
