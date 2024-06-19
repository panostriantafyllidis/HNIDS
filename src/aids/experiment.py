import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from imblearn.over_sampling import SMOTE
from collections import Counter

# Define column names for the dataset
COLUMNS = [
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


# Load dataset
def load_data(filepath):
    print("Loading data...")
    data = pd.read_csv(filepath, header=None)
    data.columns = COLUMNS
    print("Data loaded successfully.")
    return data


# Encode categorical features
def encode_categorical_features(data):
    print("Encoding categorical features...")
    categorical_columns = ["protocol_type", "service", "flag"]
    encoders = {col: LabelEncoder() for col in categorical_columns}
    for col in categorical_columns:
        data[col] = encoders[col].fit_transform(data[col])
    print("Categorical features encoded.")
    return data, encoders


# Normalize numerical features
def normalize_data(data):
    print("Normalizing data...")
    numerical_columns = [
        col
        for col in COLUMNS
        if col not in ["protocol_type", "service", "flag", "attack", "level"]
    ]
    scaler = StandardScaler()
    data[numerical_columns] = scaler.fit_transform(data[numerical_columns])
    print("Data normalized.")
    return data, scaler


# Check class imbalance
def check_class_imbalance(data):
    print("Checking class imbalance...")
    class_counts = data["attack"].value_counts()
    print("Class distribution before handling imbalance:")
    print(class_counts)
    return any(class_counts < (len(data) / len(class_counts)))


# Handle class imbalance using SMOTE with dynamic k_neighbors
def handle_class_imbalance(data):
    print("Handling class imbalance...")
    X = data.drop(columns=["attack"])
    y = data["attack"]

    class_counts = Counter(y)
    smote = SMOTE(random_state=42)

    try:
        # Determine the minimum number of samples for SMOTE to function correctly
        min_samples = min(class_counts.values())
        k_neighbors = min(min_samples - 1, 3)  # Use 3 as a fallback if min_samples > 4

        smote.k_neighbors = k_neighbors
        X_resampled, y_resampled = smote.fit_resample(X, y)
        print("SMOTE resampling completed successfully.")
    except ValueError as e:
        print(f"Error during SMOTE resampling: {e}")
        return data  # Return original data if resampling fails

    resampled_data = pd.DataFrame(X_resampled, columns=X.columns)
    resampled_data["attack"] = y_resampled
    print("Class imbalance handled.")
    return resampled_data


# Main function to perform data processing and analysis
def main(filepath):
    data = load_data(filepath)
    print("Data loaded with shape:", data.shape)

    # Basic statistics
    print("\nBasic statistics of the dataset:")
    print(data.describe(include="all"))

    # Encode categorical features
    data, encoders = encode_categorical_features(data)

    # Check and print class distribution
    if check_class_imbalance(data):
        print("Class imbalance detected.")
    else:
        print("No significant class imbalance detected.")

    # Normalize data
    data, scaler = normalize_data(data)

    # Handle class imbalance
    balanced_data = handle_class_imbalance(data)

    # Print final class distribution after handling imbalance
    print("\nClass distribution after handling imbalance:")
    print(balanced_data["attack"].value_counts())


if __name__ == "__main__":
    main("data/raw/KDDTrain+.txt")
