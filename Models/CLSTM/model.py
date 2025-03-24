import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.preprocessing import LabelEncoder, RobustScaler
from tensorflow.keras.models import load_model

# ---------------------------
# 1. Load and Clean the New Traffic Data
# ---------------------------
file_path = './data/dos_traffic.csv'
df_generated = pd.read_csv(file_path)

# --- Remove columns with ≥90% zeros ---
zero_percentage = (df_generated == 0).sum() / len(df_generated) * 100
columns_to_remove = zero_percentage[zero_percentage >= 90].index.tolist()
print("Columns with 90% or more zeros (to be removed):")
print(columns_to_remove)
df_generated = df_generated.drop(columns=columns_to_remove)

# --- Check for missing values ---
missing_values = df_generated.isnull().sum()
columns_with_missing = missing_values[missing_values > 0]
print("\nColumns with missing values and their counts:")
print(columns_with_missing)
total_missing = columns_with_missing.sum()
print(f"\nTotal missing values in the dataset: {total_missing}")


# ---------------------------
# 2. Rename DOS file columns to match training features where possible
# ---------------------------
# Create a mapping from the DOS file columns to training feature names.
# (Only rename the columns that are available in the DOS file.)
dos_to_training_mapping = {
    "protocol": "Protocol",
    "timestamp": "Timestamp",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_header_len": "Fwd Header Length",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "pkt_size_avg": "Average Packet Size"
}
df_generated.rename(columns=dos_to_training_mapping, inplace=True)
print("\nColumns after renaming:")
print(df_generated.columns.tolist())

# ---------------------------
# 3. Drop high-cardinality and unmapped columns
# ---------------------------
# These columns are not used during training.
for col in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'src_mac', 'dst_mac',
            "tot_fwd_pkts", "totlen_fwd_pkts"]:
    if col in df_generated.columns:
        df_generated.drop(columns=[col], inplace=True)

# ---------------------------
# 4. Reindex to match the training features
# ---------------------------
# Training features used for model training:
training_features = [
    'Bwd IAT Mean', 'Flow IAT Min', 'Fwd IAT Std', 'Down/Up Ratio', 'Idle Min', 
    'Idle Mean', 'Fwd IAT Max', 'Flow Packets/s', 'Subflow Bwd Packets', 
    'Bwd Packet Length Max', 'Flow IAT Max', 'Fwd Packet Length Min', 'Idle Max', 
    'Active Min', 'Bwd Header Length', 'Fwd Packet Length Max', 'Subflow Fwd Packets', 
    'Subflow Bwd Bytes', 'Active Max', 'Subflow Fwd Bytes', 'Flow Duration', 
    'Fwd IAT Mean', 'Fwd Header Length', 'ACK Flag Count', 'Fwd IAT Min', 'Protocol', 
    'Fwd IAT Total', 'Flow IAT Std', 'Bwd Packets/s', 'Bwd Packet Length Mean', 
    'Average Packet Size', 'Bwd IAT Min', 'Bwd Packet Length Min', 'Packet Length Mean', 
    'Active Mean', 'Bwd IAT Max', 'Idle Std', 'Flow Bytes/s', 'Fwd Packet Length Mean', 
    'Fwd Packets/s', 'Flow IAT Mean', 'Bwd IAT Total', 'Timestamp'
]
print("\nExpected training features ({}):".format(len(training_features)))
print(training_features)

# Reindex the DataFrame so that it contains exactly these columns.
# Missing columns are filled with 0.
df_aligned = df_generated.reindex(columns=training_features, fill_value=0)
print(f"\nShape after reindexing: {df_aligned.shape}")

# ---------------------------
# 5. Further Preprocessing on Runtime Data
# ---------------------------
# If 'Protocol' is present, encode it.
if 'Protocol' in df_aligned.columns:
    le = LabelEncoder()
    df_aligned['Protocol'] = le.fit_transform(df_aligned['Protocol'])

# Convert 'Timestamp' to numerical (seconds since epoch)
if 'Timestamp' in df_aligned.columns:
    df_aligned['Timestamp'] = pd.to_datetime(df_aligned['Timestamp'], errors='coerce')
    df_aligned['Timestamp'] = df_aligned['Timestamp'].astype('int64', errors='ignore') // 10**9
    df_aligned['Timestamp'].fillna(0, inplace=True)

# ---------------------------
# 6. Scaling the Features
# ---------------------------
scaler = RobustScaler()
scaled_features = scaler.fit_transform(df_aligned.values)
scaled_df = pd.DataFrame(scaled_features, columns=df_aligned.columns)

# ---------------------------
# 7. Create Sequences to Match Model Input
# ---------------------------
def create_sequences(X, seq_length=10):
    X_seq = []
    for i in range(len(X) - seq_length + 1):
        X_seq.append(X[i:i+seq_length])
    return np.array(X_seq)

X_seq_runtime = create_sequences(scaled_df.values, seq_length=10)
print(f"\nRuntime traffic sequences shape: {X_seq_runtime.shape}")
# This shape should be [num_sequences, 10, 43] if training_features has 43 elements.

# ---------------------------
# 8. Load the Pre-trained Model and Predict
# ---------------------------
model_path = "./model/clstm_anomaly_detection_model.h5"
clstm_model = load_model(model_path)

predictions = clstm_model.predict(X_seq_runtime)
predicted_labels = (predictions > 0.5).astype(int)

# ---------------------------
# 9. Save and Summarize the Results
# ---------------------------
results = pd.DataFrame(X_seq_runtime[:, -1, :], columns=scaled_df.columns)
results["Predicted_Label"] = predicted_labels
output_file_path = "./data/predicted_results.csv"
results.to_csv(output_file_path, index=False)
print(f"\nPredictions saved to '{output_file_path}'.")
print("\nPrediction Summary:")
print(results["Predicted_Label"].value_counts())