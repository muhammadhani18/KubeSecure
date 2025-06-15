import pandas as pd

def load_and_encode(csv_path, label_column):
    # Load the CSV file into a pandas DataFrame
    df = pd.read_csv(csv_path)
    
    # Encode labels: convert all values not equal to 0 into 1
    df[label_column] = df[label_column].apply(lambda x: 1 if x != 0 else 0)
    
    return df

# Example usage
if __name__ == "__main__":
    csv_file = "./data/structured_k8s_traffic.csv"  # Change to your actual CSV file path
    label_col = "Label"  # Change to the actual column name containing labels
    
    df_encoded = load_and_encode(csv_file, label_col)
    print(df_encoded.head())

    df_encoded.to_csv("./data/structured_k8s_traffic.csv", index=False)