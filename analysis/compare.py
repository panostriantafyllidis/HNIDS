import pandas as pd


# Function to compare columns of two CSV files and create a new CSV with the differences
def compare_csv_columns(listA_path, listB_path, output_path):
    # Read the content of listA.csv and listB.csv
    df_listA = pd.read_csv(listA_path, nrows=0, sep=",")  # Read only the header
    df_listB = pd.read_csv(listB_path, nrows=0, sep=",")  # Read only the header

    # Get the column names
    columns_listA = df_listA.columns.tolist()
    columns_listB = df_listB.columns.tolist()

    # Find columns in A not in B, B not in A, and common columns
    columns_in_A_not_in_B = [col for col in columns_listA if col not in columns_listB]
    columns_in_B_not_in_A = [col for col in columns_listB if col not in columns_listA]
    common_columns = [col for col in columns_listA if col in columns_listB]

    # Create the DataFrame for listC
    listC_df = pd.DataFrame(
        [columns_in_A_not_in_B, columns_in_B_not_in_A, common_columns],
        index=["In_A_not_in_B", "In_B_not_in_A", "Common"],
    )

    # Save the DataFrame to a new CSV file
    listC_df.to_csv(output_path, index=False, header=False)


# Define file paths
listA_path = "listA.csv"
listB_path = "listB.csv"
output_path = "listC.csv"

# Call the function
compare_csv_columns(listA_path, listB_path, output_path)
