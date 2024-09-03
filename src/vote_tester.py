import os
import sys

import numpy as np

# Assuming the `src` directory is in the same directory as this script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

from src.aids.aids_main import random_testing
from src.aids.preprocessing import df

# Initialize counters
agreement_count = 0
match_count = 0
total_runs = 10000
used_indices = set()  # Set to track used indices

# Initialize counters for each model's correct predictions
model_correct_count = {"SVC": 0, "One-Class SVM": 0, "Ensemble": 0}

# Perform iterations of random testing
for i in range(total_runs):
    final_prediction, predictions, selected_row_index = random_testing(used_indices)

    if selected_row_index is not None:
        # Update used indices
        used_indices.add(selected_row_index)

        # Retrieve the actual label from the dataset using the selected index
        actual_label = df.loc[selected_row_index, "Label"]

        # Check if all models agreed (either all 1s or all 0s)
        if predictions is not None and len(set(predictions)) == 1:
            agreement_count += 1

        # Check if the final prediction matches the actual label
        if final_prediction == actual_label:
            match_count += 1

        # Update model-specific accuracy counts
        model_names = ["SVC", "One-Class SVM", "Ensemble"]
        for model_name, model_prediction in zip(model_names, predictions):
            if model_prediction == actual_label:
                model_correct_count[model_name] += 1

        # Prepare the prediction results for display
        prediction_results = {
            name: pred for name, pred in zip(model_names, predictions)
        }

        print(
            f"Run {i + 1}: Random row with Actual Label = {actual_label}, "
            f"individual predictions: {prediction_results}, "
            f"final decision: {'Attack' if final_prediction == 1 else 'Normal'}"
        )
    else:
        print("No more unique rows available for testing.")
        break

# Calculate the percentage of agreement
agreement_percentage = (agreement_count / total_runs) * 100

# Calculate the percentage of matching final verdicts
match_percentage = (match_count / total_runs) * 100

# Calculate accuracy ratio for each model
model_accuracy_ratio = {
    model: (correct_count / total_runs) * 100
    for model, correct_count in model_correct_count.items()
}

# Print the results
print(f"\nPercentage of agreement: {agreement_percentage:.2f}%")
print(f"Percentage of matching final verdicts: {match_percentage:.2f}%")

# Print accuracy ratio for each model
print("\nModel Accuracy Ratios:")
for model, ratio in model_accuracy_ratio.items():
    print(f"{model}: {ratio:.2f}%")
