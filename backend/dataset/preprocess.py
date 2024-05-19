import pandas as pd
import numpy as np
from sklearn.model_selection import KFold
import json
import os

# Load the dataset
data = pd.read_csv('dataset_full.csv')

# Split features and target variable
X, y = data.iloc[:, :-1], data.iloc[:, -1]

# Initialize a KFold splitter
kf = KFold(n_splits=5, shuffle=True, random_state=0)

# Initialize lists to store the train-test splits
X_train_list, X_test_list, y_train_list, y_test_list = [], [], [], []

# Perform k-fold cross-validation
for train_index, test_index in kf.split(X):
    X_train, X_test = X.iloc[train_index], X.iloc[test_index]
    y_train, y_test = y.iloc[train_index], y.iloc[test_index]
    X_train_list.append(X_train)
    X_test_list.append(X_test)
    y_train_list.append(y_train)
    y_test_list.append(y_test)

# Save the train-test splits as numpy arrays
np.save('X_train.npy', np.vstack(X_train_list))
np.save('X_test.npy', np.vstack(X_test_list))
np.save('y_train.npy', np.hstack(y_train_list))
np.save('y_test.npy', np.hstack(y_test_list))

# Prepare test data for JSON
test_data = dict()
test_data['X_test'] = [df.values.tolist() for df in X_test_list]
test_data['y_test'] = [series.tolist() for series in y_test_list]

# Ensure the directory exists
output_dir = '../../static'
os.makedirs(output_dir, exist_ok=True)

# Save test data to JSON
with open(os.path.join(output_dir, 'testdata.json'), 'w') as tdfile:
    json.dump(test_data, tdfile)
    print('Test Data written to testdata.json')

print('Data saved successfully!')
