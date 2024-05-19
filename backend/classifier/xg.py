from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
import numpy as np

# Load training and test data
X_train = np.load('../dataset/X_train.npy')
y_train = np.load('../dataset/y_train.npy')
X_test = np.load('../dataset/X_test.npy')
y_test = np.load('../dataset/y_test.npy')

# Define the XGBClassifier with default hyperparameters
clf = XGBClassifier()

# Fit the classifier on the training data
clf.fit(X_train, y_train)

# Make predictions on the test data
pred = clf.predict(X_test)

# Calculate accuracy
accuracy = accuracy_score(y_test, pred)
print('Accuracy: {}'.format(accuracy))
