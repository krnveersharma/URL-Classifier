from lightgbm import LGBMClassifier
from sklearn.metrics import accuracy_score
import numpy as np
import json
import dump

# Load training and test data
X_train = np.load('../dataset/X_train.npy')
y_train = np.load('../dataset/y_train.npy')
X_test = np.load('../dataset/X_test.npy')
y_test = np.load('../dataset/y_test.npy')

# Define the LGBMClassifier with specified hyperparameters
clf = LGBMClassifier(learning_rate=0.1, n_estimators=200, max_depth=5)

# Fit the classifier on the training data
clf.fit(X_train, y_train)

# Make predictions on the test data
pred = clf.predict(X_test)

# Calculate accuracy
accuracy = accuracy_score(y_test, pred)
print('Accuracy: {:.4f}'.format(accuracy))

# Save the classifier to a JSON file
json.dump(dump.lgb_forest_to_json(clf), open('../../static/classifier.json', 'w'))
print("done")
