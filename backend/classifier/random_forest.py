from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import RandomizedSearchCV, cross_val_score
from sklearn.metrics import accuracy_score
import numpy as np
import json
import dump

# Load training and test data
X_train = np.load('../dataset/X_train.npy')
y_train = np.load('../dataset/y_train.npy')
X_test = np.load('../dataset/X_test.npy')
y_test = np.load('../dataset/y_test.npy')

# Define the RandomForestClassifier
clf = RandomForestClassifier()

# Define the parameter grid
param_grid = {
    'n_estimators': [100, 200, 300], # Number of trees in the forest
    'max_depth': [None, 10, 20, 30], # Maximum depth of the trees
    'min_samples_split': [2, 5, 10], # Minimum number of samples required to split an internal node
    'min_samples_leaf': [1, 2, 4], # Minimum number of samples required to be at a leaf node
    'bootstrap': [True, False] # Whether bootstrap samples are used when building trees
}

# Define RandomizedSearchCV with 5-fold cross-validation
random_search = RandomizedSearchCV(estimator=clf, param_distributions=param_grid, n_iter=10, cv=5, scoring='accuracy', n_jobs=-1, random_state=42)

# Perform the RandomizedSearchCV
random_search.fit(X_train, y_train)

# Get the best parameters
best_params = random_search.best_params_
print("Best Parameters:", best_params)

# Get the best estimator
best_clf = random_search.best_estimator_

# Calculate cross-validation score
cv_score = np.mean(cross_val_score(best_clf, X_train, y_train, cv=10))
print('Cross Validation Score: {0}'.format(cv_score))

# Fit the best estimator on the training data
best_clf.fit(X_train, y_train)

# Make predictions on the test data
pred = best_clf.predict(X_test)

# Calculate accuracy
accuracy = accuracy_score(y_test, pred)
print('Accuracy: {}'.format(accuracy))
