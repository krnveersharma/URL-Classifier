from lightgbm import LGBMClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.metrics import accuracy_score
import numpy as np
import pickle

# Load training and test data
X_train = np.load('../dataset/X_train.npy')
y_train = np.load('../dataset/y_train.npy')
X_test = np.load('../dataset/X_test.npy')
y_test = np.load('../dataset/y_test.npy')

# Define the LGBMClassifier
clf = LGBMClassifier()

# Hyperparameter tuning with GridSearchCV
param_grid = {
    'learning_rate': [0.2],
    'n_estimators': [300],
    'max_depth': [7]
}

# Grid search
grid_search = GridSearchCV(clf, param_grid, scoring='accuracy', verbose=1)
grid_search.fit(X_train, y_train)

# Get the best model
best_clf = grid_search.best_estimator_

# Fit the best classifier on the training data
best_clf.fit(X_train, y_train)

# Make predictions on the test data
pred = best_clf.predict(X_test)

# Calculate accuracy
accuracy = accuracy_score(y_test, pred)
print('Accuracy: {:.4f}'.format(accuracy))

# Print the best hyperparameters
print("Best Hyperparameters:", grid_search.best_params_)

# Save the best model to a file
with open('best_lgbm_model.pkl', 'wb') as f:
    pickle.dump(best_clf, f)