import pandas as pd
import numpy as np
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from feature_extraction import main
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load data
df = pd.read_csv('malicious_phish_updated.csv')
print("Original shape:", df.shape)

# Extract features for all URLs
X = df['url'].apply(main).tolist()
X = np.array(X)
y = df['type']

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, shuffle=True, random_state=5)

# Train model
rf = RandomForestClassifier(n_estimators=100, max_features='sqrt')
rf.fit(X_train, y_train)
y_pred_rf = rf.predict(X_test)

# Evaluate
print(classification_report(y_test, y_pred_rf, target_names=['benign', 'defacement', 'phishing', 'malware']))
score = accuracy_score(y_test, y_pred_rf)
print("accuracy:   %0.3f" % score)

# Save model
joblib.dump(rf, 'rf_model.pkl')