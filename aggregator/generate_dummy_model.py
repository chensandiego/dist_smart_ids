from sklearn.ensemble import IsolationForest
from joblib import dump
import numpy as np

# Create a dummy Isolation Forest model
dummy_model = IsolationForest(random_state=42)
# Fit it with some dummy data (it doesn't matter for just saving the model structure)
dummy_model.fit(np.array([[0,0,0,0]]))

# Save the dummy model
dump(dummy_model, "/Users/chen/Desktop/dist_smart_ids/model/isolation_forest_model.joblib")
print("Dummy isolation_forest_model.joblib created successfully.")