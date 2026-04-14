import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

# -----------------------------
# LOAD DATA
# -----------------------------

df = pd.read_csv("cleaned_dataset.csv")

# 🔥 ONLY USE 2 FEATURES
X = df[["Flow Duration", "Flow Bytes/s"]]

# rename for clarity
X.columns = ["rtt", "rss"]

# -----------------------------
# ISOLATION FOREST
# -----------------------------

iso = IsolationForest(contamination=0.1, random_state=42)
iso.fit(X)

joblib.dump(iso, "models/isolation.pkl")
print("✅ Isolation Forest saved")

# -----------------------------
# LOF
# -----------------------------

lof = LocalOutlierFactor(n_neighbors=20, novelty=True)
lof.fit(X)

joblib.dump(lof, "models/lof.pkl")
print("✅ LOF saved")