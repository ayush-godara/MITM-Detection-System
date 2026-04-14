import pandas as pd
from sklearn.preprocessing import StandardScaler

# Load dataset
df = pd.read_csv("dataset.csv")

print("Original shape:", df.shape)

# -----------------------------
# CLEANING
# -----------------------------

# Drop non useful columns (ignore if not present)
df = df.drop(columns=["application_name", "category_name", "server_fingerprint"], errors='ignore')

# Convert Label to numeric
df['Label'] = df['Label'].map({
    'normal': 0,
    'arp_spoofing': 1
})

# Remove missing values
df = df.dropna()

# -----------------------------
# FEATURE SELECTION
# -----------------------------

# Keep only numeric columns
df = df.select_dtypes(include=['int64', 'float64'])

# Separate features and label
X = df.drop("Label", axis=1)
y = df["Label"]

# Select first 15 features (simple selection)
X = X.iloc[:, :15]

# -----------------------------
# NORMALIZATION
# -----------------------------

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Save cleaned dataset
processed = pd.DataFrame(X_scaled)
processed['Label'] = y.values

processed.to_csv("cleaned_dataset.csv", index=False)

print("✅ Preprocessing done")