import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OrdinalEncoder
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

# 1) Load your cleaned CSV
df = pd.read_csv("network_traffic_unified.csv")  
FEATURE_ORDER = ['proto','service','duration','orig_bytes','resp_bytes','conn_state']

# 2) Save LabelEncoders for reference (for proto/service/conn_state → string ↔ number mapping)
label_encoders = {}
for col in ['proto','service','conn_state']:
    le = LabelEncoder()
    le.fit(df[col].astype(str))
    joblib.dump(le, f"encoder_{col}.pkl")
    label_encoders[col] = le  # Optional if you want to use in memory

# 3) Build preprocessing and model pipeline
categorical = ['proto','service','conn_state']
numerical   = ['duration','orig_bytes','resp_bytes']

preproc = ColumnTransformer([
    ("cat", OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1), categorical),
    ("num", StandardScaler(), numerical)
])

pipeline = Pipeline([
    ("preproc", preproc),
    ("clf", XGBClassifier(
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42
    ))
])

# 4) Train model
X = df[FEATURE_ORDER]
y = df['label']
X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

pipeline.fit(X_tr, y_tr)
print("Retrain accuracy:", pipeline.score(X_te, y_te))

# 5) Save pipeline
joblib.dump(pipeline, "model_5_pipeline.pkl")
print("✅ New pipeline saved as model_5_pipeline.pkl")

# 6) (Optional) Save target label encoder if you use string labels
if y.dtype == object or y.dtype == "str":
    target_encoder = LabelEncoder().fit(y)
    joblib.dump(target_encoder, "encoder_target.pkl")
