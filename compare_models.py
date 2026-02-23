"""
Model Comparison: Random Forest vs XGBoost vs Others
Trains all models on the phishing dataset and shows who wins.
"""
import sys, time, warnings
sys.path.insert(0, '.')
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import KNNImputer
from sklearn.metrics import (
    f1_score, accuracy_score, precision_score,
    recall_score, classification_report
)
from sklearn.ensemble import (
    RandomForestClassifier, GradientBoostingClassifier, AdaBoostClassifier
)
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier

# ── Load dataset ───────────────────────────────────────────────────────────
print("Loading dataset...")
df = pd.read_csv('Network_Data/phisingData.csv')
print(f"Dataset shape: {df.shape}")
print(f"Label distribution: {df['Result'].value_counts().to_dict()}")
print(f"Labels: -1=Phishing ({(df['Result']==-1).sum()}), 1=Safe ({(df['Result']==1).sum()})\n")

X = df.drop(columns=['Result'])
y = df['Result']

# Convert labels: -1 → 0 (phishing), 1 → 1 (safe)  — same as training pipeline
y = (y == 1).astype(int)

# Impute missing values (same as training pipeline uses KNNImputer)
imputer = KNNImputer(n_neighbors=3)
X_imputed = imputer.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(
    X_imputed, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Train: {X_train.shape[0]} samples | Test: {X_test.shape[0]} samples\n")

# ── Models to compare ─────────────────────────────────────────────────────
models = {
    "Random Forest       ": RandomForestClassifier(n_estimators=128, random_state=42),
    "XGBoost             ": XGBClassifier(
        n_estimators=128,
        learning_rate=0.1,
        max_depth=6,
        use_label_encoder=False,
        eval_metric='logloss',
        random_state=42,
        verbosity=0
    ),
    "Gradient Boosting   ": GradientBoostingClassifier(n_estimators=128, learning_rate=0.1, random_state=42),
    "Decision Tree       ": DecisionTreeClassifier(random_state=42),
    "AdaBoost            ": AdaBoostClassifier(n_estimators=128, random_state=42),
    "Logistic Regression ": LogisticRegression(max_iter=1000, random_state=42),
}

# ── Train & evaluate ──────────────────────────────────────────────────────
print("=" * 72)
print(f"{'Model':<25} {'Accuracy':>9} {'F1':>9} {'Precision':>10} {'Recall':>8} {'Time':>7}")
print("=" * 72)

results = {}
for name, model in models.items():
    t0 = time.time()
    model.fit(X_train, y_train)
    elapsed = time.time() - t0

    y_pred = model.predict(X_test)
    acc  = accuracy_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred, average='weighted')
    prec = precision_score(y_test, y_pred, average='weighted')
    rec  = recall_score(y_test, y_pred, average='weighted')

    results[name.strip()] = {'accuracy': acc, 'f1': f1, 'precision': prec, 'recall': rec, 'time': elapsed, 'model': model}
    print(f"{name} {acc*100:>8.2f}%  {f1*100:>8.2f}%  {prec*100:>9.2f}%  {rec*100:>7.2f}%  {elapsed:>5.1f}s")

print("=" * 72)

# ── Winner ────────────────────────────────────────────────────────────────
best_name = max(results, key=lambda k: results[k]['f1'])
best = results[best_name]
print(f"\n🏆  WINNER: {best_name}")
print(f"   F1={best['f1']*100:.2f}%  Accuracy={best['accuracy']*100:.2f}%  Time={best['time']:.1f}s")

rf  = results.get('Random Forest', results.get('Random Forest       ', {}))
xgb = results.get('XGBoost',       results.get('XGBoost             ', {}))
if rf and xgb:
    diff = (xgb['f1'] - rf['f1']) * 100
    if diff > 0:
        print(f"\n✅  XGBoost beats Random Forest by {diff:.2f}% F1 score")
    elif diff < 0:
        print(f"\n✅  Random Forest beats XGBoost by {abs(diff):.2f}% F1 score")
    else:
        print(f"\n🤝  XGBoost and Random Forest tied!")

# ── Detailed report for top 2 ─────────────────────────────────────────────
print("\n── Detailed report: Random Forest ──")
rf_model = list(models.values())[0]
print(classification_report(y_test, rf_model.predict(X_test), target_names=['Phishing','Safe']))

print("── Detailed report: XGBoost ──")
xgb_model = list(models.values())[1]
print(classification_report(y_test, xgb_model.predict(X_test), target_names=['Phishing','Safe']))

# ── Save the best model if XGBoost wins ───────────────────────────────────
if best_name.strip() == 'XGBoost':
    import pickle
    with open('final_model/model.pkl', 'wb') as f:
        pickle.dump(xgb_model, f)
    print("\n💾 Saved XGBoost as the new final_model/model.pkl !")
else:
    print(f"\nℹ️  Keeping existing Random Forest model (it still wins or ties).")
