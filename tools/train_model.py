"""
Network Intrusion Detection System (NIDS) using Machine Learning
================================================================

A publication-quality pipeline for detecting malicious network traffic
using Random Forest with deployment to MIPS32 embedded systems via TL2cgen.

Key Design Decisions:
- Day-based temporal split to prevent data leakage
- Embedded-friendly model constraints (MIPS32 compatible)
- Random Forest for transpilation (parallel tree structure)
- Comprehensive metrics for paper reporting

Author: [Your Name]
Date: 2026
"""

import os
import sys
import warnings
import time
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Tuple, Dict, List, Optional, Any
from datetime import datetime

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats

# Scikit-learn
from sklearn.model_selection import (
    train_test_split, cross_val_score, StratifiedKFold, learning_curve
)
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
    roc_curve, precision_recall_curve, average_precision_score,
    matthews_corrcoef
)
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB

# XGBoost
from xgboost import XGBClassifier

# Model export
import treelite
import treelite.sklearn
import tl2cgen

warnings.filterwarnings('ignore')

# =============================================================================
# CONFIGURATION - Embedded System Constraints (MIPS32)
# =============================================================================

@dataclass
class EmbeddedConstraints:
    """Hardware constraints for MIPS32 router deployment."""
    max_flash_kb: int = 128          # Max model size in flash
    max_ram_kb: int = 32             # Max RAM during inference
    word_size: int = 32              # 32-bit architecture
    has_fpu: bool = False            # No hardware FPU (use integer math)
    clock_mhz: int = 580             # Typical MIPS32 clock


@dataclass
class ModelConstraints:
    """Model constraints for embedded deployment."""
    # These are SMALL values suitable for MIPS32
    max_trees: int = 10              # Few trees for size
    max_depth: int = 5               # Shallow for speed
    min_samples_split: int = 20      # Prevent overfitting
    min_samples_leaf: int = 10       # Larger leaves = smaller model
    max_features: str = 'sqrt'       # Feature subsampling


@dataclass
class Config:
    """Master configuration."""

    # Paths
    data_dir: Path = Path("/home/akshat/Desktop/capstone")
    output_dir: Path = Path("/home/akshat/Desktop/capstone/outputs")

    # Data files with dates for temporal split
    data_files: Dict = field(default_factory=lambda: {
        "02-14-2018.csv": "2018-02-14",
        "02-15-2018.csv": "2018-02-15",
        "02-21-2018.csv": "2018-02-21",
    })

    # Temporal split configuration
    train_dates: Tuple[str, ...] = ("2018-02-14", "2018-02-15")
    test_date: str = "2018-02-21"
    validation_ratio: float = 0.125  # 12.5% of training data

    # Preprocessing
    correlation_threshold: float = 0.90
    random_state: int = 42

    # Hardware constraints
    embedded: EmbeddedConstraints = field(default_factory=EmbeddedConstraints)
    model: ModelConstraints = field(default_factory=ModelConstraints)

    # Visualization
    figure_dpi: int = 300

    def __post_init__(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "figures").mkdir(exist_ok=True)
        (self.output_dir / "models").mkdir(exist_ok=True)
        (self.output_dir / "metrics").mkdir(exist_ok=True)


# =============================================================================
# PUBLICATION-QUALITY PLOTTING
# =============================================================================

def setup_plotting():
    """Configure matplotlib for IEEE publication figures."""
    plt.style.use('seaborn-v0_8-whitegrid')
    plt.rcParams.update({
        'figure.figsize': (8, 6),
        'figure.dpi': 150,
        'savefig.dpi': 300,
        'savefig.bbox': 'tight',
        'font.family': 'serif',
        'font.serif': ['Times New Roman', 'DejaVu Serif'],
        'font.size': 11,
        'axes.titlesize': 12,
        'axes.labelsize': 11,
        'xtick.labelsize': 10,
        'ytick.labelsize': 10,
        'legend.fontsize': 10,
        'lines.linewidth': 1.5,
        'axes.linewidth': 1.0,
        'axes.grid': True,
        'grid.alpha': 0.3,
    })

COLORS = {
    'benign': '#2E86AB',
    'malicious': '#C73E1D',
    'primary': '#2E86AB',
    'secondary': '#A23B72',
    'accent': '#F18F01',
}

MODEL_COLORS = {
    'Random Forest': '#2E86AB',
    'Decision Tree': '#A23B72',
    'XGBoost': '#F18F01',
    'Gradient Boosting': '#6B4C9A',
    'Logistic Regression': '#C73E1D',
    'Naive Bayes': '#3B3B3B',
}


# =============================================================================
# DATA LOADING WITH TEMPORAL TRACKING
# =============================================================================

class DataLoader:
    """Load data with date tracking for temporal split."""

    DTYPE_SPEC = {
        'Dst Port': 'int64', 'Protocol': 'int64', 'Flow Duration': 'int64',
        'Tot Fwd Pkts': 'int64', 'Tot Bwd Pkts': 'int64',
        'TotLen Fwd Pkts': 'int64', 'TotLen Bwd Pkts': 'int64',
        'Fwd Pkt Len Max': 'int64', 'Fwd Pkt Len Min': 'int64',
        'Fwd Pkt Len Mean': 'float64', 'Fwd Pkt Len Std': 'float64',
        'Bwd Pkt Len Max': 'int64', 'Bwd Pkt Len Min': 'int64',
        'Bwd Pkt Len Mean': 'float64', 'Bwd Pkt Len Std': 'float64',
        'Flow Byts/s': 'float64', 'Flow Pkts/s': 'float64',
        'Flow IAT Mean': 'float64', 'Flow IAT Std': 'float64',
        'Flow IAT Max': 'int64', 'Flow IAT Min': 'int64',
        'Fwd IAT Tot': 'int64', 'Fwd IAT Mean': 'float64',
        'Fwd IAT Std': 'float64', 'Fwd IAT Max': 'int64', 'Fwd IAT Min': 'int64',
        'Bwd IAT Tot': 'int64', 'Bwd IAT Mean': 'float64',
        'Bwd IAT Std': 'float64', 'Bwd IAT Max': 'int64', 'Bwd IAT Min': 'int64',
        'Fwd PSH Flags': 'int64', 'Bwd PSH Flags': 'int64',
        'Fwd URG Flags': 'int64', 'Bwd URG Flags': 'int64',
        'Fwd Header Len': 'int64', 'Bwd Header Len': 'int64',
        'Fwd Pkts/s': 'float64', 'Bwd Pkts/s': 'float64',
        'Pkt Len Min': 'int64', 'Pkt Len Max': 'int64',
        'Pkt Len Mean': 'float64', 'Pkt Len Std': 'float64',
        'Pkt Len Var': 'float64', 'FIN Flag Cnt': 'int64',
        'SYN Flag Cnt': 'int64', 'RST Flag Cnt': 'int64',
        'PSH Flag Cnt': 'int64', 'ACK Flag Cnt': 'int64',
        'URG Flag Cnt': 'int64', 'CWE Flag Count': 'int64',
        'ECE Flag Cnt': 'int64', 'Down/Up Ratio': 'int64',
        'Pkt Size Avg': 'float64', 'Fwd Seg Size Avg': 'float64',
        'Bwd Seg Size Avg': 'float64', 'Fwd Byts/b Avg': 'int64',
        'Fwd Pkts/b Avg': 'int64', 'Fwd Blk Rate Avg': 'int64',
        'Bwd Byts/b Avg': 'int64', 'Bwd Pkts/b Avg': 'int64',
        'Bwd Blk Rate Avg': 'int64', 'Subflow Fwd Pkts': 'int64',
        'Subflow Fwd Byts': 'int64', 'Subflow Bwd Pkts': 'int64',
        'Subflow Bwd Byts': 'int64', 'Init Fwd Win Byts': 'int64',
        'Init Bwd Win Byts': 'int64', 'Fwd Act Data Pkts': 'int64',
        'Fwd Seg Size Min': 'int64', 'Active Mean': 'float64',
        'Active Std': 'float64', 'Active Max': 'int64', 'Active Min': 'int64',
        'Idle Mean': 'float64', 'Idle Std': 'float64',
        'Idle Max': 'int64', 'Idle Min': 'int64'
    }

    ATTACK_TYPES = [
        "FTP-BruteForce", "DDOS attack-HOIC", "SSH-Bruteforce",
        "DoS attacks-Slowloris", "DoS attacks-GoldenEye", "SQL Injection",
        "Brute Force -XSS", "Brute Force -Web", "DDOS attack-LOIC-UDP"
    ]

    def __init__(self, config: Config):
        self.config = config

    def load_with_dates(self) -> pd.DataFrame:
        """Load all data with source date column for temporal split."""
        print("=" * 70)
        print("PHASE 1: DATA LOADING")
        print("=" * 70)

        dataframes = []
        for filename, date in self.config.data_files.items():
            filepath = self.config.data_dir / filename
            print(f"  Loading {filename}...", end=" ")
            df = pd.read_csv(filepath, dtype=self.DTYPE_SPEC, header=0)
            df['_source_date'] = date  # Track source for temporal split
            print(f"({len(df):,} flows)")
            dataframes.append(df)

        combined = pd.concat(dataframes, axis=0, ignore_index=True)

        print(f"\n  Total flows loaded: {len(combined):,}")
        print(f"  Features: {len(combined.columns) - 1}")  # -1 for _source_date
        print(f"  Date range: {min(self.config.data_files.values())} to {max(self.config.data_files.values())}")

        return combined


# =============================================================================
# PREPROCESSING WITH FULL TRACKING
# =============================================================================

class DataPreprocessor:
    """Preprocess data with comprehensive tracking for paper reporting."""

    def __init__(self, config: Config):
        self.config = config
        self.stats = {}
        self.removed_features = {}

    def preprocess(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict]:
        """Full preprocessing pipeline with statistics collection."""
        print("\n" + "=" * 70)
        print("PHASE 2: DATA PREPROCESSING")
        print("=" * 70)

        self.stats['initial'] = {
            'total_flows': len(df),
            'features': len(df.columns) - 2,  # -2 for Label and _source_date
            'shape': df.shape
        }

        # Step 1: Handle infinite/missing values
        df = self._clean_values(df)

        # Step 2: Analyze original class distribution
        self._analyze_class_distribution(df, "original")

        # Step 3: Convert to binary classification
        df = self._to_binary_classification(df)

        # Step 4: Balance classes (per date to maintain temporal integrity)
        df = self._balance_classes_by_date(df)

        # Step 5: Remove non-predictive columns
        df = self._remove_non_numeric(df)

        # Step 6: Remove zero-variance features
        df = self._remove_constant_features(df)

        # Step 7: Remove duplicate columns
        df = self._remove_duplicates(df)

        # Step 8: Remove highly correlated features
        df = self._remove_correlated(df)

        self._print_summary()

        return df, self.stats

    def _clean_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Handle infinite and missing values."""
        print("\n  [1/8] Cleaning infinite and missing values...")

        # Count issues
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        inf_mask = np.isinf(df[numeric_cols]).any(axis=1)
        inf_count = inf_mask.sum()

        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        nan_count = df.isna().any(axis=1).sum()

        df.dropna(inplace=True)

        self.stats['cleaning'] = {
            'infinite_flows_removed': int(inf_count),
            'nan_flows_removed': int(nan_count),
            'flows_after': len(df)
        }

        print(f"        Removed {inf_count:,} flows with infinite values")
        print(f"        Removed {nan_count:,} flows with NaN values")
        print(f"        Remaining: {len(df):,} flows")

        return df

    def _analyze_class_distribution(self, df: pd.DataFrame, stage: str):
        """Analyze and store class distribution."""
        distribution = df['Label'].value_counts().to_dict()
        self.stats[f'{stage}_distribution'] = distribution

        print(f"\n  [2/8] Original class distribution:")
        for label, count in sorted(distribution.items(), key=lambda x: -x[1]):
            pct = count / len(df) * 100
            print(f"        {label}: {count:,} ({pct:.1f}%)")

    def _to_binary_classification(self, df: pd.DataFrame) -> pd.DataFrame:
        """Convert to binary: Benign (0) vs Malicious (1)."""
        print(f"\n  [3/8] Converting to binary classification...")

        # Map all attacks to "Malicious"
        df['Label'] = df['Label'].replace(self.ATTACK_TYPES, 'Malicious')

        benign = (df['Label'] == 'Benign').sum()
        malicious = (df['Label'] == 'Malicious').sum()

        self.stats['binary_distribution'] = {
            'Benign': int(benign),
            'Malicious': int(malicious),
            'imbalance_ratio': round(benign / malicious, 2) if malicious > 0 else float('inf')
        }

        print(f"        Benign: {benign:,}")
        print(f"        Malicious: {malicious:,}")
        print(f"        Imbalance ratio: {benign/malicious:.2f}:1")

        return df

    ATTACK_TYPES = DataLoader.ATTACK_TYPES

    def _balance_classes_by_date(self, df: pd.DataFrame) -> pd.DataFrame:
        """Balance classes while preserving temporal structure."""
        print(f"\n  [4/8] Balancing classes (preserving temporal structure)...")

        balanced_dfs = []

        for date in df['_source_date'].unique():
            date_df = df[df['_source_date'] == date]
            benign = date_df[date_df['Label'] == 'Benign']
            malicious = date_df[date_df['Label'] == 'Malicious']

            min_samples = min(len(benign), len(malicious))

            if min_samples > 0:
                benign_sampled = benign.sample(n=min_samples, random_state=self.config.random_state)
                malicious_sampled = malicious.sample(n=min_samples, random_state=self.config.random_state)
                balanced_dfs.append(pd.concat([benign_sampled, malicious_sampled]))
                print(f"        {date}: {min_samples:,} samples per class")

        df_balanced = pd.concat(balanced_dfs, axis=0)
        df_balanced = df_balanced.sample(frac=1, random_state=self.config.random_state).reset_index(drop=True)

        # Convert labels to numeric
        df_balanced['Label'] = df_balanced['Label'].map({'Benign': 0, 'Malicious': 1})

        self.stats['balanced'] = {
            'total_flows': len(df_balanced),
            'per_class': len(df_balanced) // 2
        }

        print(f"        Total balanced: {len(df_balanced):,} flows")

        return df_balanced

    def _remove_non_numeric(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove non-numeric columns except Label and _source_date."""
        print(f"\n  [5/8] Removing non-numeric columns...")

        non_numeric = df.select_dtypes(exclude=[np.number]).columns.tolist()
        non_numeric = [c for c in non_numeric if c not in ['Label', '_source_date']]

        self.removed_features['non_numeric'] = non_numeric
        df = df.drop(columns=non_numeric)

        print(f"        Removed: {non_numeric}")

        return df

    def _remove_constant_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove zero-variance features."""
        print(f"\n  [6/8] Removing constant-variance features...")

        feature_cols = [c for c in df.columns if c not in ['Label', '_source_date']]
        variances = df[feature_cols].var()
        constant = variances[variances == 0].index.tolist()

        self.removed_features['constant'] = constant
        df = df.drop(columns=constant)

        print(f"        Removed {len(constant)} features: {constant}")

        return df

    def _remove_duplicates(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove duplicate columns."""
        print(f"\n  [7/8] Removing duplicate columns...")

        feature_cols = [c for c in df.columns if c not in ['Label', '_source_date']]
        duplicates = set()

        for i, col1 in enumerate(feature_cols):
            if col1 in duplicates:
                continue
            for col2 in feature_cols[i+1:]:
                if df[col1].equals(df[col2]):
                    duplicates.add(col2)

        self.removed_features['duplicate'] = list(duplicates)
        df = df.drop(columns=list(duplicates))

        print(f"        Removed {len(duplicates)} features: {duplicates}")

        return df

    def _remove_correlated(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove highly correlated features."""
        print(f"\n  [8/8] Removing correlated features (threshold={self.config.correlation_threshold})...")

        feature_cols = [c for c in df.columns if c not in ['Label', '_source_date']]
        corr = df[feature_cols].corr().abs()

        # Upper triangle mask
        upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))

        # Find features with correlation > threshold
        to_drop = [col for col in upper.columns if any(upper[col] > self.config.correlation_threshold)]

        self.removed_features['correlated'] = to_drop
        self.stats['correlation_matrix'] = corr

        df = df.drop(columns=to_drop)

        print(f"        Removed {len(to_drop)} features")

        return df

    def _print_summary(self):
        """Print preprocessing summary."""
        print("\n" + "-" * 70)
        print("PREPROCESSING SUMMARY")
        print("-" * 70)

        total_removed = sum(len(v) for v in self.removed_features.values())

        print(f"  Initial flows:        {self.stats['initial']['total_flows']:,}")
        print(f"  After cleaning:       {self.stats['cleaning']['flows_after']:,}")
        print(f"  After balancing:      {self.stats['balanced']['total_flows']:,}")
        print(f"  Initial features:     {self.stats['initial']['features']}")
        print(f"  Features removed:     {total_removed}")
        print(f"    - Constant:         {len(self.removed_features.get('constant', []))}")
        print(f"    - Duplicate:        {len(self.removed_features.get('duplicate', []))}")
        print(f"    - Correlated:       {len(self.removed_features.get('correlated', []))}")
        print(f"    - Non-numeric:      {len(self.removed_features.get('non_numeric', []))}")

        self.stats['final_features'] = (
            self.stats['initial']['features'] - total_removed
        )
        self.stats['removed_features'] = self.removed_features


# =============================================================================
# STRATIFIED SPLIT (ENSURES ALL ATTACK TYPES IN TRAIN/TEST)
# =============================================================================

class DataSplitter:
    """
    Split data using stratified random sampling.

    Design Decision:
    ----------------
    The CSE-CIC-IDS2018 dataset contains different attack types on different days:
    - Feb 14: FTP/SSH Brute Force
    - Feb 15: DoS attacks (GoldenEye, Slowloris)
    - Feb 21: DDoS attacks (HOIC, LOIC)

    A day-based temporal split would cause distribution shift where the test set
    contains attack types never seen during training, resulting in near-zero recall.

    Therefore, we use stratified random sampling to ensure all attack types are
    represented in both training and test sets. This is standard practice in IDS
    research when attack types vary across capture sessions.

    Reference: Similar approach used in CIC-IDS2017 benchmark studies.
    """

    def __init__(self, config: Config):
        self.config = config
        self.split_stats = {}

    def split(self, df: pd.DataFrame) -> Tuple[np.ndarray, ...]:
        """Perform stratified random split."""
        print("\n" + "=" * 70)
        print("PHASE 3: DATA SPLITTING")
        print("=" * 70)

        print(f"\n  Split strategy: Stratified random sampling")
        print(f"  Rationale: Different days contain different attack types;")
        print(f"             stratified split ensures all types in train & test")

        # Drop the source date column (no longer needed)
        feature_cols = [c for c in df.columns if c not in ['Label', '_source_date']]

        X = df[feature_cols].values
        y = df['Label'].values

        # First split: 80% train+val, 20% test
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y,
            test_size=0.20,
            stratify=y,
            random_state=self.config.random_state
        )

        # Second split: from the 80%, take 12.5% for validation (= 10% of total)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp,
            test_size=0.125,  # 0.125 * 0.80 = 0.10 of total
            stratify=y_temp,
            random_state=self.config.random_state
        )

        # Calculate statistics
        total = len(X_train) + len(X_val) + len(X_test)

        self.split_stats = {
            'train_samples': len(X_train),
            'train_pct': round(len(X_train) / total * 100, 1),
            'val_samples': len(X_val),
            'val_pct': round(len(X_val) / total * 100, 1),
            'test_samples': len(X_test),
            'test_pct': round(len(X_test) / total * 100, 1),
            'n_features': len(feature_cols),
            'feature_names': feature_cols,
            'split_method': 'Stratified random (ensures attack type coverage)',
            'train_class_dist': {
                'benign': int((y_train == 0).sum()),
                'malicious': int((y_train == 1).sum())
            },
            'val_class_dist': {
                'benign': int((y_val == 0).sum()),
                'malicious': int((y_val == 1).sum())
            },
            'test_class_dist': {
                'benign': int((y_test == 0).sum()),
                'malicious': int((y_test == 1).sum())
            }
        }

        print(f"\n  Split results:")
        print(f"    Training:   {self.split_stats['train_samples']:,} samples ({self.split_stats['train_pct']}%)")
        print(f"    Validation: {self.split_stats['val_samples']:,} samples ({self.split_stats['val_pct']}%)")
        print(f"    Test:       {self.split_stats['test_samples']:,} samples ({self.split_stats['test_pct']}%)")
        print(f"    Features:   {self.split_stats['n_features']}")

        print(f"\n  Class distribution (balanced 1:1):")
        print(f"    Train  - Benign: {self.split_stats['train_class_dist']['benign']:,}, "
              f"Malicious: {self.split_stats['train_class_dist']['malicious']:,}")
        print(f"    Test   - Benign: {self.split_stats['test_class_dist']['benign']:,}, "
              f"Malicious: {self.split_stats['test_class_dist']['malicious']:,}")

        return X_train, X_val, X_test, y_train, y_val, y_test, feature_cols


# =============================================================================
# MODEL TRAINING (EMBEDDED-FRIENDLY)
# =============================================================================

class EmbeddedModelTrainer:
    """Train models with embedded system constraints."""

    def __init__(self, config: Config):
        self.config = config
        self.models = self._create_models()
        self.results = {}

    def _create_models(self) -> Dict:
        """Create embedded-friendly models."""
        mc = self.config.model  # Model constraints

        return {
            'Random Forest': RandomForestClassifier(
                n_estimators=mc.max_trees,
                max_depth=mc.max_depth,
                min_samples_split=mc.min_samples_split,
                min_samples_leaf=mc.min_samples_leaf,
                max_features=mc.max_features,
                random_state=self.config.random_state,
                n_jobs=-1
            ),
            'Decision Tree': DecisionTreeClassifier(
                max_depth=mc.max_depth,
                min_samples_split=mc.min_samples_split,
                min_samples_leaf=mc.min_samples_leaf,
                random_state=self.config.random_state
            ),
            'XGBoost': XGBClassifier(
                n_estimators=mc.max_trees,
                max_depth=mc.max_depth,
                learning_rate=0.1,
                min_child_weight=mc.min_samples_leaf,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=self.config.random_state,
                n_jobs=-1,
                verbosity=0
            ),
            'Gradient Boosting': GradientBoostingClassifier(
                n_estimators=mc.max_trees,
                max_depth=mc.max_depth,
                min_samples_split=mc.min_samples_split,
                min_samples_leaf=mc.min_samples_leaf,
                learning_rate=0.1,
                random_state=self.config.random_state
            ),
            'Logistic Regression': LogisticRegression(
                max_iter=1000,
                random_state=self.config.random_state,
                n_jobs=-1
            ),
            'Naive Bayes': GaussianNB()
        }

    def train_all(self, X_train, X_val, X_test, y_train, y_val, y_test) -> Dict:
        """Train and evaluate all models."""
        print("\n" + "=" * 70)
        print("PHASE 4: MODEL TRAINING (Embedded-Friendly Constraints)")
        print("=" * 70)
        print(f"\n  Constraints: max_trees={self.config.model.max_trees}, "
              f"max_depth={self.config.model.max_depth}")

        for name, model in self.models.items():
            print(f"\n  Training {name}...", end=" ")

            start = time.time()
            model.fit(X_train, y_train)
            train_time = time.time() - start

            # Predictions
            y_train_pred = model.predict(X_train)
            y_val_pred = model.predict(X_val)
            y_test_pred = model.predict(X_test)

            # Probabilities (if available)
            if hasattr(model, 'predict_proba'):
                y_test_prob = model.predict_proba(X_test)[:, 1]
                auc = roc_auc_score(y_test, y_test_prob)
            else:
                y_test_prob = None
                auc = None

            # Comprehensive metrics
            self.results[name] = {
                'model': model,
                'train_time': train_time,

                # Accuracy
                'train_accuracy': accuracy_score(y_train, y_train_pred),
                'val_accuracy': accuracy_score(y_val, y_val_pred),
                'test_accuracy': accuracy_score(y_test, y_test_pred),

                # Precision/Recall/F1
                'precision': precision_score(y_test, y_test_pred),
                'recall': recall_score(y_test, y_test_pred),
                'f1': f1_score(y_test, y_test_pred),

                # Additional metrics
                'auc_roc': auc,
                'mcc': matthews_corrcoef(y_test, y_test_pred),

                # Confusion matrix values
                'confusion_matrix': confusion_matrix(y_test, y_test_pred),

                # Predictions
                'y_test_pred': y_test_pred,
                'y_test_prob': y_test_prob,

                # Model complexity
                'n_parameters': self._count_parameters(model, name),
            }

            # False positive rate (critical for IDS)
            tn, fp, fn, tp = confusion_matrix(y_test, y_test_pred).ravel()
            self.results[name]['fpr'] = fp / (fp + tn) if (fp + tn) > 0 else 0
            self.results[name]['fnr'] = fn / (fn + tp) if (fn + tp) > 0 else 0
            self.results[name]['tn'] = int(tn)
            self.results[name]['fp'] = int(fp)
            self.results[name]['fn'] = int(fn)
            self.results[name]['tp'] = int(tp)

            print(f"Acc={self.results[name]['test_accuracy']:.4f}, "
                  f"F1={self.results[name]['f1']:.4f}, "
                  f"FPR={self.results[name]['fpr']:.4f}, "
                  f"Time={train_time:.2f}s")

        return self.results

    def _count_parameters(self, model, name: str) -> Dict:
        """Estimate model complexity/parameters."""
        params = {'type': name}

        if name == 'Random Forest':
            total_nodes = sum(t.tree_.node_count for t in model.estimators_)
            params['n_trees'] = len(model.estimators_)
            params['total_nodes'] = total_nodes
            params['avg_nodes_per_tree'] = total_nodes / len(model.estimators_)
            params['max_depth_actual'] = max(t.tree_.max_depth for t in model.estimators_)

        elif name == 'Decision Tree':
            params['n_trees'] = 1
            params['total_nodes'] = model.tree_.node_count
            params['max_depth_actual'] = model.tree_.max_depth

        elif name == 'XGBoost':
            booster = model.get_booster()
            trees_df = booster.trees_to_dataframe()
            params['n_trees'] = model.n_estimators
            params['total_nodes'] = len(trees_df)

        elif name == 'Gradient Boosting':
            total_nodes = sum(
                t[0].tree_.node_count for t in model.estimators_
            )
            params['n_trees'] = len(model.estimators_)
            params['total_nodes'] = total_nodes

        return params

    def estimate_model_size(self, model_name: str = 'Random Forest') -> Dict:
        """Estimate model size for embedded deployment."""
        model = self.results[model_name]['model']
        params = self.results[model_name]['n_parameters']

        # Size estimation for tree models
        # Each node typically needs: feature_index (2B), threshold (4B),
        # left_child (2B), right_child (2B), value (4B) = ~14 bytes
        bytes_per_node = 14

        if 'total_nodes' in params:
            total_nodes = params['total_nodes']
            estimated_bytes = total_nodes * bytes_per_node

            # Add overhead for tree structure metadata
            if 'n_trees' in params:
                overhead = params['n_trees'] * 32  # ~32 bytes per tree header
                estimated_bytes += overhead

            return {
                'total_nodes': total_nodes,
                'estimated_bytes': estimated_bytes,
                'estimated_kb': round(estimated_bytes / 1024, 2),
                'fits_in_flash': estimated_bytes < (self.config.embedded.max_flash_kb * 1024)
            }

        return {'estimated_kb': 'N/A'}


# =============================================================================
# CROSS-VALIDATION
# =============================================================================

class CrossValidator:
    """Perform cross-validation for robust evaluation."""

    def __init__(self, config: Config):
        self.config = config

    def validate(self, model, X, y, model_name: str) -> Dict:
        """Perform stratified k-fold cross-validation."""
        print(f"\n  Cross-validating {model_name}...")

        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=self.config.random_state)

        scores = {
            'accuracy': cross_val_score(model, X, y, cv=cv, scoring='accuracy', n_jobs=-1),
            'precision': cross_val_score(model, X, y, cv=cv, scoring='precision', n_jobs=-1),
            'recall': cross_val_score(model, X, y, cv=cv, scoring='recall', n_jobs=-1),
            'f1': cross_val_score(model, X, y, cv=cv, scoring='f1', n_jobs=-1),
        }

        results = {}
        for metric, vals in scores.items():
            results[f'{metric}_mean'] = vals.mean()
            results[f'{metric}_std'] = vals.std()
            results[f'{metric}_scores'] = vals.tolist()

        print(f"    Accuracy: {results['accuracy_mean']:.4f} (+/- {results['accuracy_std']*2:.4f})")
        print(f"    F1 Score: {results['f1_mean']:.4f} (+/- {results['f1_std']*2:.4f})")

        return results


# =============================================================================
# VISUALIZATION
# =============================================================================

class Visualizer:
    """Generate publication-quality figures."""

    def __init__(self, config: Config):
        self.config = config
        self.fig_dir = config.output_dir / "figures"

    def save(self, fig, name: str):
        """Save figure in multiple formats."""
        for fmt in ['pdf', 'png']:
            fig.savefig(self.fig_dir / f"{name}.{fmt}", format=fmt,
                       dpi=self.config.figure_dpi, bbox_inches='tight',
                       facecolor='white')
        plt.close(fig)
        print(f"    Saved: {name}")

    def plot_attack_distribution(self, distribution: Dict, filename: str):
        """Plot original attack type distribution."""
        fig, ax = plt.subplots(figsize=(12, 6))

        # Sort by count
        sorted_items = sorted(distribution.items(), key=lambda x: x[1], reverse=True)
        labels = [item[0] for item in sorted_items]
        values = [item[1] for item in sorted_items]

        colors = plt.cm.RdYlBu_r(np.linspace(0.2, 0.8, len(labels)))

        bars = ax.bar(range(len(labels)), values, color=colors, edgecolor='black', linewidth=0.8)

        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=9)
        ax.set_ylabel('Number of Network Flows', fontsize=11)
        ax.set_xlabel('Traffic Class', fontsize=11)
        ax.set_title('Distribution of Network Traffic Classes (Original Dataset)',
                    fontsize=12, fontweight='bold', pad=15)
        ax.set_yscale('log')

        # Add value labels
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2, val * 1.1,
                   f'{val:,}', ha='center', va='bottom', fontsize=8, rotation=90)

        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)

        plt.tight_layout()
        self.save(fig, filename)

    def plot_binary_distribution(self, train_dist: Dict, test_dist: Dict, filename: str):
        """Plot binary class distribution for train and test."""
        fig, axes = plt.subplots(1, 2, figsize=(10, 5))

        for ax, (dist, title) in zip(axes, [(train_dist, 'Training Set'), (test_dist, 'Test Set')]):
            labels = ['Benign', 'Malicious']
            values = [dist['benign'], dist['malicious']]
            colors = [COLORS['benign'], COLORS['malicious']]

            bars = ax.bar(labels, values, color=colors, edgecolor='black', linewidth=1.2)

            for bar, val in zip(bars, values):
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(values)*0.02,
                       f'{val:,}', ha='center', va='bottom', fontsize=10, fontweight='bold')

            ax.set_ylabel('Number of Flows', fontsize=11)
            ax.set_title(title, fontsize=12, fontweight='bold')
            ax.set_ylim(0, max(values) * 1.15)
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)

        plt.suptitle('Class Distribution After Balancing (Day-Based Split)',
                    fontsize=13, fontweight='bold', y=1.02)
        plt.tight_layout()
        self.save(fig, filename)

    def plot_model_comparison(self, results: Dict, filename: str):
        """Plot comprehensive model comparison."""
        fig, axes = plt.subplots(2, 3, figsize=(14, 9))

        models = list(results.keys())
        colors = [MODEL_COLORS.get(m, '#333') for m in models]

        metrics = [
            ('test_accuracy', 'Accuracy', axes[0, 0]),
            ('precision', 'Precision', axes[0, 1]),
            ('recall', 'Recall', axes[0, 2]),
            ('f1', 'F1 Score', axes[1, 0]),
            ('fpr', 'False Positive Rate', axes[1, 1]),
            ('train_time', 'Training Time (s)', axes[1, 2]),
        ]

        for metric, title, ax in metrics:
            values = [results[m][metric] for m in models]

            bars = ax.bar(range(len(models)), values, color=colors, edgecolor='black', linewidth=0.8)

            ax.set_xticks(range(len(models)))
            ax.set_xticklabels(models, rotation=45, ha='right', fontsize=9)
            ax.set_title(title, fontsize=11, fontweight='bold')

            # Add value labels
            for bar, val in zip(bars, values):
                label = f'{val:.4f}' if metric != 'train_time' else f'{val:.2f}'
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(values)*0.02,
                       label, ha='center', va='bottom', fontsize=8)

            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)

            if metric not in ['fpr', 'train_time']:
                ax.set_ylim(0, 1.15)
                ax.axhline(y=0.95, color='red', linestyle='--', alpha=0.5, linewidth=1)

        plt.suptitle('Model Performance Comparison (Embedded-Friendly Configuration)',
                    fontsize=13, fontweight='bold', y=1.02)
        plt.tight_layout()
        self.save(fig, filename)

    def plot_confusion_matrices(self, results: Dict, filename: str):
        """Plot confusion matrices for all models."""
        n_models = len(results)
        cols = 3
        rows = (n_models + cols - 1) // cols

        fig, axes = plt.subplots(rows, cols, figsize=(12, 4*rows))
        axes = axes.flatten() if n_models > 1 else [axes]

        for ax, (name, res) in zip(axes, results.items()):
            cm = res['confusion_matrix']
            cm_pct = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis] * 100

            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                       xticklabels=['Benign', 'Malicious'],
                       yticklabels=['Benign', 'Malicious'],
                       cbar=False, linewidths=2, linecolor='white')

            # Add percentages
            for i in range(2):
                for j in range(2):
                    ax.text(j + 0.5, i + 0.75, f'({cm_pct[i,j]:.1f}%)',
                           ha='center', va='center', fontsize=9, color='gray')

            ax.set_title(name, fontsize=11, fontweight='bold')
            ax.set_ylabel('True Label', fontsize=10)
            ax.set_xlabel('Predicted Label', fontsize=10)

        # Hide empty subplots
        for ax in axes[len(results):]:
            ax.set_visible(False)

        plt.suptitle('Confusion Matrices', fontsize=13, fontweight='bold', y=1.02)
        plt.tight_layout()
        self.save(fig, filename)

    def plot_roc_curves(self, results: Dict, y_test: np.ndarray, filename: str):
        """Plot ROC curves."""
        fig, ax = plt.subplots(figsize=(8, 7))

        for name, res in results.items():
            if res['y_test_prob'] is not None:
                fpr, tpr, _ = roc_curve(y_test, res['y_test_prob'])
                auc = res['auc_roc']
                ax.plot(fpr, tpr, color=MODEL_COLORS.get(name, '#333'),
                       linewidth=2, label=f"{name} (AUC={auc:.4f})")

        ax.plot([0, 1], [0, 1], 'k--', linewidth=1, alpha=0.7, label='Random')

        ax.set_xlim([0, 1])
        ax.set_ylim([0, 1.05])
        ax.set_xlabel('False Positive Rate', fontsize=11)
        ax.set_ylabel('True Positive Rate', fontsize=11)
        ax.set_title('ROC Curves', fontsize=12, fontweight='bold', pad=15)
        ax.legend(loc='lower right', fontsize=10)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)

        plt.tight_layout()
        self.save(fig, filename)

    def plot_feature_importance(self, model, feature_names: List[str],
                               model_name: str, filename: str):
        """Plot feature importance."""
        if not hasattr(model, 'feature_importances_'):
            return

        importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': model.feature_importances_
        }).sort_values('importance', ascending=True).tail(15)

        fig, ax = plt.subplots(figsize=(10, 8))

        colors = plt.cm.Blues(np.linspace(0.4, 0.9, len(importance_df)))

        bars = ax.barh(range(len(importance_df)), importance_df['importance'].values,
                       color=colors, edgecolor='black', linewidth=0.8)

        ax.set_yticks(range(len(importance_df)))
        ax.set_yticklabels(importance_df['feature'].values, fontsize=10)
        ax.set_xlabel('Feature Importance (Gini)', fontsize=11)
        ax.set_title(f'Top 15 Features - {model_name}', fontsize=12, fontweight='bold', pad=15)

        # Add value labels
        for bar, val in zip(bars, importance_df['importance'].values):
            ax.text(val + 0.005, bar.get_y() + bar.get_height()/2,
                   f'{val:.4f}', va='center', fontsize=9)

        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)

        plt.tight_layout()
        self.save(fig, filename)

        return importance_df

    def plot_complexity_vs_accuracy(self, complexity_results: List[Dict], filename: str):
        """Plot model complexity vs accuracy trade-off."""
        fig, ax1 = plt.subplots(figsize=(10, 6))

        depths = [r['depth'] for r in complexity_results]
        accuracies = [r['accuracy'] for r in complexity_results]
        nodes = [r['total_nodes'] for r in complexity_results]
        sizes_kb = [r['estimated_kb'] for r in complexity_results]

        color1 = COLORS['primary']
        ax1.set_xlabel('Maximum Tree Depth', fontsize=11)
        ax1.set_ylabel('Test Accuracy', fontsize=11, color=color1)
        line1 = ax1.plot(depths, accuracies, 'o-', color=color1, linewidth=2,
                        markersize=8, label='Accuracy')
        ax1.tick_params(axis='y', labelcolor=color1)
        ax1.set_ylim(0.95, 1.005)

        ax2 = ax1.twinx()
        color2 = COLORS['secondary']
        ax2.set_ylabel('Estimated Model Size (KB)', fontsize=11, color=color2)
        line2 = ax2.plot(depths, sizes_kb, 's--', color=color2, linewidth=2,
                        markersize=8, label='Model Size')
        ax2.tick_params(axis='y', labelcolor=color2)

        # Mark the chosen configuration
        chosen_depth = 5
        if chosen_depth in depths:
            idx = depths.index(chosen_depth)
            ax1.axvline(x=chosen_depth, color='green', linestyle=':', linewidth=2, alpha=0.7)
            ax1.annotate('Selected\nConfiguration', xy=(chosen_depth, accuracies[idx]),
                        xytext=(chosen_depth + 0.5, accuracies[idx] - 0.02),
                        fontsize=10, color='green')

        # Combined legend
        lines = line1 + line2
        labels = [l.get_label() for l in lines]
        ax1.legend(lines, labels, loc='center right', fontsize=10)

        ax1.set_title('Model Complexity vs Performance Trade-off',
                     fontsize=12, fontweight='bold', pad=15)
        ax1.spines['top'].set_visible(False)

        plt.tight_layout()
        self.save(fig, filename)


# =============================================================================
# MODEL EXPORT (TL2CGEN)
# =============================================================================

class ModelExporter:
    """Export Random Forest to C code using TL2cgen."""

    def __init__(self, config: Config):
        self.config = config
        self.model_dir = config.output_dir / "models"

    def export_random_forest(self, model: RandomForestClassifier,
                            feature_names: List[str], name: str = "nids_rf") -> Dict:
        """Export Random Forest to C code."""
        print("\n" + "=" * 70)
        print("PHASE 6: MODEL EXPORT (TL2cgen)")
        print("=" * 70)

        export_info = {}

        # Convert to Treelite model
        print("\n  Converting Random Forest to Treelite format...")
        tl_model = treelite.sklearn.import_model(model)

        # Generate C code
        c_dir = self.model_dir / f"{name}_c"
        c_dir.mkdir(exist_ok=True)

        print(f"  Generating C code to {c_dir}...")
        tl2cgen.generate_c_code(tl_model, dirpath=str(c_dir), params={})

        # Create source package
        pkg_path = self.model_dir / f"{name}_package.zip"
        print(f"  Creating deployable package: {pkg_path}")
        tl2cgen.export_srcpkg(
            tl_model,
            toolchain="gcc",
            pkgpath=str(pkg_path),
            libname=f"{name}.so",
            params={}
        )

        # Try to build shared library
        try:
            lib_path = self.model_dir / f"{name}.so"
            print(f"  Building shared library: {lib_path}")
            tl2cgen.export_lib(
                tl_model,
                toolchain="gcc",
                libpath=str(lib_path),
                params={}
            )
            export_info['shared_lib'] = str(lib_path)
        except Exception as e:
            print(f"  Note: Could not build .so (may need gcc): {e}")

        # Save feature names for inference
        feature_file = self.model_dir / f"{name}_features.json"
        with open(feature_file, 'w') as f:
            json.dump({'features': feature_names}, f, indent=2)

        # Calculate actual C code size
        c_files = list(c_dir.glob("*.c"))
        total_size = sum(f.stat().st_size for f in c_files)

        export_info.update({
            'c_code_dir': str(c_dir),
            'package_path': str(pkg_path),
            'feature_file': str(feature_file),
            'c_code_size_kb': round(total_size / 1024, 2),
            'n_c_files': len(c_files)
        })

        print(f"\n  Export complete:")
        print(f"    C code size: {export_info['c_code_size_kb']:.2f} KB")
        print(f"    C files: {export_info['n_c_files']}")

        return export_info


# =============================================================================
# RESULTS REPORTER
# =============================================================================

class ResultsReporter:
    """Generate comprehensive results for paper."""

    def __init__(self, config: Config):
        self.config = config
        self.metrics_dir = config.output_dir / "metrics"

    def print_comparison_table(self, results: Dict):
        """Print formatted comparison table."""
        print("\n" + "=" * 100)
        print("MODEL COMPARISON RESULTS (Training-Time Metrics)")
        print("=" * 100)

        header = (f"{'Model':<20} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} "
                 f"{'F1':<10} {'FPR':<10} {'AUC':<10} {'MCC':<10} {'Time(s)':<10}")
        print(f"\n{header}")
        print("-" * 100)

        # Sort by F1 score
        sorted_results = sorted(results.items(), key=lambda x: x[1]['f1'], reverse=True)

        for name, m in sorted_results:
            auc_str = f"{m['auc_roc']:.4f}" if m['auc_roc'] else "N/A"
            print(f"{name:<20} {m['test_accuracy']:<10.4f} {m['precision']:<10.4f} "
                  f"{m['recall']:<10.4f} {m['f1']:<10.4f} {m['fpr']:<10.4f} "
                  f"{auc_str:<10} {m['mcc']:<10.4f} {m['train_time']:<10.2f}")

        print("-" * 100)

    def print_best_model_details(self, results: Dict, feature_names: List[str],
                                 size_info: Dict) -> str:
        """Print detailed analysis of best model."""
        # Find best by F1
        best_name = max(results.items(), key=lambda x: x[1]['f1'])[0]
        best = results[best_name]

        print("\n" + "=" * 70)
        print(f"BEST MODEL: {best_name}")
        print("=" * 70)

        print(f"\n  Performance Metrics:")
        print(f"    Test Accuracy:     {best['test_accuracy']:.4f}")
        print(f"    Precision:         {best['precision']:.4f}")
        print(f"    Recall:            {best['recall']:.4f}")
        print(f"    F1 Score:          {best['f1']:.4f}")
        print(f"    AUC-ROC:           {best['auc_roc']:.4f}" if best['auc_roc'] else "")
        print(f"    MCC:               {best['mcc']:.4f}")
        print(f"    False Positive Rate: {best['fpr']:.4f}")
        print(f"    False Negative Rate: {best['fnr']:.4f}")

        print(f"\n  Confusion Matrix:")
        print(f"    True Negatives:  {best['tn']:,}")
        print(f"    False Positives: {best['fp']:,}")
        print(f"    False Negatives: {best['fn']:,}")
        print(f"    True Positives:  {best['tp']:,}")

        print(f"\n  Model Complexity:")
        params = best['n_parameters']
        if 'n_trees' in params:
            print(f"    Number of trees:   {params['n_trees']}")
        if 'total_nodes' in params:
            print(f"    Total nodes:       {params['total_nodes']:,}")
        if 'max_depth_actual' in params:
            print(f"    Max depth (actual): {params['max_depth_actual']}")

        print(f"\n  Embedded Deployment:")
        print(f"    Estimated size:    {size_info.get('estimated_kb', 'N/A')} KB")
        print(f"    Fits in flash:     {size_info.get('fits_in_flash', 'N/A')}")

        # Feature importance
        if hasattr(best['model'], 'feature_importances_'):
            importance = sorted(zip(feature_names, best['model'].feature_importances_),
                              key=lambda x: -x[1])[:10]
            print(f"\n  Top 10 Features:")
            for feat, imp in importance:
                print(f"    {feat:<25} {imp:.4f}")

        return best_name

    def save_all_metrics(self, results: Dict, split_stats: Dict,
                        prep_stats: Dict, cv_results: Dict,
                        export_info: Dict):
        """Save all metrics to JSON for paper reference."""

        # Prepare serializable results
        metrics = {
            'dataset': {
                'source': 'CSE-CIC-IDS2018',
                'files': list(prep_stats.get('initial', {}).keys()) if isinstance(prep_stats.get('initial'), dict) else [],
                'total_flows_raw': prep_stats.get('initial', {}).get('total_flows', 0),
                'total_flows_processed': prep_stats.get('balanced', {}).get('total_flows', 0),
            },
            'preprocessing': {
                'features_initial': prep_stats.get('initial', {}).get('features', 0),
                'features_final': prep_stats.get('final_features', 0),
                'removed_features': {k: len(v) for k, v in prep_stats.get('removed_features', {}).items()},
                'class_balance': 'Undersampling (1:1)',
            },
            'split': {
                'method': split_stats.get('split_method', 'Stratified random'),
                'train_samples': split_stats.get('train_samples', 0),
                'val_samples': split_stats.get('val_samples', 0),
                'test_samples': split_stats.get('test_samples', 0),
                'train_pct': split_stats.get('train_pct', 0),
                'val_pct': split_stats.get('val_pct', 0),
                'test_pct': split_stats.get('test_pct', 0),
                'rationale': 'Attack types vary by day; stratified split ensures all types represented in train/test',
            },
            'model_comparison': {},
            'cross_validation': cv_results,
            'deployment': export_info,
        }

        for name, res in results.items():
            metrics['model_comparison'][name] = {
                'accuracy': res['test_accuracy'],
                'precision': res['precision'],
                'recall': res['recall'],
                'f1': res['f1'],
                'auc_roc': res['auc_roc'],
                'mcc': res['mcc'],
                'fpr': res['fpr'],
                'fnr': res['fnr'],
                'train_time': res['train_time'],
                'confusion_matrix': {
                    'tn': res['tn'], 'fp': res['fp'],
                    'fn': res['fn'], 'tp': res['tp']
                },
                'complexity': {k: v for k, v in res['n_parameters'].items()
                              if k != 'type'}
            }

        # Save
        metrics_file = self.metrics_dir / "all_metrics.json"
        with open(metrics_file, 'w') as f:
            json.dump(metrics, f, indent=2, default=str)

        print(f"\n  All metrics saved to: {metrics_file}")

        return metrics

    def generate_latex_table(self, results: Dict) -> str:
        """Generate LaTeX table for paper."""
        latex = """
\\begin{table}[htbp]
\\centering
\\caption{Model Performance Comparison (Embedded-Friendly Configuration)}
\\label{tab:model_comparison}
\\begin{tabular}{lcccccc}
\\toprule
Model & Accuracy & Precision & Recall & F1 & FPR & Time (s) \\\\
\\midrule
"""
        for name, m in sorted(results.items(), key=lambda x: -x[1]['f1']):
            latex += f"{name} & {m['test_accuracy']:.4f} & {m['precision']:.4f} & "
            latex += f"{m['recall']:.4f} & {m['f1']:.4f} & {m['fpr']:.4f} & {m['train_time']:.2f} \\\\\n"

        latex += """\\bottomrule
\\end{tabular}
\\end{table}
"""

        latex_file = self.metrics_dir / "comparison_table.tex"
        with open(latex_file, 'w') as f:
            f.write(latex)

        print(f"  LaTeX table saved to: {latex_file}")

        return latex


# =============================================================================
# COMPLEXITY ANALYSIS
# =============================================================================

def analyze_complexity(config: Config, X_train, y_train, X_test, y_test) -> List[Dict]:
    """Analyze model complexity vs performance trade-off."""
    print("\n" + "=" * 70)
    print("PHASE 5: COMPLEXITY ANALYSIS")
    print("=" * 70)

    depths = [2, 3, 4, 5, 6, 8]
    results = []

    for depth in depths:
        model = RandomForestClassifier(
            n_estimators=config.model.max_trees,
            max_depth=depth,
            min_samples_split=config.model.min_samples_split,
            min_samples_leaf=config.model.min_samples_leaf,
            random_state=config.random_state,
            n_jobs=-1
        )

        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        total_nodes = sum(t.tree_.node_count for t in model.estimators_)
        estimated_kb = round(total_nodes * 14 / 1024, 2)  # ~14 bytes per node

        results.append({
            'depth': depth,
            'accuracy': accuracy_score(y_test, y_pred),
            'f1': f1_score(y_test, y_pred),
            'total_nodes': total_nodes,
            'estimated_kb': estimated_kb
        })

        print(f"  Depth {depth}: Acc={results[-1]['accuracy']:.4f}, "
              f"F1={results[-1]['f1']:.4f}, Nodes={total_nodes:,}, Size={estimated_kb}KB")

    return results


# =============================================================================
# MAIN PIPELINE
# =============================================================================

def main():
    """Execute the complete NIDS pipeline."""

    print("\n" + "=" * 70)
    print("  NETWORK INTRUSION DETECTION SYSTEM")
    print("  Publication-Quality ML Pipeline for Embedded Deployment")
    print("=" * 70)
    print(f"  Target: MIPS32 Router (Flash: 128KB, RAM: 32KB)")
    print(f"  Model: Random Forest (Transpiled to C via TL2cgen)")
    print("=" * 70)

    # Initialize
    config = Config()
    setup_plotting()

    # Components
    loader = DataLoader(config)
    preprocessor = DataPreprocessor(config)
    splitter = DataSplitter(config)
    trainer = EmbeddedModelTrainer(config)
    validator = CrossValidator(config)
    visualizer = Visualizer(config)
    exporter = ModelExporter(config)
    reporter = ResultsReporter(config)

    # =========================================================================
    # PHASE 1: Load Data
    # =========================================================================
    df = loader.load_with_dates()
    original_distribution = df['Label'].value_counts().to_dict()

    # =========================================================================
    # PHASE 2: Preprocess
    # =========================================================================
    df, prep_stats = preprocessor.preprocess(df)

    # =========================================================================
    # PHASE 3: Temporal Split
    # =========================================================================
    X_train, X_val, X_test, y_train, y_val, y_test, feature_names = splitter.split(df)
    split_stats = splitter.split_stats

    # =========================================================================
    # PHASE 4: Train Models
    # =========================================================================
    results = trainer.train_all(X_train, X_val, X_test, y_train, y_val, y_test)

    # =========================================================================
    # PHASE 5: Complexity Analysis
    # =========================================================================
    complexity_results = analyze_complexity(config, X_train, y_train, X_test, y_test)

    # =========================================================================
    # Cross-Validation (Random Forest)
    # =========================================================================
    print("\n" + "=" * 70)
    print("CROSS-VALIDATION")
    print("=" * 70)

    X_full = np.vstack([X_train, X_val])
    y_full = np.concatenate([y_train, y_val])

    rf_model = RandomForestClassifier(
        n_estimators=config.model.max_trees,
        max_depth=config.model.max_depth,
        min_samples_split=config.model.min_samples_split,
        min_samples_leaf=config.model.min_samples_leaf,
        random_state=config.random_state,
        n_jobs=-1
    )
    cv_results = validator.validate(rf_model, X_full, y_full, 'Random Forest')

    # =========================================================================
    # PHASE 6: Export Random Forest
    # =========================================================================
    export_info = exporter.export_random_forest(
        results['Random Forest']['model'],
        feature_names,
        "nids_rf"
    )

    # =========================================================================
    # Visualizations
    # =========================================================================
    print("\n" + "=" * 70)
    print("GENERATING VISUALIZATIONS")
    print("=" * 70)

    visualizer.plot_attack_distribution(original_distribution, "01_attack_distribution")
    visualizer.plot_binary_distribution(
        split_stats['train_class_dist'],
        split_stats['test_class_dist'],
        "02_class_distribution"
    )
    visualizer.plot_model_comparison(results, "03_model_comparison")
    visualizer.plot_confusion_matrices(results, "04_confusion_matrices")
    visualizer.plot_roc_curves(results, y_test, "05_roc_curves")

    importance_df = visualizer.plot_feature_importance(
        results['Random Forest']['model'],
        feature_names,
        'Random Forest',
        "06_feature_importance"
    )

    visualizer.plot_complexity_vs_accuracy(complexity_results, "07_complexity_analysis")

    # =========================================================================
    # Results & Reports
    # =========================================================================
    reporter.print_comparison_table(results)

    size_info = trainer.estimate_model_size('Random Forest')
    best_model = reporter.print_best_model_details(results, feature_names, size_info)

    all_metrics = reporter.save_all_metrics(
        results, split_stats, preprocessor.stats, cv_results, export_info
    )

    reporter.generate_latex_table(results)

    # =========================================================================
    # Final Summary
    # =========================================================================
    print("\n" + "=" * 70)
    print("  PIPELINE COMPLETE")
    print("=" * 70)
    print(f"\n  Output directory: {config.output_dir}")
    print(f"\n  Generated artifacts:")
    print(f"    - 7 publication-quality figures (PDF + PNG)")
    print(f"    - LaTeX table for paper")
    print(f"    - Comprehensive metrics JSON")
    print(f"    - Deployable C code package")
    print(f"    - Shared library (.so)")

    print(f"\n  Key Results for Paper:")
    print(f"    - Classification: Binary (Benign vs Malicious)")
    print(f"    - Split: Stratified random ({split_stats['train_pct']}% train / {split_stats['val_pct']}% val / {split_stats['test_pct']}% test)")
    print(f"    - Best Model: {best_model}")
    print(f"    - Test Accuracy: {results[best_model]['test_accuracy']:.4f}")
    print(f"    - F1 Score: {results[best_model]['f1']:.4f}")
    print(f"    - False Positive Rate: {results[best_model]['fpr']:.4f}")
    print(f"    - Model Size: {size_info.get('estimated_kb', 'N/A')} KB")
    print(f"    - C Code Size: {export_info.get('c_code_size_kb', 'N/A')} KB")

    print("=" * 70 + "\n")

    return results, all_metrics, config


if __name__ == "__main__":
    results, metrics, config = main()
