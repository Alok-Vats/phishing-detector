"""Dataset loading and feature matrix preparation for URL model training."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from app.ml.feature_extractor import extract_features


REQUIRED_COLUMNS = {"url", "label"}


def load_dataset(dataset_path: str | Path) -> pd.DataFrame:
    """Load and validate the phishing URL dataset."""
    dataset_file = Path(dataset_path)
    if not dataset_file.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_file}")

    dataframe = pd.read_csv(dataset_file)
    missing_columns = REQUIRED_COLUMNS - set(dataframe.columns)
    if missing_columns:
        missing = ", ".join(sorted(missing_columns))
        raise ValueError(f"Dataset is missing required columns: {missing}")

    cleaned = dataframe.loc[:, ["url", "label"]].dropna().copy()
    cleaned = cleaned.assign(
        url=cleaned["url"].astype(str).str.strip(),
        label=cleaned["label"].astype(str).str.strip().str.lower()
    )
    cleaned = cleaned[cleaned["url"] != ""]
    cleaned = cleaned[cleaned["label"].isin({"phishing", "legitimate"})]

    if cleaned.empty:
        raise ValueError("Dataset does not contain any valid rows after cleaning.")

    return cleaned.reset_index(drop=True)


def build_feature_frame(dataframe: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Convert dataset URLs into a numeric feature matrix and label vector."""
    feature_rows = [extract_features(url) for url in dataframe["url"]]
    feature_frame = pd.DataFrame(feature_rows).fillna(0)
    labels = dataframe["label"].copy()
    return feature_frame, labels
