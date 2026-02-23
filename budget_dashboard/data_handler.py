# data_handler.py
# Handles reading/writing transactions to CSV + summarizing data.

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

import pandas as pd


REQUIRED_COLUMNS = ["Date", "Category", "Note", "Amount", "Type"]
VALID_TYPES = {"Income", "Expense"}


@dataclass
class Transaction:
    date: str          # "YYYY-MM-DD"
    category: str
    note: str
    amount: float      # positive number
    tx_type: str       # "Income" or "Expense"


def ensure_csv_exists(csv_path: Path) -> None:
    """
    Ensures the CSV file exists and has the correct headers.
    If missing, creates it with headers.
    """
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    if not csv_path.exists():
        df = pd.DataFrame(columns=REQUIRED_COLUMNS)
        df.to_csv(csv_path, index=False)


def load_transactions(csv_path: Path) -> pd.DataFrame:
    """
    Loads transactions from CSV. Ensures required columns exist.
    Returns a cleaned DataFrame with parsed dates and numeric amounts.
    """
    ensure_csv_exists(csv_path)

    # Robust CSV parsing: skips malformed lines instead of crashing
    df = pd.read_csv(
        csv_path,
        engine="python",
        on_bad_lines="skip",
    )

    # Ensure columns exist even if file is weird
    for col in REQUIRED_COLUMNS:
        if col not in df.columns:
            df[col] = pd.NA
    df = df[REQUIRED_COLUMNS].copy()

    # Clean and coerce
    df["Date"] = pd.to_datetime(df["Date"], errors="coerce").dt.date
    df["Amount"] = pd.to_numeric(df["Amount"], errors="coerce")

    # Normalize Type values
    df["Type"] = df["Type"].astype(str).str.strip().str.title()
    df.loc[~df["Type"].isin(VALID_TYPES), "Type"] = pd.NA

    # Drop invalid rows
    df = df.dropna(subset=["Date", "Category", "Amount", "Type"]).copy()

    # Strings
    df["Category"] = df["Category"].astype(str).str.strip()
    df["Note"] = df["Note"].fillna("").astype(str).str.strip()

    # Amount should be positive in storage; Type decides direction
    df["Amount"] = df["Amount"].abs()

    return df


def validate_transaction(tx: Transaction) -> Tuple[bool, str]:
    """
    Validates a transaction. Returns (ok, message).
    """
    # Date should parse
    try:
        _ = pd.to_datetime(tx.date, errors="raise")
    except Exception:
        return False, "Invalid date. Use YYYY-MM-DD."

    if not tx.category or not tx.category.strip():
        return False, "Category is required."

    if tx.amount is None:
        return False, "Amount is required."
    try:
        amt = float(tx.amount)
    except Exception:
        return False, "Amount must be a number."
    if amt <= 0:
        return False, "Amount must be greater than 0."

    t = (tx.tx_type or "").strip().title()
    if t not in VALID_TYPES:
        return False, "Type must be Income or Expense."

    return True, "OK"


def add_transaction(csv_path: Path, tx: Transaction) -> None:
    """
    Appends a validated transaction to the CSV.
    Stores Amount as positive; Type indicates Income/Expense.
    """
    ok, msg = validate_transaction(tx)
    if not ok:
        raise ValueError(msg)

    ensure_csv_exists(csv_path)

    row = {
        "Date": pd.to_datetime(tx.date).date().isoformat(),
        "Category": tx.category.strip(),
        "Note": (tx.note or "").strip(),
        "Amount": abs(float(tx.amount)),
        "Type": tx.tx_type.strip().title(),
    }

    # Append without loading whole file
    df_row = pd.DataFrame([row], columns=REQUIRED_COLUMNS)
    df_row.to_csv(csv_path, mode="a", header=False, index=False)


def summarize_by_category(df: pd.DataFrame) -> pd.DataFrame:
    """
    Returns spending totals by category (Expenses only).
    """
    exp = df[df["Type"] == "Expense"].copy()
    if exp.empty:
        return pd.DataFrame(columns=["Category", "Spent"])
    out = exp.groupby("Category", as_index=False)["Amount"].sum()
    out = out.rename(columns={"Amount": "Spent"}).sort_values("Spent", ascending=False)
    return out


def summarize_by_month(df: pd.DataFrame) -> pd.DataFrame:
    """
    Returns monthly totals for Income, Expense, and Net.
    """
    if df.empty:
        return pd.DataFrame(columns=["Month", "Income", "Expense", "Net"])

    temp = df.copy()
    temp["Month"] = pd.to_datetime(temp["Date"]).dt.to_period("M").dt.to_timestamp()

    income = (
        temp[temp["Type"] == "Income"]
        .groupby("Month", as_index=False)["Amount"]
        .sum()
        .rename(columns={"Amount": "Income"})
    )
    expense = (
        temp[temp["Type"] == "Expense"]
        .groupby("Month", as_index=False)["Amount"]
        .sum()
        .rename(columns={"Amount": "Expense"})
    )

    merged = pd.merge(income, expense, on="Month", how="outer").fillna(0.0)
    merged["Net"] = merged["Income"] - merged["Expense"]
    merged = merged.sort_values("Month")
    return merged


def totals_income_vs_expense(df: pd.DataFrame) -> Dict[str, float]:
    """
    Returns totals: income, expense, net.
    """
    income = float(df.loc[df["Type"] == "Income", "Amount"].sum()) if not df.empty else 0.0
    expense = float(df.loc[df["Type"] == "Expense", "Amount"].sum()) if not df.empty else 0.0
    net = income - expense
    return {"income": income, "expense": expense, "net": net}


def budget_check(
    df: pd.DataFrame,
    budgets: Dict[str, float],
    month: Optional[pd.Timestamp] = None,
) -> pd.DataFrame:
    """
    Compares expense spending vs budget limits per category for a given month.

    - budgets: {"Food": 400, "Housing": 1200, ...}
    - month: pd.Timestamp (month start) or None (uses latest month in data)

    Returns a table with Category, Budget, Spent, Remaining, Status.
    """
    if df.empty:
        return pd.DataFrame(columns=["Category", "Budget", "Spent", "Remaining", "Status"])

    temp = df[df["Type"] == "Expense"].copy()
    temp["Month"] = pd.to_datetime(temp["Date"]).dt.to_period("M").dt.to_timestamp()

    if month is None:
        month = temp["Month"].max()

    temp = temp[temp["Month"] == month].copy()

    spent = temp.groupby("Category", as_index=False)["Amount"].sum().rename(columns={"Amount": "Spent"})
    # Ensure all budget categories appear even if spent=0
    budget_df = pd.DataFrame(
        [{"Category": k, "Budget": float(v)} for k, v in budgets.items()]
    )

    out = pd.merge(budget_df, spent, on="Category", how="left").fillna({"Spent": 0.0})
    out["Remaining"] = out["Budget"] - out["Spent"]

    def status(row) -> str:
        if row["Budget"] <= 0:
            return "No Budget"
        if row["Spent"] > row["Budget"]:
            return "Over Budget"
        if row["Spent"] >= 0.9 * row["Budget"]:
            return "Near Limit"
        return "OK"

    out["Status"] = out.apply(status, axis=1)
    out = out.sort_values(["Status", "Spent"], ascending=[True, False])
    return out
