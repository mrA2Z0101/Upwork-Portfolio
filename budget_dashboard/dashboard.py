# dashboard.py
# Streamlit UI: add transactions, show charts, budgets, and tables.

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Tuple

import pandas as pd
import streamlit as st
import plotly.express as px

from data_handler import (
    Transaction,
    add_transaction,
    budget_check,
    load_transactions,
    summarize_by_category,
    summarize_by_month,
    totals_income_vs_expense,
)

APP_DIR = Path(__file__).parent
DATA_DIR = APP_DIR / "data"
CSV_PATH = DATA_DIR / "transactions.csv"
BUDGETS_PATH = APP_DIR / "budgets.json"


def _load_budgets(path: Path) -> Dict[str, float]:
    if not path.exists():
        # Default budgets if file missing
        return {
            "Housing": 1200,
            "Food": 400,
            "Transportation": 250,
            "Utilities": 200,
            "Entertainment": 120,
            "Shopping": 150,
            "Health": 100,
        }
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Coerce to float
    budgets: Dict[str, float] = {}
    for k, v in data.items():
        try:
            budgets[str(k)] = float(v)
        except Exception:
            continue
    return budgets


def _save_budgets(path: Path, budgets: Dict[str, float]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(budgets, f, indent=2, sort_keys=True)


def _kpi_cards(totals: Dict[str, float]) -> None:
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Income", f"${totals['income']:,.2f}")
    c2.metric("Total Expenses", f"${totals['expense']:,.2f}")
    c3.metric("Net", f"${totals['net']:,.2f}")


def _date_range_defaults(df: pd.DataFrame) -> Tuple[pd.Timestamp, pd.Timestamp]:
    # Safe defaults even if df is empty
    if df.empty:
        today = pd.Timestamp.today().normalize()
        return today - pd.Timedelta(days=30), today

    dmin = pd.to_datetime(df["Date"]).min()
    dmax = pd.to_datetime(df["Date"]).max()
    return dmin, dmax


def run_app() -> None:
    st.set_page_config(page_title="Budget & Expense Dashboard", layout="wide")
    st.title("Budget & Expense Tracking Dashboard")
    st.caption("Log income/expenses, track budgets, and visualize spending trends. Data stored locally in CSV.")

    # Load data + budgets
    budgets = _load_budgets(BUDGETS_PATH)
    df = load_transactions(CSV_PATH)

    # --- Sidebar: Add Transaction ---
    st.sidebar.header("Add Transaction")

    with st.sidebar.form("add_tx_form", clear_on_submit=True):
        date = st.date_input("Date", value=pd.Timestamp.today().date())
        category = st.text_input("Category", value="Food")
        note = st.text_input("Note", value="")
        amount = st.number_input("Amount", min_value=0.01, value=10.00, step=1.00)
        tx_type = st.selectbox("Type", ["Expense", "Income"], index=0)
        submitted = st.form_submit_button("Add")

        if submitted:
            tx = Transaction(
                date=str(date),
                category=category,
                note=note,
                amount=float(amount),
                tx_type=tx_type,
            )
            try:
                add_transaction(CSV_PATH, tx)
                st.sidebar.success("Transaction added.")
                st.rerun()
            except Exception as e:
                st.sidebar.error(str(e))

    # --- Sidebar: Filters ---
    st.sidebar.header("Filters")

    dmin, dmax = _date_range_defaults(df)
    start_date, end_date = st.sidebar.date_input(
        "Date range",
        value=(dmin.date(), dmax.date()),
    )

    # Filter data
    f = df.copy()
    if not f.empty:
        f_dt = pd.to_datetime(f["Date"])
        f = f[(f_dt.dt.date >= start_date) & (f_dt.dt.date <= end_date)].copy()

    categories = sorted(f["Category"].unique().tolist()) if not f.empty else []
    category_choice = st.sidebar.selectbox("Category", ["(all)"] + categories, index=0)
    if category_choice != "(all)" and not f.empty:
        f = f[f["Category"] == category_choice].copy()

    # --- Main: KPIs ---
    totals = totals_income_vs_expense(f)
    _kpi_cards(totals)

    st.divider()

    # --- Main: Charts Row ---
    left, right = st.columns(2)

    with left:
        st.subheader("Spending by Category (Expenses)")
        by_cat = summarize_by_category(f)
        if by_cat.empty:
            st.info("No expense data in the selected range.")
        else:
            fig = px.bar(by_cat, x="Category", y="Spent", title="Expenses by Category")
            st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Monthly Trends")
        by_month = summarize_by_month(f)
        if by_month.empty:
            st.info("No monthly trend data in the selected range.")
        else:
            # Line chart: monthly expense trend (focus on expenses)
            fig = px.line(by_month, x="Month", y="Expense", title="Monthly Expense Trend")
            st.plotly_chart(fig, use_container_width=True)

    st.divider()

    # --- Budget Check ---
    st.subheader("Budget Check (This Month)")

    if f.empty:
        st.info("No data available for budget check in the selected range.")
    else:
        # Use latest month in the filtered data
        f_temp = f.copy()
        f_temp["Month"] = pd.to_datetime(f_temp["Date"]).dt.to_period("M").dt.to_timestamp()
        latest_month = f_temp["Month"].max()

        budget_table = budget_check(f, budgets, month=latest_month)
        if budget_table.empty:
            st.info("No expense categories to compare against budgets.")
        else:
            st.dataframe(budget_table, use_container_width=True)

    # --- Budget Editor ---
    with st.expander("Edit Budget Limits"):
        st.caption("Budgets are monthly category limits. Saved to budgets.json.")
        edited = {}
        cols = st.columns(2)
        items = list(budgets.items())

        for i, (cat, lim) in enumerate(items):
            col = cols[i % 2]
            edited[cat] = col.number_input(f"{cat} budget", min_value=0.0, value=float(lim), step=10.0)

        new_cat = st.text_input("Add new category budget (name)", value="")
        new_lim = st.number_input("New category limit", min_value=0.0, value=0.0, step=10.0)

        c1, c2 = st.columns(2)
        if c1.button("Save Budgets"):
            # Merge edits
            out = {k: float(v) for k, v in edited.items()}
            if new_cat.strip():
                out[new_cat.strip()] = float(new_lim)
            _save_budgets(BUDGETS_PATH, out)
            st.success("Budgets saved.")
            st.rerun()

        if c2.button("Reset to Defaults"):
            default = {
                "Housing": 1200,
                "Food": 400,
                "Transportation": 250,
                "Utilities": 200,
                "Entertainment": 120,
                "Shopping": 150,
                "Health": 100,
            }
            _save_budgets(BUDGETS_PATH, default)
            st.success("Budgets reset.")
            st.rerun()

    st.divider()

    # --- Recent Transactions Table ---
    st.subheader("Recent Transactions")
    if f.empty:
        st.info("No transactions in the selected range.")
    else:
        recent = f.sort_values("Date", ascending=False).head(30).copy()
        st.dataframe(recent, use_container_width=True)

        # Download filtered view
        csv_bytes = recent.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download recent (CSV)",
            data=csv_bytes,
            file_name="recent_transactions.csv",
            mime="text/csv",
        )

    # --- Expected Graphs Note (as requested) ---
    with st.expander("What you should expect to see"):
        st.markdown(
            """
- **Bar chart:** Categories with the largest expense totals appear highest.
- **Line chart:** Monthly expense trend goes up/down depending on total spending per month.
- **Budget table:** Shows each category's budget, spent amount, remaining amount, and status.
            """.strip()
        )