# Budget & Expense Tracking Dashboard (Python)

A Python-based budget and expense tracking application that allows users to log income and expenses, store transactions locally in CSV format, visualize spending trends, and compare actual expenses against monthly budget limits using an interactive dashboard.

This project demonstrates practical skills in Python programming, data manipulation with pandas, and building data dashboards with Streamlit and Plotly.

---

## Features

- Add income and expense transactions through a graphical interface  
- Store transactions locally in a CSV file  
- Automatic data validation and cleaning  
- Spending summaries by category and by month  
- Monthly income vs expense totals  
- Budget comparison against category limits  
- Interactive charts and tables  
- Modular and maintainable code structure  

---

## Technologies Used

- Python 3.10+  
- pandas  
- Streamlit  
- Plotly  

---

## Installation

### 1. Clone the repository

git clone https://github.com/mrA2Z0101/Upwork-Portfolio/tree/main/budget_dashboard 
cd budget_dashboard  

### 2. Create a virtual environment (recommended)

Windows:

python -m venv .venv  
.venv\Scripts\activate  

macOS / Linux:

python -m venv .venv  
source .venv/bin/activate  

### 3. Install dependencies

pip install -r requirements.txt  

---

## Running the Application

streamlit run main.py  

The dashboard will open in your web browser.

---

## Data Format

Transactions are stored in a CSV file with the following header:

Date,Category,Note,Amount,Type  

- Date: YYYY-MM-DD  
- Category: Expense category name  
- Note: Short description  
- Amount: Positive number  
- Type: Income or Expense  

---

## How to Use

1. Use the sidebar to add a new transaction  
2. Select whether it is Income or Expense  
3. Choose date, category, amount, and optional note  
4. Use filters to view specific date ranges or categories  
5. Review charts and budget status  

---

## Example Visualizations

- Bar chart showing total expenses by category  
- Line chart showing monthly expense trends  
- Budget status table showing over/under budget categories  
- Recent transactions table  

---

## Project Goals

- Practice building real-world Python applications  
- Demonstrate data processing and visualization skills  
- Provide a simple personal finance tracking tool  

---

## Future Improvements

- SQLite database support  
- User authentication  
- Recurring transactions  
- Export reports to PDF  
- Dark/light theme toggle  

---

## License

MIT License

---

## Author

Aaron Zajicek  
Computer Information Systems Graduate  

Python Automation & Data Analytics  


