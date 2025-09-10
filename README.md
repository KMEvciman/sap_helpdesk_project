# SAP Helpdesk & Reporting System

This project is a **Flask-based Helpdesk and Reporting System with SAP integration**.  
Users can create, update, and delete tickets, while admins have full access to manage tickets and inventory.  
Additionally, the system provides SAP reports, a global search module, and graphical dashboards for management support.

---

## 🚀 Features

- **User Management**
  - User registration and login/logout
  - Admin and normal user roles
- **Helpdesk Module**
  - Create, update, delete tickets
  - Track ticket status
- **SAP Reporting**
  - View reports from SAP data
  - Graphical and table-based reports
- **Search Function**
  - Global search across tickets, SAP reports, and inventory
- **Inventory Management**
  - View and manage company devices (admin only)
- **Logging & CLI Commands**
  - `flask create-admin` to create an admin user
  - `flask init-db` to initialize the database
- **Dashboard**
  - Matplotlib-based graphs
  - Summary reports

---

## 📂 Project Structure

```bash
sap_helpdesk_project/
│── app.py              # Main Flask application
│── database.db         # SQLite database
│── requirements.txt    # Python dependencies
│── .env.example        # Environment variables template
│── /templates          # HTML templates (base, login, dashboard, etc.)
│── /static             # CSS, JS, and static files
```

---

## ⚙️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/username/sap_helpdesk_project.git
cd sap_helpdesk_project
```

### 2. Setup Virtual Environment
```bash
python -m venv venv
source venv/bin/activate   # Linux / Mac
venv\Scripts\activate    # Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Setup Environment Variables
Copy `.env.example` as `.env` and configure:
```env
SECRET_KEY=your-secret-key
FLASK_ENV=development
```

### 5. Initialize Database
```bash
flask init-db
flask create-admin
```

### 6. Run the Application
```bash
flask run
```

---

## 🛠 Technologies Used

- **Backend**: Python (Flask, SQLAlchemy)
- **Database**: SQLite
- **Frontend**: HTML, CSS, Bootstrap (Jinja2 templates)
- **Others**: Matplotlib, Pandas, Flask-Login, Python-dotenv

---

## 👨‍💻 CLI Commands

```bash
flask init-db        # Create database tables
flask create-admin   # Create an admin user
```

---

## 📌 Notes

- The inventory module is only visible to admin users.  
- The global search module covers helpdesk tickets, SAP reports, and optionally inventory records.  
- The system has been fully tested and works stably.  
