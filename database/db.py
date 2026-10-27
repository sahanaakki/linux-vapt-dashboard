import sqlite3
from datetime import datetime

DATABASE = "database/vapt.db"


# ---------------------------------
# Database Connection
# ---------------------------------

def get_connection():
    return sqlite3.connect(DATABASE)


# ---------------------------------
# Create Database and Tables
# ---------------------------------

def create_database():

    connection = get_connection()
    cursor = connection.cursor()

    # Create scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            date TEXT NOT NULL,
            time TEXT NOT NULL
        )
    """)

    # Create findings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT,
            evidence TEXT,
            recommendation TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        )
    """)

    connection.commit()
    connection.close()

    print("Database created successfully!")


# ---------------------------------
# Save Scan
# ---------------------------------

def save_scan(target, scan_type):

    connection = get_connection()
    cursor = connection.cursor()

    now = datetime.now()

    cursor.execute("""
        INSERT INTO scans
        (target, scan_type, date, time)
        VALUES (?, ?, ?, ?)
    """, (
        target,
        scan_type,
        now.strftime("%d-%m-%Y"),
        now.strftime("%H:%M:%S")
    ))

    scan_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return scan_id


# ---------------------------------
# Save Finding
# ---------------------------------

def save_finding(
    scan_id,
    title,
    description,
    severity,
    evidence,
    recommendation
):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO findings
        (
            scan_id,
            title,
            description,
            severity,
            evidence,
            recommendation
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        title,
        description,
        severity,
        evidence,
        recommendation
    ))

    connection.commit()
    connection.close()


# ---------------------------------
# Test Database
# ---------------------------------

if __name__ == "__main__":

    create_database()

    scan_id = save_scan(
        "localhost",
        "Web"
    )

    save_finding(
        scan_id,
        "Missing HSTS",
        "Strict-Transport-Security header is missing.",
        "MEDIUM",
        "HSTS header not found in HTTP response.",
        "Enable Strict-Transport-Security on the web server."
    )

    print("Scan saved successfully!")
    print("Finding saved successfully!")
    print("Scan ID:", scan_id)
