import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import requests
import subprocess
import threading
from tkinterweb import HtmlFrame

class SQLiScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL Injection Vulnerability Scanner")
        
        # Create a frame for the website display
        self.website_frame = tk.Frame(root)
        self.website_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Create a frame for the results display
        self.results_frame = tk.Frame(root)
        self.results_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # URL input
        self.url_label = tk.Label(self.website_frame, text="Enter URL:")
        self.url_label.pack(pady=5)
        self.url_entry = tk.Entry(self.website_frame, width=50)
        self.url_entry.pack(pady=5)
        
        # Load button
        self.load_button = tk.Button(self.website_frame, text="Load Website", command=self.load_website)
        self.load_button.pack(pady=5)
        
        # Website display
        self.html_frame = HtmlFrame(self.website_frame, horizontal_scrollbar="auto")
        self.html_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scan button
        self.scan_button = tk.Button(self.results_frame, text="Scan for SQLi", command=self.start_scan)
        self.scan_button.pack(pady=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(self.results_frame, orient="horizontal", length=300, mode="indeterminate")
        self.progress.pack(pady=10)
        
        # Results display
        self.results_text = scrolledtext.ScrolledText(self.results_frame, width=60, height=20)
        self.results_text.pack(pady=5, fill=tk.BOTH, expand=True)

    def load_website(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL.")
            return
        
        # Check if the website exists
        if not self.check_website(url):
            messagebox.showerror("Website Error", "The website does not exist.")
            return
        
        # Load the website in the HTML frame
        self.html_frame.load_website(url)

    def start_scan(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL.")
            return
        
        # Start the scanning in a separate thread
        self.results_text.delete(1.0, tk.END)  # Clear previous results
        self.results_text.insert(tk.END, f"Scanning {url}...\n")
        self.progress.start()
        threading.Thread(target=self.scan, args=(url,)).start()

    def scan(self, url):
        try:
            # Run SQLMap and capture the output
            output = self.run_sqlmap(url)
            self.progress.stop()  # Stop the progress bar
            
            # Parse the output and display results
            databases = self.parse_sqlmap_output(output)
            if databases:
                self.results_text.insert(tk.END, "Databases found:\n")
                for db in databases:
                    self.results_text.insert(tk.END, f"{db}\n")
            else:
                self.results_text.insert(tk.END, "No databases found or no vulnerabilities detected.\n")
        
        except Exception as e:
            self.results_text.insert(tk.END, f"Error: {str(e)}\n")
            self.progress.stop()

    def check_website(self, url):
        try:
            response = requests.get(url)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def run_sqlmap(self, url):
        command = [
            'sqlmap',  # Ensure sqlmap is in your PATH or provide the full path
            '-u', url,
            '--batch',  # Non-interactive mode
            '--level=2',  # Level of tests to perform
            '--risk=2',  # Risk level of tests to perform
            '--dbs'  # Enumerate databases
        ]
        
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout

    def parse_sqlmap_output(self, output):
        databases = []
        for line in output.splitlines():
            if "Database:" in line:
                databases.append(line.strip())
        return databases

if __name__ == "__main__":
    root = tk.Tk()
    app = SQLiScannerApp(root)
    root.mainloop()
