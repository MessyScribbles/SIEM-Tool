import re
import json
from collections import defaultdict
from datetime import datetime, timedelta
import os
import tkinter as tk
from tkinter import filedialog, messagebox
import requests
import matplotlib.pyplot as plt

def load_whitelist(path):
    if os.path.exists(path):
        with open(path, "r") as wl:
            return set(ip.strip() for ip in wl.readlines())
    return set()

def parse_log(log_path, pattern):
    failed_attempts = defaultdict(list)
    try:
        with open(log_path, "r") as file:
            for line in file:
                match = re.search(pattern, line)
                if match:
                    ip = match.group(1)
                    timestamp_match = re.match(r"^([A-Za-z]{3} \d+ \d+:\d+:\d+)", line)
                    if timestamp_match:
                        ts_str = timestamp_match.group(1)
                        try:
                            ts = datetime.strptime(ts_str, "%b %d %H:%M:%S")
                            ts = ts.replace(year=datetime.now().year)
                            failed_attempts[ip].append(ts)
                        except:
                            continue
    except FileNotFoundError:
        return None
    return failed_attempts

def geoip_lookup(ip):
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = resp.json()
        if data["status"] == "success":
            return f"{data['country']} ({data['city']})"
        else:
            return "Unknown"
    except Exception:
        return "Unknown"

def detect_bruteforce(failed_attempts, whitelist, threshold, window):
    alerts = []
    for ip, times in failed_attempts.items():
        if ip in whitelist:
            continue
        times.sort()
        for i in range(len(times)):
            window_start = times[i]
            count = 1
            for j in range(i + 1, len(times)):
                if times[j] - window_start <= timedelta(minutes=window):
                    count += 1
                else:
                    break
            if count >= threshold:
                alerts.append({
                    "ip": ip,
                    "fail_count": count,
                    "alert": "Brute-force pattern",
                    "window_start": window_start.isoformat(),
                    "window_end": times[i + count - 1].isoformat()
                })
                break
    return alerts

def export_alerts(alerts, alert_path):
    os.makedirs(os.path.dirname(alert_path), exist_ok=True)
    with open(alert_path, "w") as f:
        json.dump(alerts, f, indent=4)

def plot_failed_attempts(failed_attempts):
    ip_list = []
    count_list = []
    for ip, times in failed_attempts.items():
        ip_list.append(ip)
        count_list.append(len(times))
    plt.figure(figsize=(8,4))
    plt.bar(ip_list, count_list, color="#7289DA")
    plt.xlabel("IP Address")
    plt.ylabel("Failed Attempts")
    plt.title("Failed Login Attempts per IP")
    plt.tight_layout()
    plt.show()

def show_dashboard(log_path, output_widget):
    total_lines = 0
    failed_logins = 0
    unique_ips = set()
    unique_users = set()
    pattern = r"Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)"
    try:
        with open(log_path, "r") as file:
            for line in file:
                total_lines += 1
                match = re.search(pattern, line)
                if match:
                    failed_logins += 1
                    user = match.group(1)
                    ip = match.group(2)
                    unique_users.add(user)
                    unique_ips.add(ip)
        output_widget.insert(tk.END, "\n[=] SIEM Dashboard\n")
        output_widget.insert(tk.END, f"Total log lines processed: {total_lines}\n")
        output_widget.insert(tk.END, f"Total failed logins: {failed_logins}\n")
        output_widget.insert(tk.END, f"Total unique IPs: {len(unique_ips)}\n")
        output_widget.insert(tk.END, f"Total unique usernames: {len(unique_users)}\n")
    except Exception as e:
        output_widget.insert(tk.END, f"Error generating dashboard: {e}\n")

def run_siem(log_path, threshold, window, whitelist_path, alert_path, output_widget):
    pattern = r"Failed password .* from (\d+\.\d+\.\d+\.\d+) port \d+ .*"
    whitelist = load_whitelist(whitelist_path)
    failed_attempts = parse_log(log_path, pattern)
    output_widget.config(state="normal")
    output_widget.delete(1.0, tk.END)
    # Show dashboard after clearing output
    show_dashboard(log_path, output_widget)
    if failed_attempts is None:
        output_widget.insert(tk.END, "[ERROR] Log file not found.\n")
        output_widget.config(state="disabled")
        return
    alerts = detect_bruteforce(failed_attempts, whitelist, threshold, window)
    export_alerts(alerts, alert_path)
    output_widget.insert(tk.END, "\n[+] SIEM Summary\n")
    if alerts:
        for alert in alerts:
            geo = geoip_lookup(alert['ip'])
            output_widget.insert(
                tk.END,
                f"- {alert['ip']} [{geo}] had {alert['fail_count']} failed attempts between {alert['window_start']} and {alert['window_end']}\n"
            )
    else:
        output_widget.insert(tk.END, "No suspicious activity detected.\n")
    output_widget.insert(tk.END, f"\n[✔] {len(alerts)} alerts saved to {alert_path}\n")
    output_widget.config(state="disabled")



def main():
    BG = "#23272A"
    FG = "#FFFFFF"
    ENTRY_BG = "#2C2F33"
    ENTRY_FG = "#99AAB5"
    BTN_BG = "#7289DA"
    BTN_FG = "#FFFFFF"
    OUT_BG = "#18191C"
    OUT_FG = "#43B581"

    root = tk.Tk()
    root.title("SIEM Analyzer - Dark Theme")
    root.geometry("650x420")
    root.resizable(False, False)
    root.configure(bg=BG)

    # Main frame
    main_frame = tk.Frame(root, bg=BG)
    main_frame.pack(fill="both", expand=True, padx=20, pady=20)

    # Labels and entries
    tk.Label(main_frame, text="Log file:", bg=BG, fg=FG, font=("Consolas", 11)).grid(row=0, column=0, sticky="e", pady=5, padx=5)
    log_entry = tk.Entry(main_frame, width=50, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=FG, font=("Consolas", 11), borderwidth=2, relief="flat")
    log_entry.insert(0, "f:\\SIEM1\\logs\\auth.log.txt")
    log_entry.grid(row=0, column=1, pady=5, padx=5)
    def browse_file():
        filename = filedialog.askopenfilename()
        if filename:
            log_entry.delete(0, tk.END)
            log_entry.insert(0, filename)
    browse_btn = tk.Button(main_frame, text="Browse", command=browse_file, bg=BTN_BG, fg=BTN_FG, font=("Consolas", 11), activebackground="#5865F2", activeforeground=FG, borderwidth=0)
    browse_btn.grid(row=0, column=2, pady=5, padx=5)

    tk.Label(main_frame, text="Threshold:", bg=BG, fg=FG, font=("Consolas", 11)).grid(row=1, column=0, sticky="e", pady=5, padx=5)
    threshold_entry = tk.Entry(main_frame, width=10, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=FG, font=("Consolas", 11), borderwidth=2, relief="flat")
    threshold_entry.insert(0, "5")
    threshold_entry.grid(row=1, column=1, sticky="w", pady=5, padx=5)

    tk.Label(main_frame, text="Window (min):", bg=BG, fg=FG, font=("Consolas", 11)).grid(row=2, column=0, sticky="e", pady=5, padx=5)
    window_entry = tk.Entry(main_frame, width=10, bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=FG, font=("Consolas", 11), borderwidth=2, relief="flat")
    window_entry.insert(0, "5")
    window_entry.grid(row=2, column=1, sticky="w", pady=5, padx=5)

    output = tk.Text(main_frame, height=13, width=75, font=("Consolas", 11, "bold"),
                     bg=OUT_BG, fg=OUT_FG, borderwidth=0, relief="flat", insertbackground=FG)
    output.grid(row=4, column=0, columnspan=3, pady=15, padx=5)
    output.config(state="disabled")

    def on_run():
        log_path = log_entry.get()
        try:
            threshold = int(threshold_entry.get())
            window = int(window_entry.get())
        except ValueError:
            messagebox.showerror("Input Error", "Threshold and window must be integers.")
            return
        whitelist_path = "whitelist.txt"
        alert_path = "alerts/alerts.json"
        run_siem(log_path, threshold, window, whitelist_path, alert_path, output)

    run_btn = tk.Button(main_frame, text="Run SIEM", command=on_run, bg=BTN_BG, fg=BTN_FG, font=("Consolas", 11), activebackground="#5865F2", activeforeground=FG, borderwidth=0)
    run_btn.grid(row=3, column=1, pady=10)

    # Optional: Add a button to plot failed attempts
    def on_plot():
        log_path = log_entry.get()
        pattern = r"Failed password .* from (\d+\.\d+\.\d+\.\d+) port \d+ .*"
        failed_attempts = parse_log(log_path, pattern)
        if failed_attempts:
            plot_failed_attempts(failed_attempts)
        else:
            messagebox.showerror("Error", "No failed attempts to plot or log file not found.")

    plot_btn = tk.Button(main_frame, text="Attempts", command=on_plot, bg=BTN_BG, fg=BTN_FG, font=("Consolas", 11), activebackground="#5865F2", activeforeground=FG, borderwidth=0)
    plot_btn.grid(row=3, column=2, pady=10, padx=5)

    root.mainloop()

if __name__ == "__main__":
    main()