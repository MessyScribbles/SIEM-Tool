SIEM Analyzer

A beginner-friendly Security Information and Event Management (SIEM) like tool built with Python and Tkinter.  
It analyzes authentication logs for brute-force attacks, visualizes failed login attempts, and provides a simple dashboard.

Feature Summary:
| Feature                | How it Works                                             | Why it Matters (Cybersecurity/SIEM)      
|------------------------|----------------------------------------------------------|-----------------------------------------------|
| Log Parsing            | Reads and extracts events from logs                      | Collects security events for analysis         |
| Brute-force Detection  | Finds rapid failed attempts from same IP                 | Detects password guessing attacks             |
| GeoIP Enrichment       | Adds country/city info to IPs                            | Helps spot suspicious locations               |
| Dashboard              | Shows total lines, failed logins, unique IPs/users       | Gives situational awareness                   |
| Alert Exporting        | Saves alerts to JSON                                     | Enables reporting and further analysis        |
| Visualization          | Plots failed attempts per IP                             | Makes attack patterns easy to spot            |
| GUI                    | User-friendly interface                                  | Makes tool usable for all skill levels        |



Other Features:
- Dark-themed GUI
- Browse for log files

Requirements:
- Python 3.8+
- [requests](https://pypi.org/project/requests/)
- [matplotlib](https://pypi.org/project/matplotlib/)

Install dependencies:
```sh
pip install requests matplotlib
```

Usage:
1. Clone this repo and open the folder in VS Code or your IDE.
2. Run the script:
    ```sh
    python Main.py
    ```
3. In the GUI:
    - Browse to select your log file (e.g., `/var/log/auth.log` or a sample log).
    - Set the brute-force threshold and time window.
    - Click **Run SIEM** to analyze.
    - Click **Attempts** to visualize failed attempts.

Log Format:
The tool expects logs similar to:
```
Jun 23 01:32:55 ubuntu sshd[2225]: Failed password for root from 8.8.8.8 port 5555 ssh2 or
Jun 23 01:34:25 ubuntu sshd[2225]: Failed password for root from 192.168.1.10 port 5559 ssh2
(however the location wont be displayed for the second ip as it is a private one).
```
Customization:
- Edit `whitelist.txt` to add IPs you want to ignore.
- Alerts are saved to `alerts/alerts.json`.

Screenshots:
Main functions:
screenshots\Screenshot 2025-06-24 172918.png
Graph view:
screenshots\Screenshot 2025-06-24 173154.png

