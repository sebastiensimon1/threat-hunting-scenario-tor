<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/sebastiensimon1/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered that the user "employee" downloaded a TOR installer, and it resulted in TOR-related executables being copied. These events began at 2025-05-11T02:14:21.610Z.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "window-lab2"  
| where InitiatingProcessAccountName == "username or name of the employee"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-05-11T02:14:21.610Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
![image](https://github.com/user-attachments/assets/fa086d6e-7821-48c6-934d-980d4a13cacd)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any ProcessCommandLine that contained the string "tor-browser-windows-x86_64-portable-14.5.1.exe". Based on the logs returned, at 2025-05-11T02:07:11.215Z, an employee on the "window-lab2" device ran the file tor-browser-windows-x86_64-portable-14.5.1.exe from their Downloads folder, and again silently at 2025-05-11T02:13:23.135Z.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "window-lab2"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/1540947b-ecd2-4620-a754-348e3bd04724)

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it after 2025-05-11T02:14:21.610Z. Multiple processes associated with TOR such as firefox.exe and tor.exe were created, indicating that the browser launched successfully.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "window-lab2"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/bf05c2f0-e384-4cfa-a7e1-4fa685c024e1)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At 2025-05-11T02:14:26.534Z, an employee on the "window-lab2" device successfully established connections to remote IP addresses over ports 9001, 443, and 9150. The connections were initiated by the process tor.exe.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "window-lab2"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/1c1a1375-d699-4230-83c5-44db0f6bc18a)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-05-11T02:07:11.215Z`
- **Event:** The user `"employee"` downloaded a file named `tor-browser-windows-x86_64-portable-14.5.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

---

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-05-11T02:13:23.135Z`
- **Event:** The user `"employee"` executed the file `tor-browser-windows-x86_64-portable-14.5.1.exe` in silent mode, initiating background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

---

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-05-11T02:14:21.610Z`
- **Event:** User `"employee"` opened the TOR browser. Subsequent processes associated with the TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-05-11T02:14:26.534Z`
- **Event:** Network connections to IPs like `93.208.223.108`, `172.233.164.199`, `159.69.138.31`, and `127.0.0.1` were established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`


---

### Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

### Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.
