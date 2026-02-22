<img src="https://i.imgur.com/S8Ons8k.png" height="80%" width="80%" />

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/stevenbealle/TorBrowserIncidentCreation)

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "Stefano" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `Tor Shopping List.txt` in Documents at `2026-02-17T15:11:40.544741Z`. These events began at `2026-02-17T14:32:44.0801403Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "stefano-tor-bro"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-02-17T14:32:44.0801403Z)
| where InitiatingProcessAccountName == "stefano"
| project Timestamp, DeviceName, ActionType, FolderPath, SHA256, Account = InitiatingProcessAccountName
| order by Timestamp desc

```
<img src="https://i.imgur.com/OtkB321.png" height="80%" width="80%" />



---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.6.exe". Based on the logs returned, at `2026-02-17T14:40:53.712063Z`, an employee on the "stefano-tor-bro" device ran the file `tor-browser-windows-x86_64-portable-15.0.6.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "stefano-tor-bro"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.6.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img src="https://i.imgur.com/Smf0Ls1.png" height="80%" width="80%" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2026-02-17T14:46:56.93411Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "stefano-tor-bro"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img src="https://i.imgur.com/IyFxwIx.png" height="80%" width="80%" />



---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-02-17T14:48:32.140446Z`, an employee on the "stefano-tor-bro" device successfully established a connection to the remote IP address `164.65.1.77` on port `443`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\stefano\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `9001`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "stefano-tor-bro"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img src="https://i.imgur.com/JzQsdoX.png" height="80%" width="80%" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-02-17T14:32:44.0801403Z`
- **Event:** The user "stefano" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.6.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\Stefano\Downloads\tor-browser-windows-x86_64-portable-15.0.6.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-02-17T14:40:53.712063Z`
- **Event:** The user "stefano" executed the file `tor-browser-windows-x86_64-portable-15.0.6.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.6.exe  /S`
- **File Path:** `C:\Users\Stefano\Downloads\tor-browser-windows-x86_64-portable-15.0.6.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-02-17T14:46:56.93411Z`
- **Event:** User "stefano" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\Stefano\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-02-17T14:48:32.140446Z`
- **Event:** A network connection to IP `64.65.1.77` on port `443` by user "stefano" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\stefano\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-02-17T14:48:34.9307458Z` - Connected to `38.242.230.103` on port `9001`.
  - `2026-02-17T14:48:52.5237094Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "stefano" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-02-17T15:11:40.544741Z`
- **Event:** The user "stefano" created a file named `Tor Shopping List.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Stefano\Documents\Tor Shopping List.txt`

---

## Summary

The user "stefano" on the "stefano-tor-bro" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `Tor Shopping List`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `stefano-tor-bro` by the user `stefano`. The device was isolated, and the user's direct manager was notified.

---

