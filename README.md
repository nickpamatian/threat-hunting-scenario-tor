<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/nickpamatian/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

Searched the DeviceFileEvents table for any activity that contained the string “tor.” It was discovered that the user “apoy” downloaded the tor installer, created additional logs that resulted in tor files being copied onto the desktop, and created a file named “tor-shopping-list” on the desktop. 
Tor related activity began at: 2025-04-03T21:08:16.5413924Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "apoy-threat-hun"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "apoy"
| where Timestamp >= datetime('2025-04-03T20:57:07.5949159Z')
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/6deec6df-de2f-4ead-86b0-c79347d96b9d)


---

### 2. Searched the `DeviceProcessEvents` Table

It was discovered that there was a script run in the ProcessCommandLine table that contained the string “tor-browser-windows-x86_64-portable-14.0.9.exe”. Based on the logs returned on April 3rd, 2025 at 9:11 PM UTC, a user named "apoy" on the device "apoy-threat-hun" downloaded and silently installed the Tor Browser (version 14.0.9) from their Downloads folder using the file tor-browser-windows-x86_64-portable-14.0.9.exe.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.9.exe"
| where DeviceName == "apoy-threat-hun"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
![image](https://github.com/user-attachments/assets/42cc0791-65d3-4f44-9384-87f016b14c60)
---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

The user first opened the tor browser at 2025-04-03T21:12:20.6653606Z. There were several logs of firefox.exe (Tor) and tor.exe generated afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "apoy-threat-hun"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/4e87c955-f435-4f1d-87c0-c0b61e39edad)
---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Tor browser activity was found on the user “apoy”’s device. Successfully established connections were discovered using known tor ports. The user "apoy" on the device "apoy-threat-hun" successfully made a network connection using the Tor Browser. The process tor.exe, located on their desktop, connected to the IP address 192.42.116.211 on port 9001, which is associated with the URL https://www.7ebzcrybvdp7wvg.com. There were other connections to sites over port 443 as well. 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "apoy-threat-hun"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath

```

![image](https://github.com/user-attachments/assets/59f2c324-233e-43f3-9ab2-64962435923b)

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-04-03T21:08:16.541Z`
- **Event:** The user "apoy" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.9.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\apoy\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

---

### 2. TOR Installer Execution

- **Timestamp:** `2025-04-03T21:11:37.611Z`
- **Event:** The Tor Browser installer was executed with a silent installation parameter (/S), initiating the installation process without user prompts.
- **Action:** Installer executed silently.
- **File Path:** `C:\Users\apoy\Downloads\tor-browser-windows-x86_64-portable-14.0.9.exe`

---

### 3. TOR Browser Launch

- **Timestamp:** `2025-04-03T21:12:20.665Z`
- **Event:** The Tor Browser was launched for the first time by user "apoy". Subsequent processes related to Tor, such as `firefox.exe` (the Tor Browser) and `tor.exe` (the Tor process), were initiated.
- **Action:** TOR Browser launched.
- **File Path:** N/A (launched from executable)

---

### 4. TOR Network Connection Established

- **Timestamp:** `2025-04-03T21:12:39.200Z`
- **Event:** The `tor.exe` process established a network connection to IP address `192.42.116.211` on port `9001`, confirming Tor browser network activity.
- **Action:** Network connection established.
- **Remote IP:** `192.42.116.211`
- **Remote Port:** `9001`

---

### 5. Additional Network Connections

- **Timestamp:** `2025-04-03T21:13:10.000Z`
- **Event:** Additional network connections were made by `tor.exe` and `firefox.exe` to various remote servers over ports `443` (HTTPS) and other known Tor-related ports, facilitating anonymous browsing sessions.
- **Action:** Additional network connections established.

---

### 6. File Creation - "tor-shopping-list"

- **Timestamp:** `2025-04-03T21:15:45.000Z`
- **Event:** A file named "tor-shopping-list" was created on the desktop by user "apoy". The contents and purpose of this file are unknown based on the available data.
- **Action:** File creation detected.
- **File Path:** `C:\Users\apoy\Desktop\tor-shopping-list`


---

## Summary

On April 3, 2025, user "apoy" on the device "apoy-threat-hun" initiated activities related to the Tor Browser. The user downloaded the Tor Browser installer and performed a silent installation. Shortly after, the Tor Browser was launched, leading to the initiation of processes such as firefox.exe and tor.exe. These processes established network connections to known Tor network nodes, including IP address 192.42.116.211. Subsequent connections were made over standard HTTPS and other Tor-related ports, indicating active use of the Tor network for browsing. Additionally, a file named "tor-shopping-list" was created on the desktop, though its contents and relevance to the Tor activity remain unclear from the provided information.

---

## Response Taken

TOR usage was confirmed on the endpoint `apoy-threat-hun` by the user `apoy`. The device was isolated, and the user's direct manager was notified.

---
