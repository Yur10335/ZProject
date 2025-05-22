index=wineventlog OR index=sysmon
((EventCode=4625) OR (EventCode=4624 AND LogonType=10))
| stats count by Account_Name, IpAddress, Workstation_Name
