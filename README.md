This is the code for a school project about the The Microsoft CrowdStrike Outage. Listed below are some commands and examples of cybersecurity involed in the cyberattack:

-Wireshark Filter for SMB and Citrix ICA traffic: tcp.port == 445 tcp.port == 1494 tcp.port == 2598 Look for unusual traffic volume or connections to/from new IPs -Detect potential data exfiltration: ip.dst == [external_IP] && tcp.port == 443

-Snort Detect large data transfers outbound over HTTPS alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Possible Data Exfiltration via HTTPS"; flow:established,to_server; dsize:>1000; sid:1000020;) alert tcp any any -> any 445 (msg:"SMB Lateral Movement Detected"; content:"|FF|SMB"; sid:1000030;

-Splunk Detect brute-force or suspicious logons index=wineventlog OR index=sysmon ((EventCode=4625) OR (EventCode=4624 AND LogonType=10)) | stats count by Account_Name, IpAddress, Workstation_Name

Detect credential dumping behavior (e.g., mimikatz, procdump): index=sysmon EventCode=10 TargetImage=lsass.exe

FINAL INFO (IMPORTANT) Bash Scripts are located above, but copy them from the .sh files listed on this repo.
