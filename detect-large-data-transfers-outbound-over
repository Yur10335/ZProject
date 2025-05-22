alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Possible Data Exfiltration via HTTPS"; flow:established,to_server; dsize:>1000; sid:1000020;)
