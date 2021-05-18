## Characteristics of a TOR traffic

- TLS encryption  
-  It only has Common Name in the certificate  
-  Certificate Subject Common Name is www.{random}.net. Example.  www.2wcddc5755jllu.net  
-  Certificate Issuer Common name is www.{random}.com.  
-  SNI (if available) is www.{random}.com and usually won’t resolve. Example: www.b57efm9h06hb331njjd.com  
-  It usually uses port 443 or 9001. But other ports can also be used.  

![tor_traffic](.\tor_traffic.png)

## Suricata rule to detect TOR

```
alert tcp any ![21,25,110,143,443,465,587,636,989:995,5061,5222,8443] -> any any (msg:"CUSTOM-MADE Rules possible TOR SSL traffic"; flow:established,from_server; content:"|06 03 55 04 03|"; pcre:"/^.{2}www.[0-9a-z]{8,20}.com[01]/Rs"; content:"|06 03 55 04 03|"; distance:0; pcre:"/^.{2}www.[0-9a-z]{8,20}.net/Rs"; classtype:custom-made-rule; sid:900002; rev:3; metadata:created_at 2021_05_18;)
```

