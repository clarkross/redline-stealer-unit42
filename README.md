# Line Unit 42 Wireshark Lab / Quiz for RedLine Stealer

* [Summary & Info Here](https://unit42.paloaltonetworks.com/wireshark-quiz-redline-stealer/)
* [pcap access](https://github.com/pan-unit42/Wireshark-quizzes/)
	* 2023-07-Unit42-Wireshark-quiz.pcap.zip

**LAN Details**
```
- LAN segment range: 10.7.10[.]0/24 (10.7.10[.]1 through 10.7.10[.]255)
- Domain: coolweathercoat[.]com
- Domain controller IP address: 10.7.10[.]9
- Domain controller hostname: WIN-S3WT6LGQFVX
- LAN segment gateway: 10.7.10[.]1
- LAN segment broadcast address: 10.7.10[.]255
```

**Notes & Recon**
* Redline Stealer
	* [Splunk Security Blog](https://www.splunk.com/en_us/blog/security/do-not-cross-the-redline-stealer-detections-and-analysis.html)
	* Steals sensitive information.
	* Distributed through phishing / social engineering / URLs.
#### What is the date and time in UTC the infection started?
* View -> Time Display Format
* UTC Date and Time of Day
* Display filter ```(http.request or tls.handshake.type eq 1) and !(ssdp)``` -- This is a filter provided by unit 42 within their training and has proven useful for identifying malicious web traffic.

```
# Initially, Windows Defender caught my eye and this is on http display filter.

2023-07-10 22:39:47	10.7.10.47	10.7.10.47	195.161.114.3	80	623start.site	GET /?status=start&av=Windows%20Defender HTTP/1.1 

2023-07-10 22:39:48	10.7.10.47	10.7.10.47	195.161.114.3	80	623start.site	GET /?status=install HTTP/1.1 

2023-07-10 22:39:49	10.7.10.47	10.7.10.47	92.118.151.9	80	guiatelefonos.com	GET /data/czx.jpg HTTP/1.1 
```

**Following TCP Stream on First Frame**
```
# Windows 10 -- PS GET request
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031

# Jump to last frame in the GET request and the TCP stream reveals:
GET /data/czx[.]jpg HTTP/1.1

```

Answer: The GET request (start of infection) was initiated at 2023-07-10 22:39:47

#### What is the IP address of the infected Windows client?

```
2023-07-10 22:39:49	10.7.10.47	10.7.10.47	92.118.151.9	80	guiatelefonos.com	GET /data/czx.jpg HTTP/1.1 
```

10.7.10.47

#### What is the MAC address of the infected Windows client?

```Ethernet II, Src: 80:86:5b:ab:1e:c4 (80:86:5b:ab:1e:c4)```

#### What is the hostname of the infected Windows client?

* Filter: ```ip.addr eq 10.7.10.47```
* In packet details of a subject address, NetBIOS Name Service reveals **DESKTOP-9PEA63H**

#### What is the user account name from the infected Windows host?

> NOTE: This is one that I have not learned about yet and Unit 42 does have a bit of training on finding information via Kerberos CName application as a column -- neatly displaying associated usernames.

* Attempted ```kerberos and ip.addr eq 10.7.10.47``` and seen a Kerberos entry in the packet details- however, had a difficult time finding user account name information.
* And so, we can apply ```kerberos.CNameString``` as a column in the column preference.

![Pasted image 20240224003836](https://github.com/clarkross/redline-stealer-unit42/assets/123221191/7fb6bb0a-efc5-43e5-83e4-76c3f1a98e51)

And now on the Kerberos port, we get:

```
2023-07-10 22:39:32	10.7.10.47	10.7.10.47	10.7.10.9	88	rwalters		AS-REQ
```

rwalters

#### What type of information did this RedLine Stealer try to steal?

```
# Display filter used to find the specific traffic to solve this. Unfortunately, I didn't solve this one either, but learned the importance of investigating TCP SYN traffic.

tcp.flags eq 0x0002 and !(tcp.port eq 443) and !(tcp.port eq 80) and !(ip.dst eq 10.7.10.0/24)
```

And so it was revealed, Redline was taking **A LOT** of information.
* User profile information / passwords.
* Browser sensitive information.
* Crypto wallet information.
* Various access tokens.
