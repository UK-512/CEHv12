# CEH Set A
1.  Attacker is trying to perform packet sniffing on a target network to capture all data packets passing through a network to gather sensitive information. Attacker main aim behind packet sniffing is to sniff the traffic and collect valuable information from the data packets to launch man-in-the-middle, denial-of-service, and passive sniffing attacks on the target network.
Which of the following sniffing technique attacker should use in the above scenario?
+ [x] IRDP Spoofing
+ [ ] DHCP Starvation Attack
+ [ ] MAC Flooding
+ [ ] ARP Spoofing
> **Explanation:**
> 

2.  Which of the following is considered an acceptable option when managing a risk?
+ [ ] Reject the risk
+ [ ] Deny the risk
+ [x] Mitigate the risk.
+ [ ] Initiate the risk
> **Explanation:**
> 

3.  A security consultant decides to use multiple layers of antivirus defense, such as end user desktop antivirus and e-mail gateway.This approach can be used to mitigate which attack?
+ [ ] Forensic attack
+ [ ] Address Resolution Protocol (ARP) spoofing attack
+ [x] Social engineering attack
+ [ ] Scanning attack
> **Explanation:**
> 

4.  A security administrator notices that the log file of the company's webserver contains suspicious entries: 
```
[20/Mar/2011:10:49:07] "GET /login.php?user=test'+oR+3>2%20-- HTTP/1.1" 200 9958 
[20/Mar/2011:10:51:02] "GET /login.php?user=admin';%20-- HTTP/1.1" 200 9978
```
The administrator decides to further investigate and analyze the source code of the login.php file: 
```
php 
include('../../config/db_connect.php'); 
$user = $_GET['user']; 
$pass = $_GET['pass']; 
$sql = "SELECT * FROM USERS WHERE username = '$user' AND password = '$pass'"; 
$result = mysql_query($sql) or die ("couldn't execute query"); 

if (mysql_num_rows($result) != 0) echo 'Authentication granted!'; 
else echo 'Authentication failed!'; 
?>
```
Based on the source code analysis, the analyst concludes that the login.php script is vulnerable to:
+ [ ] command injection.
+ [x] SQL injection.
+ [ ] directory traversal.
+ [ ] LDAP injection.
> **Explanation:**
> 

5.  Employees in a company are no longer able to access Internet web sites on their computers. The network administrator is able to successfully ping IP address of web servers on the Internet and open the web sites by using an IP address instead of the URL. The administrator runs the Nslookup command for www.eccouncil.org and receives an error message stating there is no response from the server. What should the administrator do next?
+ [x] Configure the firewall to allow traffic on TCP ports 53 and UDP port 53.
+ [ ] Configure the firewall to allow traffic on TCP ports 80 and UDP port 443.
+ [ ] Configure the firewall to allow traffic on TCP port 53.
+ [ ] Configure the firewall to allow traffic on TCP port 8080.
> **Explanation:**
> 

6.  Which protocol and port number might be needed in order to send log messages to a log analysis tool that resides behind a firewall?
+ [ ] UDP 123
+ [ ] UDP 541
+ [x] UDP 514
+ [ ] UDP 415
> **Explanation:**
> 

7.  Sean who works as a network administrator has just deployed an IDS in his organization’s network. Sean deploy an IDS that generates four types of alerts which include: True Positive, False Positive, False Negative and True Negative.
In which of the following condition IDS generate true positive alert?
+ [x] A true positive is a condition occurring when an event triggers an alarm and causes the IDS to react as if a real attack is in progress
+ [ ] A true positive is a condition occurring when an event triggers an alarm when no actual attack is in progress
+ [ ] A true positive is a condition occurring when an IDS fails to react to an actual attack event.
+ [ ] A true positive is a condition occurring when an IDS identifies an activity as acceptable behavior and the activity is acceptable
> **Explanation:**
> 

8.  Which security control role does encryption meet?
+ [x] Preventative
+ [ ] Detective
+ [ ] Offensive
+ [ ] Defensive
> **Explanation:**
> 

9.  Which of the following viruses tries to hide from anti-virus programs by actively altering and corrupting the chosen service call interruptions when they are being run?    
+ [ ] Cavity virus
+ [x] Polymorphic virus
+ [ ] Tunneling virus
+ [ ] Stealth virus
> **Explanation:**
> 

10.  An NMAP scan of a server shows port 69 is open. What risk could this pose?
+ [x] Unauthenticated access
+ [ ] Weak SSL version
+ [ ] Cleartext login
+ [ ] Web portal data leak
> **Explanation:**
> 

11.  Which tool would be used to collect wireless packet data?
+ [x] NetStumbler
+ [ ] John the Ripper
+ [ ] Nessus
+ [ ] Netcat
> **Explanation:**
> 

12.  Which results will be returned with the following Google search query? 
`site:target.com -site:Marketing.target.com accounting`
+ [ ] Results matching all words in the query.
+ [x] Results matching “accounting” in domain target.com but not on the site Marketing.target.com.
+ [ ] Results from matches on the site marketing.target.com that are in the domain target.com but do not include the word accounting.
+ [ ] Results for matches on target.com and Marketing.target.com that include the word “accounting.”
> **Explanation:**
> 

13. Sean is trying to perform a session hijacking attack against a private user. He needs to obtain the session IDs (valid session token) of the user to get control over an existing session or to create a new unauthorized session.
Which of the following techniques will NOT help in obtaining session ID?
+ [ ] Man-in-the-Middle attack
+ [ ] Forbidden attack
+ [x] Denial-of-Service attack
+ [ ] Cross-site scripting (XSS) attack
> **Explanation:**
> 

14.  Which solution can be used to emulate computer services, such as mail and ftp, and to capture information related to logins or actions?
+ [ ] Firewall
+ [ ] Honeypot
+ [x] Intrusion Detection System (IDS)
+ [ ] DeMilitarized Zone (DMZ)
> **Explanation:**
> 

15.  Which method can provide a better return on IT security investment and provide a thorough and comprehensive assessment of organizational security covering policy, procedure design, and implementation?
+ [x] Penetration testing
+ [ ] Social engineering
+ [ ] Vulnerability scanning
+ [ ] Access control list reviews
> **Explanation:**
> 

16.  A security engineer is attempting to map a company’s internal network. The engineer enters in the following NMAP command: 
`NMAP –n –sS –P0 –p 80 ***.***.**.** `
What type of scan is this?
+ [ ] Quick scan
+ [ ] Intense scan
+ [x] Stealth scan
+ [ ] Comprehensive scan
> **Explanation:**
> 

17.  A security consultant is trying to bid on a large contract that involves penetration testing and reporting. The company accepting bids wants proof of work so the consultant prints out several audits that have been performed. Which of the following is likely to occur as a result?
+ [ ] The consultant will ask for money on the bid because of great work.
+ [x] The consultant may expose vulnerabilities of other companies.
+ [ ] The company accepting bids will want the same type of format of testing.
+ [ ] The company accepting bids will hire the consultant because of the great work performed.
> **Explanation:**
> 

18.  A security analyst in an insurance company is assigned to test a new web application that will be used by clients to help them choose and apply for an insurance plan. The analyst discovers that the application has been developed in ASP scripting language and it uses MSSQL as a database backend. The analyst locates the application's search form and introduces the following code in the search input field:
`IMG SRC=vbscript:msgbox("Vulnerable");> originalAttribute="SRC" originalPath="vbscript:msgbox("Vulnerable");>"`
When the analyst submits the form, the browser returns a pop-up window that says "Vulnerable."
Which web applications vulnerability did the analyst discover?
+ [ ] Cross-site request forgery
+ [ ] Command injection
+ [x] Cross-site scripting
+ [ ] SQL injection
> **Explanation:**
> 

19. 

A data breach occurred in Cosmo Service, Inc. The incident results in huge losses of revenue as a result their mobile app service is withdrawn. Investigators discovered a vulnerability attackers exploited in the HTML5 used to build the app. The vulnerability concerns the use of customized queries, which bypass the mobile app login process.
What type of attack was used?
+ [ ] Click/tap jacking
+ [ ] Phishing
+ [x] SQLite injections
+ [ ] Cross Origin Resource Sharing (CORS)
> **Explanation:**
> 

20.  Which of the following is a common Service Oriented Architecture (SOA) vulnerability?
+ [ ] Cross-site scripting
+ [ ] SQL injection
+ [ ] VPath injection
+ [x] XML denial of service issues
> **Explanation:**
> 

21.  Which of the following programs is usually targeted at Microsoft Office products?
+ [ ] Polymorphic virus
+ [ ] Multipart virus
+ [x] Macro virus
+ [ ] Stealth virus
> **Explanation:**
> 

22.  What results will the following command yield: 'NMAP -sS -O -p 123-153 192.168.100.3'?
+ [ ] A stealth scan, opening port 123 and 153.
+ [ ] A stealth scan, checking open ports 123 to 153.
+ [ ] A stealth scan, checking all open ports excluding ports 123 to 153.
+ [x] A stealth scan, determine operating system, and scanning ports 123 to 153.
> **Explanation:**
> 

23.  What is the main advantage that a network-based IDS/IPS system has over a host-based solution?
+ [x] They do not use host system resources.
+ [ ] They are placed at the boundary, allowing them to inspect all traffic.
+ [ ] They are easier to install and configure.
+ [ ] They will not interfere with user interfaces.
> **Explanation:**
> 

24. Firewalk has just completed the second phase (the scanning phase) and a technician receives the output shown below. What conclusions can be drawn based on these scan results?
       TCP port 21 – no response 
       TCP port 22 – no response
       TCP port 23 – Time-to-live exceeded
+ [ ] The firewall itself is blocking ports 21 through 23 and a service is listening on port 23 of the target host.
+ [x] The lack of response from ports 21 and 22 indicate that those services are not running on the destination server.
+ [ ] The scan on port 23 passed through the filtering device. This indicates that port 23 was not blocked at the firewall.
+ [ ] The scan on port 23 was able to make a connection to the destination host prompting the firewall to respond with a TTL error.
> **Explanation:**
> 

25. A covert channel is a channel that
+ [x] Transfers information over, within a computer system, or network that is outside of the security policy.
+ [ ] Transfers information over, within a computer system, or network that is within the security policy.
+ [ ] Transfers information via a communication path within a computer system, or network for transfer of data.
+ [ ] Transfers information over, within a computer system, or network that is encrypted.
> **Explanation:**
> 

26.  A Security Engineer at a medium-sized accounting firm has been tasked with discovering how much information can be obtained from the firm's public facing web servers. The engineer decides to start by using netcat to port 80.The engineer receives this output:
```
HTTP/1.1 200 OK Server:
Microsoft-IIS/6 Expires: Tue, 17 Jan 2011
01:41:33 GMT Date: Mon, 16 Jan 2011 01:41:33 GMT
Content-Type: text/html
Accept-Ranges: bytes
Last-Modified: Wed, 28 Dec 2010 15:32:21 GMT
ETag: "b0aac0542e25c31:89d"
Content-Length: 7369
```
Which of the following is an example of what the engineer performed?
+ [ ] Cross-site scripting
+ [x] Banner grabbing
+ [ ] SQL injection
+ [ ] Whois database query
> **Explanation:**
> 

27.  The recent massive outbreak of Petya malware that shut down computers around the world has been almost universally blamed on ransomware. Petya delivers malicious code that destroys data, with no hope of recovery. What is this malicious code?
+ [ ] Bot
+ [x] Payload
+ [ ] Vulnerability
+ [ ] Honeypot
> **Explanation:**
> 

28.  An attacker has been successfully modifying the purchase price of items purchased on the company's web site. The security administrators verify the web server and Oracle database have not been compromised directly. They have also verified the Intrusion Detection System (IDS) logs and found no attacks that could have caused this. What is the mostly likely way the attacker has been able to modify the purchase price?
+ [ ] By using SQL injection
+ [x] By changing hidden form values
+ [ ] By using cross site scripting
+ [ ] By utilizing a buffer overflow attack
> **Explanation:**
> 

29.  Ron,  a customer support intern,  exploited default configurations and settings of the off-the-shelf libraries and code used in the company’s CRM platform. How will you categorize this attack?
+ [ ] Operating System attack
+ [x] Mis-configuration attack
+ [ ] Application-level attack
+ [ ] Shrink-wrap code attack
> **Explanation:**
> 

30.  After gaining access to the password hashes used to protect access to a web based application, the knowledge of which cryptographic algorithms would be useful to gain access to the application?
+ [x] SHA1
+ [ ] Diffie-Helman
+ [ ] RSA
+ [ ] AES
> **Explanation:**
> 

31. Your organization has developed a CRM application to manage its clientele across the world. You have offices and customer support executives located in different parts of the world. You need to host your CRM application on a cloud so that all your customer support executives can access the CRM application from their geographical locations. The organization has limited resources, and does not want to invest resources in purchasing server operating systems, required software, and hardware.It also does not want to invest resources to manage the security controls on the cloud such as packing and updating of operating systems, malware scanning, etc. Which of the following cloud service models meet the requirements above?
+ [x] SaaS
+ [ ] PaaS
+ [ ] IaaS
+ [ ] SECaaS
> **Explanation:**
> 

32.  Which of the following term refers to unskilled hackers who compromise systems by running scripts, tools, and software developed by real hackers? They usually focus on the quantity of attacks rather than the quality of the attacks that they initiate.
+ [ ] Hacktivist
+ [x] Script Kiddies
+ [ ] Gray Hats
+ [ ] Suicide Hackers
> **Explanation:**
> 

33. A penetration tester is conducting a port scan on a specific host. The tester found several ports opened that were confusing in concluding the Operating System (OS) version installed. Considering the NMAP result below, which of the following is likely to be installed on the target machine by the OS? 
```
Starting NMAP 5.21 at 2011-03-15 11:06 
NMAP scan report for 172.16.40.65
Host is up (1.00s latency).
Not shown: 993 closed ports

PORT        STATE       SERVICE
21/tcp  open        ftp
23/tcp  open        telnet
80/tcp      open        http
139/tcp open        netbios-ssn
515/tcp     open 
631/tcp     open        ipp
9100/tcp    open 

MAC Address: 00:00:48:0D:EE:89
```
+ [ ] The host is likely a Windows machine.
+ [ ] The host is likely a Linux machine.
+ [ ] The host is likely a router.
+ [x] The host is likely a printer.
> **Explanation:**
> 

34. Robert wants to implement Identity and Access Management (IAM) in the cloud environment to manage digital identities of users and their rights to access cloud resources.
    Which unit of standard enterprise IAM architecture allows activating operating governance and supervising the process for determining that an entity is who or what it claims to be?
+ [ ] User management
+ [x] Authentication management
+ [ ] Authorization management
+ [ ] Access management
> **Explanation:**
> 

35.  For messages sent through an insecure channel, a properly implemented digital signature gives the receiver reason to believe the message was sent by the claimed sender. While using a digital signature, the message digest is encrypted with which key?
+ [ ] Sender's public key
+ [ ] Receiver's private key
+ [ ] Receiver's public key
+ [x] Sender's private key
> **Explanation:**
> 

36. Jacob was not happy with the product that he ordered from an online retailer. He tried to contact post purchase service desk but they replied that they cannot help him in this matter. Jacob wanted to avenge this by damaging the retailer’s services. He used a utility named HOIC that he downloaded from an underground site to flood the retailer’s system with requests, so as the retailer’s site was unable to handle any further requests even from legitimate users’ purchase requests. What type of attack is Jacob using?
+ [ ] Jacob uses poorly designed input validation routines to create or alter commands to gain access to unintended data or execute commands
+ [ ] Jacob is executing commands or viewing data outside the intended target path
+ [x] Jacob is using a denial of service attack which is a valid threat used by an attacker
+ [ ] Jacob is taking advantage of an incorrect configuration that leads to access with higher-than-expected privilege
> **Explanation:**
> 

37.  A corporation hired an ethical hacker to test if it is possible to obtain users’ login credentials using methods other than social engineering. Access to offices and to a network node is granted to the hacker. Results from server scanning indicate that all are  adequately patched and physical access is denied; thus, administrators have access only through Remote Desktop. Which technique could be used to obtain login credentials?
+ [ ] Capture every users' traffic with Ettercap.
+ [ ] Capture LANMAN Hashes and crack them with LC6.
+ [ ] Guess passwords using Medusa or Hydra against a network service.
+ [x] Capture administrators RDP traffic and decode it with Cain and Abel.
> **Explanation:**
> 

38.  A tester has been hired to do a web application security test. The tester notices that the site is dynamic and must make use of a back end database. 
In order for the tester to see if an SQL injection is possible, what is the first character that the tester should use to attempt breaking a valid SQL request?
+ [ ] Semicolon
+ [x] Single quote
+ [ ] Exclamation mark
+ [ ] Double quote
> **Explanation:**
> 

39.  Which tool can be used to silently copy files from USB devices?
+ [ ] USB Grabber
+ [x] USB Dumper
+ [ ] USB Sniffer
+ [ ] USB Snoopy
> **Explanation:**
> 

40.  An attacker uses a communication channel within an operating system that is neither designed nor intended to transfer information. What is the name of the communications channel?
+ [ ] Classified
+ [ ] Overt
+ [ ] Encrypted
+ [x] Covert
> **Explanation:**
> 

41.  Which statement is TRUE regarding network firewalls preventing Web Application attacks?
+ [ ] Network firewalls can prevent attacks because they can detect malicious HTTP traffic.
+ [x] Network firewalls cannot prevent attacks because ports 80 and 443 must be opened.
+ [ ] Network firewalls can prevent attacks if they are properly configured.
+ [ ] Network firewalls cannot prevent attacks because they are too complex to configure.
> **Explanation:**
> 

42.  Your company uses cloud services from XSecCloud, Inc. to host its popular online gaming site. The online games are hosted on three replication mirror servers that serve different parts of the world. The company has subscribed to a bandwidth of 100 Mbps. The users on the site never complained about any slowdown in the service. However, during the last Christmas holidays, the company received several complaints from the North American region that the games are not responding. You have been asked to investigate the real cause of the problem and suggest cost-effective solutions to avoid any such issue in the future. During your investigation, you discover users only utilizing 50 Mbps of the available bandwidth, which signifies bandwidth is not appropriately utilized. Of the choices below, what would be your suggestion to avoid this kind of service slowdown in the future?
+ [ ] The CSP should provide broad network access
+ [ ] The CSP should provision rapid elasticity
+ [x] The CSP should provision elastic load balancing
+ [ ] The CSP should provision dynamic infrastructure scaling
> **Explanation:**
> 

43.  A web application does not have the secure flag set. Which Open Web Application Security Project (OWASP) implements a web application full of known vulnerabilities?
+ [ ] WebBugs
+ [x] WebGoat
+ [ ] VULN_HTML
+ [ ] WebScarab
> **Explanation:**
> 

44.  Which of the following Bluetooth attack allows attacker to gain remote access to a target Bluetooth-enabled device without the victim being aware of it?
+ [x] Bluebugging
+ [ ] Bluesmacking
+ [ ] BluePrinting
+ [ ] Bluejacking
> **Explanation:**
> 

45.  It refers to gaining access to one network and/or computer and then using the same to gain access to multiple networks and computers that contain desirable information.
+ [ ] Doxing
+ [x] Daisy Chaining
+ [ ] Social Engineering
+ [ ] Kill Chain
> **Explanation:**
> 

46. Michal, a reputed hacker is trying to compromise one of the cloud service provider’s servers to get the critical information. He initiates hundreds of invalid requests to a cloud server in order to render the cloud services inaccessible to the legitimate cloud users.
    Identify the type of attack Michal is using to compromise the cloud server.
+ [ ] Side Channel Attack
+ [ ] Authentication Attack
+ [x] Denial-of-Service (DoS) Attack
+ [ ] Man-in-the-middle Cryptographic Attack
> **Explanation:**
> 

47.  A hacker is attempting to use nslookup to query Domain Name Service (DNS). The hacker uses the nslookup interactive mode for the search. Which command should the hacker type into the command shell to request the appropriate records?
+ [ ] Locate type=ns
+ [ ] Request type=ns
+ [x] Set type=ns
+ [ ] Transfer type=ns
> **Explanation:**
> 

48.  Which of the following technique gathers information from search engines, web services, people search services, and so on?
+ [ ] Active footprinting
+ [ ] Scanning
+ [ ] Enumeration
+ [x] Passive Footprinting
> **Explanation:**
> 

49.  There is a WEP encrypted wireless access point (AP) with no clients connected. In order to crack the WEP key, a fake authentication needs to be performed. What information is needed when performing fake authentication to an AP?  (Choose two )
+ [ ] The IP address of the AP
+ [x] The MAC address of the AP
+ [x] The SSID of the wireless network
+ [ ] A failed authentication packet
> **Explanation:**
> 

50.  A hacker is attempting to see which IP addresses are currently active on a network. Which NMAP switch would the hacker use?
+ [ ] -sO
+ [x] -sP
+ [ ] -sS
+ [ ] -sU
> **Explanation:**
> 

51.  During a penetration test, the tester conducts an ACK scan using NMAP against the external interface of the DMZ firewall. NMAP reports that port 80 is unfiltered. Based on this response, which type of packet inspection is the firewall conducting?
+ [ ] Host
+ [ ] Stateful
+ [ ] Stateless
+ [x] Application
> **Explanation:**
> 

52. 

What is the purpose of conducting security assessments on network resources?
+ [ ] Documentation
+ [ ] Validation
+ [ ] Implementation
+ [x] Management
> **Explanation:**
> 

53.  Stored biometric is vulnerable to an attack. What is the main reason behind this?
+ [ ] The digital representation of the biometric might not be unique, even if the physical characteristic is unique.
+ [ ] Authentication using a stored biometric compares a copy to a copy instead of the original to a copy.
+ [ ] A stored biometric is no longer “something you are” and instead becomes “something you have.”
+ [x] A stored biometric can be stolen and used by an attacker to impersonate the individual identified by the biometric.
> **Explanation:**
> 

54. A certified ethical hacker (CEH) is approached by a friend who believes her husband is cheating. She offers to pay to break into her husband's email account in order to find proof so she can take him to court. What is the ethical response?
+ [x] Say no; the friend is not the owner of the account.
+ [ ] Say yes; the friend needs help to gather evidence.
+ [ ] Say yes; do the job for free
+ [ ] Say no; make sure that the friend knows the risk she’s asking the CEH to take.
> **Explanation:**
> 

55.  WPA2 uses AES for wireless data encryption at which of the following encryption levels?
+ [ ] 64 bit and CCMP
+ [ ] 128 bit and CRC
+ [x] 128 bit and CCMP
+ [ ] 128 bit and TKIP
> **Explanation:**
> 

56.  During a penetration test, a tester finds that the web application being analyzed is vulnerable to Cross Site Scripting (XSS). Which of the following conditions must be met to exploit this vulnerability?
+ [ ] The web application does not have the secure flag set.
+ [x] The session cookies do not have the HttpOnly flag set.
+ [ ] The victim user should not have an endpoint security solution.
+ [ ] The victim's browser must have ActiveX technology enabled.
> **Explanation:**
> 

57.  The use of alert thresholding in an IDS can reduce the volume of repeated alerts, but introduces which of the following vulnerabilities?
+ [ ] An attacker, working slowly enough, can evade detection by the IDS.
+ [x] Network packets are dropped if the volume exceeds the threshold.
+ [ ] Thresholding interferes with the IDS’ ability to reassemble fragmented packets.
+ [ ] The IDS will not distinguish among packets originating from different sources.
> **Explanation:**
> 

58.  A hacker, who posed as a heating and air conditioning specialist, was able to install a sniffer program in a switched environment network. Which attack could have been used by the hacker to sniff all of the packets in the network?
+ [ ] Fraggle attack
+ [ ] MAC flood attack
+ [ ] Smurf attack
+ [x] Teardrop attack
> **Explanation:**
> 

59.  Mike, a network administrator in a major IT firm, was asked to test the web server infrastructure for any mis-configuration, outdated content, and known vulnerabilities. Which of the following vulnerability assessment types he uses to perform the test?
+ [ ] Network assessments
+ [ ] Host-based assessment
+ [x] Application assessment
+ [ ] External assessment
> **Explanation:**
> 

60.  A Network Administrator was recently promoted to Chief Security Officer at a local university. One of employee's new responsibilities is to manage the implementation of an RFID card access system to a new server room on campus. The server room will house student enrollment information that is securely backed up to an off-site location.
    During a meeting with an outside consultant, the Chief Security Officer explains that he is concerned that the existing security controls have not been designed properly. Currently, the Network Administrator is responsible for approving and issuing RFID card access to the server room, as well as reviewing the electronic access logs on a weekly basis.
    Which of the following is an issue with the situation?
+ [x] Segregation of duties.
+ [ ] Undue influence.
+ [ ] Lack of experience.
+ [ ] Inadequate disaster recovery plan.
> **Explanation:**
> 

61.  A network administrator received an administrative alert at 3:00 a.m. from the intrusion detection system. The alert was generated because a large number of packets were coming into the network over ports 20 and 21. During analysis, there were no signs of attack on the FTP servers. How should the administrator classify this situation?
+ [ ] True negatives
+ [ ] False negatives
+ [ ] True positives
+ [x] False positives
> **Explanation:**
> 

62.  A pentester is using Metasploit to exploit an FTP server and pivot to a LAN. How will the pentester pivot useMetasploit?
+ [ ] Issue the pivot exploit and set the meterpreter.
+ [ ] Reconfigure the network settings in the meterpreter
+ [x] Set the payload to propagate through the meterpreter.
+ [ ] Create a route statement in the meterpreter.
> **Explanation:**
> 

63.  What statement is true regarding LAN Manager (LM) hashes?
+ [ ] LM hashes consist in 48 hexadecimal characters.
+ [ ] LM hashes are based on AES128 cryptographic standard.
+ [ ] Uppercase characters in the password are converted to lowercase.
+ [x] LM hashes limit the password length to a maximum of 14 characters.
> **Explanation:**
> 

64.  How does an operating system protect the passwords used for account logins?
+ [x] The operating system performs a one-way hash of the passwords.
+ [ ] The operating system stores the passwords in a secret file that users cannot find.
+ [ ] The operating system encrypts the passwords, and decrypts them when needed.
+ [ ] The operating system stores all passwords in a protected segment of non-volatile memory.
> **Explanation:**
> 

65. 

Nick is a novice attacker is trying to gain unauthorized access to an IoT infrastructure. He used various automated tools such as port scanners and fuzzers to detect open ports in the IoT devices. Now, he is trying to exploit the open ports to gain unauthorized access to the infrastructure.
    In the above situation, which of the following IoT vulnerability Nick is trying to exploit?
+ [ ] Insecure Web Interface
+ [ ] Insufficient Authentication/ Authorization
+ [x] Insecure Network Service
+ [ ] Insecure Mobile Interface
> **Explanation:**
> 

66. 

Alice is a penetration tester in one of the IT organization; she wanted to secure her organization from various attacks and vulnerabilities. She thought of performing various tests for vulnerabilities on the network by using social engineering toolkit. Social-Engineer Toolkit is an open-source Python-driven tool aimed at penetration testing around Social-Engineering. Alice want to obtain user names and passwords to test network security. Alice wants to draft email messages and attach malicious files and send this mail to large number of people to test whether the organization is secure or not. Identify the attack which Alice wanted to perform.
+ [ ] DoS attack
+ [ ] Trojan attacks
+ [ ] Sniffer Attack
+ [x] Spear phishing attack
> **Explanation:**
> 

67.  Which command lets a tester enumerate live systems in a class C network via ICMP using native Windows tools?
+ [ ] `ping 192.168.2.`
+ [ ] `ping 192.168.2.255`
+ [ ] `for %V in (1 1 255) do PING 192.168.2.%V`
+ [x] `for /L %V in (1 1 254) do PING -n 1 192.168.2.%V | FIND /I "Reply"`
> **Explanation:**
> 

68. 

CEH10/8/O1/1.   A hacker was able to sniff packets on a company’s wireless network. The following information was discovered: the Key10110010 01001011 andthe Ciphertext01100101 01011010.

Using the exclusive OR function, what was the original message?
+ [ ] 00101000 11101110
+ [x] 11010111 00010001
+ [ ] 00001101 10100100
+ [ ] 11110010 01011011
> **Explanation:**
> 

69.  Information gathered from social networking websites such as Facebook, Twitter and LinkedIn can be used to launch which of the following types of attacks? (Choose two.)
+ [ ] Smurf attack
+ [x] Social engineering attack
+ [ ] SQL injection attack
+ [x] Phishing attack
+ [ ] Fraggle attack
+ [ ] Distributed denial of service attack
> **Explanation:**
> 

70.  Which of the following attack vectors is a network attack in which an unauthorized person gains access to a network and stays there undetected for a long period of time. The intention of this attack is to steal data rather than to cause damage to the network or organization.
+ [x] Advanced Persistent Threats
+ [ ] Mobile Threats
+ [ ] Botnet
+ [ ] Insider Attack
> **Explanation:**
> 

71. In a mobile computing environment, when a mobile user sends a service request (ID and location) for any cloud service, that information is transmitted to a central processor of the mobile network service provider’s server. Once request is received, the cloud processes the requests and delivers the required services to the user.
    Which of the following cloud entities is responsible for processing the user’s request and delivering the required services to the end user in the cloud?
+ [x] Cloud Manager
+ [ ] Load balancer
+ [ ] Cloud Controller
+ [ ] Base Transceiver Station (BTS)
> **Explanation:**
> 

72.  A developer for a company is tasked with creating a program that will allow customers to update their billing and shipping information. The billing address field used is limited to 50 characters. What pseudo code would the developer use to avoid a buffer overflow attack on the billing address field?
+ [ ] if (billingAddress = 50) {update field} else exit
+ [ ] if (billingAddress != 50) {update field} else exit
+ [ ] if (billingAddress >= 50) {update field} else exit
+ [x] if (billingAddress <= 50) {update field} else exit
> **Explanation:**
> 

73.  How can rainbow tables be defeated?
+ [ ] Password salting
+ [x] Use of non-dictionary words
+ [ ] All uppercase character passwords
+ [ ] Lockout accounts under brute force password cracking attempts
> **Explanation:**
> 

74.  When analyzing the IDS logs, the system administrator notices connections from outside of the LAN have been sending packets where the Source IP address and Destination IP address are the same. But no alerts have been sent via email or logged in the IDS. Which type of an alert is this?
+ [ ] False positive
+ [x] False negative
+ [ ] True positive
+ [ ] True negative
> **Explanation:**
> 

75. Which NMAP feature can a tester implement or adjust while scanning for open ports to avoid detection by the network’s IDS?
+ [x] Timing options to slow the speed that the port scan is conducted.
+ [ ] Fingerprinting to identify which operating systems are running on the network.
+ [ ] ICMP ping sweep to determine which hosts on the network are not available.
+ [ ] Traceroute to control the path of the packets sent during the scan.
> **Explanation:**
> 

76.  Which of the following techniques does a vulnerability scanner use in order to detect a vulnerability on a target service?
+ [ ] Port scanning
+ [x] Banner grabbing
+ [ ] Injecting arbitrary data
+ [ ] Analyzing service response
> **Explanation:**
> 

77. Which of the following is an active reconnaissance technique?
+ [ ] Collecting information about a target from search engines.
+ [ ] Performing dumpster diving.
+ [x] Scanning a system by using tools to detect open ports.
+ [ ] Collecting contact information from yellow pages.
> **Explanation:**
> 

78.  Which of the following is a preventive control?
+ [ ] Smart card authentication
+ [x] Security policy
+ [ ] Audit trail
+ [ ] Continuity of operations plan
> **Explanation:**
> 

79.  Wilson, a cloud security advisor is working with the TheBestCloud, Inc. Wilson is closely monitoring the company’s cloud network on a regular basis. He observed that sometimes the cloud network gets overloaded and there is an increase in the response time. Wilson addresses this issue to higher management and suggests that the company needs to implement a load-balancing mechanism in the cloud environment.
    The management gives him permission to implement load balancing in the network. He is using a load-balancing algorithm in which a list of available servers is maintained and each server’s turn comes one after the other. The traffic is forwarded according to the list.
    Which of the following load balancing algorithms is Wilson using to fix this issue?
+ [ ] Random
+ [x] Round Robin
+ [ ] Weighted Round Robin
+ [ ] Least Connections
> **Explanation:**
> 

80.  Which of the statements concerning proxy firewalls is correct?
+ [ ] Proxy firewalls increase the speed and functionality of a network.
+ [ ] Firewall proxy servers decentralize all activity for an application.
+ [ ] Proxy firewalls block network packets from passing to and from a protected network.
+ [x] Computers establish a connection with a proxy firewall that initiates a new network connection for the client.
> **Explanation:**
> 

81.  Which statement best describes a server type under an N-tier architecture?
+ [x] A group of servers at a specific layer.
+ [ ] A single server with a specific role.
+ [ ] A group of servers with a unique role.
+ [ ] A single server at a specific layer.
> **Explanation:**
> 

82.  Nessus vulnerability scanner enables network connections and allows a remote connection to it from its remote clients and runs the “scan server configuration”. This will allow the port and bound interface of the Nessus daemon to be configured. What is the default port on which the Nessus daemon listens to the connections?
+ [ ] It listens to the connections on the default port 1241
+ [ ] It listens to the connections on the default port 1246
+ [x] It listens to the connections on the default port 1341
+ [ ] It listens to the connections on the default port 1441
> **Explanation:**
> 

83.  In which of the following attack the practice of spying on the user of a cash-dispensing machine or other electronic device is performed in order to obtain their personal identification number, password, and so on?
+ [ ] Eavesdropping
+ [ ] Piggybacking
+ [ ] Tailgating
+ [x] Shoulder surfing
> **Explanation:**
> 

84.  The intrusion detection system at a software development company suddenly generates multiple alerts regarding attacks against the company's external webserver, VPN concentrator, and DNS servers.  What should the security team do to determine which alerts to check first?
+ [ ] Investigate based on the maintenance schedule of the affected systems.
+ [ ] Investigate based on the service level agreements of the systems.
+ [x] Investigate based on the potential effect of the incident.
+ [ ] Investigate based on the order that the alerts arrived in.
> **Explanation:**
> 

85.  A company is using Windows Server 2003 for its Active Directory (AD). What is the most efficient way to crack the passwords for the AD users?
+ [ ] Perform a dictionary attack.
+ [ ] Perform a brute force attack.
+ [x] Perform an attack with a rainbow table.
+ [ ] Perform a hybrid attack.
> **Explanation:**
> 

86.  A company has publicly hosted web applications and an internal Intranet protected by a firewall. Which technique will help protect against enumeration?
+ [ ] Reject all invalid email received via SMTP.
+ [ ] Allow full DNS zone transfers
+ [x] Remove records for internal hosts.
+ [ ] Enable null session pipes.
> **Explanation:**
> 

87.  A network security administrator is worried about potential man-in-the-middle attacks when users access a corporate web site from their workstations. Which of the following is the best remediation against this type of attack?
+ [ ] Implementing server-side PKI certificates for all connections
+ [ ] Mandating only client-side PKI certificates for all connections
+ [x] Requiring client and server PKI certificates for all connections
+ [ ] Requiring strong authentication for all DNS queries
> **Explanation:**
> 

88.  Least privilege is a security concept,which requires that a user is….
+ [x] Limited to those functions which are required to do the job.
+ [ ] Given root or administrative privileges.
+ [ ] Trusted to keep all data and access to that data under their sole control.
+ [ ] Given privileges equal to everyone else in the department.
> **Explanation:**
> 

89.  John the Ripper is a technical assessment tool used to test the weakness of which of the following?
+ [ ] Usernames
+ [ ] File permissions
+ [ ] Firewall rulesets
+ [x] Passwords
> **Explanation:**
> 

90.  Which of the following network attacks relies on sending an abnormally large packet size that exceeds TCP/IP specifications?
+ [x] Ping of death
+ [ ] SYN flooding
+ [ ] TCP hijacking
+ [ ] Smurf attack
> **Explanation:**
> 

91.  Some passwords are stored using specialized encryption algorithms known as hashes. Why is this an appropriate method?
+ [ ] It is impossible to crack hashed user passwords unless the key used to encrypt them is obtained.
+ [ ] If a user forgets the password, it can be easily retrieved using the hash key stored by administrators.
+ [ ] Hashing is faster as compared to more traditional encryption algorithms.
+ [x] Passwords stored using hashes are non-reversible, making finding the password much more difficult.
> **Explanation:**
> 

92.  Which of the following can the administrator do to verify that a tape backup can be recovered in its entirety?
+ [ ] Restore a random file.
+ [x] Perform a full restore.
+ [ ] Read the first 512 bytes of the tape.
+ [ ] Read the last 512 bytes of the tape.
> **Explanation:**
> 

93.  Which of the following open source tools would be the best choice to scan a network for potential targets?
+ [x] NMAP
+ [ ] NIKTO
+ [ ] CAIN
+ [ ] John the Ripper
> **Explanation:**
> 

94.  Which of the following types of firewall inspects only header information in network traffic?
+ [x] Packet filter
+ [ ] Stateful inspection
+ [ ] Circuit-level gateway
+ [ ] Application-level gateway
> **Explanation:**
> 

95. Daniel was frustrated with his competitor, Xsecurity Inc., and decided to launch an attack that would result in serious financial losses. He planned the attack carefully and carried out the attack at the appropriate moment. Meanwhile, Joseph, an administrator at Xsecurity Inc., realized that their main financial transaction server had been attacked. As a result of the attack, the server crashed and Joseph needed to reboot the system. To his dismay, Joseph was not able to even reboot system with the primary diagnostics showing that the hardware firmware is corrupted. What kind of Denial of Service attack was best illustrated in the scenario above?
+ [ ] Fragmentation Attack
+ [x] Multi-Vector Denial-of-Service Attack
+ [ ] Peer-to-Peer Denial-of-Service Attack
+ [ ] Permanent Denial-of-Service Attack
> **Explanation:**
> 

96.  Diffie-Hellman (DH) groups determine the strength of the key used in the key exchange process.  Which of the following is the correct bit size of the Diffie-Hellman (DH) group 5?
+ [ ] 768 bit key
+ [ ] 1025 bit key
+ [x] 1536 bit key
+ [ ] 2048 bit key
> **Explanation:**
> 

97. A bank stores and processes sensitive privacy information related to home loans. However, auditing has never been enabled on the system. What is the first step that the bank should take before enabling the audit feature?
+ [ ] Perform a vulnerability scan of the system.
+ [ ] Determine the impact of enabling the audit feature.
+ [x] Perform a cost/benefit analysis of the audit feature.
+ [ ] Allocate funds for staffing of audit log review.
> **Explanation:**
> 

98.  Which technology do SOAP services use to format information?
+ [ ] SATA
+ [ ] PCI
+ [x] XML
+ [ ] ISDN
> **Explanation:**
> 

99.  What technique is used to perform a Connection Stream Parameter Pollution (CSPP) attack?
+ [ ] Injecting parameters into a connection string using semicolons as a separator.
+ [x] Inserting malicious Javascript code into input parameters.
+ [ ] Setting a user's session identifier (SID) to an explicit known value.
+ [ ] Adding multiple parameters with the same name in HTTP requests.
> **Explanation:**
> 

100.  What is the best defense against privilege escalation vulnerability?
+ [ ] Patch systems regularly and upgrade interactive login privileges at the system administrator level.
+ [ ] Run administrator and applications on least privileges and use a content registry for tracking.
+ [x] Run services with least privileged accounts and implement multi-factor authentication and authorization.
+ [ ] Review user roles and administrator privileges for maximum utilization of automation services.
> **Explanation:**
> 

101. 

Sean is white hat hacker, who is demonstrating a network level session hijack attacks and as part of it, he has injected malicious data into the intercepted communications in the TCP session when the victim had disabled the source-routing.
    Which of the following network level session hijacking attack is Sean showing?
+ [ ] RST Hijacking
+ [x] TCP/IP Hijacking
+ [ ] Blind Hijacking
+ [ ] UDP Hijacking
> **Explanation:**
> 

102.  Which of the following settings enables Nessus to detect when it is sending too many packets and the network pipe is approaching capacity?
+ [ ] Netstat WMI Scan
+ [ ] Silent Dependencies
+ [ ] Consider unscanned ports as closed
+ [x] Reduce parallel connections on congestion
> **Explanation:**
> 

103.  Which of the following steps in enumeration penetration testing extracts information about encryption and hashing algorithms, authentication types, key distribution algorithms, SA LifeDuration, etc.?
+ [ ] Perform SMTP enumeration
+ [x] Perform DNS enumeration
+ [ ] Perform IPsec enumeration
+ [ ] Perform NTP enumeration
> **Explanation:**
> 

104.  Which of the following is used to indicate a single-line comment in structured query language (SQL)?
+ [x] --
+ [ ] ||
+ [ ] %%
+ [ ] ''
> **Explanation:**
> 

105.  A company has hired a security administrator to maintain and administer Linux and Windows-based systems. Written in the nightly report file is the following: 
    Firewall log files are at the expected value of 4 MB. The current time is 12am. Exactly two hours later the size has decreased considerably.  Another hour goes by and the log files have shrunk in size again. 
    Which of the following actions should the security administrator take?
+ [x] Log the event as a suspicious activity and report this behavior to the incident response team immediately.
+ [ ] Log the event as a suspicious activity, call a manager, and report this as soon as possible.
+ [ ] Run an anti-virus scan because it is likely that the system is infected by malware.
+ [ ] Log the event as a suspicious activity, continue to investigate, and act according to the site's security policy.
> **Explanation:**
> 

106.  Company A and Company B have just merged and each has its own Public Key Infrastructure (PKI). What must the Certificate Authorities (CAs) establish so that the private PKIs for Company A and Company B trust one another and each private PKI can validate digital certificates from the other company?
+ [ ] Poly key exchange
+ [x] Cross certification
+ [ ] Poly key reference
+ [ ] Cross-site scripting
> **Explanation:**
> 

107.  While performing data validation of web content, a security technician is required to restrict malicious input. Which of the following processes is an efficient way of restricting malicious input?
+ [ ] Validate web content input for query strings.
+ [ ] Validate web content input with scanning tools.
+ [x] Validate web content input for type, length, and range.
+ [ ] Validate web content input for extraneous queries.
> **Explanation:**
> 

108.  Which of the following techniques can be used to mitigate the risk of an on-site attacker from connecting to an unused network port and gaining full access to the network? (Choose two)
+ [ ] Port Security
+ [ ] IPSec Encryption
+ [x] Network Admission Control (NAC)
+ [ ] Vulnerability Assessment
> **Explanation:**
> 

109.  Yancey is a network security administrator for a large electric company. This company provides power for over 100,000 people in Las Vegas. Yancey has worked for his company for over 15 years and has become very successful. One day, Yancey comes in to work and finds out that the company will be downsizing and he will be out of a job in two weeks. Yancey is very angry and decides to place logic bombs, viruses, Trojans, and backdoors all over the network to take down the company once he has left. Yancey does not care if his actions land him in jail for 30 or more years; he just wants the company to pay for what they are doing to him. What would Yancey be considered?
+ [x] Yancey would be considered a Suicide Hacker
+ [ ] Since he does not care about going to jail, he would be considered a Black Hat.
+ [ ] Because Yancey works for the company currently; he would be a White Hat.
+ [ ] Yancey is a Hacktivist Hacker since he is standing up to a company that is downsizing
> **Explanation:**
> 

110.  A consultant has been hired by the V.P. of a large financial organization to assess the company's security posture. During the security testing, the consultant comes across child pornography on the V.P.'s computer. What is the consultant's obligation to the financial organization?
+ [x] Say nothing and continue with the security testing.
+ [ ] Stop work immediately and contact the authorities.
+ [ ] Delete the pornography, say nothing, and continue security testing.
+ [ ] Bring the discovery to the financial organization's human resource department.
> **Explanation:**
> 

111.  If an e-commerce site was put into a live environment and the programmers failed to remove the secret entry point that was used during the application development, what is this secret entry point known as?
+ [ ] SDLC process
+ [ ] Honey pot
+ [ ] SQL injection
+ [x] Trap door
> **Explanation:**
> 

112.  Which of the following DNS poisoning techniques uses ARP poisoning against switches to manipulate routing table?
+ [x] Intranet DNS Spoofing
+ [ ] Internet DNS Spoofing
+ [ ] Proxy Server DNS Poisoning
+ [ ] DNS Cache Poisoning
> **Explanation:**
> 

113.  Which of the following defines the role of a root Certificate Authority (CA) in a Public Key Infrastructure (PKI)?
+ [ ] The root CA is the recovery agent used to encrypt data when a user's certificate is lost.
+ [ ] The root CA stores the user's hash value for safekeeping.
+ [x] The CA is the trusted root that issues certificates.
+ [ ] The root CA is used to encrypt email messages to prevent unintended disclosure of data.
> **Explanation:**
> 

114.  A pentester gains acess to a Windows application server and needs to determine the settings of the built-in Windows firewall. Which command would be used?
+ [x] Netsh firewall show config
+ [ ] WMIC firewall show config
+ [ ] Net firewall show config
+ [ ] Ipconfig firewall show config
> **Explanation:**
> 

115.  A technician is resolving an issue where a computer is unable to connect to the Internet using a wireless access point. The computer is able to transfer files locally to other machines, but cannot successfully reach the Internet. When the technician examines the IP address and default gateway they are both on the 192.168.1.0/24. Which of the following has occurred?
+ [x] The gateway is not routing to a public IP address.
+ [ ] The computer is using an invalid IP address.
+ [ ] The gateway and the computer are not on the same network.
+ [ ] The computer is not using a private IP address.
> **Explanation:**
> 

116.  XSecurity.com, a UK-based cloud service provider hired Paul Marsh, a renowned cloud security engineer and auditor. The company wants to increase the essential security, manageability, and flexibility in an IT environment, which enables the transition to cloud computing.
    Paul was asked to create a virtual infrastructure where a hypervisor provides a complete simulation of the underlying hardware. In addition, each virtual server is completely independent and unaware of the other virtual servers running on the physical machine.
    Which of the following virtualization techniques will Paul use to create the virtual machines based on the requirements above?
+ [ ] Full Virtualization
+ [x] Para Virtualization
+ [ ] Partial virtualization
+ [ ] OS-level virtualization
> **Explanation:**
> 

117.  Which fundamental element of information security refers to an assurance that the information is accessible only to those authorized to have access?
+ [x] Confidentiality
+ [ ] Integrity
+ [ ] Availability
+ [ ] Authenticity
> **Explanation:**
> 

118.  A certified ethical hacker (CEH) completed a penetration test of the main headquarters of a company almost two months ago, but has yet to get paid. The customer is suffering from financial problems, and the CEH is worried that the company will go out of business and end up not paying. What actions should the CEH take?
+ [ ] Threaten to publish the penetration test results if not paid.
+ [x] Follow proper legal procedures against the company to request payment.
+ [ ] Tell other customers of the financial problems with payments from this company.
+ [ ] Exploit some of the vulnerabilities found on the company webserver to deface it
> **Explanation:**
> 

119.  A computer technician is using a new version of a word processing software package when it is discovered that a special sequence of characters causes the entire computer to crash. The technician researches the bug and discovers that no one else has experienced the problem. What is the appropriate next step?
+ [ ] Ignore the problem completely and let someone else deal with it.
+ [ ] Create a document that will crash the computer when opened and send it to friends.
+ [ ] Find an underground bulletin board and attempt to sell the bug to the highest bidder.
+ [x] Notify the vendor of the bug and do not disclose it until the vendor gets a chance to issue a fix.
> **Explanation:**
> 

120.  How can telnet be used to fingerprint a web server?
+ [x] telnet webserverAddress 80 HEAD / HTTP/1.0
+ [ ] telnet webserverAddress 80 PUT / HTTP/1.0
+ [ ] telnet webserverAddress 80 HEAD / HTTP/2.0
+ [ ] telnet webserverAddress 80 PUT / HTTP/2.0
> **Explanation:**
> 

121.  Which of the following is an example of two factor authentication?
+ [ ] PIN Number and Birth Date
+ [ ] Username and Password
+ [ ] Digital Certificate and Hardware Token
+ [x] Fingerprint and Smartcard ID
> **Explanation:**
> 

122.  Which of the following business challenges could be solved by using a vulnerability scanner?
+ [ ] Auditors want to discover if all systems are following a standard naming convention.
+ [x] A web server was compromised and management needs to know if any further systems were compromised.
+ [ ] There is an urgent need to remove administrator access from multiple machines for an employee that quit.
+ [ ] There is a monthly requirement to test corporate compliance with host application usage and security policies.
> **Explanation:**
> 

123.  Which component of the malware conceals the malicious code of malware via various techniques, thus making it hard for security mechanisms to detect or remove it?
+ [ ] Downloader
+ [ ] Crypter
+ [x] Obfuscator
+ [ ] Payload
> **Explanation:**
> 

124.  Adam, a web server administrator, was browsing his company’s site; he surprisingly experienced a change in the visual appearance of his company’s site. After initial analysis of the incident, he realized that their webserver’s security is compromised and the attacker has replaced the hosted webpage in the website directory with their page.
Identify the website attack in above scenario.
+ [x] Defacement attack
+ [ ] Directory traversing attack
+ [ ] DoS Attack
+ [ ] Cross Site Scripting attack
> **Explanation:**
> 

125.  John is black hat hacker, who is trying to hack the company’s web server. As part of it, he decided to copy an entire website and its content onto the local drive to get the information about site’s directory structure, file structure, external links, images, web pages, and so on.
    Which of the following tool does John need to use to this?
+ [x] HTTrack
+ [ ] Nikto2
+ [ ] Nessus
+ [ ] Paros
> **Explanation:**
> 

126. 
