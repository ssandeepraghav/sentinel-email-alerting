# Automated SIEM Security Email Alerting using Microsoft Sentinel

> A fully automatic pipeline that detects Windows security incidents in Microsoft Sentinel and sends a customised HTML alert email, with no analyst action. Project report (M.Tech thesis) in Markdown form.

**Stack:** Microsoft Sentinel · Azure Monitor Agent · KQL · Logic Apps · SMTP · Sentinel Workbooks

## Contents

- [Abstract](#abstract)
- [Abbreviations](#abbreviations)
- [1. Introduction](#1-introduction)
- [2. Literature Review](#2-literature-review)
- [3. Methodology](#3-methodology)
- [4. Results and Discussion](#4-results-and-discussion)
- [5. Conclusions and Future Directions](#5-conclusions-and-future-directions)
- [Appendix A: Queries and Playbook Configuration](#appendix-a-queries-and-playbook-configuration)
- [References](#references)

---

## Abstract

Security Information and Event Management (SIEM) tools detect suspicious activity, but their alert emails are often fixed in format, so SOC analysts reformat them by hand before sending them to clients. A recent paper proposes a web tool in which an analyst exports logs to Excel, uploads them and fills a form to send a customised email; this still needs a person for every alert.

This thesis replaces that manual workflow with an automatic pipeline in Microsoft Sentinel. Security events from a Windows virtual machine are collected with the Azure Monitor Agent. Three scheduled analytics rules detect RDP brute force, a successful login after a brute force, and creation of a new local user. Each incident triggers an automation rule and a Logic App playbook that extracts the attacker IP address, account and host and sends a styled HTML email through SMTP. A workbook shows incidents by severity, time, rule and attacker IP.

All three use cases produced an incident and an email in testing. The time from incident to email was about one minute with no human action, while the delay from event to incident was several minutes because of agent upload and the five-minute rule schedule. Alert grouping and suppression removed duplicate emails, and the Windows Security Events via AMA connector solved a problem with missing event 4720. The base paper gives no timing figures, so the manual time of about 8 to 13 minutes per alert is the author's estimate. The tests were single runs on one lab virtual machine.

**Keywords:** SIEM, Microsoft Sentinel, email alert, Logic App, KQL, RDP brute force, SOC automation

## Abbreviations

| Abbreviation | Meaning |
| --- | --- |
| **AI** | Artificial Intelligence |
| **AMA** | Azure Monitor Agent |
| **CTI** | Cyber Threat Intelligence |
| **IDS / IPS** | Intrusion Detection / Prevention System |
| **MFA** | Multi-Factor Authentication |
| **ML** | Machine Learning |
| **SOAR** | Security Orchestration, Automation and Response |
| **DCR** | Data Collection Rule |
| **KQL** | Kusto Query Language |
| **RDP** | Remote Desktop Protocol |
| **SIEM** | Security Information and Event Management |
| **SMTP** | Simple Mail Transfer Protocol |
| **SOC** | Security Operations Centre |
| **UTC** | Coordinated Universal Time |
| **IST** | Indian Standard Time (UTC+5:30) |
| **VM** | Virtual Machine |

## 1. Introduction

### 1.1 Motivation and Overview

Organisations rely on Security Information and Event Management (SIEM) platforms to collect logs from servers, endpoints and network devices, to detect suspicious activity, and to alert the people who must respond. A Security Operations Centre (SOC) analyst, however, rarely forwards the raw SIEM alert to a client. The client normally expects a formatted email that follows the SOC's own template and contains only the relevant details of the incident, such as the affected host, the source address and the account involved.

Many SIEM products send alert emails in a fixed format that cannot be edited, or provide no custom email feature at all. The base paper for this work, "Intelligent-based SIEM security email alert" [1], describes this problem and proposes a web tool in which an analyst exports logs to an Excel file, uploads the file, fills in a form and sends the formatted email. The tool removes copy-and-paste formatting, but every alert still depends on a person starting the process.

This thesis keeps the paper's goal, a customised and well-filtered security email, but replaces the manual Excel-upload and form workflow with a fully automatic pipeline built on Microsoft Sentinel. Windows security events are collected from a virtual machine, detection rules raise incidents, and an automation rule runs a Logic App playbook that sends a styled HTML email containing the attacker IP address, account, host and a link to the incident. A workbook dashboard summarises the incidents.

### 1.2 Issues and Challenges

- **Manual workflow.** In the base paper an analyst must export logs, upload them, fill a form and confirm sending for every alert, so the delay depends on analyst availability.
- **Fixed or missing email customisation.** Several SIEM products do not allow editing of alert emails [1].
- **Raw data in the email.** A usable alert should name the attacker IP, the account and the host rather than dump a log record.
- **Alert volume.** Rules that run on a schedule and look back over a time window can fire repeatedly for the same attack and flood the mailbox.
- **Data collection.** A detection rule works only if the required event types reach the SIEM; incorrect collection settings leave a rule silent.
- **Cost limits.** The work uses an Azure free account, so collection volume and virtual machine run time had to be controlled.

### 1.3 Objectives

- To replace the manual Excel-upload and form process of the base paper with automatic, incident-driven email alerting.
- To detect three attack scenarios on a Windows host: RDP brute force, a successful login after a brute force, and creation of a new local user.
- To send a customised HTML alert email containing the incident title, severity, time, attacker IP, account, host and a link to the incident.
- To present incident statistics in a workbook dashboard.
- To measure the delay from event to incident to email and compare it with the manual workflow of the base paper.

### 1.4 Contributions of the Thesis

- A working Microsoft Sentinel implementation with three scheduled analytics rules, one automation rule and one Logic App playbook.
- An HTML email template filled automatically from incident entities (IP addresses, accounts and hosts) using Select and Join steps.
- A tuning study showing how alert grouping and suppression remove duplicate incidents and emails.
- A fix for missing event 4720 collection by using the Windows Security Events via AMA connector.
- A measured timing comparison and a feature comparison with the manual workflow of the base paper.

### 1.5 Outline of Thesis

Chapter 2 reviews SIEM systems, compares existing products and analyses the base paper. Chapter 3 describes the proposed framework, lab environment, detection rules, playbook, email template and dashboard. Chapter 4 reports test results, issues found and the timing comparison. Chapter 5 concludes and lists future work. Appendix A gives the queries and playbook configuration.

## 2. Literature Review

### 2.1 Introduction

This chapter reviews the literature that motivates the thesis. Five papers are studied in detail: the base paper "Intelligent-based SIEM security email alert" [1], a comparative study of intrusion events in different SIEM systems [2], a study that combines artificial intelligence, SIEM, multi-factor authentication and incident response [3], a review of SIEM tools for cyber situation awareness [4], and a study of layered network security with Suricata, Wazuh and Splunk [5]. Each paper is summarised, its findings are discussed, and its relevance to this work is stated. Ten further works that these papers cite, covering SIEM integration, security orchestration, open-source SIEM tools and situation awareness, are used in the discussion [6]-[15]. The chapter ends with a comparison table and the research gap.

### 2.2 Security Information and Event Management

A SIEM combines security information management, which collects and stores log data, with security event management, which monitors in real time, raises notifications and correlates events [1]. A typical SIEM gathers logs from hosts, software and devices, places them in a central platform, classifies them (for example successful or failed logins) and generates alerts when predefined rules are met [1]. Unal et al. describe the same processing chain as collection, normalisation, correlation and alerting to an analyst, and place SIEM in the perceive, comprehend, project and resolve steps of cyber situation awareness [4].

Several works stress that a SIEM is rarely used alone. Sridharan and Kanchana discuss the integration of SIEM with security orchestration, automation and response (SOAR), where the SIEM detects and the SOAR layer automates the response [6]. Muhammad et al. integrate a SIEM with an intrusion detection system (IDS) that acts as a sensor and uses machine learning for live analysis [7]. Ayu et al. add machine learning to a SIEM to improve attack detection, because rule-based systems can miss attacks and produce many false positives [8]. Lekidis et al. study incident response orchestration and automation for an advanced metering infrastructure, where data must be visible in real time [12]. Tilbury and Flowerday examine how automation can support human analysts in security operations centres [13]. Common to these works is the view that detection alone is not enough; the alert must reach the responsible person quickly and in a usable form.

### 2.3 Comparison of Existing SIEM Products

The base paper compares seven SIEM products on real-time monitoring, compliance reporting, notification type and customisable email alerts [1]. Table 2.1 reproduces that comparison. Three products have no customisable email alerts, and the products that do offer them use fixed templates that may not match a SOC's operating manual.

**Table 2.1: Comparison of SIEM brands (adapted from [1])**

| **SIEM model** | **Real-time monitoring** | **Compliance reporting** | **Alert notification type** | **Customisable email alerts** |
| --- | --- | --- | --- | --- |
| IBM Security QRadar | Capable | Not capable | Email, MS Teams, SMS, Telegram | Not capable |
| SolarWinds Security Event Manager | Capable | Capable | Email | Capable |
| Splunk Enterprise Security | Capable | Capable | Email | Capable |
| ArcSight Enterprise Security Manager | Capable | Capable | Not capable | Capable |
| LogRhythm NextGen SIEM | Capable | Capable | Email, SMS | Not capable |
| Exabeam Fusion SIEM | Not capable | Capable | Email, security dashboard | Capable |
| Rapid7 InsightIDR | Capable | Not capable | Email | Not capable |

### 2.4 Intelligent-based SIEM security email alert

The base paper, "Intelligent-based SIEM security email alert" by Chi et al. [1], was presented at the 11th International Conference on Information and Communication Technology (ICoICT) in 2023 and developed with TM One, a Malaysian telecommunications company. It addresses a practical problem in SOC work. Alerts produced by a SIEM are raw and unformatted, so analysts must copy information from several sources and rewrite it in the client's email format before sending it. The authors note that this is tedious, can introduce human error, and becomes a serious problem when a client needs an alert immediately. They also observe that most SIEM products offer either no email customisation or a fixed template, which is the point of their comparison in Table 2.1.

**Proposed system.** The system is a web application with six steps. In step 1 the user selects a log file and extracts its content, which is shown in a table. In step 2 the user enters the recipient addresses, either as "TO" (a direct action) or "CC" (for information only). In step 3 the user completes dropdown settings and filling information that will appear in the email. In step 4 the user confirms the entries and may save them as a setting file on the local device, so that the same inputs need not be typed again. In step 5 the system converts the raw log data and the user inputs into the company's email template and shows a preview. In step 6 the user submits the email, and the screen reports whether sending succeeded.

**Implementation.** The front end uses HTML, CSS and JavaScript, and the server side uses PHP with the PHPMailer library to send mail over SMTP. Two algorithms are given as pseudocode. Algorithm I checks that the uploaded file is an .xlsx or .xls file, reads it with a spreadsheet library, converts the sheet to JSON and builds an HTML table that is shown on the page and stored in session storage. Algorithm II reads the receiver and CC lists, sets the SMTP host, port 587 and TLS, adds the subject, the HTML body and embedded header and footer images, sends the message, and prints a success or error status. The pseudocode sets the SMTP account details directly in the program, which is not a safe way to store credentials.

**Evaluation.** The paper tests three combinations of browser, log type and receiving mail platform (Table 2.2). In each case the log data was extracted and the generated email arrived with the extracted content. The third test uses a Remote Desktop Protocol brute force log, which is the same attack type as use case 1 of this thesis. The authors report that the prototype was tried by TM One.

**Table 2.2: Test cases reported in the base paper [1]**

| **Case** | **Browser** | **Log data type** | **Receiver platform** |
| --- | --- | --- | --- |
| 1 | Google Chrome | D-Link DCS-2530L information disclosure vulnerability | Gmail |
| 2 | Firefox | Log4j zero-day vulnerability containing SSL | Yahoo Mail |
| 3 | Microsoft Edge | SERVER-OTHER Remote Desktop Protocol brute force attempt | Microsoft Outlook |

**Discussion.** The strength of the paper is that it solves a real SOC problem and shows that the generated email works across browsers and mail services. Its weaknesses are also clear. The tool formats and sends logs that already exist and does not detect anything. Every alert still needs a person to export the log, upload it and fill in the form, so the delay depends on the analyst. The paper does not measure time, error rates or the effort saved, so the claimed benefit is qualitative. The authors themselves state that the system runs only in a browser and accepts only Excel files. These limits define the starting point of this thesis: keep the idea of a customised email, but remove the manual steps.

**Design choices in the base paper.** The first page offers three controls: "Choose File" opens the file dialogue, "Extraction" reads the selected file, and "Cancel" clears the screen so a new log can be chosen. The flowchart in the paper shows decision points after each stage, for example whether the log data is correct, whether to proceed with extraction, and whether to save the current settings. When the user chooses to save, the setting file is stored in a directory on the user's own device by a PHP script, so the shortcut is local to one analyst and is not shared with the team. The confirmation page converts the raw data and the inputs into the email template, and the user can go back to the settings page if the preview is wrong. These choices give the analyst full control, which is the strength of the tool, but they also mean that every alert passes through the same sequence of clicks.

**Mapping the manual steps to this thesis.** Each manual step of the base paper has an automatic counterpart in the pipeline built here. Exporting the log to Excel corresponds to the Azure Monitor Agent sending events to the workspace. Uploading and extracting the file corresponds to the analytics rule that parses the event and extracts the IP address, account and host. Entering the recipient addresses corresponds to the fixed address in the playbook connection. Filling the dropdown and filling information corresponds to the template expressions that read the incident title, severity, time and entities. The preview and submit steps correspond to the playbook run and the SMTP send action. What is lost in the exchange is the analyst's ability to edit the content before it is sent, which is discussed as a limitation in Chapter 4.

### 2.5 Comparison of Open-Source SIEM Systems

Andronache, Vulpe and Burileanu, "A comparative study of intrusion events in different SIEM systems" [2], was presented at the IEEE SAMI 2025 symposium. The authors observe that attacks are increasingly hard to follow in large networks, that operating systems behave differently under attack, and that SOC teams cannot track every event by hand. They compare three open-source SIEM systems, Wazuh, OSSIM and OSSEC, by installing each with a Windows 10 agent and an Ubuntu 22.04 agent in the same network and attacking the agents from Kali Linux.

**Related work cited.** The paper reviews earlier work: a SIEM-based solution for industrial infrastructure with real-time counters and detection of man-in-the-middle, ARP spoofing and DDoS attacks [12]; a comparison of Wazuh, OSSIM and the ELK stack that concentrates on the choice of tool [9]; a dockerized Elastic Stack used as an intrusion detection SIEM with low latency and stable CPU and memory use [10]; and a comparative study of open-source SIEM solutions [11]. It also cites work on SIEM integration with SOAR [6], on SIEM with IDS and machine learning [7] and on adding machine learning to SIEM [8].

**Method.** Five attacks were run: a port scan with Nmap, phishing with the Social-Engineer Toolkit, a Metasploit reverse-shell payload, a brute force attack with Legion (which uses Nmap and Hydra), and a denial-of-service flood with hping3. The SIEM systems were used with default rules, because the aim was to see what each detects out of the box. The authors also scored the installation effort, documentation, real-time monitoring, alert generation, vulnerability scanning and scalability.

**Findings.** Table 2.3 summarises the detection results. Nmap scans were detected by all three systems and on both operating systems, although the alert wording differed. Wazuh detected all five attacks on the Windows agent and detected only the scan and phishing on the Ubuntu agent. OSSIM detected the scan on both agents and the brute force attack on Ubuntu. OSSEC detected only the scan. The authors conclude that detection of anything beyond basic scans needs additional rules, and that some events were not monitored even at the basic level. In the Windows tests, the antivirus program flagged the executable payload, but the SIEM dashboard did not.

**Table 2.3: Attack detection reported in [2] (Yes = detected by the SIEM)**

| **Attack** | **Wazuh Windows** | **Wazuh Ubuntu** | **OSSIM Windows** | **OSSIM Ubuntu** | **OSSEC Windows** | **OSSEC Ubuntu** |
| --- | --- | --- | --- | --- | --- | --- |
| Nmap scan | Yes | Yes | Yes | Yes | Yes | Yes |
| Phishing | Yes | Yes | No | No | No | No |
| Metasploit payload | Yes | No | No | No | No | No |
| Brute force | Yes | No | No | Yes | No | No |
| hping3 DoS | Yes | No | No | No | No | No |

**Practical observations.** OSSEC was the weakest: its dashboard did not work with the latest version, the agents disconnected repeatedly, and it lacked scalability. OSSIM was more stable and had useful alerts, but its documentation was limited. Wazuh was the best overall, with good documentation, a stable dashboard and automated response, but it needed more hardware, and its agent raised CPU and memory use. File integrity events in Wazuh were reported with a delay of one to two minutes. The authors also note that a SIEM records so many events that separating security events from ordinary ones becomes difficult. They plan to study post-attack analysis and sandboxing in future work.

**Relevance to this work.** Two points matter here. First, brute force detection varied between products and operating systems, and default rules were not enough, which supports writing explicit rules for brute force and successful login as done in this thesis. Second, the paper evaluates detection but not what happens after an alert: nobody is told in a usable form. The one to two minute reporting delay it observes is also a useful reference for the detection delays measured in Chapter 4.

**Tool descriptions and trade-offs.** Wazuh is described as focused on host-based intrusion detection, with traffic-pattern detection, file integrity monitoring and the ability to block traffic with deny rules for denial-of-service attacks. Its drawbacks are that it depends on the administrator's decisions rather than interpreting events on its own, and that it needs fairly large resources: a downloaded virtual machine is enough for a network of about ten devices, but larger networks need more. OSSEC also uses agents with separate policies for Windows and Linux and records unusual events, but if the administrator does not notice an alert in time the malicious file continues to spread, and the Wazuh project has absorbed OSSEC to ease migration. OSSIM (LevelBlue) provides an integrated intrusion detection platform, correlates events, can use Open Threat Exchange threat information, and works with LDAP and Active Directory. Vazão et al. [11], as cited in the paper, rate alert creation as of medium difficulty and agent installation as medium to difficult, and note that OSSIM cannot manage logs and is not scalable.

**Practical comparison tables.** In the paper's operating-mode table all three tools are open source, have a dashboard and use a manager and agents, and none was easy to configure at first. Only Wazuh had good documentation, because the OSSIM documentation is aimed at AT&T employees and the OSSEC documentation is old. In the capability table, Wazuh and OSSIM support simple and complex scenarios, scalability, integration with other platforms and automated response, while OSSEC supports only the simple scenarios. A test with four agents instead of two gave the same trend, with OSSEC blocking more often and leaving some attacks unrecorded. The authors also suggest segmenting the network so that each part has its own IDS, which lets the SIEM isolate a segment that produces a larger flow of events.

### 2.6 AI, SIEM, MFA and Incident Response

Pulivarthy, "Enhancing cybersecurity and IT service desk support with artificial intelligence, SIEM tools, MFA integration, and incident response" [3], was presented at ICICNIS 2025. The paper argues that earlier studies treat artificial intelligence, SIEM, multi-factor authentication (MFA) and incident response separately and rarely combine them, and that many approaches lack real-time automation, which makes detection and response slow.

**Literature discussed.** The paper reviews five areas. AI supports faster and more accurate threat detection and fewer false positives. SIEM tools collect, normalise and correlate logs, and adding machine learning improves detection of zero-day attacks. MFA reduces the success of phishing, brute force and credential stuffing attacks. Incident response plans reduce damage when detection, containment and recovery are well defined, and automated response, such as quarantining hosts or blocking IP addresses, reduces human effort and time. AI at the IT service desk can triage tickets and answer routine problems, leaving staff free for complex ones. The paper also mentions compliance with GDPR and HIPAA. It cites work on automation in security operations centres [13] and on SOAR architectures. The effect of automation on the analyst's workload is therefore a central theme.

**Proposed framework.** The architecture has four parts: an AI-based threat detection module that applies machine learning to user behaviour, network traffic and logs; SIEM integration, where the AI module passes alerts to the SIEM for correlation; an MFA system using biometrics, one-time passwords or hardware tokens; and an incident response module that isolates systems, blocks malicious IP addresses and alerts security staff. The paper defines three metrics: threat detection rate, TDR = TP / (TP + FN); incident response time, IRT = `T_response - T_detection`; and MFA success rate, the ratio of successful MFA authentications to all MFA attempts.

**Results.** Table 2.4 reproduces the comparison with traditional methods. The authors report a threat detection rate of 92% against 75%, an average incident response time of 7.2 minutes against 20 minutes, and an MFA success rate of 98.5% against 85%. They also report less time spent on manual security tasks after the system was introduced. The discussion admits that the system needs substantial computing resources and that integrating AI with SIEM and several authentication factors adds complexity.

**Table 2.4: Performance comparison reported in [3]**

| **Metric** | **Proposed approach** | **Traditional methods** | **Change** |
| --- | --- | --- | --- |
| Threat detection rate | 92% | 75% | +17% |
| Incident response time | 7.2 minutes | 20 minutes | -12.8 minutes |
| MFA success rate | 98.5% | 85% | +13.5% |

**Critical view.** The paper is useful because it measures response time and links automation to a drop in that time. Its experimental description is brief, however. It says the system ran in a real-time network environment with security event logs and traffic data but does not give the size of the data, the number of incidents or how the traditional baseline was measured, so the numbers cannot be reproduced. It also concentrates on machine learning detection rather than on how the alert is communicated to a person.

**Relevance to this work.** The incident response time metric is close to the alerting delay measured in this thesis, and the 7.2 against 20 minute result gives context for expecting minutes rather than hours from an automated pipeline. The paper supports the argument that automation reduces human intervention, but it leaves the final delivery of the alert unspecified, which this thesis implements as a customised email.

**Experimental set-up and metrics.** The experiment is described as a real-time network environment that uses security event logs and system traffic data, and it tests detection accuracy, incident response time and MFA effectiveness. The parameters named are the thresholds for anomaly detection, the incident response times and the MFA settings such as biometrics and one-time passwords. The data collection step gathers event information from networked devices, retry records of users and server traffic. When a threat is detected the SIEM analyses it in the context of the whole network to judge its size, and then malicious IP addresses are blacklisted, the network is isolated and, where needed, an automatic incident response runs.

**Further results and conclusion.** Besides the comparison in Table 2.4, the paper plots the true positive and false negative rates for training and testing, the average response time for malware, unauthorised access, denial-of-service and phishing incidents, the MFA success and failure rates for administrators, regular users and guests, and the time spent before and after the system on threat detection, incident response and MFA handling. The authors state that the novelty lies in joining AI, SIEM, MFA and automated incident response in one setting, which reduces manual and error-prone work. They propose better prediction algorithms, adaptation to organisational context, blockchain for secure data storage and continued testing against new threats as future work.

### 2.7 SIEM and Cyber Situation Awareness

Unal, Kahya, Kurtlutepe and Dag, "Investigation of cyber situation awareness via SIEM tools: a constructive review" [4], was presented at the 6th International Conference on Computer Science and Engineering (UBMK) in 2021. The review asks how recent improvements to SIEM tools support cyber situation awareness (SA), meaning the ability of analysts to perceive, comprehend, project and resolve events in the cyber domain. The authors follow the reference model of Onwubiko [14] and consider SIEM a systemic factor of SA, because it collects data, correlates it and passes alerts to the analyst.

**Background.** The paper divides SIEM tools by functional features (the correlation and analytics) and technical features (deployment, vendor and evolution). It cites a report that more than 70% of SIEM tools used in organisations are adjusted with data-centric technologies such as AI and machine learning. It then explains cyber threat intelligence (CTI) at four levels: strategic, tactical, operational and technical, the last being indicators of compromise such as malicious IP addresses. A cited survey found that organisations prefer technical (41%), operational (27%), tactical (18%) and strategic (13%) intelligence. CTI gives a SIEM context, which is expected to reduce false positives and help analysts decide.

**Studies reviewed.** The reviewed studies are grouped by implementation area (Table 2.5 summarises their criteria). Plug-in tools include a method that detects lateral movement from user risk scores, a LogRhythm-based approach that changes the kill-chain model so that alarms carry enough detail for root-cause analysis, and a neural-network ensemble of weak learners that gives high detection with few resources. Enterprise tools include an autoencoder method that detected 11 of 15 attacks in the CICIDS2017 dataset and explained alerts through clustering, a Sysmon-based method that uses command length to find malicious activity and runs on Splunk, a study of Active Directory attack chains by logon type with Splunk, a deep-learning SIEM that reduces the number of notifications sent to analysts, a rule-based detector for denial-of-service attacks in server logs, and a containerised ELK stack with custom rules [10]. SCADA studies use a kill-chain approach with Security Onion and Kibana, and machine learning on PLC sensor data from a water system. For IoT, a blockchain-based tool secures event data. The authors also classify each study by whether it changes the infrastructure, the software or uses neural methods.

**Conclusions of the review.** The authors find no single direction of progress, because the dynamic cyber domain shapes each result. They conclude that cooperation between CTI and SIEM supports enterprises and critical infrastructure, that SIEM benefits mostly from technical and tactical intelligence, and that the trends are machine learning, blockchain and IoT-based infrastructure.

**Table 2.5: Criteria used in [4] to classify SIEM improvements**

| **Criterion** | **Values** | **Examples from the review** |
| --- | --- | --- |
| Enhanced SIEM process | Collection and storage, correlation, alerting | Alarm detail (LogRhythm), correlation of risk scores |
| Implementation area | Plug-in, enterprise, SCADA, IoT | Lateral movement plug-in; Splunk Active Directory study |
| CTI artefact | Technical, tactical, operational, strategic | Indicators of compromise, attack techniques |
| Solution type | Infrastructure, programmatic, neural | Containerised ELK; deep-learning SIEM |

**Relevance to this work.** The review is relevant in three ways. It shows that poor alert detail is a main problem for analysts, which is the reason the email in this thesis carries the IP address, account, host and a link to the incident. It cites Windows-focused work that separates attack chains by logon type, which is the same idea as using logon type 10 and 3 in Rule 2. And it classifies SIEM improvements as plug-in or enterprise tools, so the pipeline in this thesis can be seen as an enterprise-level improvement to alerting rather than to detection. Its limit is that it is a review without new experiments, and it does not discuss alert delivery or email.

**Situation awareness and the role of CTI.** The paper starts from the situation awareness model of Endsley as reworked by Onwubiko [14], in which an operator perceives the environment, comprehends it, projects what will happen and then resolves the issue. It argues that human abilities alone are no longer sufficient in a complex cyber domain, so automation is needed, and it cites a business report that SOC and network operations centres are adopting AI and machine learning analytics. In the paper's illustration of CTI in a SIEM, data from databases, operating systems, applications and user activity is turned into intelligence, correlated in the SIEM, and delivered as analysis reports to the analyst, which is meant to lower the false positive rate.

**More detail on selected studies.** The Sysmon-based study collects logs on an experimental test bed, checks the event GUID against a Windows threat index, and if no match is found tests for zero-day activity by command length; when an anomaly such as malware is found its hash is calculated and the event is tagged as a threat to raise an alarm, with Splunk used for the analysis. The Active Directory study chooses attack scenarios from the attacker's point of view, groups attack chains by user logon type and checks whether Windows logs can detect them. The SCADA study with machine learning compares six models (logistic regression, Gaussian naive Bayes, k-nearest neighbours, support vector machines, decision trees and random forests) in four experiments, from binary classification to the suggestion of several threat scenarios over a confidence level. The IoT study uses blockchain so that stored events cannot be altered, since attackers who manipulate security data have a high impact.

### 2.8 Layered Security with Suricata, Wazuh and Splunk

Shanmugarathinam et al., "Enhance the network security in enterprise network using IDPS tools" [5], was presented at ICCAMS 2025. The paper argues that cyberattacks have become more targeted and stealthy, that firewalls and antivirus alone are inadequate, and that enterprises need defence in depth. It proposes a layered model of three tools and quotes a global cybercrime cost above 8 trillion US dollars in 2023 as motivation.

**The three layers.** Suricata is an open-source network threat detection engine from the Open Information Security Foundation that works as an IDS, an intrusion prevention system (IPS) and a network security monitoring tool [15]. It uses multi-threaded processing, understands protocols such as HTTP, TLS and SSH, supports Snort-compatible rules and writes JSON (eve.json) logs for SIEM tools. Wazuh is an open-source host-based platform with lightweight agents that forward logs to a manager. It provides file integrity checks, rootkit and unauthorised access detection, compliance mapping to PCI DSS, GDPR and HIPAA, and integration with the Elastic Stack. Splunk is a commercial SIEM that indexes machine data in real time and offers dashboards, searches in its Search Processing Language, an Enterprise Security product, machine learning and SOAR integration, but at a licensing cost.

**Architecture.** The authors built a simulated enterprise network with switches, servers and endpoint agents. Suricata inspects traffic, Wazuh monitors endpoints, and logs from both are pushed to Splunk through syslog or connectors such as Filebeat, where dashboards visualise network alerts, host events and the behaviour correlated between them. The paper describes installation commands, configuration files and screenshots for each tool. It concludes that the combination gives visibility across the perimeter, the endpoints and central analytics, and that the model scales from small businesses to large enterprises.

**Critical view.** The paper is clear on how to deploy the tools and is a good practical introduction, but it is descriptive. It gives no measured detection rates, delays or alert volumes, so its claims of speed and precision are not tested. It also notes that the log volume and licensing cost of Splunk, and the hardware needs of the agents, have to be managed. The role of alerts after detection is mentioned only as automation of alerts and actions.

**Relevance to this work.** The paper confirms the usual pattern of host agents feeding a central SIEM, which is what the Azure Monitor Agent and Sentinel do in this thesis. The Sentinel workspace and KQL rules in this work correspond to the Splunk layer and its search language, and the Sentinel playbooks correspond to the SOAR integration that Splunk offers. The difference is that this thesis uses one cloud platform and measures the alerting delay, which the paper does not.

**Installation and use of the tools.** Suricata is installed on a Linux server that can see mirrored or tapped network traffic. Its main file, suricata.yaml, defines the interface, the rules and the log formats, and community rules such as Emerging Threats Open are fetched with suricata-update. The engine runs in IDS mode on an interface or in IPS mode through iptables and NFQUEUE. Its alerts go to fast.log, complete events to eve.json and packets to pcap files, which can be forwarded to a SIEM. Wazuh has three components: the manager that analyses events, the indexer that stores alerts and the dashboard that visualises them. An installation script sets them up, and an agent package installed on each endpoint connects to the manager over an encrypted channel. Splunk Enterprise indexes the data, and the administrator defines inputs, indexes and dashboards and writes searches in the Search Processing Language. Dashboards in Splunk then combine network alerts from Suricata, host events from Wazuh and the behaviour correlated between them.

**Advantages claimed.** For Suricata, the paper lists protocol awareness regardless of port, high performance, file extraction for sandbox analysis, JSON logging, Snort rule compatibility, community support and flexible IDS, IPS or passive deployment. For Wazuh it lists host visibility, compliance mapping, real-time alerting, scalability to thousands of agents, integration with the ELK stack, Splunk and VirusTotal, and reporting. For Splunk it lists real-time indexing, scalability, more than a thousand integrations, machine learning, and alerting with SOAR integration. The paper also cites the NIST guide to intrusion detection and prevention systems [15] and the MITRE ATT&CK framework, which form the usual background for the layered, defence-in-depth approach that it adopts. Because Splunk is a commercial product, the authors present the combination as cost-effective: open-source tools collect at the network and host layers and the commercial platform is used for correlation and visualisation.

### 2.9 Microsoft Sentinel and Automated Response

Microsoft Sentinel is a cloud SIEM built on Azure Log Analytics. It stores data in a workspace, runs scheduled analytics rules written in Kusto Query Language (KQL) and groups the resulting alerts into incidents. Automation rules run when an incident is created and can start a playbook, which is an Azure Logic App that can read the incident and its entities and call other services, such as an SMTP server. Workbooks provide dashboards over the workspace data. These features correspond to the SIEM and SOAR layers discussed in the literature [6], [12] and allow the manual steps of the base paper to be automated inside one platform.

### 2.10 Summary and Research Gap

**Table 2.6: Summary of the reviewed papers**

| **Ref.** | **Focus** | **Method** | **Main result** | **Limitation** |
| --- | --- | --- | --- | --- |
| [1] | Customised SIEM alert email | Web tool: Excel upload, form, PHPMailer | Email delivered in three tests | Manual; no detection; no timing |
| [2] | Open-source SIEM comparison | Wazuh, OSSIM, OSSEC with five attacks | Wazuh detected most attacks | Default rules; no alert delivery study |
| [3] | AI, SIEM, MFA and incident response | Integrated framework, three metrics | IRT 7.2 vs 20 min; TDR 92% | Brief setup; no data details |
| [4] | SIEM and situation awareness | Review of SIEM improvements and CTI | CTI and SIEM support awareness | No experiments; no alert delivery |
| [5] | Layered network security | Suricata, Wazuh and Splunk | Layered visibility across network and host | Descriptive; no measurements |

Taken together, the papers show that detection technology is mature and that automation reduces response time, but that the final step of telling a person about an incident in a clear, customised form is treated lightly. The base paper handles this step but only manually; the other four papers concentrate on detection, comparison or architecture and report little on alert delivery. No reviewed paper measures the delay from incident to notification in an automated pipeline. This thesis fills the gap by combining detection, incident creation and a customised HTML email in one automatic Microsoft Sentinel pipeline, and by measuring the resulting delay.

## 3. Methodology

### 3.1 Introduction

This chapter describes the design and implementation of the proposed system. The work was done in the Azure portal and the Microsoft Defender portal, where Sentinel is accessed.

### 3.2 Proposed Framework

Figure 3.1 shows the pipeline. Security events from a Windows virtual machine are sent by the Azure Monitor Agent to a Log Analytics workspace. Scheduled analytics rules query the data and create incidents. An automation rule starts the playbook for each new incident. The playbook extracts the IP addresses, accounts and hosts, fills the HTML template and sends the email. The incident table also feeds the workbook.

<p align="center">
  <img src="images/figure-3-1.png" alt="Figure 3.1" width="85%">
  <br><em>Figure 3.1: Architecture of the proposed automatic alerting pipeline</em>
</p>

### 3.3 Lab Environment

**Table 3.1: Components of the lab environment**

| **Component** | **Details** |
| --- | --- |
| Subscription | Azure free account |
| Resource group | rg-sentinel-project |
| Workspace | law-sentinel-project (Central India) with Microsoft Sentinel enabled; accessed through the Defender portal |
| Monitored host | Windows virtual machine vm-victim01 (Standard B2s v2, Central India), RDP enabled |
| Collection | Azure Monitor Agent with data collection rules dcr-windows-security and dcr-sentinel-security |
| Playbook | Consumption Logic App playbook-email-alert (Sentinel incident trigger, SMTP connector) |
| Mail account | Gmail with an app password, used through the SMTP connector |

The Gmail connector, the Outlook.com connector and SendGrid could not be used in this environment, so the generic SMTP connector with a Gmail app password was adopted. This is suitable for a lab but not for production.

### 3.4 Log Collection

The virtual machine was first connected through the data collection rule dcr-windows-security, which used the XPath filters shown in Figure 3.2 to collect events 4624 (successful logon), 4625 (failed logon) and 4720 (user account created) into the Event table. The first two events arrived, but event 4720 never reached the workspace although Windows logged it (Section 4.4). The Windows Security Events via AMA connector was therefore installed from the Content Hub, and a second rule, dcr-sentinel-security, collected the Security log into the `SecurityEvent` table (Figure 3.3). The setting "AllEvents" was used, which is heavier than the "Common" set and should be reduced after testing.

<p align="center">
  <img src="images/figure-3-2.png" alt="Figure 3.2" width="85%">
  <br><em>Figure 3.2: Data collection rule with XPath filters for events 4624, 4625 and 4720</em>
</p>

<p align="center">
  <img src="images/figure-3-3.png" alt="Figure 3.3" width="85%">
  <br><em>Figure 3.3: Windows Security Events via AMA connector with the dcr-sentinel-security rule</em>
</p>

**Table 3.2: Windows events used by the detection rules**

| **Event ID** | **Meaning** | **Fields used** |
| --- | --- | --- |
| 4625 | Failed account logon | Source IP address (`IpAddress`), account |
| 4624 | Successful account logon | Source IP address, account, logon type |
| 4720 | A user account was created | `TargetUserName` (new user), `SubjectUserName` (creator) |

### 3.5 Detection Rules

Three scheduled analytics rules were created. Table 3.3 summarises them, and the full queries are in Appendix A. Rules 1 and 2 read the Event table and extract fields from the XML in EventData with `parse_xml`; Rule 3 reads the `SecurityEvent` table, where the fields are already columns.

**Table 3.3: Summary of analytics rules**

| **No.** | **Rule name** | **Severity** | **Logic** |
| --- | --- | --- | --- |
| 1 | RDP Brute Force on vm-victim01 | High | Five or more 4625 events from the same IP, account and host |
| 2 | RDP Brute Force Followed by Successful Login | High | Five or more 4625 events from an IP, followed by a 4624 (logon type 10 or 3) from the same IP and host |
| 3 | New Local User Created on vm-victim01 | Medium | Any 4720 event; new user and creator extracted |

All rules run every five minutes with a look-back window of one hour, create incidents, and map the IP, account and host entities so that the playbook can read them. After testing, Rule 2 was changed to summarise its output by IP, account and host, to enable one-hour suppression and to group alerts into one incident when all entities match (Section 4.5). The Rule 2 summary page is shown in Figure 3.4.

<p align="center">
  <img src="images/figure-3-4.png" alt="Figure 3.4" width="85%">
  <br><em>Figure 3.4: Review page of the rule "RDP Brute Force Followed by Successful Login"</em>
</p>

### 3.6 Automation Rule and Playbook

The automation rule "Email on new incident" runs when an incident is created and has no conditions, so every analytics rule triggers the playbook (Figure 3.5). The Sentinel Automation Contributor role was assigned so that Sentinel can run the playbook.

<p align="center">
  <img src="images/figure-3-5.png" alt="Figure 3.5" width="85%">
  <br><em>Figure 3.5: Automation rule that runs playbook-email-alert on every new incident</em>
</p>

The playbook (Figure 3.6) uses the Sentinel incident trigger, then calls the Entities - Get IPs, Get Accounts and Get Hosts actions. A Select action after each one keeps a single field (Address, Name or HostName), and the Join function turns each list into a comma-separated text. The final SMTP Send Email (V3) action sends the message with the "`IsHtml`" flag set to true.

<p align="center">
  <img src="images/figure-3-6.png" alt="Figure 3.6" width="85%">
  <br><em>Figure 3.6: Logic App designer showing the Select step for IP addresses</em>
</p>

### 3.7 HTML Email Template

The email is a table with a red header bar showing the incident title, followed by rows for severity, creation time (UTC), attacker IP(s), account(s) and host(s), and a button that opens the incident in Sentinel. Only inline CSS is used, because Gmail ignores many style blocks. The width is set to 100% with a maximum of 600 pixels so that the table fits on small screens. For incidents without an IP address, such as a new local user, the IP row is empty.

### 3.8 Monitoring Dashboard

A Sentinel workbook named "SIEM Email Alert Dashboard" has four tiles built on the `SecurityIncident` and `SecurityAlert` tables: incidents by severity, incidents over time, incidents by rule and top attacker IPs. The incident queries keep only the latest record for each `IncidentNumber` with `arg_max` so that updates to one incident are not counted twice.

### 3.9 Evaluation Method

Each use case was triggered once on the virtual machine, and the times of three stages were recorded: the event time in the workspace, the incident creation time and the arrival time of the email. The email arrival time was read from Gmail in IST, and the incident creation time was read in UTC from the email and converted to IST (UTC+5:30). Detection delay is the time from event to incident, and alerting delay is the time from incident to email.

## 4. Results and Discussion

### 4.1 Test Setup

The tests were run on vm-victim01 on 1 to 3 October 2026. The RDP client was the author's own computer, so the "attacker" IP addresses in the results ([source IP A] and [source IP B]) are lab source addresses, not real attackers. Each use case was run once, so the timings below are single measurements and not averages.

### 4.2 Use Case 1: RDP Brute Force

Eight failed RDP logins were generated against the virtual machine. Rule 1 created incident 5, "RDP Brute Force on vm-victim01", with the host vm-victim01, the IP [source IP A] and the account [admin account] as entities (Figure 4.1). The playbook then produced the HTML email in Figure 4.2, with severity High, the attacker IP, account and host.

<p align="center">
  <img src="images/figure-4-1.png" alt="Figure 4.1" width="85%">
  <br><em>Figure 4.1: Incident 5 with its host, IP and account entities</em>
</p>

<p align="center">
  <img src="images/figure-4-2.png" alt="Figure 4.2" width="85%">
  <br><em>Figure 4.2: HTML email for the RDP brute force incident</em>
</p>

### 4.3 Use Case 2: Successful Login after Brute Force

Six failed RDP logins were followed by a correct login. The last failed event reached the workspace at about 17:44 IST. Rule 2 created an incident, and the email in Figure 4.3 arrived at 17:51 IST, showing the IP [source IP B], the account [admin account] and the host vm-victim01. The incident was created at 12:20:56 UTC (17:50:56 IST). A later duplicate email is shown in Figure 4.4 and is discussed in Section 4.5.

<p align="center">
  <img src="images/figure-4-3.png" alt="Figure 4.3" width="85%">
  <br><em>Figure 4.3: First email for the successful-login-after-brute-force incident (17:51 IST)</em>
</p>

<p align="center">
  <img src="images/figure-4-4.png" alt="Figure 4.4" width="85%">
  <br><em>Figure 4.4: Duplicate email for the same attack (18:46 IST)</em>
</p>

### 4.4 Use Case 3: New Local User

A user named testuser was created inside the virtual machine with the command "net user". Windows logged event 4720 (Figure 4.5 shows the event for an earlier test user), but the first collection rule never delivered it to the workspace, even after a restart and a wait of several hours. After the Windows Security Events via AMA connector was added, a query on the `SecurityEvent` table returned the event at 9:03 AM on 3 October, with the new user testuser and the creator [admin account] (Figure 4.6).

<p align="center">
  <img src="images/figure-4-5.jpg" alt="Figure 4.5" width="85%">
  <br><em>Figure 4.5: Event 4720 for testuser2 in Windows Event Viewer on the virtual machine</em>
</p>

<p align="center">
  <img src="images/figure-4-6.png" alt="Figure 4.6" width="85%">
  <br><em>Figure 4.6: SecurityEvent query returning event 4720 (testuser created by [admin account])</em>
</p>

Rule 3 was then changed to read the `SecurityEvent` table. It created incident 57, "New Local User Created on vm-victim01" (Medium) with the account testuser and the host vm-victim01 (Figure 4.7). The email in Figure 4.8 arrived at about 09:34 IST. Two emails arrived within about a minute, so the rule fired twice after it was edited; suppression was set to one hour to prevent repeats. The IP row is empty, which is expected for this event.

<p align="center">
  <img src="images/figure-4-7.png" alt="Figure 4.7" width="85%">
  <br><em>Figure 4.7: Incident list showing incident 57, "New Local User Created on vm-victim01"</em>
</p>

<p align="center">
  <img src="images/figure-4-8.png" alt="Figure 4.8" width="85%">
  <br><em>Figure 4.8: HTML email for the new local user incident</em>
</p>

### 4.5 Issues Observed and Tuning

#### Duplicate incidents and emails

After Rule 2 was first enabled, the same six failures and one success were matched again at every five-minute run, because the look-back window was one hour. Dozens of incidents and emails were produced, as seen in the inbox in Figure 4.9. The incident count for Rule 2 reached about 50. The rule was disabled, its query was changed to summarise results by IP, account and host, suppression for one hour was enabled and alert grouping by matching entities was turned on. After re-enabling it, no new emails arrived.

<p align="center">
  <img src="images/figure-4-9.png" alt="Figure 4.9" width="85%">
  <br><em>Figure 4.9: Inbox showing repeated emails before the fix</em>
</p>

#### Event 4720 not collected

Collecting events with only an XPath filter in the first data collection rule did not deliver event 4720, although events 4624 and 4625 arrived from the same rule. The cause was not identified. Using the Sentinel connector solved the problem. The side effect is that 4624 and 4625 are now present in both the Event and `SecurityEvent` tables.

#### Other points

- Windows event field positions in `parse_xml` (for example `Data[19]` for the IP in 4625) are fragile and depend on the event layout.
- Event 4720 was first tried on the author's own computer instead of the virtual machine, which produced no data; commands must run inside the monitored host.

### 4.6 Timing Comparison

**Table 4.1: Measured delays for the proposed system (single runs)**

| **Stage** | **Use case 2** | **Use case 3** | **Note** |
| --- | --- | --- | --- |
| Event in workspace | about 17:44 IST | about 09:03 IST |  |
| Incident created | 17:50:56 IST | about 09:34 IST | From email "Created" time |
| Email received | 17:51 IST | about 09:34 IST | Gmail time |
| Event to incident | about 7 min | about 31 min | Use case 3 affected by rule edit |
| Incident to email | about 1 min | under 1 min | Playbook run |

The detection delay depends on the agent upload time and the five-minute rule schedule. In use case 3 the delay was longer because the rule was being edited during the test, so this number should not be taken as typical. The alerting delay, which is the part that the automation replaces, was about one minute or less in both cases with no human step.

The base paper gives no timing figures [1]. The manual time in Table 4.2 is therefore the author's own estimate from the steps listed in the paper (export to Excel, upload and extract, fill the form, preview and send), and was not measured in an experiment.

For context, Pulivarthy [3] reports an average incident response time of 7.2 minutes for an automated system against 20 minutes for traditional methods, and Andronache et al. [2] observed reporting delays of one to two minutes for file integrity events in Wazuh. These figures come from different systems, tasks and definitions, so they are not directly comparable with Table 4.1, but they show that a delay of minutes is the usual range for automated detection and response.

**Table 4.2: Comparison with the base paper**

| **Aspect** | **Base paper (manual tool)** | **Proposed system** |
| --- | --- | --- |
| Start of the process | Analyst, after noticing an alert | Incident creation |
| Human steps per alert | About six steps | None |
| Active time per alert | About 8 to 13 min (estimate) | About 1 min (measured) |
| Waiting for an analyst | Not bounded | None |
| Detection | None; formats exported logs | Three scheduled rules |
| Email content | Template filled from Excel by form | HTML table filled from incident entities |
| Input | .xlsx or .xls files only | Live events through the agent |
| Credentials | Set in source code (pseudocode) | Stored in the Logic App connection |
| Limitation | Web page only | Needs events to reach Sentinel; detection delay of several minutes |

### 4.7 Dashboard

Figures 4.10 to 4.12 show the workbook. At the time of the screenshots there were 61 incidents: 58 High and 3 Medium. Incidents by rule shows about 51 for Rule 2, which reflects the duplicates before tuning, 7 for Rule 1 and 3 for Rule 3. The top attacker IP chart lists [source IP B] with 51 alerts and [source IP A] with 5. The over-time chart shows a peak caused by the duplicate flood.

<p align="center">
  <img src="images/figure-4-10.png" alt="Figure 4.10" width="85%">
  <br><em>Figure 4.10: Dashboard tiles: incidents by severity and incidents over time</em>
</p>

<p align="center">
  <img src="images/figure-4-11.png" alt="Figure 4.11" width="85%">
  <br><em>Figure 4.11: Dashboard tiles: incidents by rule and top attacker IPs (IP labels removed)</em>
</p>

<p align="center">
  <img src="images/figure-4-12.png" alt="Figure 4.12" width="85%">
  <br><em>Figure 4.12: Top attacker IPs tile after saving the workbook</em>
</p>

### 4.8 Discussion and Limitations

- The system removes the manual steps of the base paper, but its detection delay is several minutes because of agent upload time and the rule schedule.
- Each use case was run once on one virtual machine, and the source IP was the author's computer, so the results show that the pipeline works but do not give statistical timing.
- The manual-process time is an estimate, not a measurement.
- The automation rule emails every incident, including low-value ones; production use would filter by severity.
- Gmail SMTP with an app password is for a lab only.
- The base paper's tool lets the user choose the email content and recipients through a form, whereas this system uses a fixed template and fixed recipients.
- The dashboard counts include test duplicates; closing them would give cleaner numbers.

## 5. Conclusions and Future Directions

### 5.1 Summary and Contributions

This thesis replaced the manual Excel-upload and form workflow of the base paper with an automatic alerting pipeline in Microsoft Sentinel. Three detection rules (RDP brute force, successful login after brute force and new local user) were built and tested. Each created an incident and, through an automation rule and a Logic App playbook, a styled HTML email with the IP address, account and host. The alerting delay from incident to email was about one minute with no human action. Tuning with suppression and alert grouping removed duplicate emails, and the Sentinel connector solved the missing 4720 events. A dashboard summarised the results.

### 5.2 Future Work

- Run repeated tests and report mean and spread of the delays, and time the manual workflow with real users.
- Add severity-based routing and multiple recipients, and allow the analyst to choose email fields as in the base paper.
- Use a production mail service instead of Gmail SMTP.
- Add more rules (for example privilege changes and log clearing) and more hosts.
- Reduce collection to the "Common" event set or custom filters to control cost.
- Include enrichment such as IP geolocation in the email.

## Appendix A: Queries and Playbook Configuration

### A.1 Analytics Rule Queries

#### Rule 1: RDP Brute Force on vm-victim01

```kusto
Event
| where EventID == 4625
| extend Data = parse_xml(EventData)
| extend IpAddress = tostring(Data.DataItem.EventData.Data[19]["#text"]),
         Account = tostring(Data.DataItem.EventData.Data[5]["#text"])
| summarize Attempts = count(), FirstAttempt = min(TimeGenerated),
            LastAttempt = max(TimeGenerated) by IpAddress, Account, Computer
| where Attempts >= 5
```

#### Rule 2: RDP Brute Force Followed by Successful Login

```kusto
let failed = Event
| where EventID == 4625
| extend Data = parse_xml(EventData)
| extend IpAddress = tostring(Data.DataItem.EventData.Data[19]["#text"])
| where isnotempty(IpAddress) and IpAddress != "-"
| summarize Attempts = count(), LastAttempt = max(TimeGenerated) by IpAddress, Computer
| where Attempts >= 5;
let success = Event
| where EventID == 4624
| extend Data = parse_xml(EventData)
| extend IpAddress = tostring(Data.DataItem.EventData.Data[18]["#text"]),
         Account = tostring(Data.DataItem.EventData.Data[5]["#text"]),
         LogonType = tostring(Data.DataItem.EventData.Data[8]["#text"])
| where LogonType in ("10", "3")
| project SuccessTime = TimeGenerated, IpAddress, Account, Computer;
failed
| join kind=inner success on IpAddress, Computer
| where SuccessTime > LastAttempt
| summarize SuccessTime = min(SuccessTime), Attempts = max(Attempts)
            by IpAddress, Account, Computer
```

#### Rule 3: New Local User Created on vm-victim01

```kusto
SecurityEvent
| where EventID == 4720
| project TimeGenerated, NewUser = TargetUserName,
          CreatedBy = SubjectUserName, Computer
```

### A.2 Dashboard Queries

```kusto
// Incidents by severity
SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| summarize Incidents = count() by Severity

// Incidents over time
SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| summarize Incidents = count() by bin(CreatedTime, 1h)
| order by CreatedTime asc

// Incidents by rule
SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| summarize Incidents = count() by Title
| order by Incidents desc

// Top attacker IPs
SecurityAlert
| where AlertName has "RDP Brute Force"
| extend Ent = parse_json(Entities)
| mv-expand Ent
| where tostring(Ent.Type) == "ip"
| summarize Alerts = count() by IP = tostring(Ent.Address)
| order by Alerts desc
| take 10
```

### A.3 Playbook Configuration

The playbook playbook-email-alert has the following actions in order: Microsoft Sentinel incident trigger; Entities - Get IPs; Select (from the IPs list, value Address); Entities - Get Accounts; Select (value Name); Entities - Get Hosts; Select (value HostName); SMTP Send Email (V3) with `IsHtml` set to true. The email body expressions use the trigger fields title, severity, createdTimeUtc and incidentUrl, and join(body(...), ', ') for each Select output.

## References

**[1]** C. H. Chi, S. Y. Ooi, E. H. Othman, Y. H. Pang, M. K. Abu Yan and K. I. Sidin, "Intelligent-based SIEM Security Email Alert," Proc. 11th International Conference on Information and Communication Technology (ICoICT), 2023, pp. 481-486.

**[2]** M.-M. Andronache, A. Vulpe and C. Burileanu, "A Comparative Study of Intrusion Events in Different SIEM Systems," Proc. IEEE 23rd World Symposium on Applied Machine Intelligence and Informatics (SAMI), 2025, pp. 65-70.

**[3]** A. Pulivarthy, "Enhancing Cybersecurity and IT Service Desk Support with Artificial Intelligence, SIEM Tools, MFA Integration, and Incident Response," Proc. 6th International Conference on IoT Based Control Networks and Intelligent Systems (ICICNIS), 2025, pp. 1958-1964.

**[4]** U. Unal, C. N. Kahya, Y. Kurtlutepe and H. Dag, "Investigation of Cyber Situation Awareness via SIEM Tools: A Constructive Review," Proc. 6th International Conference on Computer Science and Engineering (UBMK), 2021, pp. 676-681.

**[5]** G. Shanmugarathinam, A. G. Jesudoss, A. Joseph, K. Yadav and A. Shashidar, "Enhance the Network Security in Enterprise Network Using IDPS Tools," Proc. 2nd International Conference on New Frontiers in Communication, Automation, Management and Security (ICCAMS), 2025.

**[6]** A. Sridharan and V. Kanchana, "SIEM Integration with SOAR," Proc. International Conference on Futuristic Technologies (INCOFT), 2022, pp. 1-6.

**[7]** A. R. Muhammad, P. Sukarno and A. A. Wardana, "Integrated Security Information and Event Management (SIEM) with Intrusion Detection System (IDS) for Live Analysis based on Machine Learning," Procedia Computer Science, vol. 217, pp. 1406-1415, 2023.

**[8]** M. A. Ayu et al., "Enhancing Security Information and Event Management (SIEM) by Incorporating Machine Learning for Cyber Attack Detection," Proc. IEEE 9th International Conference on Computing, Engineering and Design (ICCED), 2023, pp. 1-6.

**[9]** R. Amami, M. Charfeddine and S. Masmoudi, "Exploration of Open Source SIEM Tools and Deployment of an Appropriate Wazuh-Based Solution for Strengthening Cyberdefense," Proc. 10th International Conference on Control, Decision and Information Technologies (CoDIT), 2024, pp. 1-7.

**[10]** F. Mulyadi et al., "Implementing Dockerized Elastic Stack for Security Information and Event Management," Proc. 5th International Conference on Information Technology (InCIT), 2020, pp. 243-248.

**[11]** A. Vazao et al., "SIEM Open Source Solutions: A Comparative Study," Proc. 14th Iberian Conference on Information Systems and Technologies (CISTI), 2019, pp. 1-5.

**[12]** A. Lekidis, V. Mavroeidis and K. Fysarakis, "Towards Incident Response Orchestration and Automation for the Advanced Metering Infrastructure," Proc. IEEE 20th International Conference on Factory Communication Systems (WFCS), 2024, pp. 1-8.

**[13]** J. Tilbury and S. Flowerday, "Humans and Automation: Augmenting Security Operation Centers," Journal of Cybersecurity and Privacy, vol. 4, pp. 388-409, 2024.

**[14]** C. Onwubiko, "Understanding Cyber Situation Awareness," International Journal on Cyber Situational Awareness, vol. 1, no. 1, pp. 11-30, 2016.

**[15]** K. Scarfone and P. Mell, Guide to Intrusion Detection and Prevention Systems (IDPS), NIST Special Publication 800-94, 2007.
