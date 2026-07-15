# SOC Alert Investigation: Whoami Command Detected in Request Body

<img width="1049" height="254" alt="image" src="https://github.com/user-attachments/assets/783bffff-7c44-4e9b-a926-9fb3a03aa7af" />

Our investigation starts here with a high-severity **LetsDefend SOC Alert: SOC168 - Whoami Command Detected in Request Body**. This is a Web Attack alert, so I'm going to be looking at suspicious web activity and, according to the rule name, signs of Command Injection. 

To begin the investigation, I've created a case for the alert and I'll work through the provided playbook.


## Playbook Step 1: Understand Why the Alert Was Triggered

The first step of the playbook asks me to understand why the alert was triggered before making any decisions. I'm going to review the requested URL and identify what part of the request matched the detection rule.

<img width="799" height="525" alt="image" src="https://github.com/user-attachments/assets/87deb02a-e4d4-4e93-9741-17cb2d9411fd" />

After expanding the original alert, I've been able to find the following details:

<img width="1144" height="683" alt="image" src="https://github.com/user-attachments/assets/5fa97a6a-d825-4d5b-b998-4228a5d53d3f" />

Based on the rule name, this alert appears to be related to a possible Command Injection attack. The rule name specifically mentioned `Whoami Command Detected in Request Body`, which suggests that the alert was triggered because the request body contained the `whoami` command.

The requested URL was:

`https://172.16.17.16/video/`

This URL stood out because it was the endpoint that received the suspicious request. However, the suspicious value might not necessarily be in the URL itself. Since the rule name mentions `Request Body`, the important evidence is likely inside the submitted POST data.

The original alert also shows that the request method was `POST`, which means the activity involved data being submitted to the server. This is important because command injection payloads may be sent through form fields, parameters, or request body data rather than appearing directly in the URL.

Because the request body appears to contain the `whoami` command, this could indicate a possible Command Injection attempt where an attacker is testing whether the web application can execute operating system commands on the server.


## Playbook Step 2: Collect Data

The next step of the playbook asks me to collect quick context about the traffic so I can better understand what devices and IP addresses are involved. For this step, I’ll review the source and destination information, determine whether the traffic is coming from an external address or from inside the company network, and gather any available ownership or reputation details.

Since this alert involves suspicious web traffic, I’ll focus on identifying the source device, the destination address, and whether the IP or URL has any suspicious reputation indicators.

<img width="800" height="562" alt="image" src="https://github.com/user-attachments/assets/0d084ef1-f723-4cad-a5ce-ae16d554607c" />

I started by reviewing the logs tied to the alert:

<img width="1071" height="766" alt="image" src="https://github.com/user-attachments/assets/976bc009-f4fc-471c-a7d6-d22317005dab" />

As I can see here, there are 5 events that correlate back to the same source IP address. I'll start by looking at the original log that triggered the alert.

<img width="1069" height="767" alt="image" src="https://github.com/user-attachments/assets/ce77d471-00f4-49ec-a59f-a6c0e5e47b4d" />

<img width="1077" height="768" alt="image" src="https://github.com/user-attachments/assets/f2e3818c-1094-4e1c-bcf4-928fe50e6476" />

The event type was listed as `Firewall`, and the device action was `Permitted`, meaning the traffic was allowed rather than blocked.

The log showed traffic from the source address `61.177.172.87` to the destination address `172.16.17.16` over port `443`. The requested URL was:

`https://172.16.17.16/video/`

This request stood out because the submitted parameter contained `whoami`, which is a command used to identify the current user context on a system. In a normal web request, seeing `whoami` submitted as a parameter is suspicious because it may indicate that an attacker is testing whether the application can execute operating system commands.

The related parameter was:

`?c=whoami`

Since the alert is related to a possible Command Injection attack, this request is suspicious because it appears to be testing whether the application is vulnerable to command execution through user-supplied input.

After investigating the logs that pertained to the alert, I went to investigate both IP addresses in Endpoint Security. However, I was only able to find one IP that pertained to the original alert.

<img width="1094" height="669" alt="image" src="https://github.com/user-attachments/assets/f3f47305-57f5-4aa8-ae3e-0a700ceb311b" />

As I can see here, the destination address's endpoint is `172.16.17.16`. The endpoint was identified as `WebServer1004`, which is part of the `letsdefend.local` domain, and operated by the user `webadmin3`. The last login time was listed as `Feb, 10, 2022, 11:11 AM`.

As I mentioned above, I couldn't find the source address `61.177.172.87` in Endpoint Security, so I looked it up on VirusTotal because I suspected it was external to the company network.

<img width="1222" height="918" alt="image" src="https://github.com/user-attachments/assets/30efcec7-67c6-45fd-9ea2-b6431a9fa88c" />

As I suspected, the IP address associated with the source address was external to the company network. The IP address was associated with `AS4134 Chinanet`, and the country was listed as `CN`.

VirusTotal showed that `2/91` security vendors flagged this IP address as malicious. An additional vendor also marked it as suspicious. The community score was negative at `-1`, and the most recent analysis was listed as `12 days ago`.

While IP reputation alone does not prove malicious activity, the external source address, malicious reputation indicators, and the request body containing the `whoami` command support treating this traffic as suspicious.


## Playbook Step 3: Examine HTTP Traffic
The next step of the playbook asks me to examine the HTTP traffic for signs of a web attack. Since this alert is related to a possible Command Injection attack, I need to review the full HTTP request and look for suspicious values in the URL or request fields.

<img width="796" height="616" alt="image" src="https://github.com/user-attachments/assets/f911062f-24b1-4856-b827-686da44f58c3" />

In this case, the requested URL was:

`https://172.16.17.16/video/`

The URL itself shows the endpoint that received the suspicious request, but the more important evidence is the submitted POST parameter. The request included the parameter:

`?c=whoami`

This stood out because `whoami` is an operating system command used to identify the current user account. Seeing this command submitted to a web application is suspicious because it may indicate that an attacker is testing whether the application can execute system commands through their input.

Because the suspicious command was submitted through a POST request, this suggests that the attacker may have been testing whether the application was vulnerable to Command Injection.


## Playbook Step 4: Is Traffic Malicious?

The next step of the playbook asks me to decide whether the traffic is malicious based on the investigation so far.

<img width="796" height="429" alt="image" src="https://github.com/user-attachments/assets/924ff12d-975e-493b-b1fd-519926872bbf" />

Before making that decision, I’m going to review the related logs and put together a timeline of the activity. There are multiple logs that appear to correlate with this alert at different points in time, so I want to understand how the requests occurred, whether they came from the same source address, and whether similar command injection attempts appeared multiple times.

By reviewing the sequence of events, I can better determine whether this was normal web traffic or suspicious activity that may indicate actual Command Injection attempts.


The first related event occurred on `Feb, 28, 2022, 04:11 AM`. The source address `61.177.172.87` sent a `POST` request to the destination web server `172.16.17.16`.

<img width="1073" height="768" alt="image" src="https://github.com/user-attachments/assets/190659df-5e48-4466-9cb5-514ce4497e23" />

<img width="1072" height="771" alt="image" src="https://github.com/user-attachments/assets/6d7c6ed4-5aa4-42bb-b80e-50fcfe57afd3" />

The requested URL was:

`https://172.16.17.16/video/`

The POST parameter was:

`?c=ls`

This request stood out because `ls` is a command commonly used on Linux and Unix-like systems to list files and directories. Seeing this command submitted through a web request is suspicious because it could indicate that the attacker is testing whether the application can execute operating system commands through their input and seeing what files and directories exist.

The request was listed as `Permitted`, and the server returned HTTP response status `200` with a response size of `1021`. This means the server successfully responded to the request. At this point, the activity appears suspicious, but I cannot fully determine whether the command execution was successful yet because I need to compare this response size and status against the other related logs.


The next related event occurred on `Feb, 28, 2022, 04:12 AM`. This was the original log that triggered the SOC alert. The same source address `61.177.172.87` sent another `POST` request to the destination web server `172.16.17.16`.


<img width="1069" height="767" alt="image" src="https://github.com/user-attachments/assets/ce77d471-00f4-49ec-a59f-a6c0e5e47b4d" />

<img width="1077" height="768" alt="image" src="https://github.com/user-attachments/assets/f2e3818c-1094-4e1c-bcf4-928fe50e6476" />

The requested URL was:

`https://172.16.17.16/video/`

The POST parameter was:

`?c=whoami`

This request stood out because `whoami` is a command commonly used to identify the current user account on a system. In command injection testing, attackers may use `whoami` to determine whether their input is being executed by the server and to learn what user account the web application is running under.

The request was listed as `Permitted`, and the server returned HTTP response status `200` with a response size of `912`. This is important because the server successfully responded to the request, and the response size differed from the previous `ls` request. This may suggest that the submitted command affected the server response.

At this point, the activity looks highly suspicious and the attack may have been successful, but I still want to review the remaining related logs to see whether the response statuses and response sizes continue to support command execution.


The third related event occurred on `Feb, 28, 2022, 04:13 AM`. The same source address `61.177.172.87` sent another `POST` request to the destination web server `172.16.17.16`.
<img width="1077" height="773" alt="image" src="https://github.com/user-attachments/assets/8e96b888-2bae-4bbc-8503-d770dfad69ab" />

<img width="1073" height="771" alt="image" src="https://github.com/user-attachments/assets/d01a32a0-84a8-47d4-976f-1cea3ba4baec" />

The requested URL was:

`https://172.16.17.16/video/`

The POST parameter was:

`?c=uname`

This request stood out because `uname` is a Unix/Linux command used to display system information, such as the operating system or kernel name. In the context of a possible Command Injection attack, this is suspicious because the attacker may be testing whether they can run system commands and gather information about the server.

The request was listed as `Permitted`, and the server returned HTTP response status `200` with a response size of `910`. This means the server successfully responded to the request. Since the response size differs from the previous command attempts, this further supports the possibility that the submitted command affected the server response.

At this point in the timeline, the activity continues to look like command injection testing, and the attack appears increasingly likely to have been successful.


The next related event occurred on `Feb, 28, 2022, 04:14 AM`. The same source address `61.177.172.87` sent another `POST` request to the destination web server `172.16.17.16`.

<img width="1074" height="769" alt="image" src="https://github.com/user-attachments/assets/460bea5b-2fa3-4f98-a238-53aaf0af8f01" />

<img width="1070" height="765" alt="image" src="https://github.com/user-attachments/assets/db8b22af-1ff0-413f-bc8c-ee97629e9703" />

The requested URL was:

`https://172.16.17.16/video/`

The POST parameter was:

`?c=cat /etc/passwd`

This request stood out as highly suspicious because `cat` is a command used to read and print file contents, and `/etc/passwd` is a sensitive Linux/Unix file that contains local user account information. In the context of a possible Command Injection attack, this suggests that the attacker may have moved from simple command testing to attempting to read sensitive system files.

The request was listed as `Permitted`, and the server returned HTTP response status `200` with a response size of `1321`. This response size was larger than the earlier command attempts, which further supports the possibility that the server returned output from the command.

At this point in the timeline, the activity appears highly suspicious and strongly suggests that the command injection attempt may have been successful.


The final related event occurred on `Feb, 28, 2022, 04:15 AM`. The same source address `61.177.172.87` sent another `POST` request to the destination web server `172.16.17.16`.

<img width="1070" height="766" alt="image" src="https://github.com/user-attachments/assets/5c918c45-834d-474b-847f-b8d9f21b7c98" />

<img width="1072" height="767" alt="image" src="https://github.com/user-attachments/assets/35eb571a-8dce-4c19-b8b2-c867e837d1a7" />

The requested URL was:

`https://172.16.17.16/video/`

The POST parameter was:

`?c=cat /etc/shadow`

This request stood out as highly suspicious because `cat` is a command used to read and print file contents, and `/etc/shadow` is a sensitive Linux/Unix file that stores local user password hashes. In the context of a possible Command Injection attack, this suggests that the attacker may have attempted to read sensitive credential-related data from the server.

The request was listed as `Permitted`, and the server returned HTTP response status `200` with a response size of `1501`. This response size was larger than the earlier command attempts, which supports the possibility that the server returned output from the command.

At this point in the timeline, the activity strongly suggests that the command injection attempt was successful, because the attacker submitted commands to read sensitive system files and the server returned successful responses with varying response sizes.


Looking at the timeline as a whole, the requested URL itself did not appear suspicious because each request targeted the same normal-looking endpoint:

`https://172.16.17.16/video/`

However, the POST parameters painted a completely different picture. The traffic came from an external source IP address, `61.177.172.87`, and targeted the internal web server `172.16.17.16`. The source IP address also had suspicious reputation indicators, with VirusTotal showing vendors marking it as malicious or suspicious.

The related POST parameters included commands such as `ls`, `whoami`, `uname`, `cat /etc/passwd`, and `cat /etc/shadow`. These commands are suspicious because they suggest the attacker was attempting to execute operating system commands through the web application. The activity appeared to start with basic command execution testing and then escalated into attempts to read sensitive system files.

In addition, the related requests returned HTTP response status `200`, and the response sizes varied between requests. This suggests that the server successfully responded to the submitted commands and may have returned different output depending on the command that was executed.

Based on the external source IP address, the suspicious command-based POST parameters, the successful HTTP responses, and the varying response sizes, I assessed the traffic as **Malicious**.

Based on this evidence, I selected **Malicious** in the playbook.


## Playbook Step 5: What Is The Attack Type?

The next step of the playbook asks me to identify the attack type based on the malicious traffic observed during the investigation.

<img width="800" height="370" alt="image" src="https://github.com/user-attachments/assets/ce95af31-516c-4eee-a711-0dc6597cc1ed" />

Based on the requested URL, POST parameters, and alert context, I selected **Command Injection** as the attack type. The requested URL itself did not appear suspicious:
`https://172.16.17.16/video/`

However, the POST parameter from the original alert contained the `whoami` command:

`?c=whoami`

This suggests a possible Command Injection attempt because the attacker appeared to be submitting operating system commands through a web application parameter to test whether the server would execute them.

The `whoami` command is suspicious in this context because it is commonly used to identify the current user context on a system. If successful, it can help an attacker determine what account the web application or server process is running under.

Because the suspicious request involved an operating system command being submitted through a web application parameter, **Command Injection** was the best description of the attack type from the available options.


## Playbook Step 6: Check if it is a Planned Test

The next step of the playbook asks me to determine whether the malicious traffic may have been part of a planned test or attack simulation. Security testing activity can sometimes trigger alerts, so I am going to check whether there is any evidence that this traffic was expected.

<img width="804" height="549" alt="image" src="https://github.com/user-attachments/assets/112ecd38-f3d9-43c6-92b0-6f75f0b291fc" />

To do this, I will search for related information such as the hostname, username, and IP addresses in the mailbox. I will also review whether the device involved appears to belong to an attack simulation product or testing platform.

<img width="1148" height="715" alt="image" src="https://github.com/user-attachments/assets/24a00b71-5d5d-40fc-ad99-31f5554f9e96" />

<img width="1146" height="709" alt="image" src="https://github.com/user-attachments/assets/a2a9f832-9026-4c02-8f5c-3c0ec40d4207" />

<img width="1147" height="721" alt="image" src="https://github.com/user-attachments/assets/29e0032e-ab9c-410e-9d1f-4f418e068a35" />

<img width="1153" height="718" alt="image" src="https://github.com/user-attachments/assets/910466b1-0e52-49c3-bf1f-6ef49a962247" />

I searched for `172.16.17.16`, `WebServer1004`, and `webadmin3`, but no related emails were found. I also searched for the keyword `test` to check whether there were any emails mentioning approved testing activity during 2022, but I did not find any related test notifications.

I also reviewed the device and request details, and I did not find evidence that the traffic was generated by an attack simulation product.

Based on this, I determined that there was no evidence of a planned test, so I selected **Not Planned** in the playbook.


## Playbook Step 7: Determine Direction of Traffic

The next step of the playbook asks me to identify the direction of the malicious traffic.

<img width="798" height="415" alt="image" src="https://github.com/user-attachments/assets/3bcc0446-370d-4061-a273-b56bfa1fbf61" />

Based on the original log, the source address was `61.177.172.87`, which appears to be external to the company network. The destination address was `172.16.17.16`, which belongs to the internal company network.

Because the traffic originated from an external Internet-based source and targeted an internal company web server, I selected **Internet → Company Network**.


## Playbook Step 8: Check Whether the Attack was Successful

The next step of the playbook asks me to determine whether the attack was successful based on the available evidence.

<img width="798" height="696" alt="image" src="https://github.com/user-attachments/assets/ae152882-1f73-4e0c-88da-42927a2d270d" />

I referred back to the original log, which was the second log generated by the attacker:

<img width="1069" height="767" alt="image" src="https://github.com/user-attachments/assets/ce77d471-00f4-49ec-a59f-a6c0e5e47b4d" />

<img width="1077" height="768" alt="image" src="https://github.com/user-attachments/assets/f2e3818c-1094-4e1c-bcf4-928fe50e6476" />

`https://172.16.17.16/video/`

The POST parameter in the original alert contained the `whoami` command:

`?c=whoami`

I also reviewed the other related logs generated by the attacker. The POST parameters showed multiple operating system commands being submitted through the same web application endpoint, including `ls`, `whoami`, `uname`, `cat /etc/passwd`, and `cat /etc/shadow`.

<img width="1061" height="580" alt="image" src="https://github.com/user-attachments/assets/472914fa-db51-4701-a2ac-42eab6b04f77" />

I also checked in Endpoint Security the terminal history of the device for the commands, and they were present on the web server. These commands appeared to build on top of one another. The attacker started with basic command execution testing, then moved into system discovery, and eventually attempted to read sensitive system files.

The related requests returned HTTP response status `200`, which indicates that the server successfully processed the requests. The response sizes also varied between the commands, which suggests that the server returned different output depending on the command that was submitted.

Because multiple command-based POST parameters were submitted, the server returned successful `200` responses, the commands appeared in terminal history, and the response sizes varied across the requests, I determined that the attack was successful.


## Playbook Step 9: Was the Attack Successful?

The next playbook question asks me to confirm whether the attack was successful based on the previous investigation step.

<img width="798" height="364" alt="image" src="https://github.com/user-attachments/assets/3d5309dd-d061-4d61-bd3c-08aa3cd7800f" />

Based on the HTTP response status `200` and the varying response sizes across the command-based requests, I determined that the attack was successful. The submitted commands appear to have reached the server and generated different responses depending on the command that was sent.

I also checked Endpoint Security and found the submitted commands in the terminal history of the affected device. This further supports that the commands were executed on the server rather than only being submitted through the web request.

Based on the successful HTTP responses, varying response sizes, and terminal history evidence, I selected **Yes** in the playbook.

## Playbook Step 10: Containment

The next step of the playbook explains that containment is required when there is evidence that a device may be compromised. Since the investigation showed that multiple commands were submitted, the server returned successful responses, and the commands appeared in the device’s terminal history, containment is the appropriate next step.

<img width="799" height="595" alt="image" src="https://github.com/user-attachments/assets/e231efae-865d-4250-b7be-6cb1367f5362" />

To reduce the impact of the attack and restrict any further attacker activity, I went to the Endpoint Security page and requested containment for the affected device.

<img width="1092" height="672" alt="image" src="https://github.com/user-attachments/assets/712cfc7a-7090-47dc-a5af-db9440d45c32" />


## Playbook Step 11: Add Artifacts

<img width="798" height="446" alt="image" src="https://github.com/user-attachments/assets/18ed98a5-b0df-4962-b06e-67b89478c4ec" />

Based on the evidence collected so far, I added the source IP address `61.177.172.87` as an `IP Address` artifact because it was the external address associated with the command injection activity against the internal web server.

I also added the targeted endpoint `https://172.16.17.16/video/` as a `URL Address` artifact because it was the web endpoint that received the suspicious POST requests. The command injection evidence came from the POST parameters, including commands such as `ls`, `whoami`, `uname`, `cat /etc/passwd`, and `cat /etc/shadow`.


## Playbook Step 12: Do You Need Tier 2 Escalation?

The next step of the playbook asks me to determine whether Tier 2 escalation is needed. According to the playbook, escalation is required if the attack succeeds or if an internal device is compromised.

<img width="798" height="656" alt="image" src="https://github.com/user-attachments/assets/e770c515-12dc-4627-8ccd-5d8c17fe2010" />

In this case, the attack came from the Internet toward the company network, and the evidence showed that the attack was successful. The command-based POST requests returned HTTP response status `200`, and the response sizes varied between requests, which suggests the server returned different output depending on the command submitted.

I also confirmed through Endpoint Security that the submitted commands appeared in the terminal history of the affected web server. This provided additional evidence that the commands were executed on the device rather than only being sent in the HTTP requests.

Although the affected device was contained, Tier 2 escalation was still needed because the attack was successful and the internal web server showed evidence of command execution. Because of this, I selected **Yes** for Tier 2 escalation.


## Playbook Step 13: Analyst Notes

The next step of the playbook asks me to add analyst notes for the case. I used this section to summarize the main findings from the investigation, including why the traffic looked malicious and whether there was evidence that the attack succeeded.

<img width="798" height="510" alt="image" src="https://github.com/user-attachments/assets/8efe0cdd-e6bb-45a2-9893-58cec5ea7d53" />

Analyst Note: On `Feb. 28, 2022`, the system detected a possible Command Injection attempt from the external source IP address `61.177.172.87`. The activity targeted the internal web server at `172.16.17.16` through the endpoint `https://172.16.17.16/video/`.

During the investigation, I found multiple related logs from the same source address. The submitted POST parameters included commands such as `ls`, `whoami`, `uname`, `cat /etc/passwd`, and `cat /etc/shadow`. The activity appeared to escalate from basic command execution testing to system discovery and then to attempts to read sensitive system files.

The source IP address appeared to be external to the company network. VirusTotal showed that security vendors flagged the IP address as malicious or suspicious, which added further context to the investigation.

There was no evidence that this activity was part of a planned test. I searched for related emails and did not find anything indicating approved testing activity. Since the source IP was external, the commands were suspicious, and the activity was not planned, I assessed the traffic as malicious.

The command-based requests returned HTTP response status `200` with varying response sizes, and Endpoint Security showed the submitted commands in the terminal history of the affected web server. Based on this evidence, I assessed the attack as successful and escalated the case for Tier 2 review.


## Playbook Step 14: Finish the Playbook!

The final playbook step was to confirm the investigation and close the case. At this point, I had already added the relevant artifacts, summarized my findings into the analyst notes, and completed all the required playbook actions.

<img width="798" height="346" alt="image" src="https://github.com/user-attachments/assets/d7819091-ed53-4609-a61c-512030a78b18" />


## Final Verdict and Closing Case: True Positive

<img width="602" height="439" alt="image" src="https://github.com/user-attachments/assets/8634a2bc-4576-4298-90d8-309f17684ced" />

After completing the playbook, I reviewed the evidence collected throughout the investigation to determine whether the alert was a true positive or false positive.

My final verdict is that this alert is a **True Positive**. The traffic appeared malicious because the external source IP address `61.177.172.87` sent multiple web requests to the internal web server `WebServer1004` at `172.16.17.16` using command-based POST parameters.

The requested URL, `https://172.16.17.16/video/`, did not appear suspicious by itself. However, the POST parameters told a different story. The attacker submitted commands such as `ls`, `whoami`, `uname`, `cat /etc/passwd`, and `cat /etc/shadow`. These commands strongly suggest a Command Injection attempt because they are operating system commands being passed through a web application request.

Another important detail is that the device action was listed as `Permitted`, meaning the requests were allowed through the security control. The attack also appears to have been successful because the related requests returned HTTP response status `200`, the response sizes varied between commands, and Endpoint Security showed the submitted commands in the terminal history of the affected web server.

The source IP address `61.177.172.87` also had suspicious reputation indicators. VirusTotal showed that `2/91` security vendors flagged the IP address, with `1` vendor marking it as malicious and `1` vendor marking it as suspicious. While reputation alone does not prove malicious activity, it adds context when combined with the command injection evidence.

Based on the command-based POST parameters, the external-to-internal traffic direction, the successful server responses, the terminal history evidence on `WebServer1004`, the source IP reputation indicators, and the lack of evidence that this was planned testing, I assessed this alert as a **True Positive**.


## Results!!

<img width="972" height="834" alt="image" src="https://github.com/user-attachments/assets/82f549cd-8308-46b8-8fb7-6c2358c89b52" />

Hooray, we were able to correctly identify that the URL was a true positive!


## MITRE ATT&CK Framework

Reference: https://attack.mitre.org/techniques/T1190/

This alert maps most closely to **Initial Access - Exploit Public-Facing Application (T1190)**. The traffic came from an external source and targeted a web application endpoint on the internal web server.

The requested URL, `https://172.16.17.16/video/`, did not appear suspicious by itself. However, the POST parameters contained operating system commands such as `ls`, `whoami`, `uname`, `cat /etc/passwd`, and `cat /etc/shadow`. This suggests that the attacker attempted to exploit exposed web application functionality to execute commands on the server.

Command Injection is the specific web attack type observed in the alert, while **T1190 - Exploit Public-Facing Application** is the broader MITRE ATT&CK technique that best matches the behavior. Since the commands appeared in the terminal history of `WebServer1004`, the activity also showed evidence that the command injection attempt was successful.
