# SOC Alert Investigation: LS Command Detected in Requested URL

<img width="1049" height="254" alt="image" src="https://github.com/user-attachments/assets/783bffff-7c44-4e9b-a926-9fb3a03aa7af" />

Our investigation starts here with a high-severity **LetsDefend SOC Alert: SOC167 - LS Command Detected in Requested URL**. This is a Web Attack alert, so I'm going to be looking at suspicious web activity and, according to the rule name, signs of command injection because of `ls`. 

To begin the investigation, I've created a case for the alert and I'll work through the provided playbook.


## Playbook Step 1: Understand Why the Alert Was Triggered

The first step of the playbook asks me to understand why the alert was triggered before making any decisions. I'm going to review the requested URL and identify what part of the request matched the detection rule.

<img width="799" height="525" alt="image" src="https://github.com/user-attachments/assets/87deb02a-e4d4-4e93-9741-17cb2d9411fd" />

After expanding the original alert, I've been able to find the following details:

<img width="1147" height="677" alt="image" src="https://github.com/user-attachments/assets/37212ade-66a4-4695-b33e-078fcaa8ad8d" />

Based on the rule name, this alert appears to be related to a possible Command Injection detection. However, I do not want to make a conclusion yet based only on the alert name.

The requested URL was:

`https://letsdefend.io/blog/?s=skills`

The HTTP request method was:

`GET`

At first glance, the URL does not appear obviously malicious. The part that stands out is the search parameter:

`?s=skills`

The value `skills` contains the letters `ls`, which is also a Linux/Unix command used to list files and directories. However, in this case, `ls` appears as part of a normal word rather than as a standalone command.

Because of this, the alert may have triggered due to the detection rule matching the `ls` substring inside `skills`. At this point, I cannot determine that the traffic is malicious based only on the original alert details. I need to review the related logs, request context, and any additional activity before deciding whether this is a true Command Injection attempt or a false positive. Since this alert is related to possible Command Injection, I am going to focus on the request parameters and look for signs of operating system commands, command separators, or suspicious input being passed to the application.


## Playbook Step 2: Collect Data

The next step of the playbook asks me to collect quick context about the traffic so I can better understand what devices and IP addresses are involved. For this step, I’ll review the source and destination information, determine whether the traffic is coming from an external address or from inside the company network, and gather any available ownership or reputation details.

<img width="800" height="562" alt="image" src="https://github.com/user-attachments/assets/0d084ef1-f723-4cad-a5ce-ae16d554607c" />

Since this alert involves suspicious web traffic, I’ll focus on identifying the source device, the destination address, and whether the IP or URL has any suspicious reputation indicators.

I started by reviewing the original logs tied to the alert:

<img width="1073" height="767" alt="image" src="https://github.com/user-attachments/assets/bff14c01-7331-4977-a7ab-11affed9eebb" />

As I can see here, there are 7 events that correlate back to the same source IP address. I'll start by looking at the original log that triggered the alert.

<img width="1071" height="767" alt="image" src="https://github.com/user-attachments/assets/02762286-6cab-4966-a5cb-b6b88d5f6ca7" />

<img width="1076" height="770" alt="image" src="https://github.com/user-attachments/assets/fc48e44e-756b-4648-9471-a52bd99d9aa9" />

After reviewing the original log that triggered the alert, the request does not appear suspicious at first glance. The source address `172.16.17.46` sent a `GET` request to the destination address `188.114.96.15` over port `443`.

The requested URL was:

`https://letsdefend.io/blog/?s=skills`

The request was listed as `Permitted`, and the server returned HTTP response status `200` with a response size of `2577`.

In the context of a possible Command Injection alert, I focused on the request parameter. The URL contained the parameter:

`?s=skills`

Although the value `skills` contains the letters `ls`, this does not appear to be a standalone Linux command. Instead, it appears to be part of a normal search term on the LetsDefend blog. I also do not see command separators such as `;`, `&&`, `|`, or other command execution syntax.

Based on the original log alone, this request does not appear to show clear evidence of Command Injection. At this stage, I need to review the related logs to determine whether there is any additional suspicious activity or whether this alert may be a false positive caused by a substring match.

After reviewing the original log, I went to Endpoint Security to identify the source and destination addresses involved in the alert.

<img width="908" height="547" alt="image" src="https://github.com/user-attachments/assets/f8831b67-4521-4051-b5ed-2960d28380b9" />

I was able to find the source address `172.16.17.46` in Endpoint Security. This endpoint was identified as `EliotPRD`, which is part of the `letsdefend.local` domain. The device is a `64-bit` Ubuntu `16.04.4` client, and the primary user is listed as `eliot`.

<img width="837" height="574" alt="image" src="https://github.com/user-attachments/assets/58dea624-3773-41fd-83da-db326a531681" />

<img width="838" height="574" alt="image" src="https://github.com/user-attachments/assets/19dc7836-d0df-4538-ab6f-e3fe5e400353" />

I was not able to find the destination address `188.114.96.15` as an internal endpoint. Based on the Network Action and Browser History tabs, this destination address appears to be associated with the external website that `EliotPRD` was browsing.

The browser history showed normal-looking LetsDefend blog activity leading up to the alert, including visits to several LetsDefend blog pages. The URL that triggered the alert was:

`https://letsdefend.io/blog/?s=skills`

At this stage, the activity looks more like normal user browsing than a clear Command Injection attempt. The alert appears to have triggered because the search parameter value `skills` contains the substring `ls`, but I do not see `ls` submitted as a standalone command or combined with command execution syntax.

<img width="1222" height="918" alt="image" src="https://github.com/user-attachments/assets/a49cc817-5957-4449-bd95-5521fea54da6" />

<img width="1111" height="852" alt="image" src="https://github.com/user-attachments/assets/a15a5ba0-35a3-4c8f-8c9e-cb9600563240" />

As an extra precaution, I also checked the destination IP address `188.114.96.15` in VirusTotal and AbuseIPDB. Both checks did not return suspicious results or evidence that the IP address was malicious.

This further supports the idea that the destination address was simply the external website being accessed by the user, rather than a known malicious host.


## Playbook Step 3: Examine HTTP Traffic
The next step of the playbook asks me to examine the HTTP traffic for signs of a web attack. Since this alert is related to a possible Command Injection detection, I need to review the full HTTP request and look for suspicious values in the URL or request fields.

<img width="796" height="616" alt="image" src="https://github.com/user-attachments/assets/f911062f-24b1-4856-b827-686da44f58c3" />

In this case, the requested URL was:

`https://letsdefend.io/blog/?s=skills`

The request method was:

`GET`

The URL shows that the user was browsing the LetsDefend blog and using the search parameter:

`?s=skills`

At first glance, this does not appear to be suspicious. The value `skills` contains the letters `ls`, which is also a Linux/Unix command, but it appears as part of a normal word rather than as a standalone command.

I also did not observe command separators or command execution syntax such as `;`, `&&`, `|`, or backticks. Because of this, the HTTP traffic does not show clear evidence of a Command Injection attempt based on the original alert.


## Playbook Step 4: Is Traffic Malicious?

The next step of the playbook asks me to decide whether the traffic is malicious based on the investigation so far.

<img width="796" height="429" alt="image" src="https://github.com/user-attachments/assets/924ff12d-975e-493b-b1fd-519926872bbf" />

Before making that decision, I’m going to review the related logs and put together a timeline of the activity. Based on the original log alone, the request does not appear clearly malicious because the value `skills` looks like a normal search term rather than a standalone command.

However, a single log can be misleading if it is reviewed without the surrounding context. Since there are multiple logs that appear to correlate with this alert, I want to understand the full sequence of activity, whether the requests came from the same source address, and whether any similar command injection attempts appeared before or after the alert.

By reviewing the timeline as a whole, I can better determine whether this was normal web browsing activity or suspicious activity that may indicate an actual Command Injection attempt.


The first related event occurred on `Feb, 27, 2022, 12:01 AM`. The source address `172.16.17.46` sent a `GET` request to the destination address `188.114.96.15` over port `443`.

<img width="1076" height="693" alt="image" src="https://github.com/user-attachments/assets/8eddc5ce-ab80-46ad-8385-069513bd9f37" />

The requested URL was:

`https://letsdefend.io/blog/`

This appears to be normal browsing activity. The user accessed the LetsDefend blog homepage, and there were no suspicious parameters, operating system commands, or command execution syntax observed in the URL.

The request was listed as `Permitted`. Based on this event alone, there is no clear evidence of Command Injection activity.


The second related event occurred on `Feb, 27, 2022, 12:05 AM`. The same source address `172.16.17.46` sent another `GET` request to the destination address `188.114.96.15` over port `443`.

<img width="1077" height="696" alt="image" src="https://github.com/user-attachments/assets/490c6997-a74a-4cad-8e79-de6ab7f6b06b" />

The requested URL was:

`https://letsdefend.io/blog/how-to-become-a-soc-analyst/`

This appears to be normal browsing behavior. The user accessed a LetsDefend blog article about becoming a SOC analyst, and there were no suspicious parameters, operating system commands, or command execution syntax observed in the URL.

The request was listed as `Permitted`. Based on this event, there is still no clear evidence of Command Injection activity.


The third related event occurred on `Feb, 27, 2022, 12:13 AM`. The same source address `172.16.17.46` sent another `GET` request to the destination address `188.114.96.15` over port `443`.

<img width="1075" height="688" alt="image" src="https://github.com/user-attachments/assets/85504bd6-d25b-4533-93bd-25a8aeeb7fd9" />

The requested URL was:

`https://letsdefend.io/blog/how-to-analyze-rtf-template-injection-attacks/`

This also appears to be normal browsing behavior. The user accessed a LetsDefend blog article about analyzing RTF template injection attacks. Even though the article topic is security-related, the URL itself does not show evidence of Command Injection activity.

There were no suspicious parameters, standalone operating system commands, or command execution syntax observed in the URL. Based on this event, the activity still appears consistent with normal blog browsing.


The fourth related event occurred on `Feb, 27, 2022, 12:23 AM`. The same source address `172.16.17.46` sent another `GET` request to the destination address `188.114.96.15` over port `443`.

<img width="1074" height="698" alt="image" src="https://github.com/user-attachments/assets/c6f08231-27ad-42ab-ae94-2239e3a2096f" />

The requested URL was:

`https://letsdefend.io/blog/red-team-vs-blue-team-learn-the-difference/`

This appears to be normal browsing behavior. The user accessed a LetsDefend blog article about the difference between red team and blue team roles.

There were no suspicious parameters, standalone operating system commands, or command execution syntax observed in the URL. Based on this event, the activity continues to look like normal blog browsing rather than Command Injection activity.


The fifth related event occurred on `Feb, 27, 2022, 12:35 AM`. The same source address `172.16.17.46` sent another `GET` request to the destination address `188.114.96.15` over port `443`.

<img width="1079" height="698" alt="image" src="https://github.com/user-attachments/assets/bdde6ea3-f8bf-4792-87c0-e4419104654b" />

The requested URL was:

`https://letsdefend.io/blog/how-to-prepare-soc-analyst-resume/`

This appears to be normal browsing behavior. The user accessed a LetsDefend blog article about preparing a SOC analyst resume.

There were no suspicious parameters, standalone operating system commands, or command execution syntax observed in the URL. Based on this event, the activity still appears consistent with normal blog browsing rather than Command Injection activity.


The sixth related event occurred on `Feb, 27, 2022, 12:36 AM`. This was the original log that triggered the SOC alert. The same source address `172.16.17.46` sent another `GET` request to the destination address `188.114.96.15` over port `443`.

<img width="1071" height="767" alt="image" src="https://github.com/user-attachments/assets/6c9d5ef1-2fa6-45a6-842c-d5aadb8763a9" />

The requested URL was:

`https://letsdefend.io/blog/?s=skills`

This request stood out because the search parameter contained the value `skills`:

`?s=skills`

At first glance, this does not appear to be malicious. The value `skills` looks like a normal search term, especially in the context of the user browsing the LetsDefend blog.

However, the word `skills` contains the letters `ls`, which is also a Linux/Unix command used to list files and directories. In this case, `ls` does not appear as a standalone command. It appears as part of a normal word and is not combined with command execution syntax such as `;`, `&&`, `|`, or backticks.

Because of this, this event appears more consistent with normal search activity than a true Command Injection attempt.


The seventh and final related event occurred on `Feb, 27, 2022, 12:37 AM`. The same source address `172.16.17.46` sent another `GET` request to the destination address `188.114.96.15` over port `443`.

<img width="1074" height="700" alt="image" src="https://github.com/user-attachments/assets/b446a116-7d99-4b4e-aa94-e604275f191d" />

The requested URL was:

`https://letsdefend.io/blog/soc-analyst-career-without-a-degree/`

This appears to be normal browsing behavior. The user accessed another LetsDefend blog article, this time about a SOC analyst career path without a degree.

There were no suspicious parameters, standalone operating system commands, or command execution syntax observed in the URL. Based on this final event, the activity continues to look like normal blog browsing rather than Command Injection activity.


Looking at the timeline as a whole, the activity appears consistent with normal user browsing on the LetsDefend blog. The user accessed several blog articles related to SOC analyst careers, resumes, red team vs blue team concepts, and security topics.

The alert appears to have triggered on the URL:

`https://letsdefend.io/blog/?s=skills`

The value `skills` contains the letters `ls`, but `ls` was not submitted as a standalone command. I also did not observe command separators or command execution syntax such as `;`, `&&`, `|`, or backticks.

Based on the full timeline reviewed so far, there is no clear evidence of a true Command Injection attempt. The activity appears more consistent with normal browsing and search behavior, so I assessed the traffic as **Non-Malicious** at this stage of the investigation.


## Playbook Step 5: Check for Different Request or Traffic

The next step of the playbook asks me to check whether there is different traffic from the same source address. Even if the HTTP request that triggered the alert appears harmless, there may still be other suspicious or malicious traffic coming from the same source device.

For this step, I need to review the related traffic from the source address and determine whether there are any additional requests besides the original alert.

<img width="800" height="484" alt="image" src="https://github.com/user-attachments/assets/0c13930a-6c66-4880-8298-2c25ca4efc47" />

After reviewing the original alert, I searched for all logs originating from the source address `172.16.17.46` to determine whether there was any different traffic from the same device.

<img width="1070" height="749" alt="image" src="https://github.com/user-attachments/assets/42e6400b-f530-43f3-a818-e09df754ae1e" />

The search returned `7` related events from the same source address. This means there was additional traffic from the same device besides the original alert. However, the related events appeared to involve normal browsing activity to the LetsDefend blog. I did not find additional requests from the source address that showed standalone operating system commands, command separators, or command execution syntax.

<img width="869" height="656" alt="image" src="https://github.com/user-attachments/assets/64588085-f44e-437f-9b95-717f0544845e" />

<img width="837" height="574" alt="image" src="https://github.com/user-attachments/assets/58dea624-3773-41fd-83da-db326a531681" />

<img width="838" height="574" alt="image" src="https://github.com/user-attachments/assets/19dc7836-d0df-4538-ab6f-e3fe5e400353" />

I also reviewed Endpoint Security for additional context. The Browser History and Network Action tabs lined up with the same LetsDefend blog activity observed in the logs. As an extra check, I reviewed the Terminal History and only found the command `date`, which does not support command injection activity.

Based on the logs, browser history, network actions, and terminal history reviewed so far, I did find additional traffic from the same source address, so I selected **Yes** in the playbook. However, the additional traffic did not appear suspicious and was consistent with normal browsing activity.


## Playbook Step 6: Analyst Notes

The next step of the playbook asks me to add analyst notes for the case. I used this section to summarize the main findings from the investigation, including why the traffic did not show clear evidence of Command Injection activity.

<img width="798" height="510" alt="image" src="https://github.com/user-attachments/assets/8efe0cdd-e6bb-45a2-9893-58cec5ea7d53" />

Analyst Note: On `Feb. 27, 2022`, the system detected a possible Command Injection attempt from the internal source IP address `172.16.17.46`. The activity involved the user browsing the LetsDefend website, with the alert triggering on the URL `https://letsdefend.io/blog/?s=skills`.

During the investigation, I found multiple related logs from the same source address. The activity appeared consistent with normal browsing behavior on the LetsDefend blog. The user accessed several blog pages related to SOC analyst topics, resumes, red team vs blue team concepts, and security articles.

The alert appears to have triggered because the search parameter value `skills` contains the letters `ls`. However, I did not observe `ls` submitted as a standalone command, and I did not find command separators or command execution syntax such as `;`, `&&`, `|`, or backticks in the related requests.

The source IP address `172.16.17.46` was identified as an internal endpoint named `EliotPRD`. I also checked reputation sources such as VirusTotal and AbuseIPDB as an extra precaution, and no malicious or suspicious results were found.

I reviewed the related logs, Browser History, Network Action, and Terminal History in Endpoint Security. The Browser History and Network Action activity lined up with normal LetsDefend blog browsing, and the Terminal History only showed the command `date`. Based on the evidence reviewed so far, I did not find signs of command injection activity or different suspicious traffic from the same source device.


## Playbook Step 7: Finish the Playbook!

The final playbook step was to confirm the investigation and close the case. At this point, I had already added the relevant artifacts, summarized my findings into the analyst notes, and completed all the required playbook actions.

<img width="798" height="346" alt="image" src="https://github.com/user-attachments/assets/d7819091-ed53-4609-a61c-512030a78b18" />


## Final Verdict and Closing Case: False Positive

<img width="598" height="435" alt="image" src="https://github.com/user-attachments/assets/57d072c2-f160-430b-acc9-60f14b7e94dd" />

After completing the playbook, I reviewed the evidence I have collected throughout the investigation to determine whether the alert was a true positive or false positive.

My final verdict is that this alert is a **False Positive**. The alert appeared to trigger because the URL contained the search parameter value `skills`, which includes the letters `ls`. However, `ls` was not submitted as a standalone operating system command.

The requested URL was:

`https://letsdefend.io/blog/?s=skills`

This URL appears to show normal browsing activity on the LetsDefend blog. The user accessed multiple LetsDefend blog pages before and after the alert, and the overall timeline was consistent with normal web browsing and search behavior.

I also did not observe command separators or command execution syntax such as `;`, `&&`, `|`, or backticks in the related requests. The Browser History and Network Action activity in Endpoint Security also lined up with the same LetsDefend blog activity seen in the logs.

As an extra check, I reviewed the Terminal History and only found the command `date`, which did not support evidence of command injection activity. Reputation checks using VirusTotal and AbuseIPDB also did not show malicious or suspicious results.

Based on the normal browsing timeline, the lack of standalone operating system commands, the lack of command execution syntax, the clean reputation checks, and the Endpoint Security evidence, I assessed this alert as a **False Positive**.


## Results!!

<img width="965" height="846" alt="image" src="https://github.com/user-attachments/assets/f2a27bf3-e3bc-4906-a4f2-d4fd28438e28" />

Hooray, we were able to correctly identify that the URL was a false positive!
