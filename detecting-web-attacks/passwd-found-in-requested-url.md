# SOC Alert Investigation: Password Found in Requested URL - Possible LFI Attack

<img width="986" height="259" alt="image" src="https://github.com/user-attachments/assets/a2a2363f-5f03-4dfa-a392-2637cecf3b3a" />

Our investigation starts here with a high-severity **LetsDefend SOC Alert: SOC170 - Passwd Found in Requested URL - Possible LFI Attack**. This is a Web Attack alert, so I'm going to be looking at suspicious web requests and Local File Inclusion attacks. 

To begin the investigation, I've created a case for the alert and I'll work through the provided playbook.

## Playbook Step 1: Understand Why the Alert Was Triggered

The first step of the playbook asks me to understand why the alert was triggered before making any decisions. Since this alert is related to a possible Local File Inclusion attack, I'm going to review the requested URL and identify what part of the request matched the detection rule.

<img width="799" height="525" alt="image" src="https://github.com/user-attachments/assets/87deb02a-e4d4-4e93-9741-17cb2d9411fd" />

After expanding the original alert, I've been able to find the following details:

<img width="962" height="641" alt="image" src="https://github.com/user-attachments/assets/c3712538-fdd4-4c71-af42-b7fdd630904a" />


Based on the rule name, this alert appears to be related to a possible Local File Inclusion attack. The rule name specifically mentioned `Passwd Found in Requested URL`, which suggests that the alert was triggered because the requested URL contained a reference te the Linux `/etc/paswd` file.

The original alert also shows us that the request method was `GET`, which means the activity involved a web request sent to retrieve a resource from a server. This helps us identify that the traffic being investigated is HTTP web traffic, and that suspicious activity occurred through the requested URL.

## Playbook Step 2: Collect Data

The next step of the playbook asks me to collect quick context about the traffic so I can better understand what devices and IP addresses are involved. For this step, I’ll review the source and destination information, determine whether the traffic is coming from an external address or from inside the company network, and gather any available ownership or reputation details.

Since this alert involves suspicious web traffic, I’ll focus on identifying the source device, the destination address, and whether the IP or URL has any suspicious reputation indicators.

<img width="800" height="562" alt="image" src="https://github.com/user-attachments/assets/08db5215-aa1f-41eb-a7c2-7c0cd50519bf" />

I started by reviewing the original log tied to the alert.

<img width="1564" height="752" alt="image" src="https://github.com/user-attachments/assets/5edf34f0-62a4-43cb-af1d-86ae0a17047d" />

The event type was listed as `Firewall`, and the device action was `Permitted`, meaning the traffic was allowed rather than blocked.

The log showed traffic from the source address `106.55.45.162` to the destination address `172.16.17.13` over port `443`. The requested URL was:
`https://172.16.17.13/?file=../../../../etc/passwd`

This URL stood out because it contains `../` which is a directory traversal pattern, and it references `/etc/passwd`, which is commonly associated with Local File Inclusion attempts.

After investigating the logs that pertained to the alert, I went to investigate both IP addresses in Endpoint Security. However, I was only able to find one IP that pertained to the original alert.

<img width="952" height="669" alt="image" src="https://github.com/user-attachments/assets/0e054f33-b881-4e21-b4db-b6a9f27755d1" />

As I can see here, the destination address's endpoint  is `172.16.17.13`. The endpoint was identified as `WebServer1006`, which is part of the `letsdefend.local` domain, and operated by the user `webadmin11`. The last login time was listed as `Feb, 19, 2022, 01:01 PM`.

As I mentioned above, I couldn't find the source address `106.55.45.162` in Endpoint Security, so I looked it up on VirusTotal because I suspected it was external to the company network.

<img width="1258" height="907" alt="image" src="https://github.com/user-attachments/assets/a1d5357f-af4a-466b-b2a4-bc802b2b0f65" />

As I suspected, the IP address associated with the source address was indeed external to the company network. The IP address was associated with `Shenzhen Tencent Computer Systems Company Limited`. VirusTotal did not show any vendor detections for the IP address, so the IP reputation alone does not prove malicious activity. However, the source being external combined with the requested URL containing `/etc/passwd` supports treating this traffic as suspicious.

## Playbook Step 3: Examine HTTP Traffic
The next step of the playbook asks me to examine the HTTP traffic for signs of a web attack. Since this alert is related to a possible Local File Inclusion attack, I need to review the full HTTP request and look for suspicious values in the URL or request fields.

<img width="796" height="616" alt="image" src="https://github.com/user-attachments/assets/f911062f-24b1-4856-b827-686da44f58c3" />

In this case, the requested URL contains `?file=../../../../etc/passwd`, which stands out because it appears to use directory traversal patterns to reference the `/etc/passwd` file. This suggests that the request may be attempting to access a local system file through the web application.

## Playbook Step 4: Is Traffic Malicious?

The next step of the playbook asks me to decide whether the traffic is malicious based on the investigation so far.

<img width="796" height="429" alt="image" src="https://github.com/user-attachments/assets/924ff12d-975e-493b-b1fd-519926872bbf" />

Based on the evidence reviewed, I assessed the traffic as **Malicious**. The request came from an external source IP address and targeted the internal web server `172.16.17.13`. The requested URL contained `?file=../../../../etc/passwd`, which appears to be an attempt to use directory traversal to access the `/etc/passwd` file.

Even though the source IP did not show vendor detections in VirusTotal, the request itself is suspicious because it matches behavior commonly associated with Local File Inclusion attempts. Based on this, I selected **Malicious** in the playbook.

## Playbook Step 5: What is The Attack Type?

The next step of the playbook asks me to identify the attack type based on the malicious traffic observed during the investigation.

<img width="800" height="370" alt="image" src="https://github.com/user-attachments/assets/ce95af31-516c-4eee-a711-0dc6597cc1ed" />


Based on the requested URL, I selected **LFI & RFI**. The request contained `?file=../../../../etc/passwd`, which suggests a Local File Inclusion attempt. The `../` sequences appear to be directory traversal used to move through the file system, while `/etc/passwd` is a sensitive local system file that's commonly targeted in LFI attempts.

Because the suspicious request was trying to access a local file through a web application parameter, I selected **LFI & RFI** because it's the best description of the attack type, from the available options.

## Playbook Step 6: Check if it is a Planned Test

The next step of the playbook asks me to determine whether the malicious traffic may have been part of a planned test or attack simulation. Security testing activity can sometimes trigger alerts, so I am going to check whether there is any evidence that this traffic was expected.

<img width="804" height="549" alt="image" src="https://github.com/user-attachments/assets/112ecd38-f3d9-43c6-92b0-6f75f0b291fc" />

To do this, I will search for related information such as the hostname, username, and IP addresses in the mailbox. I will also review whether the device involved appears to belong to an attack simulation product or testing platform.

I searched the mailbox for the related IP address, hostname, and username to check whether there was any email indicating that this activity was part of planned work or an approved test.

<img width="1010" height="702" alt="image" src="https://github.com/user-attachments/assets/befd0585-9ea7-41e5-8a3b-123dcf3149b7" />

<img width="1007" height="715" alt="image" src="https://github.com/user-attachments/assets/ee27c8f1-6819-46da-addc-98505c76fc3e" />

<img width="1010" height="719" alt="image" src="https://github.com/user-attachments/assets/0d5262b0-d3ea-405c-b562-c165268f071a" />

I searched for `172.16.17.13`, `WebServer1006`, and `webadmin11`, but no related emails were found. I also reviewed the device and request details, and I did not find evidence that the traffic was generated by an attack simulation product.

Based on this, I determined that there was no evidence of a planned test, so I selected **Not Planned** in the playbook.

## Playbook Step 7: Determine Direction of Traffic

The next step of the playbook asks me to identify the direction of the malicious traffic.

<img width="798" height="415" alt="image" src="https://github.com/user-attachments/assets/3bcc0446-370d-4061-a273-b56bfa1fbf61" />

Based on the original log, the source address was `106.55.45.162`, which appears to be external to the company network. The destination address was `172.16.17.13`, which belongs to the internal company network and is associated with `WebServer1006`, whereas the source address was based in China.

Because the traffic originated from an external source and targeted an internal company web server, I selected **Internet → Company Network**.

## Playbook Step 8: Check Whether the Attack was Successful

The next step of the playbook asks me to determine whether the attack was successful based on the available evidence.

<img width="798" height="696" alt="image" src="https://github.com/user-attachments/assets/ae152882-1f73-4e0c-88da-42927a2d270d" />

I referred back to the original log:

<img width="925" height="750" alt="image" src="https://github.com/user-attachments/assets/c09585ef-779e-4279-9e84-8137c163fcf1" />

In the original log, the HTTP response status was `500`, which indicates a server-side error. The HTTP response size was also `0`, meaning there was no response body returned from the server.

Because the request did not appear to return any file contents or useful data back to the attacker, I determined that the attack was not successful.

## Playbook Step 9: Was the Attack Successful?

The next playbook question asks me to confirm whether the attack was successful based on the previous investigation step.

<img width="798" height="364" alt="image" src="https://github.com/user-attachments/assets/3d5309dd-d061-4d61-bd3c-08aa3cd7800f" />

Based on the HTTP response status of `500` and the HTTP response size of `0`, I determined that the attack was not successful. The request appears to have reached the server, but there was no evidence that the `/etc/passwd` file contents were returned to the attacker.

Based on this evidence, I selected **No** in the playbook.

## Playbook Step 10: Add Artifacts

<img width="798" height="446" alt="image" src="https://github.com/user-attachments/assets/18ed98a5-b0df-4962-b06e-67b89478c4ec" />

Based on the evidence collected so far, I added the requested URL as a `URL Address` artifact because it contained the suspicious `?file=../../../../etc/passwd` parameter associated with the possible LFI attempt.

I also added the source IP address `106.55.45.162` as an `IP Address` artifact because it was the external address that sent the malicious web request to the internal web server.

## Playbook Step 11: Do You Need Tier 2 Escalation?

The next step of the playbook asks me to determine whether Tier 2 escalation is needed. According to the playbook, escalation is required if the attack succeeds or if an internal device is compromised.

<img width="798" height="656" alt="image" src="https://github.com/user-attachments/assets/e770c515-12dc-4627-8ccd-5d8c17fe2010" />

In this case, the attack came from the Internet toward the company network, but the evidence showed that the attack was not successful. The HTTP response status was `500`, and the response size was `0`, meaning there was no evidence that the requested file contents were returned to the attacker.

Because the attack did not succeed, I selected **No** for Tier 2 escalation.

## Playbook Step 12: Analyst Notes

The next step of the playbook asks me to add analyst notes for the case. I used this section to summarize the main findings from the investigation, including why the traffic looked malicious and whether there was evidence that the attack succeeded.

<img width="798" height="510" alt="image" src="https://github.com/user-attachments/assets/8efe0cdd-e6bb-45a2-9893-58cec5ea7d53" />

Analyst Note: The traffic originated from an external source IP address outside of the company network and targeted the internal web server. The requested URL contained directory traversal patterns and referenced /etc/passwd, which made the request look like a possible Local File Inclusion attempt.

Based on the suspicious URL structure, I assessed the traffic as malicious. However, the evidence reviewed does not indicate that the attack was successful. The HTTP response status was 500, and the HTTP response size was 0, meaning there was no evidence that the requested file contents were returned to the attacker.

## Playbook Step 13: Finish the Playbook!

The final playbook step was to confirm the investigation and close the case. At this point, I had already added the relevant artifacts, summarized my findings into the analyst notes, and completed all the required playbook actions.

<img width="798" height="346" alt="image" src="https://github.com/user-attachments/assets/2ca1432f-4944-4122-9d64-f2575b3cd889" />

## Final Verdict and Closing Case: True Positive

<img width="602" height="436" alt="image" src="https://github.com/user-attachments/assets/50fe747c-74e5-4563-a3fa-16f52800aae5" />

After completing the playbook, I reviewed the evidence I havecollected throughout the investigation to determine whether the alert was a true positive or false positive.

My final verdict is that this alert is a **True Positive**. The traffic appeared malicious because an external source IP address sent a web request to an internal web server with a URL containing directory traversal patterns and a reference to `/etc/passwd`.

The requested URL, `https://172.16.17.13/?file=../../../../etc/passwd`, strongly suggests a possible Local File Inclusion attempt. Even though the source IP address was not flagged as malicious in VirusTotal, the request itself was suspicious because it attempted to access a sensitive local system file through a web application parameter.

Another important detail is that the device action was listed as `Permitted`, meaning the request was allowed through the security control. However, the attack does not appear to have been successful because the HTTP response status was `500` and the response size was `0`, meaning there was no evidence that the requested file contents were returned to the attacker.

Based on the suspicious URL structure, the external-to-internal traffic direction, and the Local File Inclusion pattern observed in the request, I assessed this alert as a **True Positive**.

## Results!!

<img width="1005" height="835" alt="image" src="https://github.com/user-attachments/assets/3f6e7d5a-b823-4ed6-aa10-aff8307ca2f0" />

Hooray, we were able to correctly identify that the URL was a true positive!

## MITRE ATT&CK Framework 

Reference: https://attack.mitre.org/techniques/T1190/

This alert maps to **Initial Access** because the traffic appears to be an attempt to exploit an exposed web application. The requested URL contained `?file=../../../../etc/passwd`, which suggests a possible Local File Inclusion attempt against the internal web server.

Even though the attack does not appear to have been successful, the behavior still maps to **Exploit Public-Facing Application** because the attacker attempted to abuse a web application parameter to access a sensitive local file.
