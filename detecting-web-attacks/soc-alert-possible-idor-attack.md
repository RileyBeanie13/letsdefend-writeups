# SOC Alert Investigation: Possible IDOR Attack Detected

<img width="1004" height="228" alt="image" src="https://github.com/user-attachments/assets/2c2adaf5-f483-4c47-bc30-e839ecaff338" />

Our investigation starts here with a medium-severity **LetsDefend SOC Alert: SOC169 - Possible IDOR Attack**. This is a Web Attack alert, so I'm going to be looking at suspicious web requests and indicators of Insecure Direct Object Reference (IDOR) attacks. 

To begin the investigation, I've created a case for the alert and I'll work through the provided playbook.

## Playbook Step 1: Understand Why the Alert Was Triggered

The first step of the playbook asks me to understand why the alert was triggered before making any decisions. Since this alert is related to a possible IDOR attack, I'm going to review the requested URL and identify what part of the request could have matched the detection rule. I'm also going to investigate between which two devices the traffic is occurring.

<img width="799" height="525" alt="image" src="https://github.com/user-attachments/assets/8ec5fed2-b1c3-4378-8bda-fb7291ecd6cd" />

After expanding the original alert, I've been able to find the following details:

<img width="1006" height="667" alt="image" src="https://github.com/user-attachments/assets/a7e5a782-69bb-4858-be08-c7bad59890e7" />

Based on the rule name, this alert appears to be related to a possible IDOR attack. The rule name specifically mentioned `Possible IDOR Attack Detected`, which suggests that the alert was triggered because the requested URL referenced `get_user_info`, which may have involved access to user information.

The original alert also shows that the request method was `POST`, which means the activity involved a web request where data was submitted to the server. This helps identify the traffic as HTTP web traffic and shows that the suspicious activity occurred through the requested URL and submitted request data.

## Playbook Step 2: Collect Data

The next step of the playbook asks me to collect quick context about the traffic so I can better understand what devices and IP addresses are involved. For this step, I’ll review the source and destination information, determine whether the traffic is coming from an external address or from inside the company network, and gather any available ownership or reputation details.

Since this alert involves suspicious web traffic, I’ll focus on identifying the source device, the destination address, and whether the IP or URL has any suspicious reputation indicators.

<img width="800" height="562" alt="image" src="https://github.com/user-attachments/assets/08db5215-aa1f-41eb-a7c2-7c0cd50519bf" />

I started by reviewing the original logs tied to the alert:

<img width="1108" height="748" alt="image" src="https://github.com/user-attachments/assets/fffa0352-190f-45f2-8b2c-1e52e88d18c3" />

<img width="1113" height="654" alt="image" src="https://github.com/user-attachments/assets/72bfdc40-ce7d-4773-ac43-3aeb7da7a803" />

The event type was listed as `Firewall`, and the device action was `Permitted`, meaning the traffic was allowed rather than blocked.

The log showed traffic from the source address `134.209.118.137` to the destination address `172.16.17.15` over port `443`. The requested URL was:

`https://172.16.17.15/get_user_info/`

This URL stood out because it references a `get_user_info` endpoint, which appears to involve retrieving user information. Since the alert is related to a possible IDOR attack, repeated requests to this type of endpoint are suspicious because IDOR attacks involve accessing user or object information without proper authorization.

After investigating the logs that pertained to the alert, I went to investigate both IP addresses in Endpoint Security. However, I was only able to find one IP that pertained to the original alert.

<img width="984" height="592" alt="image" src="https://github.com/user-attachments/assets/21680e32-549f-41a1-b7be-6542edffb8d3" />

As I can see here, the destination address's endpoint is `172.16.17.15`. The endpoint was identified as `WebServer1005`, which is part of the `letsdefend.local` domain, and operated by the user `webadmin35`. The last login time was listed as `Feb, 15, 2022, 01:43 PM`.

As I mentioned above, I couldn't find the source address `134.209.118.137` in Endpoint Security, so I looked it up on VirusTotal because I suspected it was external to the company network.

<img width="1255" height="901" alt="image" src="https://github.com/user-attachments/assets/e162815d-6740-4bfd-b017-045cac4e5154" />

As I suspected, the IP address associated with the source address was external to the company network. VirusTotal associated the IP address with `AS14061 DigitalOcean, LLC`. VirusTotal did not show any vendor detections for the IP address, so the IP reputation alone does not prove malicious activity.

However, the source being external, combined with multiple permitted requests to the `get_user_info` endpoint, supports treating this traffic as suspicious in the context of a possible IDOR attack.

<img width="1256" height="909" alt="image" src="https://github.com/user-attachments/assets/0c76c689-7acc-4fce-9631-d230b813695d" />

However, Cisco Talos showed that the source IP reputation was poor, which is worth paying attention to.

## Playbook Step 3: Examine HTTP Traffic
The next step of the playbook asks me to examine the HTTP traffic for signs of a web attack. Since this alert is related to a possible IDOR attack, I need to review the full HTTP request and look for suspicious values in the URL or request fields.

<img width="796" height="616" alt="image" src="https://github.com/user-attachments/assets/f911062f-24b1-4856-b827-686da44f58c3" />

In this case, the requested URL contains `/get_user_info/`, which stands out because it appears to be an endpoint related to retrieving user information. Since the alert is related to a possible IDOR attack, repeated requests to this endpoint are suspicious because the attacker may be attempting to access user information without proper authorization.

## Playbook Step 4: Is Traffic Malicious?

The next step of the playbook asks me to decide whether the traffic is malicious based on the investigation so far.

<img width="796" height="429" alt="image" src="https://github.com/user-attachments/assets/924ff12d-975e-493b-b1fd-519926872bbf" />

Based on the evidence reviewed, I assessed the traffic as **Malicious**. The request came from an external source IP address and targeted the internal web server `172.16.17.15`. The requested URL was `https://172.16.17.15/get_user_info/`, which appears to be related to retrieving user information.

This stood out because multiple requests were made to the same endpoint from the same external source address. Since this alert is related to a possible IDOR attack, repeated requests to a user information endpoint may have indicated an attempt to access user or object data without proper authorization.

In addition, the source IP address did not show vendor detections in VirusTotal, but Cisco Talos listed the IP reputation as poor. While reputation alone is not enough to prove malicious activity, the poor reputation combined with repeated requests to the `get_user_info` endpoint supports treating the traffic as suspicious.

Based on this evidence, I selected **Malicious** in the playbook.

## Playbook Step 5: What Is The Attack Type?

The next step of the playbook asks me to identify the attack type based on the malicious traffic observed during the investigation.

<img width="800" height="370" alt="image" src="https://github.com/user-attachments/assets/ce95af31-516c-4eee-a711-0dc6597cc1ed" />

Based on the requested URL and the alert context, I selected **IDOR**. The request targeted the `get_user_info` endpoint, which appears to be related to retrieving user information.

This stood out because multiple requests were made to the same user information endpoint from the same external source address. In an IDOR attack, an attacker may attempt to access user or object data by manipulating or repeatedly requesting resources that should require proper authorization.

Because the suspicious activity involved repeated requests to an endpoint related to user information, **IDOR** was the best match from the available attack type options.

## Playbook Step 6: Check if it is a Planned Test

The next step of the playbook asks me to determine whether the malicious traffic may have been part of a planned test or attack simulation. Security testing activity can sometimes trigger alerts, so I am going to check whether there is any evidence that this traffic was expected.

<img width="804" height="549" alt="image" src="https://github.com/user-attachments/assets/112ecd38-f3d9-43c6-92b0-6f75f0b291fc" />

To do this, I will search for related information such as the hostname, username, and IP addresses in the mailbox. I will also review whether the device involved appears to belong to an attack simulation product or testing platform.

I searched the mailbox for the related IP address, hostname, and username to check whether there was any email indicating that this activity was part of planned work or an approved test.

<img width="1005" height="709" alt="image" src="https://github.com/user-attachments/assets/fc8c5b0c-7803-4a09-8828-6fd838c071c1" />

<img width="1008" height="712" alt="image" src="https://github.com/user-attachments/assets/dad810ff-23fb-44a7-87e7-d360f8366cbf" />

<img width="1005" height="713" alt="image" src="https://github.com/user-attachments/assets/b8fb3373-36d4-4e02-bbcf-9817ff400d01" />

I searched for `172.16.17.15`, `WebServer1005`, and `webadmin35`, but no related emails were found. I also reviewed the device and request details, and I did not find evidence that the traffic was generated by an attack simulation product.

Based on this, I determined that there was no evidence of a planned test, so I selected **Not Planned** in the playbook.

## Playbook Step 7: Determine Direction of Traffic

The next step of the playbook asks me to identify the direction of the malicious traffic.

<img width="798" height="415" alt="image" src="https://github.com/user-attachments/assets/3bcc0446-370d-4061-a273-b56bfa1fbf61" />

Based on the original log, the source address was `134.209.118.137`, which appears to be external to the company network and was associated with `DigitalOcean, LLC`. The destination address was `172.16.17.15`, which belongs to the internal company network.

Because the traffic originated from an external Internet-based source and targeted an internal company web server, I selected **Internet → Company Network**.

## Playbook Step 8: Check Whether the Attack was Successful

The next step of the playbook asks me to determine whether the attack was successful based on the available evidence.

<img width="798" height="696" alt="image" src="https://github.com/user-attachments/assets/ae152882-1f73-4e0c-88da-42927a2d270d" />

I referred back to the original log:

<img width="925" height="750" alt="image" src="https://github.com/user-attachments/assets/c09585ef-779e-4279-9e84-8137c163fcf1" />

After reviewing the related logs, I observed that the HTTP response statuses were `200`, which indicates that the server successfully processed the requests. The response sizes were also greater than `0`, which means the server returned data in response to the requests.

Because the requests received successful responses and returned data, I determined that the attack was successful.

## Playbook Step 9: Was the Attack Successful?

The next playbook question asks me to confirm whether the attack was successful based on the previous investigation step.

<img width="798" height="364" alt="image" src="https://github.com/user-attachments/assets/3d5309dd-d061-4d61-bd3c-08aa3cd7800f" />

To further investigate this, I went back to the multiple logs pertaining to the alert:

<img width="911" height="422" alt="image" src="https://github.com/user-attachments/assets/5b02b12f-9386-4d5b-997f-e3f24a736292" />

<img width="905" height="427" alt="image" src="https://github.com/user-attachments/assets/3c50fe14-dec1-4b67-b3fe-25d7f0c37d87" />

<img width="908" height="431" alt="image" src="https://github.com/user-attachments/assets/8a7295d7-dda5-47b6-922d-3e69c39fc698" />

<img width="905" height="419" alt="image" src="https://github.com/user-attachments/assets/eb0422cc-7e3d-4179-b1fe-1b7e135a914e" />

<img width="912" height="425" alt="image" src="https://github.com/user-attachments/assets/f174ddb8-9a8c-4d61-8463-6139f992a54b" />

Based on the HTTP response statuses and response sizes, I determined that the attack was successful. The related requests returned HTTP response status `200`, which indicates that the server successfully processed the requests.

The response sizes were also not `0`, with response sizes including `253`, `188`, `267`, `158`, and `351`. This means the server returned response data back to the source address.

Because the requests reached the server and the server responded successfully with data, I selected **Yes** in the playbook.

## Playbook Step 10: Containment

The next step of the playbook explains that containment is needed when there is evidence that a device may be compromised. Since the attack appeared to be successful based on the `200` HTTP response statuses and response sizes, containment is the safe next step to help limit potential attacker activity and reduce impact.

<img width="794" height="596" alt="image" src="https://github.com/user-attachments/assets/3d4620af-7ac9-45d6-b8ad-b3f3d17f9dc2" />

To continue the playbook, I went to the Endpoint Security page and changed the containment status for the `WebServer1005`.

<img width="944" height="671" alt="image" src="https://github.com/user-attachments/assets/b8e7d4b9-262f-40f2-9c2e-b62ff328b0f6" />

## Playbook Step 11: Add Artifacts

<img width="798" height="446" alt="image" src="https://github.com/user-attachments/assets/18ed98a5-b0df-4962-b06e-67b89478c4ec" />

Based on the evidence collected so far, I added the requested URL as a `URL Address` artifact because it was the endpoint targeted by the repeated suspicious requests during the possible IDOR investigation.

I also added the source IP address `134.209.118.137` as an `IP Address` artifact because it was the external address associated with the repeated requests to the internal web server.

## Playbook Step 12: Do You Need Tier 2 Escalation?

The next step of the playbook asks me to determine whether Tier 2 escalation is needed. According to the playbook, escalation is required if the attack succeeds or if an internal device is compromised.

<img width="798" height="656" alt="image" src="https://github.com/user-attachments/assets/e770c515-12dc-4627-8ccd-5d8c17fe2010" />

In this case, the attack came from the Internet toward the company network, and the evidence showed that the attack was successful. The related requests returned HTTP response status `200`, and the response sizes were greater than `0`, meaning the server successfully responded with data.

Because the attack succeeded, I selected **Yes** for Tier 2 escalation.

## Playbook Step 13: Analyst Notes

The next step of the playbook asks me to add analyst notes for the case. I used this section to summarize the main findings from the investigation, including why the traffic looked malicious and whether there was evidence that the attack succeeded.

<img width="798" height="510" alt="image" src="https://github.com/user-attachments/assets/8efe0cdd-e6bb-45a2-9893-58cec5ea7d53" />

Analyst Note: The traffic originated from an external source IP address outside of the company network and targeted an internal web server. The requested URL was associated with the `get_user_info` endpoint, which appears to involve retrieving user information. This stood out because multiple requests were made to the same endpoint from the same external source address.

Based on the repeated requests to a user information endpoint, the external source IP address, and the poor Cisco Talos reputation for the IP, I assessed the traffic as malicious. The evidence also indicates that the attack was successful because the related requests returned HTTP response status 200 and had non-zero response sizes, meaning the server responded with data.

## Playbook Step 14: Finish the Playbook!

The final playbook step was to confirm the investigation and close the case. At this point, I had already added the relevant artifacts, summarized my findings into the analyst notes, and completed all the required playbook actions.

<img width="798" height="346" alt="image" src="https://github.com/user-attachments/assets/2ca1432f-4944-4122-9d64-f2575b3cd889" />

## Final Verdict and Closing Case: True Positive

<img width="600" height="433" alt="image" src="https://github.com/user-attachments/assets/efa6e1c6-3dbd-437c-87c4-c5c89959c0c7" />

After completing the playbook, I reviewed the evidence I have collected throughout the investigation to determine whether the alert was a true positive or false positive.

My final verdict is that this alert is a **True Positive**. The traffic appeared malicious because an external source IP address sent multiple web requests to an internal web server targeting an endpoint associated with user information.

The requested URL, `https://172.16.17.15/get_user_info/`, suggests possible IDOR activity because the URL appears to involve retrieving user information. The repeated requests to this same endpoint from the same external source address made the activity suspicious, especially in the context of a possible attempt to access user or object data without proper authorization.

Another important detail is that the device action was listed as `Permitted`, meaning the requests were allowed through the security control. The attack also appears to have been successful because the related requests returned HTTP response status `200` and had non-zero response sizes, meaning the server responded with data.

Based on the repeated requests to the `get_user_info` endpoint, the external-to-internal traffic direction, the poor Cisco Talos reputation for the source IP address, and the successful server responses, I assessed this alert as a **True Positive**.

## Results!!

<img width="1004" height="841" alt="image" src="https://github.com/user-attachments/assets/569dce69-8f5f-4ae0-bd2e-2ad74a057d33" />

Hooray, we were able to correctly identify that the URL was a true positive!

## MITRE ATT&CK Framework

Reference: https://attack.mitre.org/techniques/T1190/

This alert maps most closely to **Initial Access - Exploit Public-Facing Application (T1190)**. The traffic came from an external source and targeted a web application endpoint on the internal web server.

The requested URL, `https://172.16.17.15/get_user_info/`, appears to be related to retrieving user information. Since the alert was categorized as a possible IDOR attack, the activity suggests an attempt to abuse exposed web application functionality to access user-related data without proper authorization.

IDOR is the specific web attack type observed in the alert, while **T1190 - Exploit Public-Facing Application** is the broader MITRE ATT&CK technique that best matches the behavior.
