# SOC Alert Investigation: Phishing URL Detected

<img width="1005" height="233" alt="image" src="https://github.com/user-attachments/assets/9bf635fe-d7a5-4fda-a3ff-5a70112e4cd3" />


Our investigation starts here with a high-severity LetsDefend SOC alert: **SOC141 - Phishing URL Detected**. Since this is a proxy alert, it points me toward suspicious web activity. 


To begin the investigation, I created a case for the alert and I'm going to start working thorugh the provided playbook.


## Playbook Step 1: Collect Alert Details

The first step of the playbook asks for the **source address**, **destination address**, and **user-agent** associated with the alert.

<img width="800" height="399" alt="image" src="https://github.com/user-attachments/assets/9d981ad5-9483-4b61-bb66-6c7003343112" />

After expanding the original alert details, I found these following values:

<img width="979" height="643" alt="image" src="https://github.com/user-attachments/assets/9be6e16f-a220-4419-835a-cf70e35d1bd4" />

The source address `172.16.17.49` appears to be the device that made the request, while the destination address `91.189.114.8` appears to be the address receiving the request. The user-agent shows that the request was made from a Chrome browser on a Windows 64-bit system. I also noticed that the device action was listed as **Allowed**, this might be worth noting later on.

## Playbook Step 2: Search Log

For this step, I reviewed the related log entry to gather more information about the web request.

<img width="798" height="362" alt="image" src="https://github.com/user-attachments/assets/d52b2abd-76be-4245-87c8-7fb5fdd3bc92" />

From the log details, I identified the following:

<img width="866" height="495" alt="image" src="https://github.com/user-attachments/assets/40bcc483-94f8-4b9b-b1fd-c17c98e27d4f" />

The log showed that the source port was `55662` and the destination port was `80`, meaning the request was made using HTTP. Another detail that stood out is that the source hostname is `EllieComp`, the username is `ellie`, and the request URL includes the email address `ellie@letsdefend.io`. These details appear to line up with the user involved in the alert and help tie the suspicious web request back to a specific user and device.

## Playbook Step 3: Analyze URL Address

The next step of the playbook asks me to analyze the requested URL using third-party tools and determine whether it should be classified as **Malicious** or **Non-malicious**. 

<img width="798" height="498" alt="image" src="https://github.com/user-attachments/assets/0c4835b4-cffe-4b6d-ba3b-e119c47ef23a" />

I submitted the requested URL from our previous Raw Log to VirusTotal:

<img width="1199" height="891" alt="image" src="https://github.com/user-attachments/assets/db2393ec-c7bb-44f2-92a1-ece4cb59b3a9" />

VirusTotal showed that `13/92` security vendors had flagged the URL as malicious, phishing, or suspicious. Another detail I noted is that the most recent analysis was performed `4 days ago`, which makes the result fairly recent and more useful for this investigation.

For the sake of good practice, I do not want to rely on VirusTotal as the sole answer. The URL stood out because several parts of it looked unusual in context: `http://mogagrocol.ru/wp-content/plugins/akismet/fv/index.php?email=ellie@letsdefend.io`.

First, the URL uses `http://` instead of `https://`, which means the connection is not encrypted. Although HTTP alone dosen't provie malicious activity, it's still worth noting because phishing pages often sensitive information, and legitimate login or account-related pages would normally be using HTTPS.

The destination domain `mogagrocol.ru` also doesn't match the `letsdefend.io` domain associated with the user. The `.ru` top-level domain isn't malicious by itself, but in this context it seems unrelated to the user and organization involved in the alert.

The path `/wp-content/plugins/akismet/fv/index.php` also stood out because it appears to point to a WordPress plugin directory. This could suggest that the page is being hosted inside a WordPress site path, which is worth paying attention to because compromised WordPress sites are often used to host suspicious or malicious pages.

These details alone, do not prove the URL is malicious. However, when combined with the recent VirusTotal analysis and vendor detections, they support classifying the URL as malicious.

## Playbook Step 4: Check for URL/IP Access

The next playbook step asks whether anyone accessed the suspicious IP, URL, or domain. To investigate this, I searched Log Management for the destination address `91.189.114.8`.

<img width="796" height="553" alt="image" src="https://github.com/user-attachments/assets/93cfcdb8-4705-4a0e-9d0c-0fbb97fcc697" />

The search returned `2` related events. One event appears to be the original proxy alert, while the other was a firewall log showing traffic from `172.16.17.49` to `91.189.114.8` over destination port `80`.

<img width="1053" height="746" alt="image" src="https://github.com/user-attachments/assets/182fe763-1fc3-49c2-ac2e-3b05cc315e4b" />

This firewall event matched the same source address, destination address, source port, destination port, and timestamp connected to the original alert. Using the original proxy alert details, I was also able to answer the remaining playbook questions. The user who tried to access the URL was `ellie`, and the user-agent showed the request came from a Chrome browser on a Windows 64-bit system.

The request does not appear to have been blocked because the original proxy alert listed the device action as `Allowed`. Based on the matching log evidence and the allowed proxy action, I determined that there was access to the suspicious destination and selected **Accessed** in the playbook.

## Playbook Step 5: Containment

The next step of the playbook instructed me to go to the EDR page and contain the user machine.

<img width="797" height="379" alt="image" src="https://github.com/user-attachments/assets/b1174758-c9dc-4f87-9605-ae5022ef75ac" />

Following the playbook, I proceeded to the EDR page to locate and contain the affected machine.

<img width="1034" height="528" alt="image" src="https://github.com/user-attachments/assets/102e5dff-0a32-4e8d-b02b-0bd1b1c7b856" />

## Playbook Step 6: Add Artifacts

The next step of the playbook asked me to add the relevant artifacts found during the investigation.

<img width="799" height="460" alt="image" src="https://github.com/user-attachments/assets/0760dfa4-8d5f-4fb0-8400-54b138963ac2" />

I added the suspicious URL as a `URL Address` artifact because it was the main indicator tied to the phishing alert. This was also the URL I analyzed in VirusTotal, where multiple security vendors flagged it as malicious, phishing, or suspicious.

I also added `91.189.114.8` as an `IP Address` artifact because it was the destination address associated with the original proxy alert and the related firewall event.

<img width="796" height="499" alt="image" src="https://github.com/user-attachments/assets/6d73a91a-fd72-4354-a077-775f24a28661" />

I didn't add an email sender, email domain, or MD5 hash because I didn't see those artifacts present in the evidence I reviewed for this alert.

## Playbook Step 7: Analyst Note

The playbook then asked me to add analyst notes for the case. I used this section to summarize the main findings from the investigation and explain why I assessed the alert as phishing-related.

<img width="794" height="510" alt="image" src="https://github.com/user-attachments/assets/2a356484-4d9b-4882-a0d7-c33adbddc234" />

Based on what I found, this alert looks like a real phishing-related event. The activity appears to come from the user/device tied to `ellie`, with the source hostname listed as `EllieComp`. The request went from `172.16.17.49` to `91.189.114.8` over port `80`, and the URL being accessed was:

`http://mogagrocol.ru/wp-content/plugins/akismet/fv/index.php?email=ellie@letsdefend.io`

This URL stood out to me for a few reasons. This URL uses `http://` instead of `https://`, it points to an unrelated `.ru` domain, includes a WordPress plugin path, and passes `ellie@letsdefend.io` directly in the URL as an email parameter. Although none of these details prove the URL is malicious by themselves, together they make the URL look suspicious.

I also checked the URL in VirusTotal, where multiple vendors flagged it as malicious, phishing, or suspicious. That supported what I was already seeing from the URL structure and the alert details.

In Log Management, I found a related firewall event that matched the original alert by source address, source port, destination address, destination port, and timestamp. The username `ellie`, source hostname `EllieComp`, and email parameter `ellie@letsdefend.io` all appear to line up, which helps connect the activity back to the same user or device.

Another important detail is that the device action was listed as `Allowed`, meaning the request does not appear to have been blocked at the proxy level. Based on the URL analysis, VirusTotal results, and matching log evidence, I'm assessing this alert as a true positive phishing-related event.

## Playbook Step 8: Finish the Playbook!

The final playbook step was to confirm the investigation and close the case. At this point, I had already added the relevant artifacts, summarized my findings into the analyst notes, and completed all the required playbook actions.

<img width="798" height="346" alt="image" src="https://github.com/user-attachments/assets/a55fdd8b-8053-437b-95f0-7f2fc50213e8" />

## Final Verdict and Closing Case: True Positive

<img width="600" height="754" alt="image" src="https://github.com/user-attachments/assets/b28f0800-ce81-4db6-bfa6-4ee79f315d96" />

After completing the playbook, I reviewed the evidence I've collected throughout the investigation to determine whether the alert was a true positive or false positive.

My final verdict is that this alert is indeed a **True Positive**. The user/device associated with `ellie` accessed a suspicious phishing URL, and this URL was flagged by multiple VirusTotal vendors as malicious, phishing, or suspicious. The URL structure also was unusual due to the unrelated `.ru` domain, the use of `http://`, the WordPress plugin path, and the email parameter containing `ellie@letsdefend.io`.

The related firewall event also matched the original proxy alert by source address, source port, destination address, destination port, and timestamp. Since the device action was listed as `Allowed`, the request doesn't appear to have been blocked at the proxy level.

## Results!!

<img width="1055" height="586" alt="image" src="https://github.com/user-attachments/assets/01198f94-75dc-4163-9503-54773b313376" />

This was my first completed LetsDefend SOC alert writeup for phishing analysis! (And most definitely not the last)

I completed the investigation with a **100% score** and a **100% playbook success rate**. This alert helped me practice following a SOC playbook, reviewing phishing-related evidence, and documenting the reasoning behind each investigation step. 

Thank you very much for reading through this write up!
