# SOC Alert Investigation: Malicious Attachment Detected - Phishing Alert

<img width="990" height="256" alt="image" src="https://github.com/user-attachments/assets/38bcf17b-58e7-49c4-98b9-c98d4a4a74dc" />

Our investigation starts here with a high-severity LetsDefend SOC alert: **SOC114 - Malicious Attachment Detected - Phishing Alert**. This is an Exchange-type alert, so I'm going to be looking at suspicious email activity. 

To begin the investigation, I created a case for the alert and I'm going to start working through the provided playbook.

## Playbook Step 1: Parse Email
The first step of the playbook asks me to analyze the following information about the email: when it was sent, the email's SMTP address, the sender's address, the recipient's address, whether the mail content was suspicious, and whether there were any attachments.

<img width="796" height="480" alt="image" src="https://github.com/user-attachments/assets/241dbbcf-9416-4a39-b741-ac73daa4f782" />

After expanding the original alert, I've been able to find the following details:

<img width="1003" height="674" alt="image" src="https://github.com/user-attachments/assets/ace975bf-cb7f-4ed4-9417-39ee46ff5dfb" />

The original alert was triggered on `January, 31, 2021` at `3:48 PM`, so this answers when it was sent. The email's SMTP address as provided in the original alert is `49.234.43.39` and the sender's address is `accounting@cmail.carleton.ca`. He sent this email to `richard@letsdefend.io`. From opening the original alert alone, we can't determine whether the mail content was suspicious or whether there were any attachments.

To investigate this further, I looked into Email Security, where I was able to find the email pertaining to the original alert.

<img width="1006" height="714" alt="image" src="https://github.com/user-attachments/assets/06dec3ba-d18d-4cdc-be5c-545692d994d9" />

As I can see here, there was an attachment included with this email, with the password `infected`. After clicking on the attachment it led me to this link:

<img width="1271" height="911" alt="image" src="https://github.com/user-attachments/assets/a6b46d61-d0cd-43d0-9165-b0c62e7ab649" />

After entering the password `infected`, I'm prompted to download a file.

<img width="1263" height="912" alt="image" src="https://github.com/user-attachments/assets/b4fa7dfb-d5bb-4e6e-94fb-868f3524aa40" />

This answers our initial questions about the email's details. The attachment included with the email is named c9ad9506bcccfaa987ff9fc11b91698d. From the context of the email, the email content does look suspicious. The sender claims to have attached an invoice, but interacting with the attachment leads to a password-protected page before allowing the user to download a file. That behavior doesn't match what would normally be expected from a simple invoice email, which makes the attachment more suspicious. Another detail worth noting is that this email was sent from outside the recipient's domain. Although that detail alone does not determine whether an email is phishing, in this case it adds to the suspicion because the external sender is asking the recipient to interact with a password-protected attachment that leads to a file download.

## Playbook Step 2: Confirming whether there were attachments or URLs in the email

<img width="797" height="442" alt="image" src="https://github.com/user-attachments/assets/1b9497c2-f1c1-440c-b604-6a9951ef44b3" />

From our previous playbook step, I've been able to conclude that there is indeed an email attachment in the email, so the answer is **Yes**.

## Playbook Step 3: Analyze URL/Attachment

The next step of the playbook asks me to analyze the URL or attachment in a third-party tool and determine whether or not the attachment is `malicious`. 

I submitted the URL the attachment has directed me to from the email:

<img width="1258" height="906" alt="image" src="https://github.com/user-attachments/assets/31ace6bb-c3e0-43c7-804d-748423aeb86a" />

As I can see here, VirusTotal showed that `10/92` security vendors had flagged the URL as malicious, or malware. Another detail to note here, is that the most recent analysis was performed `5 days ago`, which makes the result fairly recent and useful for our investigation.

For good practice, I do not want to rely on VirusTotal as the only source of truth. However, when we look at the broader context, such as the suspicious email content, the password-protected attachment, the attachment being presented as an invoice but redirecting to a password-protected page and leading to a file download instead, and the VirusTotal detections, it all supports classifying this document as malicious.

<img width="1724" height="847" alt="Screenshot (194)" src="https://github.com/user-attachments/assets/c31bbef8-7f71-439b-8aa2-e37b8163e7d0" />

After analyzing the URL, I also wanted to verify the file itself. Since the attachment redirected to a password-protected download page, I downloaded the file inside an isolated VM and submitted it to VirusTotal for analysis.

The VirusTotal results showed that the file was detected by multiple security vendors as malicious. This strengthened my assessment because the email claimed to contain an invoice, but the attachment did not behave like a normal invoice document. Instead, it redirected the user to a password-protected page and led to a file download that was flagged by VirusTotal.

Based on the suspicious email context, the malicious URL analysis, and the file detection results, I assessed the attachment as malicious.

The contacted URLs also raised concern because they suggest the file may have attempted to reach out to external domains. This matters more in this case because the original alert showed the device action as `Allowed`, meaning the email or related activity may not have been blocked.

Because of this, there is a possibility that the recipient could have accessed or interacted with the malicious attachment. The contacted URL `http://andaluciabeach.net/image/network.exe` is especially suspicious because it points directly to an executable file and was flagged by `12/92` security vendors.

Based on the context and the results from VirusTotal, I've selected **Yes**.

## Playbook Step 4: Check if Mail Was Delivered to the User

The next step asks me to determine whether the email was delivered by looking at the "device action" in the original alert.

<img width="799" height="358" alt="image" src="https://github.com/user-attachments/assets/a1b1cc81-ffc6-4cf6-9667-9ae6bca3c60a" />

Following the playbook, I've navigated back to the original alert details: 

<img width="1003" height="674" alt="image" src="https://github.com/user-attachments/assets/ace975bf-cb7f-4ed4-9417-39ee46ff5dfb" />

As we can see here, the device action was `Allowed`, which indicates that the email was delivered to the user.

Based on this finding, I selected **Delivered** in the playbook.

## Playbook Step 5: Delete Email From Recipient!

The next step of the playbook asks me to delete the malicious email from the recipient's inbox. Since the email has been identified as malicious, this step focused on containment, since removing the email helps prevent the recipient from interacting with the malicious attachment.

<img width="801" height="340" alt="image" src="https://github.com/user-attachments/assets/7f23f4d5-f9f2-4dcf-9be1-683cf833c3bb" />

To proceed with the playbook, I pressed **Delete** to remove the malicious email from the recipient's mailbox.

## Playbook Step 6: Check If Someone Opened the Malicious File/URL
The next step of the playbook asks me to check Log Management to determine whether the C2 address associated with the malicious file was accessed. This step will help us verify whether the malicious file may have been run or whether the recipient interacted with the malicious address.

<img width="1181" height="783" alt="image" src="https://github.com/user-attachments/assets/40cff77b-44e5-485a-b7d5-2071ee446dc7" />

After identifying the contacted URLs from the VirusTotal file analysis, I searched Log Management for the suspicious URL `http://andaluciabeach.net/image/network.exe`.

This search yielded one matching event, which indicates that the malicious address was accessed. Since the playbook asked me to select **Opened** if someone accessed the malicious address, I selected **Opened**.

## Playbook Step 7: Containment

The next step of the playbook instructs me to go to the EDR page and contain the user machine. Since the malicious address was accessed, this containment step is important because it helps isolate the affected endpoint and prevent further activity.

<img width="797" height="386" alt="image" src="https://github.com/user-attachments/assets/02304b83-fea0-4809-b1a4-cb9b5d1bd6f0" />

In order to find the source address of the endpoint, we need to look at the source address that created the log to the suspicious URL.

<img width="1105" height="747" alt="image" src="https://github.com/user-attachments/assets/6140b9ca-6876-405b-af81-73cd1dca6e9b" />

As we can see here, the source address that accessed the suspicious URL is `172.16.17.45`.

<img width="1136" height="665" alt="image" src="https://github.com/user-attachments/assets/0d67ddfe-c317-42f7-ad96-861912045178" />

This leads us to the endpoint named `RichardPRD`. We will contain this to proceed with the playbook. 

## Playbook Step 8: Add Artifacts

The next step of the playbook asked me to add the relevant artifacts found during the investigation.

<img width="796" height="434" alt="image" src="https://github.com/user-attachments/assets/69bdc1ce-f4ad-44a0-8862-488d7d26059a" />

Based on the evidence we've collected so far, I added the sender address as an `Email Sender` artifact because it was the address associated with the suspicious invoice-themed email. I also added the redirected URL as a `URL Address` artifact because it was the page the attachment led to during the investigation. In addition, I added the file's MD5 hash as an artifact which I found to be `6fdf4a6ddd6f564589dd060bdc4da2c3` because it identified the downloaded file that was analyzed in VirusTotal. 

## Playbook Step 9: Analyst Note

The playbook then asked me to add analyst notes for the case. I used this section to summarize the main findings from the investigation and explain why I assessed this alert as malicious.

<img width="794" height="506" alt="image" src="https://github.com/user-attachments/assets/b2effe61-dd3d-4ca5-9463-8a19796966da" />

Analyst Notes: The email appears suspicious based on the sender being outside the recipient's organization, which is worth noting but not enough to classify the email as suspicious by itself. The suspicion comes from the invoice-themed message asking the recipient to interact with an attachment that led to a password-protected download page instead of a normal invoice document.

The URL and downloaded file were analyzed in VirusTotal. The contacted URL `http://andaluciabeach.net/image/network.exe` stood out because it pointed directly to an executable file and was flagged by `12/92` security vendors. The downloaded file was also analyzed using its MD5 hash, `6fdf4a6ddd6f564589dd060bdc4da2c3`.

The original alert showed that the device action was listed as `Allowed`, and Log Management showed that the malicious address was accessed. Because of this, the affected machine was contained through EDR to help prevent further activity.

Based on my findings, I've assessed this email as malicious and added the sender address, suspicious URL, and file hash as artifacts.

## Playbook Step 10: Finish the Playbook!

The final playbook step was to confirm the investigation and close the case. At this point, I had already added the relevant artifacts, summarized my findings into the analyst notes, and completed all the required playbook actions.

<img width="798" height="346" alt="image" src="https://github.com/user-attachments/assets/2ca1432f-4944-4122-9d64-f2575b3cd889" />

## Final Verdict and Closing Case: True Positive

<img width="597" height="438" alt="image" src="https://github.com/user-attachments/assets/6d841427-1652-4a47-9d2c-5d999ce9ee65" />

After completing the playbook, I reviewed the evidence I've collected throughout the investigation to determine whether the alert was a true positive or false positive.

My final verdict is that this alert is a **True Positive**. The email appeared suspicious because it was an message regarding an invoice from outside the recipient's organization, and the attachment did not behave nor appear like a normal invoice document. Instead, interacting with the attachment led to a password-protected download page and eventually to a downloaded file.

The VirusTotal results supported this assessment because the contacted URL pointed directly to an executable file and was flagged by multiple security vendors. The downloaded file was also analyzed using its MD5 hash, which helped identify the file involved in the investigation.

Another important detail is that the device action was listed as `Allowed`, and Log Management showed that the malicious address was accessed. Because of this, the alert was not just a suspicious email attempt; there was evidence that the malicious address had been interacted with, which led to containing the affected machine through EDR.

Based on the suspicious email content, the malicious file analysis, the accessed malicious address, and the containment action taken, I assessed this alert as a **True Positive**.

## MITRE ATT&CK Framework 

Reference: https://attack.mitre.org/techniques/T1566/001/

This alert maps to **Initial Access** because the email appears to have been an attempt to gain access through phishing. More specifically, the technique used in this SOC alert was **Phishing**, in the form of a **Spearphishing Attachment**, because the message used an invoice-themed email to pressure the recipient into interacting with an attachment.

The attachment did not behave like a normal invoice document. Instead, it led to a password-protected download page and eventually to a file that was flagged by VirusTotal. Log Management also showed that the malicious address was accessed, which increased the severity of the investigation and led to containment through EDR.
