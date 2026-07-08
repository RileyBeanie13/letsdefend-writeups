# SOC Alert Investigation: Phishing Mail Detected - Suspicious Task Scheduler

<img width="973" height="229" alt="image" src="https://github.com/user-attachments/assets/193f3875-fa9a-4628-8a88-a38b213e2281" />

Our investigation starts here with a medium-severity LetsDefend SOC alert: **SOC140 - Phishing Mail Detected - Suspicious Task Scheduler**. This is an Exchange-type alert, so I'm going to be looking at suspicious email activity.

To begin the investigation, I've created a case for the alert and I'll work through the provided playbook.

## Playbook Step 1: Parse Email

The first step of the playbook asks me to analyze the following information about the email: when it was sent, email's SMTP address, sender's address, recipient's address, whether the mail content was suspicious, and was there any attachments?

<img width="796" height="480" alt="image" src="https://github.com/user-attachments/assets/bd43cded-0201-4be3-9b3d-a3a647dfa742" />

After expanding the original alert, I've been able to find these following details:

<img width="960" height="648" alt="image" src="https://github.com/user-attachments/assets/a3dc499f-848d-4455-8904-ddea2397314d" />

The original alert was triggered at `March, 21, 2021` at `12:26 PM` so this should answer when it was sent. The email's SMTP address as provided in the original alert is `189.162.189.159` and the sender's address is `arronlue@cmail.carleton.ca`. He's sent this email to `mark@letsdefend.io`. From opening the original alert alone, we can't determine whether the mail content was suspicious or whether there were any attachments.

To investigate this further, I looked into email security where I was able to find the email pertaining to the original alert.

<img width="1227" height="706" alt="image" src="https://github.com/user-attachments/assets/7cf541be-f87f-40c7-ae53-1843b2efae3a" />

As I can see here there was an attachment included with this email, with the password `infected`. After clicking on the attachment it led me to this link:

<img width="1272" height="920" alt="image" src="https://github.com/user-attachments/assets/fc7f285c-064a-46a5-82ff-73e68d32fdbe" />

After entering the password `infected` I'm prompted to download a file.

<img width="1263" height="912" alt="image" src="https://github.com/user-attachments/assets/7db28f68-f11c-4400-94af-b0fef4b4e018" />

This answers our initial questions about the email's details. The attachment included with the email is named `72c812cf21909a48eb9cceb9e04b865d`. From the context of the email, the email content does look suspicious. The sender talks about COVID-19 and urges the recipient to open the attachment immediately, without providing much context about the attachment. After looking at the attachment, it makes the email's contents look more suspicious because they don't have anything to do with what the sender was talking about.

## Playbook Step 2: Confirming whether there were attachments or URLs in the email

<img width="797" height="442" alt="image" src="https://github.com/user-attachments/assets/1b9497c2-f1c1-440c-b604-6a9951ef44b3" />

From our previous playbook step, I've been able to conclude that there is indeed an email attachment in the email, so the answer is **Yes**.

## Playbook Step 3: Analyze URL/Attachment

The next step of the playbook asks me to analyze the URL or attachment in a third-party tools and determine whether or not the attachment is `malicious`. 

I submitted the URL the attachment has directed me to from the email:

<img width="1258" height="905" alt="image" src="https://github.com/user-attachments/assets/c787fade-dc9b-4dda-9ccb-63fc150c16fe" />

As I can see here, VirusTotal showed that `10/92` security vendors had flagged the URL as malicious, or malware. Another detail to note here, is that the most recent analysis was performed `5 days ago`, which makes the result fairly recent and useful for our investigation.

For good practice, I do not want to rely on VirusTotal as the only source of truth. However, when we look at the broader context such as the suspicious email content, a password-protected attachment, the subject talking about a matter that pertains nothing to the attachment, and the VirusTotal detections, it all supports classifying this document as malicious. 

Based on the context and the results of the VirusTotal, I've selected **Yes**.

## Playbook Step 4: Check if Mail Was Delivered to the User

The next step asks me to determine whether the e-mail is delivered by looking at the "device action" in the original alert.

<img width="799" height="358" alt="image" src="https://github.com/user-attachments/assets/a1b1cc81-ffc6-4cf6-9667-9ae6bca3c60a" />

Following the playbook, I've navigated back to the original alert details: 

<img width="958" height="647" alt="image" src="https://github.com/user-attachments/assets/fbe4510e-61b6-435a-9f51-7ae16ef30695" />

As we can see here, the device action was `Blocked`, which indicates that the email was not delivered to the user.

Based on this finding, I selected **Not Delivered** in the playbook.

## Playbook Step 5: Add Artifacts

The next step of the playbook asked me to add the relevant artifacts found during the investigation.

<img width="796" height="434" alt="image" src="https://github.com/user-attachments/assets/69bdc1ce-f4ad-44a0-8862-488d7d26059a" />

Based on the evidence we've collected so far, I added the sender address as an `Email Sender` artifact because it was the address associated with the suspicious email. I also added the suspicious redirected URL as a `URL Address` artifact because it was identified during analysis and was flagged by VirusTotal.

<img width="796" height="504" alt="image" src="https://github.com/user-attachments/assets/e1d28ac1-d8bb-4ad3-96bb-89245a8f5129" />

## Playbook Step 7: Analyst Note

The playbook then asked me to add analyst notes for the case. I used this section to summarize the main findings from the investigation and explain why I assessed this alert as malicious.

<img width="794" height="506" alt="image" src="https://github.com/user-attachments/assets/b2effe61-dd3d-4ca5-9463-8a19796966da" />

Analyst Notes: The email appears suspicious based on the sender being outside the recipient's organization, which is worth noting but not enough to classify the mail as suspicious. The suspicion comes from the message talking about COVID-19 then urgently asking the recipient to open up a password-protected attachment that doesn't match the context of the email. This attachment/URL was analyzed in VirusTotal, where `10/92` security vendors flagged it as malicious. The original alert also showed that the device action was listed as `Blocked`, so the email appears to not have been delivered to the recipient. 

Based on my findings, I've assessed this email as malicious and added the sender address and suspicious URL as artifacts.

## Playbook Step 8: Finish the Playbook!

The final playbook step was to confirm the investigation and close the case. At this point, I had already added the relevant artifacts, summarized my findings into the analyst notes, and completed all the required playbook actions.

<img width="798" height="346" alt="image" src="https://github.com/user-attachments/assets/2ca1432f-4944-4122-9d64-f2575b3cd889" />

## Final Verdict and Closing Case: True Positive

<img width="599" height="429" alt="image" src="https://github.com/user-attachments/assets/25cad5d8-62d7-481b-b561-1f5b4695c3b4" />

After completing the playbook, I reviewed the evidence I've collected throughout the investigation to determine whether the alert was a true positive or false positive.

My final verdict is that this alert is a **True Positive**. The email appears to be malicious because a sender from outside the recipient's organization uses the urgency surrounding COVID-19 to instruct the recipient to open the attachment provided in the email. However, the attachment clearly doesn't match the context of the email. This attachment provided, was also password-protected. 

The VirusTotal result reinforced my assessment, with `10/92` security vendors flagging the analyzed artifact as malicious and malware. 

## Results!!

<img width="1156" height="840" alt="image" src="https://github.com/user-attachments/assets/53b7c742-141d-4ce6-810a-ef9b5a528a99" />

This playbook was completed with a **100% score**, and the alert was assessed as a **True Positive**!

## Final: MITRE ATT&CK Framework 

Reference: https://attack.mitre.org/techniques/T1566/001/

This alert maps to **Initial Access** because the email appears to have been an attempt to gain access through phishing. More specifically, the technique used in this SOC alert maps to **Phishing** in the form of a **Spearphishing Attachment**, beacuse the message used urgency surrounding COVID-19 to pressure the recipient into opening a password-protected attachment.
