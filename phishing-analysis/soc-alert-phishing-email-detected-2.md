# SOC Alert Investigation: Phishing Mail Detected - Internal to Internal

<img width="1007" height="261" alt="image" src="https://github.com/user-attachments/assets/53a33151-c370-4a01-a515-650e14cd507c" />

This investigation starts here with a medium-severity **LetsDefend SOC alert: SOC140 - Phishing Mail Detected - Internal to Internal**. This is an Exchange-type alert, so I'm going to be looking at suspicious email activity. 

To begin the investigation, I've created a case for the alert and I'll work through the provided playbook.

## Playbook Step 1: Parse Email
The first step of the playbook asks me to analyze the following information about the email: wwhen it was sent, the email's SMTP address, the sender's address, the recipient's address, whether the mail content was suspicious, and whether there were any attachments.

<img width="796" height="480" alt="image" src="https://github.com/user-attachments/assets/060242ba-a691-482d-99ee-c00dcd955926" />

After expanding the original alert, I've been able to find the following details:

<img width="1005" height="663" alt="image" src="https://github.com/user-attachments/assets/67406e99-1548-4d7e-a67c-706e7f00bab8" />

The original alert was triggered on `February, 07, 2021` at `4:24 AM`, so this answers when it was sent. The email's SMTP address as provided in the original alert is `172.16.20.3` and the sender's address is `john@letsdefend.io`. He sent this email to `susie@letsdefend.io`. From opening the original alert alone, we can't determine whether the mail content was suspicious or whether there were any attachments.

To investigate this further, I looked into Email Security, where I was able to find the email pertaining to the original alert.

<img width="955" height="689" alt="image" src="https://github.com/user-attachments/assets/765f05ab-c1a2-47f9-82f6-19945b129e44" />

As I can see here, there are no attachments included with the email. The email content also does not appear to look suspicious. It looks like a normal internal company email asking to arrange a meeting.

## Playbook Step 2: Confirming whether there were attachments or URLs in the email

<img width="797" height="442" alt="image" src="https://github.com/user-attachments/assets/e6a4afd9-874d-48d9-bd51-91d6a7c1e7d6" />

From our previous playbook step, there were no attachments included within the email, so my answer is **No**.

## Playbook Step 3: Add Artifacts

The next step of the playbook asked me to add the relevant artifacts found during the investigation.

<img width="796" height="434" alt="image" src="https://github.com/user-attachments/assets/9e921be8-881e-46eb-b7e9-07ba9b5ca5e5" />

At this point in the investigation, I am leaning toward this alert being a **False Positive**, but I still want to document the evidence that supports that assessment.

The email does not contain any attachments, and the message content does not appear to be suspicious. The email reads like a normal internal company message where one employee is asking another employee to arrange a meeting.

To support my assessment, I added the sender email address and email domain as artifacts. The sender is `john@letsdefend.io`, and the recipient is `susie@letsdefend.io`. Both addresses use the same `letsdefend.io` domain, which points toward the idea that this email was an internal one rather than an external phishing attempt.

## Playbook Step 4: Analyst Notes

<img width="794" height="506" alt="image" src="https://github.com/user-attachments/assets/ed1322b9-7d53-4a41-ac3e-7667072ab05b" />

Analyst Notes: Based on the evidence reviewed, I don't find this email suspicious. The email doesn't contain an attachment to interact with, the message content appears to be a typical internal meeting request, and both the sender and the recipient share the same `letsdefend.io` domain, which indicates that the email was exchanged internally.

## Playbook Step 5: Finish the Playbook!

The final playbook step was to confirm the investigation and close the case. At this point, I've already added the relevant artifacts, summarized my findings into the analyst notes, and completed all the required playbook actions.

<img width="798" height="346" alt="image" src="https://github.com/user-attachments/assets/016bb13f-c1a6-4383-8185-43cedf4dc11f" />

## Final Verdict and Closing Case: False Positive

<img width="599" height="434" alt="image" src="https://github.com/user-attachments/assets/c75c1331-40fa-4a2b-a1dd-8cf72c74fe73" />

After completing the playbook, I reviewed the evidence I've collected throughout the investigation to determine whether the alert was a true positive or false positive.

My final verdict is that this alert is a **False Positive**. The email appears to be a typical internal company message requesting a meeting between two employees. The email does not contain any attachments, and the message content does not show clear signs of phishing or malicious activity.

Additionally, both the sender and recipient use the same `letsdefend.io` domain, which supports that this was an internal email exchange. Based on the lack of suspicious content, lack of attachments, and internal sender/recipient context, I've assessed this alert as a **False Positive**.

## Results!!

<img width="954" height="549" alt="image" src="https://github.com/user-attachments/assets/18d29ead-fcc7-4b0f-b9ea-68c13a42c870" />

Our case has been closed successfully!

This SOC alert did end up being a normal internal email rather than a phishing attempt. I was able to correctly identify the alert as a **False Positive** after reviewing the sender, recipient, message content, and confirming there weren't any suspicious attachments observed during the investigation.
