"""ScamShield AI - Experiment 10 HELD-OUT EVALUATION messages.

These messages are NEVER used for training. They were written separately from
the training templates in experiment_v10_data.py, in longer, more realistic
wording. test_experiment_v10.py automatically checks that no evaluation
message duplicates (or nearly duplicates) a training example.

All names, companies, numbers, and links are fictional. Links use reserved
example domains (.example, example.com, example.net) or invented
look-alike domains. No real person's email or personal information is used.

Expected outcomes:
    "HIGH"      -> must be HIGH RISK
    "FLAGGED"   -> must be HIGH RISK or NEEDS REVIEW (must not be missed)
    "NOT_HIGH"  -> must NOT be HIGH RISK (a legitimate message)

HONESTY NOTE: The rules and these tests were written by the same people, so a
passing test suite shows the system behaves as designed. It is NOT an
independent measurement of real-world accuracy.
"""

# (category, name, message, expected)
CASES = [
    # ======================================================
    # LEGITIMATE WORKPLACE COMMUNICATION
    # ======================================================
    ("legit_workplace", "Disciplinary hearing notice (long email)",
     """Dear Employee,

NOTICE TO ATTEND A DISCIPLINARY HEARING

You are hereby notified to attend a disciplinary hearing which will be held on Thursday, 14 March, at 10:00 in Boardroom 2 at the Head Office.

The hearing relates to the following allegation: gross negligence in that you failed to follow the stock control procedure on 2 March.

You have the right to be represented by a fellow employee or a trade union representative of your choice. You may call witnesses and present documents in support of your case. Should you require an interpreter, please inform the Human Resources department in advance.

Failure to attend the hearing without a valid reason may result in the hearing proceeding in your absence.

Kindly acknowledge receipt of this notice by signing the attached copy.

Yours faithfully,
Human Resources Manager""", "NOT_HIGH"),

    ("legit_workplace", "Dismissal letter after hearing",
     """Dear Employee,

OUTCOME OF DISCIPLINARY HEARING: DISMISSAL

Following the disciplinary hearing held on 14 March, the chairperson found you guilty of the misconduct alleged. After considering the evidence, your previous record and your submissions in mitigation, the company has decided to terminate your employment with effect from 31 March.

Your final salary, together with payment for any accrued annual leave, will be paid into your usual bank account on the normal payroll date. Your certificate of service and UI-19 form will be posted to you.

You have the right to refer this matter to the CCMA within 30 days of the date of this letter.

Please return your access card, laptop and any company property to the HR office before your last working day.

Yours sincerely,
Head of Human Resources""", "NOT_HIGH"),

    ("legit_workplace", "Termination notice with final pay details",
     "Notice of termination of employment. Your employment with the company is terminated "
     "with immediate effect. Your final payment will be transferred to your bank account. "
     "Please return your access card and laptop.", "NOT_HIGH"),

    ("legit_workplace", "Precautionary suspension",
     "Dear colleague, you are placed on precautionary suspension on full pay while the "
     "investigation is completed. Please do not report for duty or contact witnesses during "
     "this period. You will be informed of the outcome in writing.", "NOT_HIGH"),

    ("legit_workplace", "Final written warning",
     "This serves as a final written warning for repeated late arrival. The warning is valid "
     "for twelve months. Any further misconduct of a similar nature may lead to further "
     "disciplinary action, which could include dismissal.", "NOT_HIGH"),

    ("legit_workplace", "Meeting invitation",
     "Hi everyone, please join the quarterly planning meeting next Wednesday from 13:00 to "
     "14:30 in Conference Room B. The agenda and last quarter's figures are attached. "
     "Regards, Thandi", "NOT_HIGH"),

    ("legit_workplace", "Supplier invoice (no bank change)",
     "Good day, please find attached our invoice 7781 for the March maintenance service. "
     "Payment terms remain 30 days as per our agreement. Let us know if you need a purchase "
     "order number on the invoice.", "NOT_HIGH"),

    ("legit_workplace", "Management instruction",
     "Team, from Monday all visitors must sign in at reception and wear a visitor badge. "
     "Please make sure your guests are escorted at all times. Thank you for your cooperation. "
     "Operations Manager", "NOT_HIGH"),

    ("legit_workplace", "HR payroll reminder",
     "Reminder: overtime claims for this month must be approved by your supervisor and "
     "handed to the payroll office by the 20th, otherwise they will be paid next month.",
     "NOT_HIGH"),

    ("legit_workplace", "Redundancy consultation",
     "Dear staff member, the company is considering restructuring the logistics division. "
     "In terms of the consultation process, we invite you to a meeting on 5 May to discuss "
     "alternatives to retrenchment and the selection criteria.", "NOT_HIGH"),

    ("legit_workplace", "Security awareness from IT",
     "IT Department: we will never ask for your password by email. If you receive a message "
     "asking you to sign in through an unfamiliar link, delete it and report it to the "
     "service desk.", "NOT_HIGH"),

    ("legit_workplace", "Onboarding instructions",
     "Welcome aboard! On your first day please report to reception at 08:00. Bring your ID "
     "and your bank confirmation letter so HR can load you on the payroll system.",
     "NOT_HIGH"),

    ("legit_workplace", "Salary increase letter",
     "We are pleased to confirm that your annual salary increase of 6% will be effective "
     "from 1 April. The adjustment will reflect on your April payslip.", "NOT_HIGH"),

    ("legit_workplace", "Grievance acknowledgement",
     "Thank you for submitting your grievance. A grievance meeting has been scheduled for "
     "Friday at 11:00 with the department head. You may be accompanied by a colleague.",
     "NOT_HIGH"),

    # ======================================================
    # WORKPLACE PHISHING / FRAUD
    # ======================================================
    ("scam_workplace", "Fake HR dismissal portal",
     "HR Department: A notice regarding your dismissal has been issued. To view the "
     "confidential letter, sign in with your Microsoft 365 email and password here: "
     "https://micros0ft-hr-docs.example-login.net/view within 12 hours or it will be "
     "deleted.", "HIGH"),

    ("scam_workplace", "Payroll diversion",
     "Payroll: due to a system upgrade, all staff must re-enter their banking details at "
     "http://payroll-staff-update.example.com before Friday or this month's salary will "
     "not be paid.", "HIGH"),

    ("scam_workplace", "CEO gift card fraud",
     "Hi, it's your CEO. I'm stuck in a board meeting and can't talk. I need you to purchase "
     "five Google Play gift cards of R1000 each for a client. Scratch the codes and send me "
     "photos. Please keep this between us for now.", "HIGH"),

    ("scam_workplace", "Supplier bank-change invoice fraud",
     "Dear Accounts, please note our banking details have changed due to an audit. Kindly "
     "make payment of the attached overdue invoice to our new account at Capitec, account "
     "number 1234509876, today. Do not use the old account.", "HIGH"),

    ("scam_workplace", "Fake job with training fee",
     "Congratulations! You have been shortlisted for the Data Capturer position with a "
     "salary of R18,000. To secure your interview, pay the once-off training fee of R750 "
     "via eWallet to 0820000000.", "HIGH"),

    ("scam_workplace", "Mailbox quota phishing",
     "Your Outlook mailbox is 99% full and incoming mail will be suspended within 24 hours. "
     "Click https://outlook-quota.example.net and log in with your password to upgrade your "
     "storage.", "HIGH"),

    ("scam_workplace", "Pay to avoid disciplinary action",
     "This is the HR office. A disciplinary case has been opened against you. To avoid "
     "dismissal you must pay an admin settlement of R2,500 today. Do not discuss this with "
     "your manager.", "HIGH"),

    ("scam_workplace", "Manager impersonation transfer",
     "This is your manager, I am using my personal number. Urgently transfer R9,800 to the "
     "supplier account I will send you. I'm in a meeting so don't call me, just do it now.",
     "HIGH"),

    ("scam_workplace", "Fake payslip download",
     "Your March payslip is ready. Download it at https://bit.ly/payslip-march and enter "
     "your employee PIN to open the document.", "HIGH"),

    ("scam_workplace", "Fake bonus with release fee",
     "Good news from management: you qualify for a performance bonus of R12,000. To release "
     "the bonus, a processing fee of R350 must be paid first.", "HIGH"),

    ("scam_workplace", "Shared document credential lure",
     "Jane from Finance shared 'Salary_Review_2026.pdf' with you. Open "
     "https://docs-share.example.org/salary and sign in with your work email and password "
     "to view.", "HIGH"),

    ("scam_workplace", "Fake IT remote access",
     "IT Support: your work computer has a virus. Download AnyDesk and give us the access "
     "code so we can take control of your device and fix it.", "FLAGGED"),

    # ======================================================
    # GENERAL LEGITIMATE MESSAGES
    # ======================================================
    ("legit_general", "Pay a friend back",
     "Can you pay me back the R50 for lunch when you get a chance?", "NOT_HIGH"),
    ("legit_general", "OTP delivery with advice",
     "Your OTP is 4821. Do not share it with anyone. We will never call you to ask for it.",
     "NOT_HIGH"),
    ("legit_general", "School trip",
     "The Grade 8 trip to the science centre is on Friday. Please bring R60 for the entry "
     "ticket and a packed lunch.", "NOT_HIGH"),
    ("legit_general", "Family message",
     "Hi love, I'll be home late tonight. There's pasta in the fridge.", "NOT_HIGH"),
    ("legit_general", "Real delivery update",
     "Your parcel was delivered to the reception desk at 14:12 and signed for by the "
     "security guard.", "NOT_HIGH"),

    # ======================================================
    # GENERAL SCAMS
    # ======================================================
    ("scam_general", "Bank account suspended link",
     "FNB: Your account has been suspended due to suspicious activity. Verify your identity "
     "within 2 hours at https://fnb-secure-verify.example.com to avoid closure.", "HIGH"),
    ("scam_general", "Family new number",
     "Hi Mom, I lost my phone and this is my new number. Please send R2,000 urgently, "
     "I'll explain later.", "FLAGGED"),
    ("scam_general", "Crypto investment",
     "Get rich quick! Guaranteed 300% returns on bitcoin in 7 days. Invest R1,000 now.",
     "FLAGGED"),
    ("scam_general", "Fake delivery fee",
     "Your parcel could not be delivered. Pay a redelivery fee of R25 at "
     "https://tinyurl.com/redeliver-parcel to avoid it being returned.", "FLAGGED"),
    ("scam_general", "Prize with PIN",
     "You have won a free Samsung tablet! To claim it, pay R99 for shipping with your card "
     "and bank PIN.", "FLAGGED"),

    # ======================================================
    # DIFFICULT EDGE CASES
    # ======================================================
    ("edge", "Scam that hides behind safety advice",
     "Never share your PIN with anyone. Payroll update: to keep receiving your salary, "
     "enter your PIN and banking details at https://staff-payroll.example.net today.",
     "HIGH"),
    ("edge", "Legit warning that quotes a phishing link",
     "IT notice: do not enter your password on https://micros0ft-login.example.net. It is a "
     "phishing site pretending to be Microsoft.", "NOT_HIGH"),
    ("edge", "Legit HR letter marked confidential",
     "Private and confidential. Please find enclosed the minutes of your disciplinary "
     "hearing. Please keep this document confidential and contact HR if you have questions.",
     "NOT_HIGH"),
    ("edge", "Legit invoice that mentions banking details",
     "Hi, as discussed on the phone, our banking details are unchanged and remain as on "
     "your supplier file. Invoice 4410 is attached for your records.", "NOT_HIGH"),
    ("edge", "Genuine-looking bank change request (must still be checked)",
     "Please update your banking details on the HR system before the 20th so that your "
     "salary is paid into your new account.", "FLAGGED"),
    ("edge", "Short urgent workplace message",
     "Urgent: the fire drill starts in 10 minutes. Please leave the building calmly via the "
     "nearest exit.", "NOT_HIGH"),
    ("edge", "OCR-style text with line breaks and odd spacing",
     "Your  Office 365\npassword   expires today.\nKeep  same password:\n"
     "https://office365-keep.example.net\nEnter  your  password  now", "HIGH"),
    ("edge", "Scam using look-alike domain only",
     "Hello, please review the updated leave policy at https://intranet-hr.example-c0mpany.net "
     "and log in with your network password.", "HIGH"),
]
