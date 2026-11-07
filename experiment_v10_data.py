"""ScamShield AI - Experiment 10 TRAINING data (workplace messages).

WHY THIS FILE EXISTS
--------------------
Experiment 7's synthetic training data had a hidden bias: every workplace and
money word (salary, payroll, company, terminated, payment, bank account...)
appeared ONLY in scam templates, while almost every "safe" template was about
school or family life. The Naive Bayes model therefore learned
"formal workplace language = scam".

This file adds 600 synthetic workplace examples:
  * 300 legitimate workplace messages (HR letters, disciplinary hearings,
    dismissal letters, meetings, invoices, payroll, management instructions)
  * 300 workplace scams (fake HR portals, payroll diversion, gift-card CEO
    fraud, invoice bank-detail changes, fake jobs with fees, credential theft)

Both groups deliberately share vocabulary (salary, payment, account,
dismissal...). The model then has to learn the BEHAVIOUR that makes a scam
(asking for passwords, changing bank details, fees, secrecy), not the topic.

IMPORTANT: these are TRAINING examples only. The evaluation messages live in
test_data_v10.py, were written separately in different wording, and are
checked automatically for overlap. No real person's email is used anywhere.
"""

import random

SEED = 2010
EXAMPLES_PER_TEMPLATE = 15

LEGIT_WORKPLACE_TEMPLATES = [
    "You are required to attend a disciplinary hearing on {day} at {time} in the {room}. You may bring a {representative} with you.",
    "This letter confirms the outcome of the disciplinary hearing held on {day}. You have the right to appeal within {days} working days.",
    "Notice of termination of employment: your final day of service is {date}. Your final salary for {month} will be paid on the normal payroll date.",
    "Your employment is terminated with effect from {date} following the hearing. Please return your {equipment} to {dept}.",
    "The {meeting} meeting has moved to {day} at {time} in the {room}. Please bring your {doc}.",
    "Please find attached invoice {inv} for {month}. Payment is due within {days} days to the account details in our signed contract.",
    "Reminder from {dept}: please submit your {doc} by {day} so payroll can process salaries this month.",
    "{manager} has asked all staff to complete the {training} training by {day}. Do not share your password with anyone.",
    "You are suspended on full pay pending the outcome of the investigation. Please do not access the {room} until {day} and return your {equipment}.",
    "Your payslip for {month} is available on the internal HR system. Contact {dept} if anything is incorrect.",
    "Please confirm receipt of this notice of the disciplinary hearing on {day} by replying to {dept}.",
    "The written warning issued on {day} will remain on your file for {months} months.",
    "Following the restructuring, your position has been made redundant. Severance pay will be included in your final salary on {date}. Contact {dept} with questions.",
    "Please review the attached policy on {policy} before the team meeting on {day}.",
    "Accounts payable has approved invoice {inv}. Payment will be made on {day} through the usual supplier process.",
    "Management instruction: the {room} will be closed on {day}, so all staff must work from the {place}.",
    "Your leave request for {month} has been approved by {manager}.",
    "Welcome to the team. Your first day is {day} at {time}. Please bring your ID document to {dept} to sign your employment contract.",
    "Your performance review with {manager} is scheduled for {day} at {time} in the {room}.",
    "If you receive an email asking you to change banking details, report it to {dept} on {day} and do not click the link in the {mail} message.",
]

SCAM_WORKPLACE_TEMPLATES = [
    "HR notice: your dismissal letter is ready. Log in with your email password at {site} within {deadline} to view it.",
    "Your salary for {month} is on hold. Update your banking details at {site} before {deadline}.",
    "This is {exec}. I need you to buy {n} {giftcard} gift cards urgently and send me the codes. Keep this confidential.",
    "We have changed our bank account. Please pay invoice {inv} of {amount} into the new account immediately.",
    "Congratulations, you are hired for a remote job. Pay a {fee} of {amount} before your start date.",
    "Your {mail} mailbox will be suspended within {deadline}. Verify your password at {site}.",
    "You have a pending disciplinary case. Pay {amount} {deadline} to avoid dismissal and keep this confidential.",
    "Payroll update required for {month}: send your PIN and card number to {dept} to receive your bonus of {amount}.",
    "{exec} here, I am in a meeting. Transfer {amount} to this supplier account now and do not call me.",
    "Your employment contract needs a signature. Sign in with your work credentials at {site} {deadline}.",
    "Job offer: earn {amount} a day working from home. Send your ID number and bank details by {deadline} to secure the position.",
    "Your {mail} account password expires {deadline}. Click {site} to keep the same password.",
    "Recruitment agency: pay {amount} for training materials before we can confirm your interview on {day}.",
    "Urgent from finance: approve the {amount} payment to the new beneficiary within {deadline} without calling anyone.",
    "Your {month} payslip could not be delivered. Open {site} and enter your login code to download it.",
    "I am the HR director. Reply with your banking details and OTP by {deadline} so we can process your severance pay of {amount}.",
    "Install {software} so the IT support desk can control your work {equipment} remotely {deadline}.",
    "{dept} shared a document about your termination. Sign in at {site} with your email password to read it.",
    "New supplier banking details: pay all outstanding invoices to account {acct} from {deadline}.",
    "Your company has selected you for a cash bonus of {amount}. Pay a processing fee by {deadline} to release it.",
]

OPTIONS = {
    "day": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
    "time": ["08:30", "09:00", "11:00", "14:00", "15:30"],
    "room": ["boardroom", "HR office", "training room", "conference room", "main office"],
    "representative": ["colleague", "union representative", "shop steward", "fellow employee", "interpreter"],
    "days": ["three", "five", "seven", "ten", "fourteen"],
    "date": ["the end of the month", "30 June", "31 March", "15 August", "1 October"],
    "equipment": ["laptop", "access card", "company phone", "keys", "uniform"],
    "dept": ["Human Resources", "the HR department", "your line manager", "the payroll office", "the people team"],
    "meeting": ["weekly operations", "project planning", "budget", "staff", "safety committee"],
    "doc": ["timesheet", "project update", "leave form", "expense claim", "monthly report"],
    "inv": ["INV-1042", "INV-2207", "INV-3381", "INV-4519", "INV-5630"],
    "month": ["January", "March", "May", "July", "September"],
    "manager": ["The managing director", "Your line manager", "The operations manager", "The head of department", "The site manager"],
    "training": ["health and safety", "cybersecurity", "data protection", "first aid", "fire safety"],
    "months": ["three", "six", "nine", "twelve", "eighteen"],
    "policy": ["remote work", "overtime", "data protection", "travel claims", "annual leave"],
    "place": ["second floor", "branch office", "home office", "east wing", "training centre"],
    "exec": ["your CEO", "the managing director", "your boss", "the finance director", "the company owner"],
    "n": ["three", "five", "six", "eight", "ten"],
    "giftcard": ["Google Play", "iTunes", "Amazon", "Steam", "store"],
    "amount": ["R450", "R1200", "R3500", "R8000", "R15000"],
    "fee": ["registration fee", "uniform fee", "training fee", "admin fee", "placement fee"],
    "mail": ["Outlook", "Office 365", "work email", "company email", "Microsoft"],
    "site": ["hr-portal-login.net", "this secure link", "payroll-update-now.com", "an external page", "the link below"],
    "deadline": ["today", "24 hours", "two hours", "the end of the day", "30 minutes"],
    "acct": ["62004417", "40991203", "10255870", "73310925", "55018462"],
    "software": ["a remote desktop tool", "a screen sharing app", "this support app", "a remote access program", "an unknown control tool"],
}


def normalise(message):
    return " ".join(message.lower().split())


def generate_workplace_examples(with_template_id=False):
    """Generate 600 unique labelled workplace examples, deterministically.

    with_template_id=True returns (message, label, template_id) so that
    calibration can hold out whole templates (a harder, fairer check).
    """
    rng = random.Random(SEED)
    output, seen = [], set()
    for label, templates in (("safe", LEGIT_WORKPLACE_TEMPLATES),
                             ("scam", SCAM_WORKPLACE_TEMPLATES)):
        for index, template in enumerate(templates):
            template_id = f"{label}{index}"
            made = attempts = 0
            while made < EXAMPLES_PER_TEMPLATE:
                attempts += 1
                if attempts > 3000:
                    raise RuntimeError("Unable to generate distinct examples")
                values = {k: rng.choice(v) for k, v in OPTIONS.items()}
                message = template.format(**values)
                key = normalise(message)
                if key not in seen:
                    seen.add(key)
                    output.append((message, label, template_id))
                    made += 1
    rng.shuffle(output)
    if with_template_id:
        return output
    return [(message, label) for message, label, _ in output]


workplace_examples = generate_workplace_examples()
