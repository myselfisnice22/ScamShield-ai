"""ScamShield AI - Experiment 11 TRAINING data (stories, scripts, school texts
and South African languages).

WHY THIS FILE EXISTS
--------------------
A Pro user checked a school play script of a traditional folktale. The AI
model said "scam" with 92% probability, although nothing in it was a scam.
The model had only learned from English SMS, emails and workplace messages,
so three things looked suspicious to it:
  * words in Sesotho, isiZulu, isiXhosa, Setswana or Afrikaans it had never seen;
  * dialogue full of commands ("Come here!", "Open the door!");
  * story words such as "taken", "plan", "closed", "quickly".

This file adds 300 synthetic examples:
  * 150 SAFE: folktales, play scripts, poems, school notices, homework,
    recipes and game rules, some using greetings and words from South
    African languages;
  * 150 SCAM: everyday South African scams (SIM swap, "new number" family
    scams, fake prizes, bank PIN requests...) that use THE SAME greetings
    and family words.

As in Experiment 10, both groups share vocabulary, so the model has to learn
the scam BEHAVIOUR (asking for PINs, fees, secrecy, links), not "unfamiliar
language = scam".

IMPORTANT: training data only. The evaluation messages are in
test_data_v11.py, written separately, and checked automatically for overlap.
All names, numbers and links are invented. The user's own document is NOT
used here (it contains real names, and training on it would make the test
meaningless).
"""

import random

SEED = 2011
EXAMPLES_PER_TEMPLATE = 10

SAFE_CREATIVE_TEMPLATES = [
    "{elder}: {greet}, {kid}! Come inside quickly, the {weather} is coming. {kid} runs home before the door is closed.",
    "Scene {n}: {kid} and {elder} sit by the fire. {elder} tells the story of the {animal} who tricked the {animal2}. Everyone laughs.",
    "Once upon a time a clever {animal} lived near the {place}. One day the {animal2} locked the gate, so the {animal} found another way out before sunset.",
    "Narrator: The village is quiet. {kid} sings a song by the {place}. '{greet}!' says the {animal}. 'Where are you going today?'",
    "Homework for {day}: read the folktale about the {animal} and the {animal2}, then write five sentences about the lesson it teaches.",
    "Drama practice is on {day} at {time} in the {schoolroom}. Bring your costume for the role of the {animal}. Learn your lines by heart.",
    "{elder}: {kid}, I must go to the {place} now. Keep the door locked and open it only for me. {kid}: Yes, {elder}. {farewell}!",
    "Poem: The {animal} runs fast, the {weather} comes at last, the gate is closed, the fire glows, and {kid} sleeps safe at home.",
    "Recipe for our {language} class: mix two cups of flour with water, knead the {food} dough for {n} minutes, then bake it. Ask an adult to help.",
    "Game rules: each player takes a turn. If you land on the {animal}, move back {n} spaces. The first player to reach the {place} wins.",
    "{greet}, class! Today we learn a song in {language}. Repeat after me, then sing it with your partner. {thanks}!",
    "Act {n}: The {animal2} hides in a dark cave and waits. {kid} hears it, warns everyone at the {place}, and the whole village is saved.",
    "Library notice: the school library will be closed on {day}. Please return your storybooks by {time} the day before.",
    "Cast list for the {language} play: {kid} (a brave child), {elder} (a wise elder), the {animal} (a trickster) and a narrator.",
    "{elder} says: {greet}, children. Sit down and listen. Long ago the {animal} had no tail, and this is how it got one.",
]

SCAM_LOCAL_TEMPLATES = [
    "{greet}! Your {network} number will be blocked today. Send the OTP we just sent you to {phone} to keep it active.",
    "{greet} {family}, it's me, I lost my phone. This is my new number. Please send R{amount} urgently, {thanks}, I will pay you back.",
    "{greet}! You won R{amount} in the {network} lucky draw. Pay a R{fee} processing fee at {site} to claim your prize.",
    "{greet}, this is {bank} security. Your card is blocked. Reply with your card number and PIN to unblock it now.",
    "{greet}! Earn R{amount} a week from home. Pay a R{fee} registration fee on WhatsApp to start today.",
    "{greet} {family}. A man from the bank will call you. Give him the code on your phone so your grant can be paid. Do not tell anyone.",
    "{greet}! Your parcel is waiting at the depot. Pay the R{fee} customs fee at {site} within 24 hours or it will be returned.",
    "{thanks} for banking with {bank}. Verify your account at {site} and enter your login details to avoid suspension.",
    "{greet} {family}, I am in trouble at the police station. Send R{amount} for bail right now and don't tell anyone.",
    "{greet}! Your {network} SIM will be disconnected in 2 hours. Dial the code and share the PIN with our agent on {phone} to stop it.",
    "{greet}, investment opportunity: double your money in 7 days, guaranteed. Send R{amount} to account {acct} today.",
    "{greet}! You qualify for a free {gift}. Click {site} and enter your banking details to pay R{fee} for delivery.",
    "{greet}! Your child has won a school bursary. Pay a R{fee} admin fee to account {acct} to release the money.",
    "{greet}, {pastor}. The church needs R{amount} urgently. Buy airtime vouchers and send me the PINs. Keep it between us.",
    "{greet}! Your electricity will be cut off today. Pay R{amount} into the new account {acct} and send proof to {phone}.",
]

OPTIONS = {
    "greet": ["Dumela", "Sawubona", "Molo", "Hallo", "Lumela", "Hello", "Hi", "Avuxeni"],
    "thanks": ["Ke a leboha", "Ngiyabonga", "Enkosi", "Baie dankie", "Thank you", "Ke a leboga"],
    "farewell": ["Sala hantle", "Sala kahle", "Totsiens", "Goodbye", "Hamba kahle"],
    "family": ["mme", "ntate", "Mama", "Gogo", "Malume", "Ousie", "Papa"],
    "kid": ["Lerato", "Thabo", "Naledi", "Sipho", "Ayanda", "Kgosi", "Lindiwe", "Pule"],
    "elder": ["Mother", "Grandmother", "Nkgono", "Gogo", "Father", "Grandfather", "Rakgadi"],
    "animal": ["hare", "tortoise", "jackal", "lion", "baboon", "crow"],
    "animal2": ["hyena", "elephant", "snake", "leopard", "crocodile", "owl"],
    "place": ["river", "mountain", "market", "village well", "cattle kraal", "forest"],
    "weather": ["storm", "rain", "wind", "night", "cold"],
    "schoolroom": ["school hall", "Grade 6 classroom", "library", "music room"],
    "language": ["Sesotho", "isiZulu", "isiXhosa", "Setswana", "Afrikaans"],
    "food": ["bread", "vetkoek", "dumpling", "pot bread", "scone"],
    "day": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
    "time": ["08:00", "10:30", "12:00", "13:45", "14:30"],
    "n": ["two", "three", "four", "five", "six"],
    "network": ["Vodacom", "MTN", "Cell C", "Telkom"],
    "bank": ["Capitec", "FNB", "Absa", "Nedbank", "Standard Bank"],
    "site": ["bit.ly/claim-now", "sa-prize-claim.com", "secure-verify-account.net", "this link", "the link below"],
    "phone": ["072 555 0199", "083 555 0147", "061 555 0123", "079 555 0180"],
    "amount": ["500", "850", "1500", "2000", "5000"],
    "fee": ["49", "99", "150", "250", "350"],
    "acct": ["62005519", "41870032", "10994471", "73001288"],
    "gift": ["phone", "tablet", "food hamper", "laptop"],
    "pastor": ["Pastor here", "your church elder", "Moruti here", "Mfundisi here"],
}


def normalise(message):
    return " ".join(message.lower().split())


def generate_local_examples(with_template_id=False):
    """Generate 300 unique labelled examples, deterministically."""
    rng = random.Random(SEED)
    output, seen = [], set()
    for label, templates in (("safe", SAFE_CREATIVE_TEMPLATES), ("scam", SCAM_LOCAL_TEMPLATES)):
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


local_examples = generate_local_examples()
