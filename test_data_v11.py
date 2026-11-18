"""ScamShield AI - Experiment 11 HELD-OUT EVALUATION messages.

NEVER used for training. Written separately from experiment_v11_data.py, in
different wording; test_experiment_v11.py checks automatically that none of
them duplicates or nearly duplicates a training example.

All names, numbers and links are invented. The real document that revealed
the problem is NOT included (it contains real people's names).

Expected outcomes (same meaning as test_data_v10.py):
    "HIGH"      -> must be HIGH RISK
    "FLAGGED"   -> must be HIGH RISK or NEEDS REVIEW
    "NOT_HIGH"  -> must NOT be HIGH RISK

HONESTY NOTE: written by the same people who wrote the fix, so passing tests
show the system behaves as designed, not real-world accuracy.
"""

# (category, name, message, expected)
CASES = [
    # ======================================================
    # STORIES, SCRIPTS, POEMS AND SCHOOL TEXTS (legitimate)
    # ======================================================
    ("legit_creative", "Folktale play script with Sesotho dialogue",
     """The Hare and the Crocodile - a short play
Theme: Oral tradition and storytelling
Characters: Hare, Crocodile, Grandmother Mmamosa, Narrator

Narrator: Long ago, by a wide brown river, there lived a hare who loved to boast.
Grandmother: Mmutla! Hare! Come home now, it is getting dark!
Hare: I am coming, Nkgono! But first I must cross the river.
Narrator: The crocodile smiles and opens his big mouth.
Crocodile: Climb on my back, little friend. I will carry you across.
Hare: Ke a leboha, Kwena! You are very kind.
Narrator: Halfway across, the crocodile stops and laughs.
Crocodile: Now I have you! Tonight I will eat hare stew!
Hare: Oh no! Wait! I left my heart hanging in the tree at home. Take me back and I will fetch it for you.
Narrator: The foolish crocodile swims back. The hare jumps to the shore and runs to Grandmother's hut. She shuts the door behind him.
Grandmother: You are safe, my child. Remember: clever thinking beats big teeth.""",
     "NOT_HIGH"),
    ("legit_creative", "isiZulu folktale retelling",
     "Kwesukela... Once there was a girl called Nomsa who walked to the stream every morning to "
     "fetch water. One day a giant bird blocked the path and would not let her pass. Nomsa sang "
     "her grandmother's song, the bird fell asleep, and she walked home safely. Cosu cosu, "
     "iyaphela.", "NOT_HIGH"),
    ("legit_creative", "Afrikaans and English school poem",
     "Die son sak stadig agter die berg. The cattle walk slowly home. My mother lights the candle, "
     "the gate is locked, the dog lies by the door, and I fall asleep to the sound of the rain.",
     "NOT_HIGH"),
    ("legit_creative", "Drama rehearsal note to parents",
     "Dear parents, the Grade 5 isiXhosa play is on Thursday at 11:00. Please send your child "
     "with a blanket and a stick for the costume. The hall doors will be closed once the play "
     "starts, so arrive early. Enkosi!", "NOT_HIGH"),
    ("legit_creative", "Setswana greeting lesson",
     "Today's Setswana lesson: Dumela rra means hello sir, Dumela mma means hello madam, and "
     "Ke a leboga means thank you. Practise greeting your partner three times, then swap roles.",
     "NOT_HIGH"),
    ("legit_creative", "Story with a cave and a trapped hunter",
     "The hunter followed the leopard into the cave. A rock rolled across the entrance and the way "
     "out was blocked. For two hours he waited in the dark until his friends came and pushed the "
     "rock away. Moral: never go hunting alone.", "NOT_HIGH"),
    ("legit_creative", "Homework instructions with commands",
     "Read the story twice. Underline every verb. Then answer the questions in full sentences and "
     "draw your favourite scene. Hand in your book on Monday morning.", "NOT_HIGH"),
    ("legit_creative", "Monologue with urgency in a story",
     "Narrator: The river is rising fast! Mother: Thabiso, quickly, take your little sister and "
     "run to the hill right now! Thabiso: Yes Mme, we are going! Narrator: By morning the "
     "whole family was safe.", "NOT_HIGH"),
    ("legit_creative", "Book report",
     "Book report: 'Jabulani and the Moon' tells the story of a boy who wants to visit the moon. "
     "His grandfather builds him a ladder from reeds. I liked the ending because it shows that "
     "dreams take patience.", "NOT_HIGH"),
    ("legit_creative", "Choir notice in Sesotho and English",
     "Lumelang! Choir practice moves to Wednesday after school because the music room is closed "
     "for painting. Bring water and your song books. Re a leboha.", "NOT_HIGH"),

    # ======================================================
    # LOCAL SCAMS USING SOUTH AFRICAN LANGUAGES (must be caught)
    # ======================================================
    ("scam_local", "SIM swap with Sesotho greeting",
     "Dumela! This is your network provider. Your SIM card will be deactivated within 2 hours "
     "because of a security problem. Reply with the PIN we SMSed you to stop this.", "HIGH"),
    ("scam_local", "Family emergency in isiZulu",
     "Sawubona Gogo, ngicela usize. It's your grandson, my phone is broken so I am using a "
     "friend's phone. Please send me R1200 by e-wallet right now, I will explain later. Don't "
     "tell my mother.", "FLAGGED"),
    ("scam_local", "Fake bank call in Afrikaans",
     "Goeie more. Hier praat Absa se bedrogafdeling. Your card has been blocked because of "
     "suspicious transactions. To unblock it, please give us your card number, expiry date and "
     "the OTP you receive now.", "HIGH"),
    ("scam_local", "Fake prize with greeting",
     "Molo! Congratulations, your number won R25 000 in the weekend draw. A R199 release fee "
     "must be paid at https://lucky-draw-sa.example.net before we can send your winnings.",
     "HIGH"),
    ("scam_local", "Fake church fundraiser",
     "Lumela mme, this is the pastor. We have an emergency at the church. Please buy R500 of "
     "Google Play cards and WhatsApp me the codes today. Keep this between the two of us.",
     "HIGH"),
    ("scam_local", "Fake grant update",
     "Dumelang! Your SASSA grant payment is on hold. Update your banking details and ID number at "
     "https://sassa-grant-update.example.com today or your grant will be cancelled.", "HIGH"),
    ("scam_local", "Fake job in mixed language",
     "Hallo! We have a job for you at a big hotel, R9 000 a month. Pay a R350 uniform fee to "
     "the HR officer on WhatsApp before your start date to confirm the position. Baie dankie.",
     "HIGH"),

    # ======================================================
    # RULE EDGE CASES (the stricter account-threat rule)
    # ======================================================
    ("edge", "Shop closed - not an account",
     "The spaza shop was closed today, so we bought bread at the market instead.", "NOT_HIGH"),
    ("edge", "Road blocked with a time phrase",
     "The road to the village was blocked by a fallen tree for 3 hours this morning. The "
     "municipality has cleared it now.", "NOT_HIGH"),
    ("edge", "Account closed with deadline (must still be flagged)",
     "Final notice: your online banking account will be closed in 24 hours. Confirm your "
     "details at https://bank-account-keep.example.net now.", "HIGH"),
    ("edge", "Mailbox suspended",
     "Your mailbox will be suspended tonight because it is full. Sign in with your email "
     "password at https://mailbox-upgrade.example.org to keep receiving messages.", "HIGH"),
    ("edge", "Genuine-looking card blocked notice (still checked)",
     "We blocked your card after an unusual purchase. If this was not you, call the number on "
     "the back of your card. We will never ask for your PIN.", "NOT_HIGH"),
]
