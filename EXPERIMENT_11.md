# ScamShield AI – Experiment 11: Stories, scripts and South African languages

## The problem
A Pro user checked a school play script of a traditional folktale (a PDF). ScamShield said
**NEEDS REVIEW – AI MODEL ONLY** (92% scam probability) and listed one warning sign:
"Mentions an account or service being blocked or suspended." Nothing in it was a scam.

## Root cause
1. **A rule that was too loose.** Experiment 8's `account_threat` rule fired on the words
   *blocked, suspended, frozen, terminated, deactivated, locked, closed, disconnected*
   **anywhere**. In the script it matched "the **closed** door". Combined with any time phrase
   ("for 3 hours") it even became a *serious* warning (`deadline_threat`). Experiment 10 rated a
   story about a road blocked for 3 hours as **HIGH RISK**.
2. **The AI had never seen this kind of text.** It learned from English SMS, emails and workplace
   messages. Sesotho/isiZulu/Afrikaans words, story dialogue and commands ("Come home now!")
   looked unusual, so it leaned towards "scam".

## What Experiment 11 changes
| Change | File |
|---|---|
| The account-threat word must be about an **account, card, number, SIM, service, grant…** in the same sentence (within 40 characters). "Your account will be closed" counts, "the closed door" doesn't | `experiment_v11.py` → `account_threat()` |
| 300 new synthetic training examples: 150 safe (folktales, play scripts, poems, school notices, recipes, game rules) and 150 local scams (SIM swap, "new number" family scams, fake prizes, bank PIN requests). Both use the **same greetings and words** (Dumela, Sawubona, Molo, Hallo, mme, Gogo…) | `experiment_v11_data.py` |
| Same Naive Bayes, retrained on Experiment 10's data + the new examples, and recalibrated the same way | `experiment_v11.py` |
| 22 new held-out test messages, written separately and checked for overlap | `test_data_v11.py` |
| 22 automated tests, including "nothing Experiment 10 got right is lost" | `test_experiment_v11.py` |
| The website, phone version, API and document checker now use Experiment 11. Experiment 10 stays frozen for comparison | `app.py`, `mobile_app.py`, `backend/api.py`, `streamlit_plans.py` |

The user's own document was **not** used for training or added to the repository (it contains
real names, and training on it would make the test meaningless). It was only checked locally:
Experiment 10 → *Needs review – AI model only (92%)*, Experiment 11 → *No known pattern (0.1%)*.

## Results (`python experiment_v11.py --model-report`)
| Test set | Version | Safe texts the AI calls scam | Safe texts flagged at all | Safe texts HIGH RISK | Scams flagged | Scams HIGH RISK |
|---|---|---|---|---|---|---|
| New (22 messages) | V10 | 8/13 | 11/13 | 1/13 | 9/9 | 8/9 |
| New (22 messages) | **V11** | **2/13** | **3/13** | **0/13** | 9/9 | 8/9 |
| Experiment 10 (44 messages) | V10 | 2/23 | 4/23 | 0/23 | 21/21 | 21/21 |
| Experiment 10 (44 messages) | **V11** | 2/23 | **3/23** | 0/23 | 21/21 | 21/21 |

## Known miss (recorded, not hidden)
"Fake church fundraiser" (*buy R500 of Google Play cards… keep this between the two of us*) is
only **NEEDS REVIEW**, in both Experiment 10 and 11. The gift-card rule only knows the words
"gift card(s)", and the secrecy rule doesn't know "between the two of us". This is the next rule fix.

## Honest limitations
* All training and test messages are synthetic or self-written by the same people, so passing
  tests show the system **behaves as designed**, not real-world accuracy.
* Only a few words from each language are covered. Longer texts fully in Sesotho, isiZulu etc.
  may still confuse the AI. The rules (which decide HIGH RISK) only understand English.
* A stricter rule can miss a scam worded in an unusual way, e.g. "they will close everything
  you have with us". Other rules and the AI still look at those messages.
