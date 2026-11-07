# ScamShield AI – Experiment 10: Fewer false positives, same scam detection

## The problem
A genuine workplace email (disciplinary hearing / dismissal letter) got:
`Original AI prediction: SCAM` → `HIGH RISK` with **0 warning signs**.

## Root cause (found in the code)
1. **Decision logic.** `experiment_v8.scan_message` contained
   `if base_prediction == 'scam': risk = 'HIGH RISK'`.
   The AI on its own was enough for HIGH RISK. Experiment 9 could only raise the risk, never lower it.
2. **Biased training data.** In V7's 600 synthetic examples, all workplace and money words appeared
   only in *scam* templates. The safe templates were mostly about school and family. Counts (scam / safe):
   `of` 30/0, `this` 70/1, `within` 45/0, `pay` 64/0, `salary` 15/0, `terminated` 15/0.
   A formal HR letter is full of these words, so the model read it as a scam.
3. **Over-confident Naive Bayes.** Each word counts as independent evidence, so long emails pile up
   evidence and the model becomes extremely sure of itself.
4. **No workplace messages in the test set,** so the problem was invisible.

## What Experiment 10 changes
| Change | File |
|---|---|
| The AI alone can only reach **NEEDS REVIEW - AI MODEL ONLY**. HIGH RISK needs rule evidence | `experiment_v10.py` → `decide()` |
| 600 new synthetic workplace training examples (300 legit, 300 scam) that share vocabulary | `experiment_v10_data.py` |
| Retrained V10 Naive Bayes (same algorithm as V7, more balanced data) | `experiment_v10.py` |
| Calibrated probability (length-normalised, fitted on the 60 dev messages) | `experiment_v10.py` |
| New workplace-fraud rules: fake HR portals, payroll diversion, gift-card "CEO fraud", invoice bank-detail changes, job fees, pay-to-avoid-dismissal, look-alike links, secrecy | `experiment_v10.py` → `warning_signs_v10()` |
| Fix: in V8, writing "Never share your PIN" anywhere switched off the credential rule. V10 only checks the same sentence | `_unnegated()` |
| Every verdict says whether it came from the **AI model**, the **security rules**, or **both** | `scan_message()` + app |
| 44 hand-written held-out test messages, never used for training | `test_data_v10.py` |
| 42 automated tests (unit tests, held-out cases, data leakage, privacy, OCR, Streamlit app) | `test_experiment_v10.py` |
| Black/red/white theme saved in a file | `.streamlit/config.toml` |

## How a verdict is decided
1. A strong fraud pattern (e.g. a password request through a look-alike link) → **HIGH RISK**
2. 2 serious signs, or a serious sign + a medium sign → **HIGH RISK**
3. AI says scam + a serious sign (or 2 medium signs) → **HIGH RISK**
4. One serious sign, or AI + one medium sign → **NEEDS REVIEW - STRONG WARNING SIGNS**
5. AI says scam with no supporting rule → **NEEDS REVIEW - AI MODEL ONLY**
6. Only minor signs → **NEEDS REVIEW - CHECK CONTEXT**
7. Nothing found → **NO KNOWN PATTERN - NOT PROOF OF SAFETY**

## How to run
```
python -m unittest test_experiment_v10 -v
python experiment_v10.py --model-report
python experiment_v10.py --self-test
streamlit run mobile_app.py
```

## Honest limitations
* The training data is synthetic, and the held-out tests were written by the same people who wrote the
  rules. Passing tests show the system *behaves as designed*, not how accurate it is in the real world.
* On held-out synthetic templates the V10 model scores 599/600. That is too easy to trust, and it is
  why calibrating on synthetic data failed (it suggested being *more* confident).
* The calibration was fitted on only 60 messages.
* A genuine "please update your bank details" message and a fraudulent one can use identical words.
  ScamShield flags both. Always verify through a phone number or system you already trust.
* The next big step is real, anonymised messages kept in a separate test set that is used only once.
