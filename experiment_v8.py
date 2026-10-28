"""ScamShield V8: frozen V7 classifier plus transparent safety checks.

No external APIs, no network requests, no third-party packages.
Place beside experiment_v7.py and the V7 dependencies.

Usage:
    py experiment_v8.py               # Interactive scanner
    py experiment_v8.py --self-test   # Simple functional checks
    py experiment_v8.py --dev-check   # Optional REUSED 60-message development check

V8's warning rules are hand-written heuristics, NOT explanations of V7's
internal reasoning. They are not evidence of independent accuracy.
"""

import argparse
import csv
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

from experiment_v7 import predict_v7

URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")

# These domains are shared hosting/shortening services, not automatically malicious.
HOSTING_SUFFIXES = ("web.core.windows.net", "pages.dev", "github.io", "netlify.app", "vercel.app")
SHORTENER_HOSTS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at"}

CREDENTIALS = r"(?:pin|otp|one[- ]time (?:pin|password|code)|password|cvv|card (?:number|details|security code)|banking details|security code|login code)"
REQUEST = r"(?:send|share|provide|enter|submit|give|forward|reply with|upload|type|reveal)"


def extract_urls(message):
    """Extract URLs for local inspection. Never fetches or follows links."""
    result = []
    for match in URL_PATTERN.finditer(message):
        raw = match.group().rstrip('.,;:!?)]}')
        if raw and raw not in result:
            result.append(raw)
    return result


def hostname_for(url):
    try:
        candidate = url if '://' in url else 'https://' + url
        return (urlsplit(candidate).hostname or '').lower().rstrip('.')
    except ValueError:
        return ''


def looks_like_security_advice(text):
    return bool(re.search(
        r"\b(?:never|do not|don't|should not|must not|avoid)\s+"
        r"(?:\w+\s+){0,5}(?:share|send|provide|enter|reveal|give)\b",
        text
    )) or bool(re.search(r"\b(?:will never|would never)\s+ask\b", text))


def warning_signs(message):
    """Return transparent safety signals, not a learned explanation."""
    text = message.lower()
    findings = []
    seen = set()

    def add(code, description, severity):
        if code not in seen:
            findings.append({"code": code, "description": description, "severity": severity})
            seen.add(code)

    urls = extract_urls(message)
    if urls:
        add("link", "Contains a link. Verify its destination through an official channel.", "low")
        for url in urls:
            host = hostname_for(url)
            if not host:
                add("invalid_url", "The link address could not be interpreted reliably.", "medium")
                continue
            if any(host == suffix or host.endswith('.' + suffix) for suffix in HOSTING_SUFFIXES):
                add("shared_host", "Link uses shared cloud hosting; this alone does not prove fraud.", "medium")
            if host in SHORTENER_HOSTS:
                add("shortener", "Shortened link obscures the final destination.", "medium")
            try:
                ipaddress.ip_address(host)
                add("ip_link", "Link uses a numeric IP address rather than a recognizable domain.", "medium")
            except ValueError:
                pass

    urgency = bool(re.search(
        r"\b(?:urgent|immediately|right now|act now|within\s+\d+\s*"
        r"(?:minutes?|mins?|hours?|hrs?)|\bin\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)|"
        r"\d+\s*(?:hrs?|hours?|mins?|minutes?)|today only)\b", text
    ))
    account_threat = bool(re.search(
        r"\b(?:blocked|suspended|frozen|terminated|deactivated|locked|closed|disconnected)\b", text
    ))
    if urgency and account_threat:
        add("deadline_threat", "A short deadline is combined with a threatened account/service interruption.", "high")
    elif urgency:
        add("urgency", "Uses urgent or time-limited language. Context matters.", "low")
    elif account_threat:
        add("account_threat", "Mentions an account or service being blocked or suspended.", "low")

    credential_request = bool(re.search(
        rf"\b{REQUEST}\b.{{0,75}}\b{CREDENTIALS}\b", text, re.DOTALL
    ))
    if credential_request and not looks_like_security_advice(text):
        add("credential_request", "Appears to request a password, PIN, OTP, or other sensitive details.", "high")

    if re.search(r"\b(?:guaranteed|risk[- ]free)\b.{0,55}\b(?:returns?|profits?|investment|crypto(?:currency)?|double your money)\b", text):
        add("guaranteed_profit", "Promises unusually certain investment returns.", "high")

    if re.search(r"\b(?:won|prize|reward|refund|grant|bursary|inheritance)\b", text) and re.search(
        r"\b(?:pay|deposit|transfer|advance (?:fee|payment)|processing (?:fee|charge))\b", text
    ):
        add("advance_fee", "Connects a prize, refund, or grant with an upfront payment.", "high")

    if re.search(r"\b(?:new number|changed my number|lost my phone)\b", text) and re.search(
        r"\b(?:send|transfer|pay)\b.{0,35}\b(?:money|cash|r\s*\d+)\b", text
    ):
        add("impersonation", "New-phone-number story combined with a money request; verify the sender.", "high")

    if re.search(r"\b(?:install|download)\b.{0,65}\b(?:remote (?:access|desktop)|screen shar(?:e|ing)|control your (?:phone|computer|device))\b", text) and not looks_like_security_advice(text):
        add("remote_access", "Requests remote-control software or device access.", "high")

    if urls and re.search(r"\b(?:bank|fica|kyc|banking|account|verification)\b", text):
        add("account_link", "An account or identity claim directs you to a link; verify independently.", "medium")

    return findings, urls


def scan_message(message):
    """Return a non-definitive assessment; never mark a message definitively safe."""
    if not isinstance(message, str) or not message.strip():
        raise ValueError('Please enter a nonempty message.')
    if len(message) > 5000:
        raise ValueError('Please scan messages under 5,000 characters.')

    base_prediction = predict_v7(message)
    findings, urls = warning_signs(message)
    serious = [f for f in findings if f['severity'] == 'high']

    if base_prediction == 'scam':
        risk = 'HIGH RISK - POSSIBLE SCAM'
    elif serious:
        risk = 'NEEDS REVIEW - STRONG WARNING SIGNS'
    elif findings:
        risk = 'NEEDS REVIEW - CHECK CONTEXT'
    else:
        risk = 'NO KNOWN PATTERN - NOT PROOF OF SAFETY'

    return {
        'v7_prediction': base_prediction,
        'risk': risk,
        'warnings': findings,
        'urls': urls,
        # A conservative experimental binary screening rule for development tests.
        # It can increase false alarms. It is NOT a real-world benchmark.
        'v8_screening_label': 'scam' if base_prediction == 'scam' or serious else 'safe',
    }


def evaluate_development():
    """REUSED development messages only. NEVER treat as independent final test."""
    from evaluate_scams import tests
    results = []
    for message, actual in tests:
        analysis = scan_message(message)
        results.append((message, actual, analysis['v7_prediction'], analysis['v8_screening_label']))

    def metrics(index):
        n = len(results)
        correct = sum(row[index] == row[1] for row in results)
        missed = sum(row[1] == 'scam' and row[index] == 'safe' for row in results)
        false_alarms = sum(row[1] == 'safe' and row[index] == 'scam' for row in results)
        return correct / n * 100, missed, false_alarms

    print('REUSED DEVELOPMENT DATA - NOT FINAL ACCURACY')
    for label, index in [('Frozen V7', 2), ('V8 warning-based screen', 3)]:
        acc, missed, false = metrics(index)
        print(f'{label}: {acc:.1f}% accuracy | missed scams: {missed} | false alarms: {false}')
    out = Path(__file__).with_name('v8_development_screening.csv')
    with out.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.writer(stream)
        writer.writerow(['message', 'actual', 'v7', 'v8_screen'])
        writer.writerows(results)
    print('Saved:', out.name)


def self_test():
    examples = [
        ('Standard Bank: Your Account will be blocked in 2hrs due to a failed FICA update. TAP-> https://stdbankkyc.z13.web.core.windows.net/ & update', {'deadline_threat', 'shared_host'}),
        ('Never share your OTP or PIN with anyone.', set()),
        ('Hey, swimming practice moved to Wednesday.', set()),
        ('Guaranteed cryptocurrency profits if you invest R500 today.', {'guaranteed_profit'}),
        ('I am your aunt using a new number. Transfer R850 to me now.', {'impersonation'}),
    ]
    for message, expected in examples:
        analysis = scan_message(message)
        codes = {w['code'] for w in analysis['warnings']}
        assert expected.issubset(codes), (message, expected, codes)
        print('OK:', message[:65])
    print('All 5 functional checks passed. These do NOT establish prediction accuracy.')


def main():
    parser = argparse.ArgumentParser(description='ScamShield V8 experimental safety layer')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--dev-check', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.dev_check:
        evaluate_development()
        return

    print('\nSCAMSHIELD V8 - EXPERIMENTAL MESSAGE SCANNER')
    print('Runs locally. Does not open suspicious links.')
    print('Type exit to quit. Do not paste private banking credentials.')
    while True:
        try:
            message = input('\nMessage: ').strip()
        except (EOFError, KeyboardInterrupt):
            print('\nGoodbye!')
            break
        if message.lower() == 'exit':
            break
        if not message:
            continue
        try:
            report = scan_message(message)
        except ValueError as error:
            print(error)
            continue
        print('V7 machine-learning prediction:', report['v7_prediction'].upper())
        print('V8 assessment:', report['risk'])
        if report['warnings']:
            for finding in report['warnings']:
                print(' -', finding['description'])
        else:
            print('No predefined warning signs detected.')
        print('This is an experimental screening tool, not a confirmation of safety.')


if __name__ == '__main__':
    main()
