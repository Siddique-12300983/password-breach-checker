# password-breach-checker

A small Python CLI that tells you whether a password has turned up in known data
breaches, using the [Have I Been Pwned](https://haveibeenpwned.com/Passwords)
Pwned Passwords API. It checks without ever sending your password anywhere,
using k-anonymity. No API key needed.

## Why it matters

Attackers do not guess passwords at random. They try passwords that have already
leaked, because people reuse them. A password can look strong and still be
useless if it is already on a public breach list. This tool checks a password
against roughly a billion leaked ones, and also gives a rough strength rating so
you can see both things at once.

## How k-anonymity keeps the password private

The obvious way to check a password would be to send it to a server, which you
should never do. This tool does not. It works like this:

1. It takes the SHA-1 hash of your password locally, for example
   `password` becomes `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`.
2. It sends only the **first five characters** of that hash (`5BAA6`) to the
   API. Nothing else leaves your machine.
3. The API replies with every hash suffix it knows that starts with those five
   characters, along with a breach count for each (hundreds of results).
4. The tool compares your hash's remaining characters against that list
   **locally** and reads off the count.

The server never sees your password, never sees your full hash, and cannot tell
which of the hundreds of returned hashes was the one you asked about. The tool
also sets the `Add-Padding` header so the response size does not leak anything
either.

The password is read with `getpass`, so it is not shown on screen, not stored,
not logged, and never accepted as a command-line argument.

## Install

Python 3.9 or newer.

```bash
git clone https://github.com/Siddique-12300983/password-breach-checker.git
cd password-breach-checker
pip install -r requirements.txt
```

Or install it as a command:

```bash
pip install .
password-breach-checker
```

## Usage

```bash
python -m breachchecker
```

It prompts for the password (hidden) and prints the result:

```
$ python -m breachchecker
Password (hidden):
BREACHED : found in 52,372,427 known breaches. Do not use this password.
Strength : Weak (8 chars, 1 character types)
           tip: use at least 12 characters; mix in uppercase, digit, symbol
```

```
$ python -m breachchecker
Password (hidden):
OK       : not found in any known breach.
Strength : Strong (18 chars, 4 character types)
```

Exit codes: `0` not breached, `1` breached, `2` no password entered, `3` the API
could not be reached. That makes it usable in a script.

## Running the tests

The tests mock the API, so they run offline and never touch the network.

```bash
pip install -r requirements-dev.txt
pytest
```

They cover the hashing and k-anonymity logic (including that only the 5-char
prefix is sent), the range parsing and padding handling, the strength ratings,
and the CLI, including a check that the password itself is never printed. The
same suite runs in GitHub Actions on every push.

## Layout

```
breachchecker/
  hibp.py       SHA-1, k-anonymity range query, response parsing
  strength.py   length and character-variety rating
  cli.py        getpass prompt and output
tests/          pytest suite, API mocked
```

## A note

This is a learning project. For real use, a password manager that generates long
random passwords and has its own breach monitoring is the better habit. The
value here is seeing how k-anonymity lets you check something against a server
without handing the secret over.

## License

MIT. See [LICENSE](LICENSE).
