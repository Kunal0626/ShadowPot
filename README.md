# ShadowPot

**SSH honeypot and attacker analytics**

> Status: Code is being added to this repository.

A fake SSH server records every login attempt and command; SQL queries turn the logs into a picture of how attackers actually behave.

## How it works
1. Cowrie presents a fake SSH server and records login attempts and commands.
2. Session logs are loaded into a normalized SQL schema (sessions, credentials, commands, source IPs).
3. Queries rank the most-tried credentials, repeat source IPs and common post-login commands.

## Stack
- Python
- Cowrie
- SQL (SQLite / MySQL)
- Linux

## CS concepts
- Honeypots
- Log parsing
- Normalization and SQL aggregation
- Attacker behaviour

## Roadmap
- [ ] Cowrie setup notes (isolated environment)
- [ ] Log parser into SQL
- [ ] Schema (sessions, credentials, commands)
- [ ] Analytics queries
- [ ] Sample report

## Usage
Coming soon.

---
Part of my portfolio: [github.com/Kunal0626](https://github.com/Kunal0626)
