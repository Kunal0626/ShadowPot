# Deploying ShadowPot's honeypot (Part B)

**You execute this document. Nothing in this repository deploys anything.**

Part A — everything else in this repo — runs offline on your laptop against
generated data. Part B is a real SSH honeypot on the public internet. It is
the only way to get numbers you may put on a resume, and it is the only part
with real risk.

| | |
|---|---|
| Verified against | Cowrie **3.1.5** (released 2026-10-31), docs read 2026-11-09 |
| Reference OS | Debian 12 "bookworm", which is what Cowrie's own install guide verifies against |
| Time to do once | about 90 minutes, carefully |
| Time to run | 7 days minimum for the numbers to mean anything |

Sources for every Cowrie command below: the project's own
[`INSTALL.rst`](https://github.com/cowrie/cowrie/blob/master/INSTALL.rst) and
the bundled `src/cowrie/data/etc/cowrie.cfg.dist`. Cowrie 3.0 changed
installation substantially — there is a new `cowrie init`, state lives under
the working directory, and `[honeypot] data_path` was removed — so older blog
posts will mislead you.

---

## 0. The three rules

**Do not run this on your laptop, your home network, or any college or
university network.** A honeypot invites tens of thousands of hostile
connections per week. On a home network it puts every other device behind that
router in the blast radius. On a campus network it will look exactly like a
compromised host to the people who run that network, and the consequences are
administrative, not technical.

**Put nothing on the box you would mind losing or leaking.** No personal
files, no other projects, no cloud API keys, no reused passwords, no SSH key
that opens anything else. Assume from the start that the box will be
destroyed, and plan to destroy it yourself at the end.

**The honeypot must never hold a credential that reaches you.** Logs are
*pulled* by your laptop, never *pushed* by the honeypot. Section 9 explains
why that direction is the whole security model.

---

## 1. What you are actually risking

Be precise about this, because "honeypot" sounds more dangerous than Cowrie
is, and less dangerous in the one place it matters.

**Cowrie is low-interaction.** It emulates a shell in Python. There is no real
shell, no real filesystem and no real command execution, so an attacker typing
`rm -rf /` destroys a fake filesystem and `./malware` runs nothing. This is
the main reason Cowrie is far safer than standing up a deliberately
vulnerable real machine.

**But Cowrie does make outbound requests on an attacker's behalf.** When an
attacker runs `wget http://x/payload`, Cowrie **really fetches that URL** so
it can store the sample — that is where `cowrie.session.file_download` and its
`shasum` come from. So your box will issue HTTP requests to attacker-chosen
addresses. That is a deliberate trade: block it and you capture no malware,
allow it and your IP appears in someone's logs fetching a payload. Section 5
allows ports 80 and 443 outbound and blocks everything else, which is the
usual compromise. Decide knowingly.

**An attacker can tell it is a honeypot.** Cowrie's emulated shell is
incomplete; `cowrie.command.failed` events are exactly the commands it does
not implement, and a human probing with obscure busybox applets will work it
out in a minute. That is fine. The traffic worth measuring is automated and
does not check.

**The real risk is the host, not the honeypot.** The genuine failure modes are:
you leave your real `sshd` on port 22 with password auth and *that* gets brute
forced; the box is used to attack someone else and your provider suspends you;
or you lock yourself out mid-configuration. Sections 3 to 5 are about those,
in that order, and they come before Cowrie is installed at all.

---

## 2. Where to run it

A separate, disposable cloud VPS. Cheapest tier is fine — Cowrie is idle
almost all the time and the whole dataset is a few hundred megabytes.

| Provider | Notes |
|---|---|
| **Hetzner Cloud** | Cheapest of the three for a small instance; EU and US regions. |
| **DigitalOcean** | Simplest console and snapshots; well documented. |
| **Vultr** | Many regions, hourly billing, easy to destroy and recreate. |

Oracle Cloud and Google Cloud both have free tiers that people use for this,
but their terms are stricter and their abuse handling is more automated.

**Read the provider's acceptable-use policy before you start, and search it
for "honeypot".** Most providers permit a honeypot you own on your own
instance; several require that it not be used to attack others, which is what
the egress rules in section 5 are for. A few forbid it outright. You are
looking for the sections on security research, intrusion detection and network
abuse. If the policy is ambiguous, open a support ticket and ask — a one-line
"yes, that's fine" in writing is worth having.

Expect an abuse email at some point anyway, usually because your box fetched a
payload from an address someone monitors. Answer it honestly: it is a
research honeypot, here is what it does, here are the egress restrictions.

**Region:** pick one geographically far from you. The volume of traffic is
similar everywhere; keeping the box away from your own networks is free.

---

## 3. Create the box, with nothing on it

Create the smallest instance, Debian 12, and **add your SSH public key during
creation** so password login is never enabled.

Generate a key that exists only for this box. Do not reuse your GitHub key, or
any key that opens anything else:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/shadowpot_admin -C "shadowpot admin $(date +%Y-%m)"
```

Then, on the box, before anything else:

```bash
sudo apt-get update && sudo apt-get -y upgrade
```

```bash
sudo timedatectl set-timezone UTC
```

UTC matters. Cowrie's `[honeypot] timezone` defaults to `UTC`, and that value
becomes the `TZ` environment variable for the process, which is what decides
whether timestamps end in `Z` or in a numeric offset. Keeping the whole box on
UTC means one timestamp format in the logs. ShadowPot's loader handles both
(`docs/LOG_FORMAT.md` §3), but there is no reason to create the problem.

Set a hostname that is not your name:

```bash
sudo hostnamectl set-hostname web-01
```

---

## 4. Move the real sshd first

**This is the step that locks people out. Read all of it before typing any of
it.**

Your real SSH server is on port 22. Cowrie needs port 22. So the real one
moves to a high port, and only then does Cowrie take 22.

**Open a second terminal and SSH into the box now, and leave that session
open for the whole of this section.** If you break the configuration, that
already-authenticated session is how you fix it. Without it, your only option
is the provider's web console.

Write a drop-in rather than editing `sshd_config`, because Debian 12's
`sshd_config` has `Include /etc/ssh/sshd_config.d/*.conf` at the top and the
*first* value for a keyword wins:

```bash
sudo tee /etc/ssh/sshd_config.d/99-shadowpot.conf >/dev/null <<'EOF'
# The real administrative SSH server. Cowrie gets port 22.
Port 61022
# Keys only. A password-authenticated real sshd on a box that advertises
# itself as an SSH target is the one genuinely dangerous mistake here.
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
PermitEmptyPasswords no
# Nothing on this box should be forwarding anything anywhere.
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
MaxAuthTries 3
EOF
```

Check the syntax before restarting. This catches typos while you are still
logged in:

```bash
sudo sshd -t && echo "config OK"
```

**Check whether your system uses socket activation.** On systems where `ssh`
is started by `ssh.socket`, the `Port` directive in `sshd_config` is *ignored*
and the listening port comes from the socket unit instead. Debian 12 normally
uses `ssh.service`, but verify:

```bash
systemctl is-enabled ssh.socket 2>/dev/null || echo "not socket-activated: Port directive applies"
```

If it reports `enabled`, set the port on the socket instead:

```bash
sudo systemctl edit ssh.socket
```

and add:

```ini
[Socket]
ListenStream=
ListenStream=61022
```

Now restart and verify:

```bash
sudo systemctl restart ssh && sudo ss -ltnp | grep -E 'sshd|:61022'
```

**From a third terminal on your laptop, confirm the new port works before you
close anything:**

```bash
ssh -i ~/.ssh/shadowpot_admin -p 61022 youruser@YOUR_BOX_IP 'echo reachable'
```

Only once that prints `reachable` should you let the old session go. Add the
host to `~/.ssh/config` so you stop typing flags:

```
Host shadowpot
    HostName YOUR_BOX_IP
    User youruser
    Port 61022
    IdentityFile ~/.ssh/shadowpot_admin
    IdentitiesOnly yes
```

---

## 5. Firewall, inbound and outbound

Debian 12 uses nftables. This ruleset does three things: lets the world reach
the honeypot, lets you reach the admin port, and **stops the box being used to
attack anyone else** — which is both the ethical minimum and what most
providers' acceptable-use policies require.

Note the ordering, because getting it wrong silently drops all your attacker
traffic: the `nat` `prerouting` hook rewrites port 22 to 2222 **before** the
filter `input` hook sees the packet. So `input` must accept **2222**, not 22.

```bash
sudo tee /etc/nftables.conf >/dev/null <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        iif lo accept
        ct state established,related accept
        ct state invalid drop

        # Cowrie. Port 22 arrives here already rewritten to 2222 by the
        # nat prerouting rule below, so this is the rule that matters.
        tcp dport 2222 accept

        # Administrative sshd, moved in section 4.
        tcp dport 61022 accept

        icmp type echo-request limit rate 5/second accept
        icmpv6 type { nd-neighbor-solicit, nd-router-solicit,
                      nd-neighbor-advert, nd-router-advert } accept
    }

    chain forward {
        # This box routes for nobody.
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy drop;

        oif lo accept
        ct state established,related accept

        # DNS and time.
        udp dport 53 accept
        tcp dport 53 accept
        udp dport 123 accept

        # Package updates, AND payload capture: when an attacker runs
        # `wget http://x/y`, Cowrie really fetches it to store the sample.
        # Remove these two ports and you capture no malware; keep them and
        # your IP appears in logs fetching attacker-chosen URLs. Section 1
        # explains the trade. Rate-limited so the box cannot be turned into
        # a flooding source.
        tcp dport { 80, 443 } ct state new limit rate 20/second accept

        # Deliberately NOT accepted outbound, and this is the point of the
        # whole chain: 22 and 23 (so the box cannot brute force other SSH or
        # telnet hosts), 25 and 587 (so it cannot send spam), 445 and 3389
        # (so it cannot spread), and everything else by default policy.
    }
}

# REDIRECT lives in a family-specific nat table. IPv4:
table ip nat {
    chain prerouting {
        type nat hook prerouting priority -100;
        tcp dport 22 redirect to :2222
    }
}

# IPv6, if your provider gave you an address. Harmless if it did not.
table ip6 nat {
    chain prerouting {
        type nat hook prerouting priority -100;
        tcp dport 22 redirect to :2222
    }
}
EOF
```

Apply it, again **with your existing session still open**:

```bash
sudo nft -c -f /etc/nftables.conf && echo "ruleset parses"
```

```bash
sudo systemctl enable --now nftables && sudo nft list ruleset | head -40
```

Confirm from your laptop, in a new terminal, that you are not locked out:

```bash
ssh shadowpot 'echo still reachable'
```

If you *are* locked out: the provider's web console gives you a root shell
that does not go through SSH. `nft flush ruleset` there, then fix the file.

Also turn on the provider's own firewall if it has one, with the same two
inbound ports. Two layers cost nothing.

---

## 6. Install Cowrie

As a dedicated unprivileged user. **Cowrie refuses to start as root.**

System dependencies, from Cowrie's own install guide:

```bash
sudo apt-get install -y python3-pip python3-venv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal
```

Create the user. `--disabled-password` means there is no password to brute
force, and no way to log in as `cowrie` except via `sudo su`:

```bash
sudo adduser --disabled-password --gecos "" cowrie
```

Install into a self-contained directory. **The directory you run `cowrie` from
is the state directory** — logs, downloads, host keys and the PID file are all
relative to it — so pick it deliberately and always `cd` there first:

```bash
sudo -u cowrie -H bash -lc '
  mkdir -p ~/honeypot && cd ~/honeypot &&
  python3 -m venv cowrie-env &&
  source cowrie-env/bin/activate &&
  python -m pip install --upgrade pip &&
  python -m pip install cowrie &&
  cowrie --version
'
```

Initialize the state directory. This writes `etc/cowrie.cfg` from the bundled
template and creates `var/log/cowrie`, `var/lib/cowrie`,
`var/lib/cowrie/downloads`, `var/lib/cowrie/tty` and `var/run`:

```bash
sudo -u cowrie -H bash -lc '
  cd ~/honeypot && source cowrie-env/bin/activate && cowrie init
'
```

`cowrie init` is **not idempotent** — it refuses with a non-zero exit if
`etc/cowrie.cfg` already exists, rather than overwriting your edits. That is
deliberate on Cowrie's part and is a feature, not a problem.

---

## 7. Configure Cowrie

The defaults are already close to what ShadowPot wants: the bundled
`cowrie.cfg.dist` sets `log_path = var/log/cowrie`,
`logtype = rotating`, `[output_jsonlog] enabled = true` and
`logfile = ${honeypot:log_path}/cowrie.json`. That produces exactly the file
layout the loader expects: `cowrie.json` for today and
`cowrie.json.YYYY-MM-DD` for each earlier day.

Set the handful of keys that matter anyway, because a deployment guide that
depends on a default you did not write down will break when the default
changes:

```bash
sudo -u cowrie tee /home/cowrie/honeypot/etc/cowrie.cfg >/dev/null <<'EOF'
[honeypot]
# What attackers see at the prompt. Something boring and plausible.
hostname = web-01

# UTC, so timestamps are the ...Z form. This value becomes the process's TZ.
timezone = UTC

# Daily rotation: cowrie.json becomes cowrie.json.YYYY-MM-DD at midnight.
# ShadowPot's loader handles both this layout and externally gzipped files.
logtype = rotating

# Cap what a single fetch and a single session recording can cost you in
# disk. Both are commented out in the shipped template, which means
# unlimited. On a box with 20 GB that is a real way to fill the disk.
download_limit_size = 10485760
ttylog_limit_size = 10485760

[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json

# The plain-text log is for you to read while debugging, not for the loader.
[output_textlog]
enabled = false

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0

# The banner Cowrie presents. Keep it consistent with the hostname and the
# emulated OS; an attacker comparing a Debian banner against a RHEL
# /etc/issue is one of the ways a honeypot gets spotted.
version = SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3

# Refuse to proxy anything. Left false by default; stated here because this
# is the single setting that could turn your honeypot into someone else's
# attack relay.
forward_redirect = false
forward_tunnel = false

[telnet]
# Leave off for a first deployment. One protocol at a time, and ShadowPot's
# analytics are written around SSH.
enabled = false
EOF
```

### Which credentials to accept

`etc/userdb.txt` decides what gets in. Rules are read top to bottom and the
first match wins. The default file accepts a lot; narrow it so that one
credential succeeds and you can see what attackers do *after* getting in:

```bash
sudo -u cowrie tee /home/cowrie/honeypot/etc/userdb.txt >/dev/null <<'EOF'
# username:uid:password   -- '*' matches anything, '!' denies.
# First match wins, read top to bottom.

# Deny the one password a real sysadmin might actually have set, so that a
# lucky guess never looks like a real finding.
root:x:!honeypot-should-never-accept-this

# Accept exactly one weak credential. This is the staged credential your
# report will name, and the reason the report says a success is not a
# compromise.
root:x:123456

# Everything else fails.
*:x:!*
EOF
```

There is an alternative worth knowing about: `[honeypot] auth_class =
AuthRandom` lets a login succeed after a random number of attempts, which
looks more like a real misconfigured box. It also makes "which credential
worked" meaningless. Use `UserDB` for a first deployment.

### Start it

```bash
sudo -u cowrie -H bash -lc '
  cd ~/honeypot && source cowrie-env/bin/activate && cowrie start
'
```

```bash
sudo -u cowrie -H bash -lc 'cd ~/honeypot && tail -20 var/log/cowrie/cowrie.log'
```

If you see `ERROR: cowrie is not initialized`, you are in the wrong directory.
`cowrie start`, `cowrie stop` and `cowrie status` must all be run from the
state directory.

### Survive a reboot

```bash
sudo apt-get install -y supervisor
```

```bash
sudo tee /etc/supervisor/conf.d/cowrie.conf >/dev/null <<'EOF'
[program:cowrie]
command=/home/cowrie/honeypot/cowrie-env/bin/cowrie start -n
directory=/home/cowrie/honeypot
user=cowrie
autostart=true
autorestart=true
redirect_stderr=true
EOF
```

```bash
sudo supervisorctl reread && sudo supervisorctl update && sudo supervisorctl status cowrie
```

`directory=` must be the state directory. This is the same "runs in the
current working directory" rule as everywhere else.

---

## 8. Verify, from somewhere else

**The port-22 redirect does not apply to loopback**, so testing from the box
itself proves nothing. Test from your laptop:

```bash
ssh -o StrictHostKeyChecking=no -p 22 root@YOUR_BOX_IP
```

You should get a password prompt. Enter `123456`, land in a fake shell, and
try a few commands:

```
uname -a
cat /proc/cpuinfo
wget http://example.invalid/test.sh
exit
```

Then confirm the events were written in the shape the loader expects:

```bash
ssh shadowpot 'sudo -u cowrie tail -3 /home/cowrie/honeypot/var/log/cowrie/cowrie.json'
```

Every line should be one JSON object with `eventid`, `timestamp`, `session`
and `src_ip`. If `cowrie.json` does not exist, check
`[output_jsonlog] enabled` and the `log_path` above.

Also confirm port 2222 is reachable directly and 61022 is still yours:

```bash
nc -zv YOUR_BOX_IP 22 2222 61022
```

### Snapshot now

Take a provider snapshot while the box is clean and working. It costs very
little and it is how you recover from a configuration mistake on day 4
without redoing this whole document.

---

## 9. Getting the logs off the box

**Your laptop pulls. The honeypot never pushes.**

This is the most important design decision in Part B. If the honeypot held an
SSH key for your laptop, then compromising the honeypot would give an attacker
a path to your machine. Pulling inverts that: the private key lives on your
laptop, the honeypot holds only a public key, and the honeypot has no
credential for anything of yours at all.

Make a second keypair, for reading logs only:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/shadowpot_logs -C "shadowpot log pull"
```

On the honeypot, let that key do exactly one thing. `restrict` disables
port forwarding, agent forwarding, X11 and PTY allocation; `command=` means
the key cannot run anything else even if someone steals it from your laptop:

```bash
sudo -u cowrie mkdir -p /home/cowrie/.ssh && sudo -u cowrie chmod 700 /home/cowrie/.ssh
```

```bash
sudo -u cowrie tee -a /home/cowrie/.ssh/authorized_keys >/dev/null <<'EOF'
restrict,command="/usr/bin/rrsync -ro /home/cowrie/honeypot/var/log/cowrie" ssh-ed25519 AAAA...PASTE_shadowpot_logs.pub... shadowpot log pull
EOF
```

```bash
sudo -u cowrie chmod 600 /home/cowrie/.ssh/authorized_keys && ls -l /usr/bin/rrsync || sudo apt-get install -y rsync
```

`rrsync` ships with rsync on Debian (sometimes as
`/usr/share/doc/rsync/scripts/rrsync`; if `/usr/bin/rrsync` is missing, copy
it there and `chmod +x`). `-ro` makes it read-only, so even a stolen key
cannot write to the honeypot.

Add it to your laptop's `~/.ssh/config`:

```
Host shadowpot-logs
    HostName YOUR_BOX_IP
    User cowrie
    Port 61022
    IdentityFile ~/.ssh/shadowpot_logs
    IdentitiesOnly yes
```

Pull:

```bash
rsync -av --info=progress2 shadowpot-logs:./ ~/shadowpot-real-logs/
```

The trailing `./` is relative to the directory `rrsync` was pinned to, so this
copies `cowrie.json`, every `cowrie.json.YYYY-MM-DD`, and nothing else.

### Load and report, on your laptop

```bash
cd /path/to/shadowpot && make load LOGS=~/shadowpot-real-logs DB=data/real.db
```

```bash
make report DB=data/real.db OUT=reports/real-report.md
```

The report will have **no** `SYNTHETIC SAMPLE DATA` banner, which is how you
know these numbers are real. If the banner appears, you have loaded generated
logs into the same database — start again with a fresh `--db` path, because a
mixed database makes every aggregate unusable.

### Daily cron, on your laptop

The cron runs on the analysis machine, not the honeypot. The loader is
incremental and idempotent, so running it every day reads only new bytes and
never duplicates a row:

```bash
crontab -e
```

```cron
# ShadowPot: pull honeypot logs and reload, every day at 06:30 local time.
30 6 * * * cd $HOME/code/shadowpot && rsync -a shadowpot-logs:./ $HOME/shadowpot-real-logs/ >> /tmp/shadowpot-pull.log 2>&1 && make load LOGS=$HOME/shadowpot-real-logs DB=data/real.db >> /tmp/shadowpot-pull.log 2>&1 && make report DB=data/real.db OUT=reports/real-report.md >> /tmp/shadowpot-pull.log 2>&1
```

Check that it is working after the first run:

```bash
sqlite3 data/real.db 'SELECT run_id, lines_read, lines_applied FROM ingest_runs ORDER BY run_id DESC LIMIT 5;'
```

A run with `lines_read = 0` is correct and expected when the honeypot had no
new traffic.

---

## 10. The 7-day checklist

Seven days is the minimum for the numbers to mean anything: fewer and you
cannot distinguish a returning attacker from a one-off scan, and
`repeat_offenders` and `sessions_per_day` are both empty or meaningless.

Each day, pull and reload, then spend five minutes on one question.

| Day | Do this | The question to answer |
|---|---|---|
| 1 | `make load` + `make report`. Check `ingest_quality`. | Is anything arriving at all, and is any line being dropped? A malformed-line count above zero on day 1 means the format assumptions need checking. |
| 2 | Look at `attempts_per_source`. | Is this a few busy hosts or a long tail of one-shot addresses? |
| 3 | Look at `top_credential_pairs` and `shared_credentials`. | Which dictionary is being used, and is it shared across addresses? |
| 4 | Look at `first_commands` and `top_commands`. | Did anybody get past login, and what did they do in the first second? |
| 5 | Look at `downloads_and_fetchers`. | Did anything get fetched? Record the hashes; do **not** run the samples. |
| 6 | Look at `repeat_offenders` and `sessions_per_hour`. | Who came back? Is the traffic flat across the clock, as software is? |
| 7 | Full `make report`, then fill in the table below. | What can I honestly claim from this? |

Also, every day: `df -h` on the box. `ttylog` and `downloads` grow, and the
limits set in section 7 bound each file but not the total.

```bash
ssh shadowpot 'df -h / && sudo du -sh /home/cowrie/honeypot/var/*'
```

### Recording template

Fill this in from `reports/real-report.md`. **Every number must come from the
report, not from memory**, and anything you did not measure stays as
"not measured".

```markdown
## ShadowPot real deployment

| | |
|---|---|
| Provider / region       |                    |
| Cowrie version          |                    |
| Deployed from (UTC)     |                    |
| Deployed to (UTC)       |                    |
| Days deployed           |                    |
| Total sessions          |                    |
| Unique source IPs       |                    |
| Total login attempts    |                    |
| Successful logins       |                    |
| Sessions reaching a shell |                  |
| Distinct commands seen  |                    |
| Files captured (by hash)|                    |
| Lines dropped as malformed |                 |

Top 3 credential pairs:

| # | username | password | attempts | distinct IPs |
|---|---|---|---:|---:|
| 1 |  |  |  |  |
| 2 |  |  |  |  |
| 3 |  |  |  |  |

Top 3 source addresses:

| # | IP | sessions | attempts | days active |
|---|---|---:|---:|---:|
| 1 |  |  |  |  |
| 2 |  |  |  |  |
| 3 |  |  |  |  |

Not measured: geolocation, ASN, attacker identity, whether any sample was
functional.
```

Come back to this repository with that table and the real logs, and the README
results section and the resume bullets get filled in from it.

---

## 11. Tearing it down

Do this when you are finished. A honeypot you have stopped watching is just an
exposed box.

Get the logs off first — they are the only thing on the machine worth keeping:

```bash
rsync -av shadowpot-logs:./ ~/shadowpot-real-logs/ && ls -la ~/shadowpot-real-logs/
```

```bash
cd /path/to/shadowpot && make load LOGS=~/shadowpot-real-logs DB=data/real.db && make report DB=data/real.db OUT=reports/real-report.md
```

Then stop Cowrie and destroy the instance:

```bash
ssh shadowpot 'sudo supervisorctl stop cowrie; sudo nft flush ruleset'
```

- **Destroy the instance** from the provider console. Not "power off" —
  destroy, so the disk is released.
- **Delete the snapshots** too, or you keep paying for them and keep the data.
- **Delete the DNS record**, if you made one.
- **Remove both keys** from your laptop and from your `~/.ssh/config`:
  ```bash
  rm -f ~/.ssh/shadowpot_admin ~/.ssh/shadowpot_admin.pub ~/.ssh/shadowpot_logs ~/.ssh/shadowpot_logs.pub
  ```
- **Keep the logs.** They are the evidence behind every number you publish,
  and they are not reproducible.

### If the box is actually compromised

Cowrie does not execute anything, so this would mean a flaw in the real
`sshd`, in the kernel, or in Cowrie itself. If you suspect it: do not
investigate on the box, because anything it tells you is untrustworthy.
Snapshot it for later, pull the logs, destroy the instance, and rotate the two
keys. Nothing of value was on it, which is the entire reason section 0 insists
on that.

---

## 12. Privacy and ethics

**Attacker IP addresses are public data in the sense that they arrived
unsolicited at your host, but publish aggregates, not raw logs.** The top-N
tables this project produces are aggregates. The raw `cowrie.json` is not:
it is a per-connection record of a third party's activity, some of which will
be from compromised machines belonging to people who have no idea. ShadowPot's
`.gitignore` excludes `cowrie.json*` for this reason, and the report's tables
are top-N by construction.

**Never retaliate.** Do not scan, probe, connect back to, or "test" an
attacking address. It is illegal in most jurisdictions regardless of who
started it, the address is very often a compromised third party rather than
the attacker, and it converts you from the person being attacked into the
person attacking. This is also why ShadowPot makes **no** outbound lookups
against attacker addresses, not even passive ones: no GeoIP API, no reverse
DNS, no reputation services. Geolocation is supported only from an offline
database you supply yourself.

**Report abuse through the proper channel or not at all.** If you want an
address dealt with, the mechanism is its network's published abuse contact, or
a service like AbuseIPDB. Cowrie has an output plugin for that; it is disabled
by default and this guide leaves it disabled, because reporting is a decision
with consequences for whoever owns that machine and should be deliberate.

**Do not publish the captured samples.** Record hashes. Hashes are safe to
publish, identify the sample unambiguously to anyone with the file, and cannot
hurt anyone. Do not email the binary to yourself, do not put it in the
repository, and do not run it.

**Say what you measured.** Everything in this project is built around that:
the report names its heuristics as heuristics, states what it did not measure,
reports what it threw away, and refuses to call a honeypot login a compromise.
Carry that into how you talk about the project. "I ran a honeypot for 7 days
and recorded 4,812 login attempts from 193 addresses" is a strong, checkable
claim. "I detected and blocked attacks" is not, and an interviewer who knows
the area will ask the follow-up question.
