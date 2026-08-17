# NetGuard demo — VHS tape (https://github.com/charmbracelet/vhs)
#
# Renders the whole story into docs/demo.gif + docs/demo.mp4:
#   1. the stack is up (Suricata sharing the target's netns)
#   2. the four original rules were self-referential -> quarantined, excluded
#   3. one command launches a labeled attack catalogue and SCORES it -> 9/10
#   4. a dead capture can't fake the score -> the self-test proves it
#
# Render it (best from Linux or WSL, where python3 + Docker "just work"):
#   vhs docs/demo.tape
#
# Everything below runs REAL commands against the real stack. The only setup
# hidden from the recording is bringing the lab up (Hide/Show), so the film
# starts on a ready prompt. For a shorter cut, swap SCENARIO=all for a subset
# (see the commented line) — though only the full run reaches 9/10.

Output docs/demo.gif
Output docs/demo.mp4

Require docker

Set Shell "bash"
Set FontSize 18
Set Width 1240
Set Height 760
Set Padding 26
Set TypingSpeed 42ms
Set PlaybackSpeed 1.0

# Palette matched to the published scorecard: slate ground, teal signal accent,
# green = detected, amber = the documented miss.
Set Theme { "name": "netguard", "background": "#0a111b", "foreground": "#e7eef7", "cursor": "#2dd4bf", "selection": "#22303f", "black": "#0a111b", "red": "#e5534b", "green": "#3fb950", "yellow": "#e3b341", "blue": "#4c8fd4", "magenta": "#a371f7", "cyan": "#2dd4bf", "white": "#c9d4e0", "brightBlack": "#63748c", "brightRed": "#f0645c", "brightGreen": "#56d364", "brightYellow": "#f0c674", "brightBlue": "#6ba7e0", "brightMagenta": "#bd8bff", "brightCyan": "#5eead4", "brightWhite": "#ffffff" }

# ── setup (hidden): bring the lab up, wait for a live capture, clear ──
Hide
Type "docker compose up -d --build --wait --wait-timeout 120 suricata traffic-generator && echo NETGUARD_$(printf STACK_READY) || exit 1" Enter
Wait+Screen@150s /NETGUARD_STACK_READY/
Type "clear" Enter
Sleep 1s
Show

# ── title ──
Type "#  NetGuard: a network IDS lab whose detection is MEASURED, not asserted." Enter
Sleep 2s

# ── act 1: the stack is up ──
Type "#  Suricata runs inside the monitored app's netns and captures its traffic." Enter
Sleep 1s
Type "docker compose ps" Enter
Sleep 3.5s

# ── act 2: the self-referential rules, quarantined ──
Type "#  The 4 original rules matched the lab's OWN traffic. Quarantined in" Enter
Type "#  demo.rules and EXCLUDED from the score; they prove liveness, not detection:" Enter
Sleep 1s
Type "grep -n 'sid:' services/suricata/rules/demo.rules" Enter
Sleep 4s

# ── act 3: measure real detection ──
Type "#  Real detection is measured: launch a labeled attack catalogue," Enter
Type "#  join the alerts Suricata actually produced, and score it." Enter
Sleep 1.5s
Type "SCENARIO=all ./scripts/run-catalogue.sh && echo NETGUARD_$(printf BASELINE_PASS) || exit 1" Enter
# Uncomment for a faster cut (does not reach 9/10):
# Type "SCENARIO=A01,A04,A07,A09,A10 ./scripts/run-catalogue.sh" Enter
# The full local catalogue consistently finishes in about 60-75 seconds. VHS's
# ttyd screen scraper can stop refreshing during this long, busy command, so a
# measured capture window is more reliable than a regex wait here. The command
# still emits an unmistakable marker only after the baseline gate passes.
Sleep 85s
Sleep 4s

Type "#  9/10, precision 1.0, ZERO false positives, MTTD ~0.01s." Enter
Type "#  A08 is a documented miss; its DNS never reaches the monitored netns." Enter
Sleep 3s

# ── act 4: the honesty guarantee ──
Type "#  A dead capture can't fake a passing score. The scorer proves it:" Enter
Sleep 1s
Type `docker run --rm -v "$PWD":/w -w /w python:3.12-alpine python -m unittest -q tests.test_scorer 2>&1 && echo NETGUARD_TESTS_PASS || exit 1` Enter
# This command takes about three seconds after the image is cached. A fixed
# pause avoids a ttyd screen-scrape edge case after the catalogue's long output.
Sleep 10s
Type "#  ...and CI fails any change that drops recall or raises false positives." Enter
Sleep 2.5s

# ── outro ──
Type "clear" Enter
Sleep 0.5s
Type "#  clone -> run -> read the score in ~10 minutes." Enter
Type "#  ET-Open/suricata-7.0.7 | 52,328 rules | pinned & regression-gated." Enter
Type "#  github.com/nemuel-nuhyel/netguard" Enter
Sleep 4s
