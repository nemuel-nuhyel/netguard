FROM python:3.12-alpine

# nmap provides the A01/A02 scan payloads; everything else is stdlib Python.
# tini gives the one-shot process a real PID 1 so signals/exit codes are clean.
RUN apk add --no-cache nmap nmap-scripts tini

WORKDIR /app
COPY catalogue.py run_catalogue.py ./

# Runs root: nmap -sS needs raw sockets (grant CAP_NET_RAW in compose). This is
# an ephemeral, profile-gated, lab-only attack box — root here is intentional
# and its blast radius is one throwaway container on netguard-lab.

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "run_catalogue.py"]
