# WireGuard Runtime Configuration

NetGuard uses `lscr.io/linuxserver/wireguard` to generate WireGuard server and peer configuration at runtime. Generated keys and peer files are stored in the `wireguard-config` Docker volume, not in this repository.

Use environment variables in `.env` to control the generated subnet, server port, and peer count.
