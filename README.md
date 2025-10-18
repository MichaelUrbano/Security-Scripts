# Security Scripts

These scripts are actively being worked on, if you would like to get the only one currently present in the repository:

`wget https://raw.githubusercontent.com/MichaelUrbano/Security-Scripts/refs/heads/main/Linux/linux-harden-comp.sh`

The following environment variables can be set, which can be set either in a file called .env at /root/.env, or by passing them directly into the script:
- `BAKDIR`: Will change the directory used for backups. Backups will be placed within a child directory (`b4`), located in your specified directory.