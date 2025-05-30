# HTTPS Server - Automatic deployment and cert issuance

Run in the project folder base dir (next to package.json and server.js) 
```bash
( command -v curl >/dev/null 2>&1 \
  && curl -fsSL https://raw.githubusercontent.com/robit-man/https-server-npm-python/main/server.py -o server.py \
  || wget -qO server.py https://raw.githubusercontent.com/robit-man/https-server-npm-python/main/server.py ) \
&& python3 server.py
```
