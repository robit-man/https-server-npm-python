# HTTPS Server - Automatic deployment and cert issuance

```bash
python3 app.py
```


    It will find your Fastify / Node app folder (wherever you cloned it).

    Create a virtualenv & install cryptography just once.

    Generate cert.pem/key.pem up front.

    Escalate to root (binding port 443) without re-installing.

    Spin up your Fastify/WebSocket server over HTTPS via npm install && npm run start.

