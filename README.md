# flared

Python client for [`cloudflared`](https://github.com/cloudflare/cloudflared) quick tunnels and access proxies.

## Install

```bash
pip install flared
```

## Basic Usage

```python
from yarl import URL
from flared import QuickTunnel

tunnel = QuickTunnel(URL("http://localhost:8000"))
print(tunnel)
```
