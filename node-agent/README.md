# Node Agent

This is the monitoring agent that runs on each remote server you want to monitor.

## Quick deploy

1. Copy `agent.php` to the remote server:

```bash
scp agent.php root@your-server:/var/www/html/agent.php
```

2. Edit the token on the remote server:

```bash
nano /var/www/html/agent.php
```

Change this line:
```php
define('AGENT_TOKEN', getenv('NODE_AGENT_TOKEN') ?: 'CHANGE-ME-TO-A-RANDOM-STRING');
```

To a secure random token, for example:
```php
define('AGENT_TOKEN', getenv('NODE_AGENT_TOKEN') ?: 'h7Kx9mPqR2vL5nWjY8');
```

Or set the `NODE_AGENT_TOKEN` environment variable in your web server config.

3. Test it works:

```bash
curl "http://your-server/agent.php?token=h7Kx9mPqR2vL5nWjY8"
```

You should get a JSON response with CPU, memory, disk, network metrics.

4. In the **Node Status admin panel**, add a new node:
   - **Name**: e.g. `NL-01 Amsterdam`
   - **Type**: `remote`
   - **Endpoint URL**: `http(s)://your-server/agent.php`
   - **API Token**: same token you set above (e.g. `h7Kx9mPqR2vL5nWjY8`)
   - **Country**: `NL` (ISO 3166-1 alpha-2 code, for the map)

## Requirements

- PHP 8.0+ with web server (Apache/Nginx)
- Linux with `/proc` filesystem
- The agent only reads system metrics — it does **not** need a database

## Security

- Always set a strong `AGENT_TOKEN` — without it, anyone can read your server metrics
- Consider restricting access via firewall to only your main status server IP
- The agent sends `X-Robots-Tag: noindex` to prevent search engine indexing

## Files

| File | Purpose |
|------|---------|
| `agent.php` | Single-file agent — the only file you need to deploy |

That's it. One file, no dependencies, no database.
