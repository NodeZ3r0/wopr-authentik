# Authentik

> SSO and identity management

**Replaces:** Okta, Auth0

## Quick Start

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Edit configuration
nano .env

# 3. Start the service
docker compose up -d
```

## SSO Configuration

**Type:** NONE



This is a core infrastructure module and does not require SSO.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DOMAIN` | Your domain | required |
| `TZ` | Timezone | UTC |

## Resources

- **RAM:** 1024MB recommended
- **Port:** 9000

## Files

- `docker-compose.yml` - Container configuration
- `caddy/Caddyfile` - Reverse proxy config
- `authentik/config.yaml` - SSO provider config
- `.env.example` - Environment template

## Part of WOPR Sovereign Suite

https://github.com/NodeZ3r0/wopr-installer
