# Scam Intel

Solana token risk scanner with live honeypot checks, authority analysis, liquidity intelligence, holder concentration, and append-only historical scans.

## Local development

```bash
bun install
bun run dev
```

## Environment variables

Set these locally and in Railway:

```text
VITE_SUPABASE_URL=your_database_url
VITE_SUPABASE_PUBLISHABLE_KEY=your_publishable_key
HELIUS_API_KEY=your_helius_api_key
```

Never commit a private API key. The included `.env` file is excluded from the downloadable archive.

## Railway deployment

1. Push this project to a GitHub repository.
2. Create a Railway project from that repository.
3. Add the environment variables above in Railway.
4. Deploy. `railway.toml` configures the build and production server.

## Production build

```bash
bun run build
bun run start
```