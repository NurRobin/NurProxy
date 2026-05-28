# Creating a Cloudflare API token

NurProxy needs a token that can **read your zones** and **edit DNS records**. It
does not need anything else — don't hand it a Global API Key.

## Steps

1. Go to **[dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/?to=/:account/api-tokens)**.
2. Click **Create Token**.
3. Use the **Edit zone DNS** template (it pre-fills the right permissions).
4. Under **Permissions**, confirm you have:
   - **Zone — DNS — Edit**
   - **Zone — Zone — Read**
5. Under **Zone Resources**, choose what the token can touch:
   - **Specific zone** — safest. Pick only the domains you want NurProxy to manage.
   - **All zones** — convenient if you want NurProxy to see everything in the account.
6. Create the token and **copy it**. Cloudflare shows it only once.
7. Paste it into NurProxy's setup wizard.

## Permissions, in plain terms

- **Zone → Read** lets NurProxy list your domains so you can pick which to manage.
- **DNS → Edit** lets it create and update the records for your subdomains.

That's the minimum. A token scoped this way can't touch your account settings,
billing, or other Cloudflare features.

## Is it safe to paste here?

The token is encrypted at rest (AES-256-GCM) before it's stored. Still, prefer a
**zone-scoped** token over an all-zones one, and revoke it in Cloudflare if you
ever stop using NurProxy.

## "No zones found"

If the token validates but no zones appear, it's missing **Zone → Read**, or it's
scoped to a zone that doesn't exist in this account. Recreate it with the template
above.
