# Harbor Collective

A private, multi-user web app for a small trading group. Each person creates
their own account and logs their own records — every member sees only their
own data, never anyone else's. The first account created becomes the admin.

## What it tracks

### 10-Day Investments
- Add a principal, start date (Day 1), payment method, and return method.
- The app computes the Day 10 due date automatically (start date + 9 days,
  due by 11:59pm).
- Enter the ending value and the app computes the split:
  - Ending value **above** principal: manager keeps **20% of the net profit**,
    investor receives **principal + 80% of the net profit**.
  - Ending value **at or below** principal: **no fee**, investor receives the
    **full principal back** (money-back).
- Statuses: active, due (past the due date and not marked paid), paid.
- A notes field on each deal for updates and proof notes.

### Partner Contributions
- Add a contribution amount, date, and method.
- Your share % = your total contributions ÷ total contributions of all
  partners.
- The admin sets the pooled ending account value, and payouts follow the
  contract:
  - Pool **gained**: manager keeps **20% of the net profit**, partners split
    the remainder by share %.
  - Pool **lost or flat**: **no fee**, each partner receives their share % of
    the ending value (losses shared proportionally).
- You see only your own contributions and payout — never other members'
  amounts.

### Admin overview and user management
The admin (first account) sees all users, all deals, totals, and manager-fee
totals, and is the only person who can set the pooled ending account value.
The admin cannot edit another user's records.

**Users list.** The admin overview lists every user — name, email, signup
date, counts of their 10-day deals and partner contributions, and their fund
totals (deal principal, deal payouts due back, contributions, partner
payout). No user is hidden from this list.

**Fund tracking.** All totals are computed from the stored records, never
typed in by hand:
- 10-Day program: total principal in, total manager fees, total due back to
  investors (all deals with an ending value set), total paid (deals marked
  paid), and still owed (due back minus paid).
- Partner pool: total contributions, pooled ending value (when set), total
  manager fee, and total partner payouts — plus the per-user breakdown in
  the users list.

**Removing a user.** The admin can remove a non-admin user from the users
list. Removal asks for confirmation first (a confirm page — never a
one-click link) and permanently deletes that user's deals and contributions
too. Safeguards: an admin can never remove their own account, and admin
accounts can never be removed at all, so the app can never be left without
an admin.

## How to run locally

Requirements: Node.js 18 or newer. No packages to install, no build step.

```bash
node server.js
```

Then open http://localhost:3000 in a browser.

- To use a different port: `PORT=8080 node server.js`
- To keep session signatures stable across restarts, set a secret:
  `HARBOR_SECRET=some-long-random-value node server.js`
  (Sessions still live in memory and are invalidated on restart.)

## How to create the admin

1. Start the server and open the site.
2. Click **Create account** and sign up. The very first account created
   automatically becomes the admin — no separate setup step.
3. Everyone else signs up normally and gets a regular member account.

## Pages

| Page | What it does |
| --- | --- |
| `/` | Public landing page with the two programs and a risk note |
| `/signup`, `/login` | Create an account, log in |
| `/dashboard` | Your totals: deals, principal, contributions, share %, payouts |
| `/deals` | Add and manage your 10-day deals (ending value, paid, notes, delete) |
| `/partners` | Add and manage your contributions (notes, delete) |
| `/admin` | Admin only: all users, all deals, totals, manager fees, pooled value |
| `/admin/users/:id/remove` | Admin only: confirm page, then remove a user and all their records |

## Security notes

- Passwords are hashed with `crypto.scrypt` plus a per-user salt. Plain
  passwords are never stored or logged.
- Sessions use signed, `httpOnly` cookies (`SameSite=Lax`). Every record
  carries a `userId`, and every read and write is filtered by the logged-in
  user on the server — requesting another user's record returns 403.
- Authenticated forms carry a per-session CSRF token.

## Hosting notes

This app needs a host that runs Node.js. For real use:

1. **Use HTTPS.** Put the app behind HTTPS (a reverse proxy such as Nginx
   or Caddy, or a platform that terminates TLS). The session cookie is
   marked `Secure` automatically when the connection itself is encrypted.
2. **Set `HARBOR_SECRET`** to a long random value in the hosting environment.
3. **Back up `data.json`.** All records live in `data.json` in the project
   directory. That suits a small group; if the group grows, move the store
   to a real database (SQLite or Postgres) before traffic grows.
4. **Keep the server process running** with a process manager (e.g.
   `systemd`, `pm2`) so it restarts if it stops.
5. **Never expose `data.json` directly.** Serve only through this app
   (the app has no route that serves it).

## Data file

`data.json` is created automatically on first run and starts empty — no
demo users, no sample records. Deleting it resets the app to an empty state
(all accounts and records are gone, so back it up first if it has real data).

## Risk note

Trading involves risk, including possible loss. Under the partner program,
a partner can get back less than they put in. Nothing in this app is
financial advice, and no return is guaranteed by the market.
