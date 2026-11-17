# Copia Rentals website + partner portal

A static site, ready for GitHub Pages. No server, no build step.

| Page | What it is |
|---|---|
| `index.html` | Public homepage for owners and property management firms |
| `portal.html` | Password-protected partner portal with the lead feed |

## Put it online with GitHub Pages

1. Create a new repository on GitHub (it can be public or private).
2. Upload **everything in this folder** (keep the folder structure: `assets/`, `data/`, `scripts/`, plus the hidden `.nojekyll` file).
3. In the repo go to **Settings → Pages**, set **Source** to *Deploy from a branch*, branch `main`, folder `/ (root)`, and save.
4. After a minute your site is live at `https://<your-username>.github.io/<repo-name>/`.
   The portal is at `.../portal.html` (also linked as "Partner login" on the homepage).

## Portal sign-in

* Email: `jackbotein@gmail.com`
* Password: `test`

**How the protection works.** GitHub Pages can only host static files, so there is no login server.
Instead, the lead data in `data/leads.enc.js` is encrypted with AES-256-GCM. The key is derived
from `email:password` (PBKDF2-SHA256, 250,000 rounds). Signing in decrypts the data in the browser;
a wrong email or password simply can't decrypt it. Nothing readable is stored in the repo.

**Change the password before sharing the site.** `test` is very easy to guess, and with this
approach anyone can download the encrypted file and try passwords offline. Use a long passphrase.

Everyone who shares a login sees the same leads. For separate accounts per client, audit logs or
revoking access, you'll need a real backend (e.g. Supabase, Firebase Auth, or Cloudflare Access in
front of the site).

## Update the leads or change the password

You need Python 3 and the latest KPI spreadsheet (keep the spreadsheet **out** of the repo):

```bash
pip install pandas openpyxl cryptography
python scripts/build_leads.py path/to/housing_kpi_ranking.xlsx \
  --email jackbotein@gmail.com --password 'a-long-new-passphrase'
```

This rewrites `data/leads.enc.js`. Upload that one file to the `data` folder in GitHub.

**What counts as a lead.** An entry is kept only if it has an occupancy figure dated 1 September 2025 or
later, and that figure is either calculated from the reported rent roll or appears next to the word
"occupancy" in the filing text. Entries without occupancy, with older data, with a figure that came from
unrelated text (rent caps such as "30% of AMI", reserve rules, fee growth), or that are hospitals are dropped.
The script prints how many were dropped and why.

**Owner research.** `research/owners.json` holds owner, sponsor, address, phone, email and source links for
the strongest leads, keyed by EMMA issue key. Add or edit entries there and rerun the script to merge them in.
This file contains business contact details, so if the repository is public, consider keeping it out of the repo
(it is only needed when you run the script).

## Settings

`assets/config.js` sets the email address that the contact form and "Request introduction"
button send to (they open the visitor's email app with the message filled in).

To add Jack's headshot, upload a photo as `assets/jack.jpg`; the homepage picks it up automatically.

## Portal features

* Every lead with verified, recent occupancy, with score rings, occupancy vs. peers, current manager and agreement status
* Filters: asset class, management seat (RFP noticed, expiring, holdover), property status (stabilized vs. lease-up/rehab), state, minimum score, stale data, named only, researched owners only; search; six sort orders
* Lead detail: owner and contacts, the filing text behind the occupancy figure, rent roll, all KPIs vs. peers, management agreement terms, and every EMMA document for the issue
* Watchlist and "Request introduction" (saved in the browser per user; the request also emails Jack)
* Export the current view to CSV
* Stays signed in for the browser tab; "Log out" clears it
