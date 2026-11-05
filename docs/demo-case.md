# Demo case: "account limited" PayPal impersonation

This is the documented demo case shipped with NardTrace (`POST /api/demo/seed`, or **Load demo case** in the UI).
It is built from a **synthetic** message (`backend/nardtrace/demo/demo_phish.eml`). Every address is fictitious,
and the recipient is `recipient@example.net`, which is masked in redacted exports.

> **First real case.** The suspicious email Brianna received is meant to be the first real documented case.
> Bring it in with **Cases → New case**, upload the original `.eml`, and add your name or address to the case's
> *redaction terms*. Any public copy of the report should use the **Redacted** export. Never commit the real `.eml`.
> The `.gitignore` excludes `data/` and `cases/`.

## What the message does

- **From:** `"PayPal Billing Department" <billing.dept.notice.demo@gmail.com>`, a free Gmail mailbox using a brand display name.
- **Reply-To:** `paypal.resolution.center.demo@outlook.com`, a *different* free provider, so replies go to a mailbox the scammer controls.
- **Link:** text says `https://www.paypal.com/signin`, but the link goes through a Google redirect to `secure-paypa1-review.top` (the "l" in "paypal" is the digit 1).
- **Attachment:** `Account_Statement.pdf` is actually an HTML document.

## What NardTrace concludes, and how each conclusion is known

| Finding | Tag | Why |
|---|---|---|
| Route: 3 hops; hand-off from `mail-sor-f41.google.com [209.85.220.41]` into `mx.google.com` | CONFIRMED | Read from Received headers |
| SPF, DKIM and DMARC all **pass** for `gmail.com` | CONFIRMED | Authentication-Results from the receiving server |
| …which does **not** make the mail legitimate | (not-established) | Anyone can send authenticated mail from their own Gmail account |
| No originating-client IP headers | CONFIRMED | Gmail strips the sender's device IP. The sender's own IP is not in the message |
| From ≠ Reply-To domain (free mail) | CONFIRMED, high | Header comparison |
| Display-name spoofing (brand name on a personal mailbox) | ASSUMPTION, high | Heuristic |
| Link text ≠ link destination | CONFIRMED, high | HTML anchor vs href |
| `secure-paypa1-review.top` resembles `paypal.com` | ASSUMPTION, high | Homoglyph / string comparison |
| Attachment named `.pdf` is HTML | CONFIRMED | Magic bytes |
| Sending provider is Google (Gmail) | ASSUMPTION | Hand-off hostname, DKIM domain, `X-Gm-Message-State` / `X-Google-Smtp-Source` |
| Network owner / abuse contact for 209.85.220.41 | EXTERNAL INTEL (or UNKNOWN offline) | RDAP lookup |

## Where it should be reported

1. **Google**, which hosts the sending account: the Gmail abuse form (https://support.google.com/mail/contact/abuse), quoting the From address and Message-ID.
2. **Microsoft**, which hosts the Reply-To mailbox: phish@office365.microsoft.com.
3. **The registrar** of `secure-paypa1-review.top`, at the abuse contact from Domain Intelligence.
4. **PayPal** (the impersonated brand), through its own phishing-report channel.
5. reportfraud.ftc.gov, and ic3.gov if money or credentials were lost.

## What this case does **not** establish

Who the sender is or where they are. The only IP in the route belongs to Google's outbound mail
infrastructure. It identifies Google, not a person. Only Google can link the account to its user, and normally
only under legal process.
