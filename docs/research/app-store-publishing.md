# Publishing NardTrace to Google Play and the Apple App Store (US solo developer)

Research date: 2026-11-11. Primary sources only (Google, Apple, Capacitor, PWABuilder, Chrome, GitHub, Codemagic docs).
Claims that could not be confirmed on a primary page are marked **UNVERIFIED**. Quoted text is verbatim from the cited page.

## Executive summary

1. Costs: Google Play Console is a US$25 one-time fee [G1]; Apple Developer Program is US$99 per membership year [A1]. Both can be joined as an individual with no company, D-U-N-S number or legal entity [G5][A1][A4].
2. Google gate: a *personal* Play account created after 13 Nov 2023 must run a closed test with at least 12 testers opted in continuously for 14 days, then apply for production access (review "usually takes seven days or less") [G2]; it must also verify an Android 10+ physical device via the Play Console mobile app [G3].
3. Apple gate: enrolment needs an Apple Account with two-factor auth and your legal name (which becomes the public seller name) [A1]; App Review "typically" clears 50% of submissions in under 24 h and 90% in under 48 h [A6].
4. Build toolchain: Capacitor 8 wraps the existing Vite/React `dist` folder (`npx cap add android|ios`, `npx cap sync`) [C1]; iOS builds need macOS with Xcode 26+ [C2] or a cloud Mac (GitHub Actions `macos-latest`, Codemagic) [GH1][CM1].
5. Platform floors: new Play apps must target API 36 (Android 16) from 31 Aug 2026 [G4]; Capacitor 8 targets SDK 36 and supports API 24+ / iOS 15+ [C5][C3][C4]; uploads to App Store Connect must be built with Xcode 26 / iOS 26 SDK [A5].
6. Monetization rule: any paid download, in-app unlock or subscription must go through Google Play Billing [G6] and Apple In-App Purchase [A7]. Ads (AdMob) and a free app are the only routes that avoid store billing.
7. Fees: Google (US, after 30 Jun 2026): 10% + 5% billing fee on the first US$1M/yr, then 20% + 5% [G7][G8]; Apple Small Business Program: 15% up to US$1M proceeds/yr, otherwise 30% [A8].
8. Payout paperwork: Google payments profile + bank verification (deposit challenge, up to 5 days) [G5]; Apple Paid Apps Agreement + W-9 (SSN or EIN) + one bank account [A9][A10]; Apple pays within 45 days of month end [A11], Google on the 15th for the prior month [G19].
9. Listing paperwork (both stores): public privacy-policy URL even if no data is collected [G9][G10], Google Data safety form [G11], Apple App Privacy details [A12], content-rating questionnaire [G12][A13], icon 512 px (Play) / 1024 px (Apple), min 2 phone screenshots (Play) / 1 per required size (Apple) [G13][A14][A15].
10. Realistic timeline from zero: Android about 4-6 weeks (dominated by the 14-day closed test plus production-access review); iOS about 1-2 weeks after a Mac/cloud build pipeline exists. Budget ~US$124 in fees plus optional cloud build minutes.

## 1. Google Play Console developer account

- Registration: Google Account, age 18+, accept the Developer Distribution Agreement, "US$25 one-time registration fee" by credit/debit card (no prepaid cards) [G1].
- Account type: choose *personal* or *organization* at sign-up [G1]. Personal accounts need: developer name, legal name, legal address, contact email/phone, developer email; "Google will display your legal name, your country (as per your legal address), and developer email address on Google Play. If you decide to monetize on Google Play then Google will display your full address." [G5]
- Organization accounts additionally need a D-U-N-S number ("completely free", "can take up to 30 days"), organization website, and Google displays "legal name, legal address, developer email address, and developer phone number" [G5]. Organization registration is *mandatory* only for financial, health, VPN and government apps [G14]; NardTrace fits none, so personal is allowed.
- Identity verification: "you may be asked for a valid government ID and a credit card, both under your legal name" [G1]; legal name/address come from the linked Google payments profile [G5].
- Testing gate for personal accounts created after 13 Nov 2023: "must run a closed test for their app with a minimum of 12 testers who have been opted in continuously for at least 14 days", then "apply for production access" by answering questions about the test, the app and production readiness; "Review usually takes seven days or less" [G2]. Opt-outs reset the 14-day clock [G2].
- Device verification (personal accounts, since early 2024): scan a QR code with the Play Console mobile app on "any non-rooted physical Android mobile device that runs at least the Android 10 operating system" [G3].
- Separately, Android developer verification (identity + package-name registration for all certified Android devices) rolls out from 30 Sep 2026 in selected countries and "globally ... in 2027"; Play Console developers must register package names [G14][G15].

## 2. Apple Developer Program

- Fee: "The Apple Developer Program is 99 USD per membership year." [A1] Enrolment via the web or the Apple Developer app; the app bills it as an auto-renewing subscription [A4].
- Individual vs organization: an individual or sole proprietor needs "an Apple Account with two-factor authentication turned on and be the legal age of majority"; "Your name will be displayed as the seller name of your apps on the App Store." [A1] "If you're enrolling as an individual, you don't need a D-U-N-S Number." [A3] Organizations must be a legal entity (no DBAs), hold a D-U-N-S number, a domain email and a working website [A1]; D&B issues numbers free, "allow up to 5 business days" plus 2 days for Apple to receive it [A3].
- Enrolment timing: Apple gives no SLA; "If you haven't received a membership confirmation within 24 hours of your purchase, contact us." Individuals paying by card must use their own card or will be asked for photo ID [A4].
- Hardware/software: Capacitor says "To build iOS apps, you will need macOS" and "Capacitor 8 requires a minimum of Xcode 26.0" [C2]; Apple's current Xcode requires "macOS Tahoe 26.6 or later" [A16]; App Store Connect uploads "must be built with Xcode 26 or later using an SDK for iOS 26" (since 28 Apr 2026) and target iOS 13+ [A5].
- Cloud alternatives (no Mac owned): GitHub-hosted `macos-latest` / `macos-26` / `xcode-27` runners exist; standard runners are "free and unlimited on public repositories", otherwise US$0.062/min against a US$12/month included allowance on GitHub Free [GH1][GH2]. Codemagic documents an Ionic/Capacitor iOS workflow using an App Store Connect API key, distribution certificate and provisioning profile, publishing to TestFlight/App Store [CM1]. Ionic Appflow still offers cloud iOS builds but "Sales of Appflow Enterprise plans have been discontinued" [C6]; Capacitor's own docs still say local tools are "highly recommended" [C2].
- Guideline 4.2 Minimum Functionality: "Your app should include features, content, and UI that elevate it beyond a repackaged website. If your app is not particularly useful, unique, or 'app-like,' it doesn't belong on the App Store." 4.2.2: apps "shouldn't primarily be marketing materials, advertisements, web clippings, content aggregators, or a collection of links." 4.2.6 rejects apps "created from a commercialized template or app generation service" unless submitted by the content owner [A7]. A Capacitor build that bundles the full NardTrace toolset locally (not a WebView pointing at GitHub Pages) is the defensible reading of 4.2.
- Also relevant: 2.5.1 "Apps may only use public APIs and must run on the currently shipping OS"; 2.3.1(a) names "iOS-based virus and malware scanners" as an example of misleading marketing; 5.1.1(ix) says highly regulated services should be submitted by a legal entity, not an individual (NardTrace is not in that list) [A7].

## 3. Technical wrapping path for Vite + React

### Capacitor (Android + iOS)
- Requirements: Node 22+; Android Studio 2025.2.1+ with an SDK platform for API 24+; macOS + Xcode 26 for iOS [C2]. The web project needs a `package.json`, a built-assets folder and an `index.html` with a `<head>` [C1].
- Commands [C1]:
  `npm i @capacitor/core && npm i -D @capacitor/cli` -> `npx cap init` (sets `appId`, `appName`, `webDir`) -> `npm i @capacitor/android @capacitor/ios` -> `npx cap add android` / `npx cap add ios` -> `npx cap sync`.
  `webDir` is "The directory of your compiled web assets. This directory should contain the final `index.html`" [C7]; for NardTrace set `webDir: 'dist'` and keep Vite `base: './'` (already set in `frontend/vite.config.js`).
- Routing: the app already uses `HashRouter` (`frontend/src/main.jsx`). Capacitor serves from `https://localhost` on Android (`androidScheme` default `https`) and `capacitor://localhost` on iOS; the config docs warn that custom Android schemes break path routing and suggest "a hash-based url strategy" [C7], so HashRouter is the compatible choice.
- Platform floors: Capacitor 8 Android template ships `minSdkVersion = 24`, `compileSdkVersion = 36`, `targetSdkVersion = 36` [C5]; "API 24+ (Android 7 or later) is supported" [C3]; "iOS 15+ is supported. Xcode 26.0+ is required" [C4]. Play requires new apps to target API 36 from 31 Aug 2026 (extension to 1 Nov 2026) [G4], which the template already meets.
- Plugins NardTrace would use: `@capacitor/filesystem` (`npm install @capacitor/filesystem && npx cap sync`; iOS needs a `PrivacyInfo.xcprivacy` with `NSPrivacyAccessedAPICategoryFileTimestamp`/`C617.1`; Android 10-and-older needs READ/WRITE_EXTERNAL_STORAGE only for `Directory.Documents`/`ExternalStorage`) [C8]; `@capacitor/share` for exporting reports (Android shares only from the cache folder unless `file_paths.xml` is extended) [C9]. Reading user-picked `.eml` files via the standard `<input type="file">` needs no extra permission.
- Android signing: Play uses Android App Bundles and Play App Signing; `versionCode` must increase per upload (max 2,100,000,000) [G16].

### Trusted Web Activity / PWABuilder (Android only)
- A TWA renders "your Progressive Web App (PWA)" from the web, verified by Digital Asset Links; "The host app doesn't have direct access to web content" and content must meet Add-to-Home-Screen criteria [CH1].
- PWABuilder uses Bubblewrap to generate a TWA; prerequisites: "A valid PWA with a web manifest, published to the web and secured through HTTPS", a US$25 Play account, an Android device/emulator; output requires Android 7.0 (API 24)+ [P1]. You must host `/.well-known/assetlinks.json` at the PWA's host and update it with Play's SHA-256 after Play re-signs the bundle, and "PWAs on Android cannot currently target children" (set 13+) [P1]. Note: GitHub Pages serves `thankcheeses.github.io/NardTrace/`, so assetlinks.json would have to live at `https://thankcheeses.github.io/.well-known/assetlinks.json` (user-site root, not the project site) - **UNVERIFIED** whether a project-page-only setup can satisfy this; a custom domain avoids the question.
- A TWA has no iOS equivalent; Apple's 4.2 "repackaged website" language also makes a remote-URL wrapper the weaker iOS option [A7].

## 4. Monetization rules

### Google Play
- "Developers charging for app downloads from Google Play must use Google Play's billing system" and in-app purchases of "app functionality or content (such as an ad-free version of an app or new features not available in the free version)" and "subscription services" must use Play Billing unless an alternative-billing program applies [G6]. Play Billing "must not be used" for physical goods/services, P2P payments or tax-exempt donations [G6]. Apps "may not lead users to a payment method other than Google Play's billing system" via listing, in-app links or sign-up flows outside the permitted programs [G6].
- Alternative billing / user choice billing: eligible markets include the United States for mobile/tablet apps, but the "Developer must be registered as a business" [G17], so a personal account cannot use it. An "Expanded Billing Choice" and external-web-link option for the US launched 30 Jun 2026 under the new fee model [G8]; detailed US external-link program terms: **UNVERIFIED** (page says "Program details will be shared in the coming months").
- Service fees for US users (effective 30 Jun 2026, "new installs"): first US$1M annual earnings 10% + 5% billing fee; standard 20% + 5% (non-recurring) and 10% + 5% (subscriptions); 15% + 5% with the Apps Experience program (from 30 Sep 2026); external web links 20%/15% with no billing fee [G7][G8]. The older 15%/30% tier still applies in markets not yet rolled out and requires enrolling an Account Group in Play Console [G7][G18].
- Paid apps: set free/paid on the App pricing page; "Once your app has been offered for free, the app can't be changed to paid" [G20]. Selling requires a payments profile (legal name, physical address, no PO box, bank in same country) [G21]; bank account verified by deposit challenge or documents, "can take up to 5 days" [G5]. Google collects and remits US state sales tax for Play Billing purchases [G22]. Payouts start "each month on the 15th for the previous month's sales" [G19]. US tax form (W-9) inside the payments profile: **UNVERIFIED** on a Google page (the profile stores a "tax ID (when required legally)" [G23]).

### Apple App Store
- 3.1.1: "If you want to unlock features or functionality within your app, (by way of example: subscriptions ... or unlocking a full version), you must use in-app purchase." 3.1.1(a): entitlements for external purchase links "are not required for developers to include buttons, external links, or other calls to action in their United States storefront apps." 3.1.3(e): physical goods/services consumed outside the app must *not* use IAP [A7].
- Small Business Program: "reduced commission rate of 15% on paid apps and Apple In-App Purchases" for developers with up to US$1M prior-year proceeds, including new developers; enrol as Account Holder after accepting the Paid Apps agreement; rate applies 15 days after the end of the approval month [A8]. Standard rate otherwise 30% (**UNVERIFIED** on the fetched pages; stated only as "the standard commission rate").
- Paid apps: choose from up to 800 price points, a base country, Apple generates the other 174 storefronts [A17].
- Agreements/Tax/Banking: "the Account Holder must sign the Paid Apps Agreement" (free apps need only the Program License Agreement) [A9]; "All developers must complete a US tax form ... If you're based in the United States, you're prompted to complete a W-9 form" with SSN (individual) or EIN (entity); submitted forms cannot be edited in App Store Connect [A10]; one bank account, added under Business > Agreements > Bank Accounts [A18]; payments "within 45 days of the last day of the fiscal month"; US minimum payment threshold US$0.02 [A11][A19].

### AdMob (both stores)
- Sign up with a Google Account, phone verification, payment details; "verification process typically takes up to 24 hours, but in rare cases, can take up to 2 weeks" [AD1]. Address PIN verification by postal mail (about 3 weeks) once earnings reach the verification threshold [AD2]. Ads must be declared in Play Console ("Contains ads" label) [G24] and Apple's privacy details must include ad-SDK data [A12]. AdMob payment threshold amount: **UNVERIFIED** on the fetched pages.

## 5. Store listing compliance

- Privacy policy (Play): "All apps must post a privacy policy link in the designated field within Play Console, and a privacy policy link or text within the app itself" - public, non-PDF, non-geofenced URL naming the developer, data types, security, retention/deletion; "Apps that do not access any personal and sensitive user data must still submit a privacy policy" [G9][G10].
- Privacy policy (Apple): 5.1.1(i) requires a privacy policy link in App Store Connect and in the app; App Privacy "Privacy Policy (Required): The URL to your publicly accessible privacy policy" [A7][A12].
- Data safety (Play): "All developers must declare how they collect and handle user data", including SDKs; "Even developers with apps that do not collect any user data must complete this form"; data "only processed locally on the user's device and not sent off device does not need to be disclosed"; ephemeral off-device processing is declared but not shown [G11]. For NardTrace: DNS/RDAP/ipinfo queries send hostnames/IPs the user typed to third parties but store nothing - declare per [G11]'s ephemeral rules.
- App Privacy (Apple): required for every submission; "Data that is processed only on device is not 'collected'"; "collect" means transmitting data off device in a way accessible beyond servicing the request [A12].
- Content rating: Play IARC questionnaire required for all new apps; "Unrated apps may be removed" [G12][G24]. Apple age rating is "a required app information field" generated from a questionnaire (4+/9+/13+/16+/18+) [A13].
- Assets (Play): icon 512x512 32-bit PNG <=1024 KB; feature graphic 1024x500 JPEG/24-bit PNG; at least 2 screenshots, 320-3840 px, longest side <= 2x shortest (recommended >=4 at 1080 px, 16:9 or 9:16); short description 80 chars, full 4,000 [G13][G16].
- Assets (Apple): App Store icon layout 1024x1024 px, sRGB/P3 [A14]; at least one screenshot (max 10) for "iPhone with Dynamic Island (medium display)" e.g. 1179x2556 or 1206x2622, iPad 13" 2064x2752 if iPad is supported, no alpha; larger sizes are auto-scaled down [A15].
- Required declarations in Play Console App content: privacy policy, ads, sign-in details (none for NardTrace), target audience, content rating, Data safety [G24].

## 6. Special concerns for a security / anti-phishing tool

- Google "Malware" policy lists phishing, spyware, stalkerware, hostile downloaders etc. NardTrace *analyzes* phishing artefacts without fetching URLs or executing files, so it does not fit any category; the policy does, however, apply to every bundled SDK [G25].
- Google "Deceptive Behavior": no misleading claims ("An app that claims to be an antivirus app, but only contains a text guide" is a violation example); metadata must "accurately and clearly describe their functionality"; no hidden/dormant features; app must behave identically for reviewers [G26]. Describe NardTrace as an investigation/reporting workbench, not a scanner or protection product.
- Google "User Data": apps with "anti-virus or security functionality ... must post a privacy policy that, together with any in-app disclosures, explain what user data your app collects and transmits, how it's used, and the type of parties with whom it's shared" - list dns.google / cloudflare-dns / rdap.org / ipinfo.io / optional VirusTotal, AbuseIPDB, Safe Browsing [G9]. Also: "Apps that depict or display unverified or real world phone numbers, contacts, addresses, or personally identifiable information of non-consenting individuals" is a Deceptive Behavior violation [G26]; RDAP/WHOIS output must be framed as infrastructure/abuse-contact data (the README already states the tool is not for locating private individuals).
- Google "Permissions": request only permissions "necessary to implement current features"; `MANAGE_EXTERNAL_STORAGE` needs a declaration and is unnecessary when the Storage Access Framework (file picker) suffices [G27]. Keep the manifest to INTERNET only.
- Google "Spam": apps "whose primary purpose is to provide a webview of a website" are disallowed without owner permission; "Repetitive Content" forbids near-duplicate apps [G28]. Ship the bundle locally and do not publish several thin variants.
- Apple: 5.1.1(iii) data minimization and (viii) no compiling personal information from public databases without consent [A7] - present RDAP lookups as user-initiated, per-query, unstored; 2.3.1(a) forbids promoting "iOS-based virus and malware scanners" [A7] - never market the hash module as malware detection; 1.1.6 forbids "False information and features" [A7] - keep the "ASSUMPTION" tags on heuristic verdicts; 2.5.1 public APIs only [A7] - Capacitor/WKWebView is fine.
- Optional third-party keys (VirusTotal, AbuseIPDB, Safe Browsing): if the user enters their own key, disclose the third-party transfer in both privacy forms [G11][A12].

## Recommended path for NardTrace

1. Register a *personal* Google Play Console account now (US$25) and complete identity + device verification; the 14-day closed test is the long pole, so start recruiting 12+ testers immediately [G1][G2][G3].
2. Enrol in the Apple Developer Program as an individual (US$99/yr) under the legal name; no D-U-N-S needed [A1][A3]. Expect the legal name to be public on both stores [G5][A1].
3. Add Capacitor 8 to `frontend/` with `webDir: 'dist'`, keep `HashRouter` and `base: './'`, add `@capacitor/share` (and `@capacitor/filesystem` only if saving reports to disk is needed) [C1][C7][C8][C9]. Build the web bundle into the app; do not load GitHub Pages in a WebView (4.2 and Play Spam policy) [A7][G28].
4. Android: build an AAB with Play App Signing, upload to Internal then Closed testing, run the 14-day test, apply for production, then publish [G2][G16]. Target SDK 36 is already met by Capacitor 8 [C5][G4].
5. iOS: with no Mac, use a GitHub Actions `macos-latest` job (free on a public repo) or Codemagic with an App Store Connect API key to archive, sign and upload to TestFlight [GH1][CM1]; otherwise Xcode 26 on macOS 26 [C2][A16].
6. Publish one privacy policy page on the project site covering the DNS/RDAP/IP providers, optional API keys, local-only file hashing and no account/analytics; link it in both consoles and inside the app [G9][G10][A12].
7. Listing copy: "email and infrastructure investigation workbench"; avoid "antivirus", "scanner", "protection" [G26][A7]. Rating questionnaire: utility, no user-generated content.
8. Monetization order of least friction: (a) free app + optional AdMob banner (declare ads) [AD1][G24]; (b) one-time "Pro" unlock via Play Billing / Apple IAP (15% Apple Small Business, 10% + 5% Google first $1M) [A8][G7]; (c) paid upfront download (cannot later become free-to-paid on Play) [G20]. Complete the Paid Apps Agreement + W-9 + bank (Apple) and payments profile + bank verification (Google) before creating products [A9][A10][G21][G5].
9. Keep a `docs/adr/` entry for the wrapping decision and re-check the Play fee/external-link program pages after 30 Sep 2026 [G8].

## Sources

- [G1] https://support.google.com/googleplay/android-developer/answer/6112435 - Get started with Play Console (fee, age, account types, ID check)
- [G2] https://support.google.com/googleplay/android-developer/answer/14151465 - App testing requirements for new personal developer accounts
- [G3] https://support.google.com/googleplay/android-developer/answer/14316361 - Device verification requirements
- [G4] https://support.google.com/googleplay/android-developer/answer/11926878 - Target API level requirements
- [G5] https://support.google.com/googleplay/android-developer/answer/13628312 - Required information to create a developer account (display rules, D-U-N-S, payment verification)
- [G6] https://support.google.com/googleplay/android-developer/answer/9858738 - Payments policy
- [G7] https://support.google.com/googleplay/android-developer/answer/112622 - Service fees
- [G8] https://support.google.com/googleplay/android-developer/answer/16954621 - Understanding Google Play's lower service fees (rollout timeline)
- [G9] https://support.google.com/googleplay/android-developer/answer/10144311 - User Data policy (privacy policy, security-app clause)
- [G10] https://support.google.com/googleplay/android-developer/answer/9859455 - Prepare your app for review (privacy policy requirements)
- [G11] https://support.google.com/googleplay/android-developer/answer/10787469 - Data safety section
- [G12] https://support.google.com/googleplay/android-developer/answer/9859655 - Content rating requirements
- [G13] https://support.google.com/googleplay/android-developer/answer/9866151 - Preview assets (icon, feature graphic, screenshots)
- [G14] https://support.google.com/googleplay/android-developer/answer/10788890 - Play Console Requirements policy
- [G15] https://support.google.com/android-developer-console/answer/16561738 - Android developer verification
- [G16] https://support.google.com/googleplay/android-developer/answer/9859152 - Create and set up your app (AAB, versionCode, listing limits)
- [G17] https://support.google.com/googleplay/android-developer/answer/12570971 - User choice billing pilot
- [G18] https://support.google.com/googleplay/android-developer/answer/10632485 - 15% service fee tier enrollment
- [G19] https://support.google.com/paymentscenter/answer/7159355 - Merchant payout schedule
- [G20] https://support.google.com/googleplay/android-developer/answer/6334373 - Set up your app's prices
- [G21] https://support.google.com/googleplay/android-developer/answer/7161426 - Create a payments profile
- [G22] https://support.google.com/paymentscenter/answer/7161449 - Sales tax rates (US)
- [G23] https://support.google.com/paymentscenter/answer/9028746 - Create and manage your payments profile
- [G24] https://support.google.com/googleplay/android-developer/answer/9859455 - App content declarations (ads, rating)
- [G25] https://support.google.com/googleplay/android-developer/answer/9888380 - Malware policy
- [G26] https://support.google.com/googleplay/android-developer/answer/9888077 - Deceptive Behavior policy
- [G27] https://support.google.com/googleplay/android-developer/answer/9888170 - Permissions and APIs that Access Sensitive Information
- [G28] https://support.google.com/googleplay/android-developer/answer/9899034 - Spam policy (webviews, repetitive content)
- [A1] https://developer.apple.com/programs/enroll/ - Apple Developer Program enrollment
- [A3] https://developer.apple.com/support/D-U-N-S/ - D-U-N-S Number support
- [A4] https://developer.apple.com/support/enrollment/ - Enrollment support
- [A5] https://developer.apple.com/news/upcoming-requirements/ - Upcoming requirements (Xcode 26 / iOS 26 SDK)
- [A6] https://developer.apple.com/distribute/app-review/ - App Review
- [A7] https://developer.apple.com/app-store/review/guidelines/ - App Review Guidelines
- [A8] https://developer.apple.com/app-store/small-business-program/ - Small Business Program
- [A9] https://developer.apple.com/help/app-store-connect/manage-agreements/sign-and-update-agreements - Paid Apps Agreement
- [A10] https://developer.apple.com/help/app-store-connect/provide-tax-information/provide-us-tax-information - US tax information (W-9)
- [A11] https://developer.apple.com/help/app-store-connect/getting-paid/overview-of-receiving-payments - Receiving payments
- [A12] https://developer.apple.com/app-store/app-privacy-details/ - App privacy details
- [A13] https://developer.apple.com/help/app-store-connect/reference/age-ratings - Age ratings
- [A14] https://developer.apple.com/design/human-interface-guidelines/app-icons - App icons (specifications)
- [A15] https://developer.apple.com/help/app-store-connect/reference/screenshot-specifications - Screenshot specifications
- [A16] https://developer.apple.com/support/xcode/ - Xcode support (macOS requirement)
- [A17] https://developer.apple.com/help/app-store-connect/manage-app-pricing/set-a-price - Set a price
- [A18] https://developer.apple.com/help/app-store-connect/manage-banking-information/enter-banking-information - Banking information
- [A19] https://developer.apple.com/help/app-store-connect/reference/reporting/minimum-payment-threshold - Minimum payment threshold
- [C1] https://capacitorjs.com/docs/getting-started - Installing Capacitor
- [C2] https://capacitorjs.com/docs/getting-started/environment-setup - Environment setup
- [C3] https://capacitorjs.com/docs/android - Android support (API 24+)
- [C4] https://capacitorjs.com/docs/ios - iOS support (iOS 15+)
- [C5] https://raw.githubusercontent.com/ionic-team/capacitor/main/android-template/variables.gradle - Android template SDK versions
- [C6] https://ionic.io/docs/appflow - Appflow
- [C7] https://capacitorjs.com/docs/config - Capacitor configuration (webDir, schemes, hash routing)
- [C8] https://capacitorjs.com/docs/apis/filesystem - Filesystem plugin
- [C9] https://capacitorjs.com/docs/apis/share - Share plugin
- [P1] https://docs.pwabuilder.com/#/builder/android - PWABuilder: Publishing PWAs to Google Play
- [CH1] https://developer.chrome.com/docs/android/trusted-web-activity - Trusted Web Activity overview
- [GH1] https://docs.github.com/en/actions/reference/runners/github-hosted-runners - GitHub-hosted runners
- [GH2] https://docs.github.com/en/billing/concepts/product-billing/github-actions - GitHub Actions billing
- [CM1] https://docs.codemagic.io/yaml-quick-start/building-an-ionic-app/ - Codemagic Ionic Capacitor workflow
- [AD1] https://support.google.com/admob/answer/7356219 - Sign up for AdMob
- [AD2] https://support.google.com/admob/answer/2772302 - AdMob address verification (PIN)
