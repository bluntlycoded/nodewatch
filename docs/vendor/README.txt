Third-party scripts the dashboard loads, pinned and served from here
instead of a CDN: a compromised or unreachable CDN cannot take over an
admin's session, and a self-hosted master works without internet access.

supabase-js-2.117.3.js
  @supabase/supabase-js 2.117.3, dist/umd/supabase.js, MIT licence.
  From the npm tarball, checked against the registry's integrity hash
  npm integrity sha512-K+f8PimXDunPWQ63CKRXaF5pbVPJxmfw5ryAnh0s9S9PkwcuqBjiSpIaqpF7KLDljeYwXIL85ST8QxaO0+XuvA==

tailwind-play-3.4.17.js
  Tailwind CSS play CDN build 3.4.17 (https://cdn.tailwindcss.com/3.4.17),
  MIT licence.

To update: fetch the new file the same way, check it, replace it here and
change the <script> tag in ../index.html.

SHA-256
d6a5c4414a5d4ce646d9c1de223aa7067d3ff664c15394ffeb7fcffc763354a3  supabase-js-2.117.3.js
176e894661aa9cdc9a5cba6c720044cbbf7b8bd80d1c9a142a7c24b1b6c50d15  tailwind-play-3.4.17.js
