<pre align="center">
Heathc1iff Blog 🚀 A clean, elegant, and fast static blog powered by Astro
</pre>

<div align="center">
<img alt="Heathc1iff Logo" src="https://github.com/heathc1iff-sec/heathc1iff-sec.github.io/blob/main/logo.png" width="280px">
</div>

[![license](https://badgen.net/github/license/heathc1iff-sec/heathc1iff-sec.github.io)](https://github.com/heathc1iff-sec/heathc1iff-sec.github.io/blob/main/LICENSE)  
[![release](https://badgen.net/github/release/heathc1iff-sec/heathc1iff-sec.github.io)](https://github.com/heathc1iff-sec/heathc1iff-sec.github.io/releases)

[**🖥️ Blog Demo**](https://heathc1iff-sec.github.io)  

---

## 📷 Preview

![preview](./preview-light.png)

---

## ✨ Features

- ✅ Light / Dark mode
- ✅ Fast performance & SEO friendly
- ✅ Page transition animations (ClientRouter)
- ✅ Article search (Pagefind)
- ✅ Responsive design (Tailwind CSS + daisyUI)
- ✅ RSS feed support
- 🛠️ Easy to customize via `frosti.config.yaml`

---

## ✒️ Article Info

| Name | Meaning | Required |
|------|---------|----------|
| title | Article title | Yes |
| description | Article description | Yes |
| pubDate | Publication date | Yes |
| image | Cover image | No |
| categories | Categories | No |
| tags | Tags | No |
| badge | Badge | No |
| draft | Draft status | No |

> **Tip**:  
> - Use `badge: Pin` to pin an article  
> - Use `draft: true` to hide it from the list  

---

## ⬇️ Usage

```bash
npm i -g pnpm         # Install pnpm if needed
git clone https://github.com/heathc1iff-sec/heathc1iff-sec.github.io.git
cd heathc1iff-sec.github.io
pnpm i                 # Install dependencies
pnpm run search:index   # Generate search index
pnpm run dev            # Start dev server
