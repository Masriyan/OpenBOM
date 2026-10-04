# Vendored front-end libraries

Shipped locally so the OpenBOM console works offline / on-prem and the dashboard CSP can stay `'self'`.

| File | Package | Version | License |
|------|---------|---------|---------|
| arco.min.js, arco-icon.min.js, arco.min.css, arco-locale-en-US.js (wrapped lib/locale/en-US.js) | @arco-design/web-react (ByteDance) | 2.66.16 | MIT |
| react.production.min.js | react | 18.3.1 | MIT |
| react-dom.production.min.js | react-dom | 18.3.1 | MIT |
| htm.umd.js | htm | 3.1.1 | Apache-2.0 |

Update: `npm pack <pkg>@<version>` and copy the UMD builds listed above.

```
ca1ee9637d368c62fb72f38df67fff7158b14399257978ec099975112387e526  arco-icon.min.js
c5625760318d3a0df24847017bd28bdd04fe1315c8bbedb413fd03922a462a08  arco.min.js
7a31776e04bd4afde0d4308177d26f377716fcf7e4bd70be590746d6aa594f08  htm.umd.js
35f4f974f4b2bcd44da73963347f8952e341f83909e4498227d4e26b98f66f0d  react-dom.production.min.js
d949f1c3687aedadcedac85261865f29b17cd273997e7f6b2bfc53b2f9d4c4dd  react.production.min.js
7084c7bbaee03dadb995e80a6b7f02fa0c304454c8ebe8184690784b18277ea8  arco.min.css
```
