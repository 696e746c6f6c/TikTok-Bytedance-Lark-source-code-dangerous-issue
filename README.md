Recently we have discovered few TikTok's Lark & ByteDance subdomains (https://www.feishu.cn/ & https://people.bytedance.net) sharing the same endpoints with the same parameter which is supposed to redirect users to malicious pages and such eval() function which is the un-trusted data type is being used. But why does XSS fails here?
```javascript
var BFP = __webpack_require__(6825)
          , collectFingerprintInfo = function() {
            return __awaiter(void 0, void 0, void 0, (function() {
                var t, e, r, n, o, i, s, a, u;
                return __generator(this, (function(c) {
                    switch (c.label) {
                    case 0:
                        return [4, BFP.get()];
                    case 1:
                        return t = c.sent(),
                        e = {},
                        r = BFP.hashComponents(t),
                        Object.keys(t).forEach((function(r) {
                            e[r] = t[r].value || ""
                        }
                        )),
                        n = void 0 !== document.referrer ? document.referrer : "unknown",
                        o = void 0 !== document.location.href ? document.location.href : "unknown",
                        i = void 0 !== navigator.hardwareConcurrency ? navigator.hardwareConcurrency : "unknown",
                        s = void 0 !== navigator.appVersion ? navigator.appVersion : "unknown",
                        a = {
                            width: void 0 !== window.screen.width ? window.screen.width : "unknown",
                            height: void 0 !== window.screen.height ? window.screen.height : "unknown",
                            colorDepth: void 0 !== window.screen.colorDepth ? window.screen.colorDepth : "unknown"
                        },
                        u = void 0 !== document.cookie ? document.cookie : "unknown",
                        [2, {
                            info: e,
                            id: r,
                            referer: n,
                            uri: o,
                            cpucores: i,
                            appversion: s,
                            screensize: a,
                            cookie: u
                        }]
                    }
                }
                ))
            }
            ))
        };
        collectFingerprintInfo().then((function(result) {
            eval("window.function_name_01")(result)
        }
        ))
    }
```
Here you can see this `collectFingerprintInfo` function is being defined with empty parameter and at the end we can see dangerous `eval()` function un-trusted data type being evaluated/executed at the end following this code snippet:
```javascript
 collectFingerprintInfo().then((function(result) {
            eval("window.function_name_01")(result)
        }
```
Here `collectFingerprintInfo()` gets invoked and it was likely waiting for a Promise because of `.then` argument being used to handle the asynchronous `res` which defines another function and takes a result as a parameter and after that its trying to call a function called `function_name_01` of the global window object but it fails because of the invalid syntax and XSS can't happen here. However `eval()` doesn't fail to be executed here due to this following code snippet:
```javascript
function function_name_01(t) {
    return ("undefined" == typeof window ? global : window)._$jsvmprt("484e4f4a403f524300143423dfb57089d801749a00000000000000dc1b001b000b021a001d00011b000b07201d00021b000b07221e0003240200040200050a0002101c1b000b07221e0006241b000b031b000b04221e000724131e00081a00221b000b061d00092202000a1d000b22131e000c22011700071c02000d1d000e0a000110040a0001101c00000f0001700f302e332f043522232229332e262b3404283722290417081413412f333337347d68682b28207e6a352237283533693d2e2d2e2226372e6924282a682a28292e33283518253528303422356824282b2b22243368317568252633242f0434222923093433352e29202e213e0608252d22243304232633260924282b2b222433283503332620091715080d0204130e03032b282003372e23", [, , "undefined" != typeof XMLHttpRequest ? XMLHttpRequest : void 0, void 0 !== encrypt ? encrypt : void 0, "undefined" != typeof JSON ? JSON : void 0, function_name_01, t])
}
```
This code checks if the string `undefined` is equal to the typeof operand of the `window` object. If this comparison is true, then it returns the global object. Otherwise, it returns the `window` object. However this code snippet is not too much interesting, what does get interesting is the following code snippet:
```javascript
var s = /^([a-z0-9.+-]+:)/i,
        a = /:[0-9]*$/,
        u = /^(\/\/?(?!\/)[^\?\s]*)(\?[^\s]*)?$/,
        c = [
          '{',
          '}',
          '|',
          '\\',
          '^',
          '`'
        ].concat(['<',
        '>',
        '"',
        '`',
        ' ',
        '\r',
        '\n',
        '\t']),
        l = [
          '\''
        ].concat(c),
        f = [
          '%',
          '/',
          '?',
          ';',
          '#'
        ].concat(l),
        h = [
          '/',
          '?',
          '#'
        ],
        p = /^[+a-z0-9A-Z_-]{0,63}$/,
        d = /^([+a-z0-9A-Z_-]{0,63})(.*)$/,
        v = {
          javascript: !0,
          'javascript:': !0
        },
        g = {
          javascript: !0,
          'javascript:': !0
        },
        m = {
          http: !0,
          https: !0,
          ftp: !0,
          gopher: !0,
          file: !0,
          'http:': !0,
          'https:': !0,
          'ftp:': !0,
          'gopher:': !0,
          'file:': !0
        },
```
variable `s`, this regex expression gets assigned at it maches `http:` and `https:` schemes which introduces open redirection on these subdomains. `a` variable goes with port and etc. But however we can see some arrays and objects. But wait notice `v` object which provides this:
```javascript
 javascript: !0,
'javascript:': !0
```
and same for `g` object. This means that javascript schemes are allowed but in our case no? Why are these declarations used in URL parsing mostly `g` object if app doesn't support javascript scheme by itself?
```javascript
return function (t, e) {
            var r = t.auth,
            o = t.query,
            i = t.hostname,
            s = t.protocol,
            a = t.port;
            a &&
            '0' !== a ||
            (a = e.port),
            '0.0.0.0' !== i &&
            '::' !== i ||
            !e.hostname ||
            0 !== e.protocol.indexOf('http') ||
            (i = e.hostname),
            !i ||
            '127.0.0.1' === i ||
            'https:' !== e.protocol &&
            '0.0.0.0' !== t.hostname ||
            (s = e.protocol);
            var u = o.sockHost ||
            i,
            c = o.sockPath ||
            '/sockjs-node',
            l = o.sockPort ||
            a;
            return 'location' === l &&
            (l = e.port),
            n.format({
              protocol: s,
              auth: r,
              hostname: u,
              port: l,
              pathname: c
            })
          }(r, e = 'string' == typeof e && '' !== e ? n.parse(e) : self.location)
        }
      }
```
Let's read this code snippet in the depth of the analysis. First of all the function has two parameters `t` and `e`. It extracts some properties from `t` such as `auth`, `query`, `hostname`, `protocol`, and `port`. Another thing is if the port is not specified it sets `a` to `e.port` property. It checks if the hostname is `0.0.0.0` or `::` and the protocol of `e` must start with `http`. If that's true then it updates `i` to `e.hostname`. But if not, it checks if `i` is not empty, not `127.0.0.1` ipv4 and `e.protocol` is not `https:` or `t.hostname` is `0.0.0.0`. If true, it updates s to `e.protocol`. It assigns values to `u` & `c` and l based on properties in `o`. If `l` is `location`, it updates `l` to `e.port`. And then it finally returns a formatted URL string using the `n.format` function with the updated properties.

