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
Here `collectFingerprintInfo()` gets invoked and it was likely waiting for a Promise because of `.then` argument being used to handle the asynchronous `res` which defines another function and takes a result as a parameter and after that its trying to call a function called `function_name_01` of the global window object but it fails because of the invalid syntax and XSS can't happen here. If it wasnt using `eval()` which always require double quotes for such execution of the string in js code then XSS would happen and then at the end it calls the result function with it's argument.




