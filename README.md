# Pufferphish

An automated dynamic analysis approach to extracting exfiltration URLs from phishing sites and documents.

## REST API

Analyze a URL:

```bash
$ curl "http://localhost:1234/submit" -X POST -d "url=https://pub-20cffe933ea147e7911147f1c88f341b.r2.dev/index.html"
```

```json
{
  "exfiltration": [
    {
      "body": "",
      "credential_types": [
        "username"
      ],
      "method": "GET",
      "url": "https://dashboard.example.com/web/site/go-back?usr=USERNAME&token=9704A-4FC48-AE885-98DCB-DCDF5-7F3FD-EF-16-81851-875"
    }
  ],
  "html": "...",
  "solver_html": "..."
}
```

Alternatively, you can analyze an HTML file:

```bash
$ curl "http://localhost:1234/submit" -X POST -F "html=@phish.html"
```

## Credit

* [selenium_phishing_detector](https://github.com/nf1s/selenium_phishing_detector) and their paper [A New Heuristic Based Phishing Detection Approach Utilizing Selenium Web-driver](https://comserv.cs.ut.ee/ati_thesis/datasheet.php?id=58598&year=2017) for inspiration
* [FlareSolverr](https://github.com/FlareSolverr/FlareSolverr) for getting past hCaptcha
* [selenium-wire](https://github.com/wkeeling/selenium-wire) for intercepting and manipulating requests
* [mitmproxy](https://github.com/mitmproxy/mitmproxy) which selenium-wire is built on top of
* [undetected_chromedriver](https://github.com/ultrafunkamsterdam/undetected-chromedriver) to avoid any chromedriver-specific anti-bot protection
