# ytf

YARA Test Framework

## Sample Output
~~~~
Rule Set: CVE Must Fix List (CVE)
✓ PASS: (CVE001) Reports should not have Critical CVEs (CVE-2000-0001)
✓ PASS: (CVE002) Reports should not have Critical CVEs (CVE-2001-0002)

Rule Set: HTML JavaScript (HTMLJ)
✓ PASS: (HTMLJ001) Script tags should include SRI
✓ PASS: (HTMLJ002) JavaScript Event triggers should not be in HTML tags

Rule Set: HTTP Headers (HTTPH)
✗ FAIL: (HTTPH001) HTTP Response Headers should include CORS Header
✓ PASS: (HTTPH002) HTTP Response Headers should include HTST Header

Test Summary:  5 passed  1 failed 
~~~~