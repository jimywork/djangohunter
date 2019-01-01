# Djangohunter
##### Tool designed to help identify incorrectly configured Django applications that are exposing sensitive information.
https://www.reddit.com/r/django/comments/87qcf4/28165_thousand_django_running_servers_are_exposed/
https://twitter.com/6ix7ine/status/978598496658960384?lang=en

 ### Usage
 ```
Usage: python3 djangohunter.py --key {shodan}
Dorks: 'DisallowedHost', 'KeyError', 'OperationalError', 'Page not found at /'
```
### Requirements
- Shodan  
- Pyfiglet  
- Requests  
- BeautifulSoup  

```pip install -r requirements.txt```   

### Demo
[![asciicast](https://asciinema.org/a/210648.svg)](https://asciinema.org/a/210648)

### Disclaimer
Code samples are provided for educational purposes. Adequate defenses can only be built by researching attack techniques available to malicious actors. Using this code against target systems without prior permission is illegal in most jurisdictions. The authors are not liable for any damages from misuse of this information or code.


## Donations
* XMR: `49m12JEEC6HPCHkLMX5QL4SrDQdKwh6eb4Muu8Z9CwA9MwemhzFQ3VcgHwyuR73rC22WCymTUyep7DVrfN3GPt5JBCekPrR `
