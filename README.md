[![PyPi Downloads][PyPi-downloads]][PyPi-url]
[![PyPi Version][PyPi-version]][PyPi-url]
[![License][License-shield]][License-url]

This is a python3 fork of [Richard Penman's Browser Cookie](https://github.com/richardpenman/browsercookie)

# Browser Cookie

* ***What does it do?*** Loads cookies used by your web browser into a cookiejar object.
* ***Why is it useful?*** This means you can use python to download and get the same content you see in the web browser without needing to login.
* ***Which browsers are supported?*** Chrome, Firefox, LibreWolf, Opera, Opera GX, Edge, Chromium, Brave, Vivaldi, Safari, W3m and Lynx.
* ***How are the cookies stored?*** Most currently-supported browsers store cookies in a sqlite database in your home directory. Some browsers store them in tab-separated txt files.

## Install
```bash
pip install browser-cookie3
```

## Python usage

Here is a *dangerous* hack to extract the title from a webpage:
```python
#!python

>>> import re
>>> get_title = lambda html: re.findall('<title>(.*?)</title>', html, flags=re.DOTALL)[0].strip()
```

And here is the webpage title when downloaded normally:
```python
#!python

>>> import urllib2
>>> url = 'https://bitbucket.org/'
>>> public_html = urllib2.urlopen(url).read()
>>> get_title(public_html)
'Git and Mercurial code management for teams'
```

Now let's try with browser_cookie3 - make sure you are logged into Bitbucket in Firefox before trying this example:
```python
#!python

>>> import browser_cookie3
>>> cj = browser_cookie3.firefox()
>>> opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
>>> login_html = opener.open(url).read()
>>> get_title(login_html)
'richardpenman / home &mdash; Bitbucket'
```

You should see your own username here, meaning the module successfully loaded the cookies from Firefox.

Here is an alternative example with [requests](http://docs.python-requests.org/en/latest/), this time loading the Chrome cookies. Again make sure you are logged into Bitbucket in Chrome before running this:
```python
#!python

>>> import browser_cookie3
>>> import requests
>>> cj = browser_cookie3.chrome()
>>> r = requests.get(url, cookies=cj)
>>> get_title(r.content)
'richardpenman / home &mdash; Bitbucket'
```

Alternatively if you don't know/care which browser has the cookies you want then all available browser cookies can be loaded:
```python
#!python

>>> import browser_cookie3
>>> import requests
>>> cj = browser_cookie3.load()
>>> r = requests.get(url, cookies=cj)
>>> get_title(r.content)
'richardpenman / home &mdash; Bitbucket'
```

Alternatively if you are only interested in cookies from a specific domain, you can specify a domain filter.
```python
#!python

>>> import browser_cookie3
>>> import requests
>>> cj = browser_cookie3.chrome(domain_name='www.bitbucket.com')
>>> r = requests.get(url, cookies=cj)
>>> get_title(r.content)
'richardpenman / home &mdash; Bitbucket'
```

### Multi-Profile Support

browser_cookie3 now supports loading cookies from specific browser profiles. This is useful when you have multiple profiles set up in your browser.

#### Chromium-based browsers (Chrome, Edge, Brave, etc.)

For Chromium-based browsers, profiles are typically named "Default", "Profile 1", "Profile 2", etc.:

```python
#!python

>>> import browser_cookie3
>>> import requests

# Load cookies from the default profile (default behavior)
>>> cj = browser_cookie3.chrome()

# Load cookies from a specific profile
>>> cj = browser_cookie3.chrome(profile_name="Profile 1")
>>> cj = browser_cookie3.chrome(profile_name="Default")
>>> cj = browser_cookie3.edge(profile_name="Profile 2")
```

#### Firefox-based browsers (Firefox, LibreWolf)

For Firefox-based browsers, profiles are named according to your profiles.ini file:

```python
#!python

>>> import browser_cookie3
>>> import requests

# Load cookies from default profile (default behavior)
>>> cj = browser_cookie3.firefox()

# Load cookies from a specific profile by name
>>> cj = browser_cookie3.firefox(profile_name="default-release")
>>> cj = browser_cookie3.librewolf(profile_name="Profile0")
```

#### Listing Available Profiles

You can list all available profiles for any browser:

```python
#!python

>>> import browser_cookie3

# List profiles for a specific browser
>>> profiles = browser_cookie3.list_chrome_profiles()
>>> print(profiles)
['Default', 'Profile 1', 'Profile 2']

>>> profiles = browser_cookie3.list_firefox_profiles()
>>> print(profiles)
['default-release', 'Profile0', 'work-profile']

# List profiles using the generic function
>>> profiles = browser_cookie3.list_profiles('chrome')
>>> print(profiles)
['Default', 'Profile 1']

# List profiles for all browsers
>>> all_profiles = browser_cookie3.list_profiles()
>>> print(all_profiles)
{
    'chrome': ['Default', 'Profile 1'],
    'firefox': ['default-release'],
    'edge': ['Default', 'Profile 1', 'Profile 2']
}

# Available list functions for each browser:
>>> browser_cookie3.list_chrome_profiles()
>>> browser_cookie3.list_chromium_profiles()
>>> browser_cookie3.list_edge_profiles()
>>> browser_cookie3.list_brave_profiles()
>>> browser_cookie3.list_opera_profiles()
>>> browser_cookie3.list_opera_gx_profiles()
>>> browser_cookie3.list_vivaldi_profiles()
>>> browser_cookie3.list_arc_profiles()
>>> browser_cookie3.list_firefox_profiles()
>>> browser_cookie3.list_librewolf_profiles()
```

#### Combining Profile Selection with Domain Filtering

You can combine profile selection with domain filtering:

```python
#!python

>>> import browser_cookie3
>>> import requests

# Load cookies from a specific profile and domain
>>> cj = browser_cookie3.chrome(
...     profile_name="Profile 1",
...     domain_name="example.com"
... )
>>> r = requests.get('https://example.com', cookies=cj)
```

## Command-line usage

Run `browser-cookie --help` for all options. Brief examples:

```sh
$ browser-cookie --firefox stackoverflow.com acct
t=BASE64_STRING_DESCRIBING_YOUR_STACKOVERFLOW_ACCOUNT

$ browser-cookie --json --chrome stackoverflow.com acct
{"version": 0, "name": "acct", "value": "t=BASE64_STRING_DESCRIBING_YOUR_STACKOVERFLOW_ACCOUNT",
"port_specified": false, "domain": ".stackoverflow.com", "domain_specified": true,
"domain_initial_dot": true, "path": "/", "path_specified": true, "secure": 1,
"expires": 1657049738, "discard": false, "rfc2109": false}

$ browser-cookie nonexistent-domain.com nonexistent-cookie && echo "Cookie found" || echo "No cookie found"
No cookie found
```

### Profile Selection via Command Line

You can specify a profile using the `--profile` or `-p` option:

```sh
# Load cookies from a specific Chrome profile
$ browser-cookie --chrome --profile "Profile 1" example.com cookie_name

# Load cookies from a specific Firefox profile
$ browser-cookie --firefox --profile "default-release" example.com cookie_name

# List all available profiles for a browser
$ browser-cookie --chrome --list-profiles
Default
Profile 1
Profile 2

$ browser-cookie --firefox --list-profiles
default-release
Profile0
work-profile
```

## Advanced Features

### Multi-Profile Support

browser_cookie3 supports loading cookies from specific browser profiles. See [EXAMPLES.md](EXAMPLES.md) for detailed examples.

**Quick Start:**
```python
# List available profiles
profiles = browser_cookie3.list_chrome_profiles()

# Load from specific profile
cj = browser_cookie3.chrome(profile_name="Profile 1")
```

**Command Line:**
```bash
# List profiles
$ browser-cookie --chrome --list-profiles

# Use specific profile
$ browser-cookie --chrome --profile "Profile 1" example.com cookie_name
```

## Fresh cookie files
Creating and testing a fresh cookie file can help eliminate some possible user specific issues. It also allows you to upload a cookie file you are having issues with, since you should never upload your main cookie file!
### Chrome and chromium
For linux and assumably mac:

Run `google-chrome-stable --user-data-dir=browser_cookie3 #replace google-chrome-stable with your command to start chrome/chromium` and when you close the browser you will have a new cookie file at `browser_cookie3/Default/Cookies`

If you want to share a cookie file then visit some site that will generate cookie (without logging in!), example https://www.theverge.com/ will save cookies after you accept the GDPR notice.

## Planned backwards incompatible changes for 1.0
- more sensible cookie file checking order, like first using the default defined in profiles.ini for FireFox-based browsers

## Contribute
So far the following platforms are supported:

* **Chrome:** Linux, MacOS, Windows
* **Firefox:** Linux, MacOS, Windows
* **LibreWolf:** Linux, MacOS, Windows
* **Opera:** Linux, MacOS, Windows
* **Opera GX:** MacOS, Windows
* **Edge:** Linux, MacOS, Windows
* **Chromium:** Linux, MacOS, Windows
* **Brave:** Linux, MacOS, Windows
* **Vivaldi:** Linux, MacOS, Windows
* **Safari:** MacOS
* **W3m:** Linux
* **Lynx:** Linux

You are welcome to contribute support for other browsers, or other platforms.

## Testing Dates  (dd/mm/yy)

Browser  |  Linux   |  MacOS   | Windows  |
:------  | :------: | :------: | :------: |
Chrome   | 31/01/23 | 31/01/23 | 31/01/23 |
Firefox  | 05/06/23 | 05/06/23 | 05/06/23 |
LibreWolf| 05/06/23 | 05/06/23 | 05/06/23 |
Opera    | 31/01/23 | 31/01/23 | 31/01/23 |
Opera GX |    -     | 31/01/23 | 31/01/23 |
Edge     | 31/01/23 | 31/01/23 | 31/01/23 |
Chromium | 07/24/21 | 15/06/22 | 15/06/22 |
Brave    | 31/01/23 | 31/01/23 | 31/01/23 |
Vivaldi  | 31/01/23 | 31/01/23 | 15/06/22 |
Safari   |    -     | 31/01/23 |    -     |
W3m      | 05/07/23 |    -     |    -     |
Lynx     | 05/07/23 |    -     |    -     |

However I only tested on a single version of each browser and so am not sure if the cookie sqlite format changes location or format in earlier/later versions. If you experience a problem please [open an issue](https://github.com/borisbabic/browser_cookie3/issues/new) which includes details of the browser version and operating system. Also patches to support other browsers are very welcome, particularly for Chrome and Internet Explorer on Windows.

## Acknowledgements ##
Special thanks to Nathan Henrie for his example of [how to decode the Chrome cookies](http://n8henrie.com/2013/11/use-chromes-cookies-for-easier-downloading-with-python-requests/).

[PyPi-downloads]: https://img.shields.io/pypi/dm/browser-cookie3
[PyPi-url]: https://pypi.org/project/browser-cookie3/
[License-shield]: https://img.shields.io/github/license/borisbabic/browser_cookie3?color=00aaaa
[License-url]: https://github.com/borisbabic/browser_cookie3/blob/master/LICENSE
[PyPi-version]: https://img.shields.io/pypi/v/browser-cookie3?color=00aa00
