# browser_cookie3 Examples

This document provides comprehensive examples for using browser_cookie3's multi-profile support and profile listing features.

## Table of Contents

1. [Listing Available Profiles](#listing-available-profiles)
2. [Loading Cookies from Specific Profiles](#loading-cookies-from-specific-profiles)
3. [Combining Profile Selection with Domain Filtering](#combining-profile-selection-with-domain-filtering)
4. [Working with Firefox Profiles](#working-with-firefox-profiles)
5. [Command-Line Usage](#command-line-usage)
6. [Practical Use Cases](#practical-use-cases)

## Listing Available Profiles

### List Profiles for a Specific Browser

```python
import browser_cookie3

# List Chrome profiles
chrome_profiles = browser_cookie3.list_chrome_profiles()
print(chrome_profiles)  # ['Default', 'Profile 1', 'Profile 2']

# List Firefox profiles
firefox_profiles = browser_cookie3.list_firefox_profiles()
print(firefox_profiles)  # ['default-release', 'Profile0']

# List Edge profiles
edge_profiles = browser_cookie3.list_edge_profiles()
print(edge_profiles)  # ['Default', 'Profile 1']

# List profiles for other browsers
brave_profiles = browser_cookie3.list_brave_profiles()
opera_profiles = browser_cookie3.list_opera_profiles()
vivaldi_profiles = browser_cookie3.list_vivaldi_profiles()
librewolf_profiles = browser_cookie3.list_librewolf_profiles()
```

### List Profiles Using Generic Function

```python
import browser_cookie3

# List profiles for a specific browser
profiles = browser_cookie3.list_profiles('chrome')
print(profiles)  # ['Default', 'Profile 1']

# List profiles for all browsers
all_profiles = browser_cookie3.list_profiles()
print(all_profiles)
# Output:
# {
#     'chrome': ['Default', 'Profile 1'],
#     'firefox': ['default-release'],
#     'edge': ['Default', 'Profile 1', 'Profile 2'],
#     'brave': ['Default']
# }
```

### Handle Errors When Listing Profiles

```python
import browser_cookie3

try:
    profiles = browser_cookie3.list_chrome_profiles()
    if profiles:
        print(f"Found {len(profiles)} profiles: {profiles}")
    else:
        print("No profiles found")
except browser_cookie3.BrowserCookieError as e:
    print(f"Error: {e}")
```

## Loading Cookies from Specific Profiles

### Chromium-based Browsers

For Chromium-based browsers (Chrome, Edge, Brave, Opera, etc.), profiles are typically named:
- `"Default"` - The default profile
- `"Profile 1"`, `"Profile 2"`, etc. - Additional profiles

```python
import browser_cookie3
import requests

# Load from default profile (default behavior)
cj = browser_cookie3.chrome()

# Load from a specific profile
cj = browser_cookie3.chrome(profile_name="Profile 1")
cj = browser_cookie3.chrome(profile_name="Default")

# Works with all Chromium-based browsers
cj = browser_cookie3.edge(profile_name="Profile 2")
cj = browser_cookie3.brave(profile_name="Default")
cj = browser_cookie3.opera(profile_name="Profile 1")
cj = browser_cookie3.vivaldi(profile_name="Default")
```

### Firefox-based Browsers

For Firefox-based browsers, profiles are named according to your `profiles.ini` file:

```python
import browser_cookie3
import requests

# Load from default profile
cj = browser_cookie3.firefox()

# Load from a specific profile by name
cj = browser_cookie3.firefox(profile_name="default-release")
cj = browser_cookie3.firefox(profile_name="Profile0")
cj = browser_cookie3.firefox(profile_name="work-profile")

# Works with LibreWolf too
cj = browser_cookie3.librewolf(profile_name="default-release")
```

### Complete Example: Load and Use Cookies

```python
import browser_cookie3
import requests

# List available profiles
profiles = browser_cookie3.list_chrome_profiles()
print(f"Available profiles: {profiles}")

# Load cookies from a specific profile
if profiles:
    profile_name = profiles[0]  # Use first profile
    cj = browser_cookie3.chrome(profile_name=profile_name)
    
    # Use cookies with requests
    r = requests.get('https://example.com', cookies=cj)
    print(f"Status code: {r.status_code}")
```

## Combining Profile Selection with Domain Filtering

You can combine profile selection with domain filtering to get cookies from a specific profile for a specific domain:

```python
import browser_cookie3
import requests

# Load cookies from Profile 1 for github.com only
cj = browser_cookie3.chrome(
    profile_name="Profile 1",
    domain_name="github.com"
)

# Count cookies
cookie_count = len(list(cj))
print(f"Found {cookie_count} cookies for github.com in Profile 1")

# Use with requests
r = requests.get('https://github.com', cookies=cj)
```

### Iterate Through All Profiles for a Domain

```python
import browser_cookie3

domain = "github.com"
profiles = browser_cookie3.list_chrome_profiles()

for profile_name in profiles:
    try:
        cj = browser_cookie3.chrome(
            profile_name=profile_name,
            domain_name=domain
        )
        cookies = list(cj)
        print(f"{profile_name}: {len(cookies)} cookies for {domain}")
    except browser_cookie3.BrowserCookieError as e:
        print(f"{profile_name}: Error - {e}")
```

## Working with Firefox Profiles

Firefox profiles are managed differently than Chromium-based browsers:

```python
import browser_cookie3

# List Firefox profiles
firefox_profiles = browser_cookie3.list_firefox_profiles()
print(f"Firefox profiles: {firefox_profiles}")

# Load from a specific profile
if firefox_profiles:
    profile_name = firefox_profiles[0]
    cj = browser_cookie3.firefox(profile_name=profile_name)
    
    # Use cookies
    import requests
    r = requests.get('https://example.com', cookies=cj)
```

## Command-Line Usage

### List Profiles

```bash
# List Chrome profiles
$ browser-cookie --chrome --list-profiles
Default
Profile 1
Profile 2

# List Firefox profiles
$ browser-cookie --firefox --list-profiles
default-release
Profile0
work-profile

# List Edge profiles
$ browser-cookie --edge --list-profiles
Default
Profile 1
```

### Use Specific Profile

```bash
# Get a cookie from a specific Chrome profile
$ browser-cookie --chrome --profile "Profile 1" example.com cookie_name

# Get a cookie from a specific Firefox profile
$ browser-cookie --firefox --profile "default-release" example.com cookie_name

# Get JSON output with profile selection
$ browser-cookie --json --chrome --profile "Profile 2" example.com cookie_name
```

## Practical Use Cases

### Use Case 1: Work vs Personal Profiles

```python
import browser_cookie3
import requests

# You have separate work and personal Chrome profiles
profiles = browser_cookie3.list_chrome_profiles()

# Find work profile
work_profile = next((p for p in profiles if 'work' in p.lower()), None)

if work_profile:
    # Load work profile cookies
    cj = browser_cookie3.chrome(profile_name=work_profile)
    
    # Access work-related sites
    r = requests.get('https://work-site.com', cookies=cj)
    print(f"Accessed work site with {len(list(cj))} cookies")
```

### Use Case 2: Testing with Different Profiles

```python
import browser_cookie3

# Test the same site with different profiles
site = "example.com"
profiles = browser_cookie3.list_chrome_profiles()

for profile_name in profiles:
    try:
        cj = browser_cookie3.chrome(
            profile_name=profile_name,
            domain_name=site
        )
        cookies = list(cj)
        print(f"{profile_name}: {len(cookies)} cookies for {site}")
    except browser_cookie3.BrowserCookieError as e:
        print(f"{profile_name}: {e}")
```

### Use Case 3: Aggregate Cookies from Multiple Profiles

```python
import browser_cookie3
import http.cookiejar

# Combine cookies from multiple profiles
combined_cj = http.cookiejar.CookieJar()
profiles = browser_cookie3.list_chrome_profiles()

for profile_name in profiles:
    try:
        cj = browser_cookie3.chrome(profile_name=profile_name)
        for cookie in cj:
            combined_cj.set_cookie(cookie)
    except browser_cookie3.BrowserCookieError:
        pass

print(f"Combined {len(list(combined_cj))} cookies from {len(profiles)} profiles")
```

### Use Case 4: Profile-Specific Cookie Analysis

```python
import browser_cookie3
from collections import Counter

# Analyze cookies across all profiles
profiles = browser_cookie3.list_chrome_profiles()
domain_counter = Counter()

for profile_name in profiles:
    try:
        cj = browser_cookie3.chrome(profile_name=profile_name)
        for cookie in cj:
            domain_counter[cookie.domain] += 1
    except browser_cookie3.BrowserCookieError:
        pass

# Show most common domains
print("Most common domains across all profiles:")
for domain, count in domain_counter.most_common(10):
    print(f"  {domain}: {count} cookies")
```

### Use Case 5: Load from All Browsers with Profile Support

```python
import browser_cookie3

# Load cookies from all browsers (using default profile for each)
cj = browser_cookie3.load()
print(f"Total cookies from all browsers: {len(list(cj))}")

# Note: You can also specify a profile_name, but it will only work
# if all browsers have a profile with that name
# cj = browser_cookie3.load(profile_name="Default")
```

## Error Handling

Always handle errors when working with profiles:

```python
import browser_cookie3

try:
    # List profiles
    profiles = browser_cookie3.list_chrome_profiles()
    
    if not profiles:
        print("No profiles found")
        return
    
    # Load from profile
    cj = browser_cookie3.chrome(profile_name=profiles[0])
    
except browser_cookie3.BrowserCookieError as e:
    print(f"Browser cookie error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Notes

- **Profile Names**: 
  - Chromium-based browsers: Use exact names like `"Default"`, `"Profile 1"`, `"Profile 2"`, etc.
  - Firefox-based browsers: Use profile names from `profiles.ini` (e.g., `"default-release"`, `"Profile0"`)

- **Default Behavior**: If `profile_name` is not specified, the default profile is used (same as before)

- **Profile Discovery**: The `list_profiles()` functions scan the browser's data directories to find available profiles

- **Error Handling**: If a specified profile doesn't exist, a `BrowserCookieError` is raised

- **Backward Compatibility**: All existing code continues to work without changes

