#!/usr/bin/env python3
"""
Examples demonstrating browser_cookie3 multi-profile support and profile listing features.

This file contains practical examples of how to use the new profile-related features
in browser_cookie3. Focused on Chrome only.
"""

import browser_cookie3


def example_list_profiles():
    """Example: List all available Chrome profiles"""
    print("=" * 60)
    print("Example 1: Listing Available Chrome Profiles")
    print("=" * 60)
    
    # List Chrome profiles
    try:
        chrome_profiles = browser_cookie3.list_chrome_profiles()
        print(f"\nChrome profiles: {chrome_profiles}")
        return chrome_profiles
    except browser_cookie3.BrowserCookieError as e:
        print(f"\nChrome not found or no profiles: {e}")
        return []


def example_load_from_specific_profile():
    """Example: Load cookies from a specific browser profile"""
    print("\n" + "=" * 60)
    print("Example 2: Loading Cookies from Specific Profile")
    print("=" * 60)
    
    # First, list available profiles
    try:
        profiles = browser_cookie3.list_chrome_profiles()
        if profiles:
            print(f"\nAvailable Chrome profiles: {profiles}")
            
            # Load cookies from the first non-default profile (if available)
            if len(profiles) > 1:
                profile_name = profiles[1]  # Use second profile
                print(f"\nLoading cookies from profile: {profile_name}")
                try:
                    cj = browser_cookie3.chrome(profile_name=profile_name)
                    cookie_list = list(cj)
                    print(f"Loaded {len(cookie_list)} cookies from {profile_name}")
                    if cookie_list:
                        print(f"Sample cookie domains: {set(c.domain for c in cookie_list[:5])}")
                except browser_cookie3.BrowserCookieError as e:
                    print(f"\nError loading from {profile_name}: {e}")
                    print("Note: On Windows, make sure Chrome is closed and the Local State file is accessible.")
                    print("The encryption key is shared across all profiles and is stored in:")
                    print("  %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State")
            else:
                print("\nOnly default profile available, loading from default...")
                cj = browser_cookie3.chrome()
                print(f"Loaded {len(list(cj))} cookies from default profile")
        else:
            print("\nNo Chrome profiles found")
    except browser_cookie3.BrowserCookieError as e:
        print(f"\nError: {e}")


def example_profile_with_domain_filter():
    """Example: Combine profile selection with domain filtering"""
    print("\n" + "=" * 60)
    print("Example 3: Profile Selection + Domain Filtering")
    print("=" * 60)
    
    try:
        # Load cookies from a specific profile for a specific domain
        cj = browser_cookie3.chrome(
            profile_name="Default",
            domain_name="github.com"
        )
        
        cookies = list(cj)
        print(f"\nFound {len(cookies)} cookies for github.com in Default profile")
        
        # Show cookie names
        for cookie in cookies[:5]:  # Show first 5
            print(f"  - {cookie.name}")
        if len(cookies) > 5:
            print(f"  ... and {len(cookies) - 5} more")
            
    except browser_cookie3.BrowserCookieError as e:
        print(f"\nError: {e}")


def example_iterate_all_profiles():
    """Example: Iterate through all profiles and load cookies"""
    print("\n" + "=" * 60)
    print("Example 5: Iterating Through All Profiles")
    print("=" * 60)
    
    try:
        profiles = browser_cookie3.list_chrome_profiles()
        print(f"\nFound {len(profiles)} Chrome profiles")
        
        for profile_name in profiles:
            try:
                cj = browser_cookie3.chrome(profile_name=profile_name)
                cookie_count = len(list(cj))
                print(f"  {profile_name}: {cookie_count} cookies")
            except browser_cookie3.BrowserCookieError as e:
                print(f"  {profile_name}: Error - {e}")
                
    except browser_cookie3.BrowserCookieError as e:
        print(f"\nError: {e}")


def example_test_default_profile():
    """Example: Test loading from default profile"""
    print("\n" + "=" * 60)
    print("Example 4: Testing Default Profile")
    print("=" * 60)
    
    try:
        print("\nLoading cookies from default Chrome profile...")
        cj = browser_cookie3.chrome()
        cookies = list(cj)
        print(f"Successfully loaded {len(cookies)} cookies from default profile")
        if cookies:
            print(f"Sample domains: {set(c.domain for c in cookies[:10])}")
    except browser_cookie3.BrowserCookieError as e:
        print(f"\nError: {e}")


def example_practical_use_case():
    """Example: Practical use case - accessing a site with specific profile"""
    print("\n" + "=" * 60)
    print("Example 7: Practical Use Case")
    print("=" * 60)
    
    print("\nScenario: You have a work profile and personal profile in Chrome.")
    print("You want to access a website using your work profile cookies.\n")
    
    try:
        # List profiles
        profiles = browser_cookie3.list_chrome_profiles()
        print(f"Available profiles: {profiles}")
        
        # Find work profile (assuming it contains "work" or "Work" in the name)
        work_profile = None
        for profile in profiles:
            if 'work' in profile.lower() or 'Work' in profile:
                work_profile = profile
                break
        
        if work_profile:
            print(f"\nUsing work profile: {work_profile}")
            cj = browser_cookie3.chrome(profile_name=work_profile)
            
            # Use cookies with requests
            try:
                # Example: Access a site that requires authentication
                r = requests.get('https://httpbin.org/cookies', cookies=cj, timeout=5)
                print(f"Successfully made request with {len(list(cj))} cookies")
                print(f"Response status: {r.status_code}")
            except Exception as e:
                print(f"Request failed: {e}")
        else:
            print("\nNo work profile found, using default profile")
            cj = browser_cookie3.chrome()
            print(f"Loaded {len(list(cj))} cookies from default profile")
            
    except browser_cookie3.BrowserCookieError as e:
        print(f"\nError: {e}")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("browser_cookie3 Chrome Profile Examples")
    print("=" * 60)
    
    # Run examples
    profiles = example_list_profiles()
    example_test_default_profile()
    example_load_from_specific_profile()
    example_profile_with_domain_filter()
    example_iterate_all_profiles()
    example_practical_use_case()
    
    print("\n" + "=" * 60)
    print("Examples completed!")
    print("=" * 60 + "\n")

