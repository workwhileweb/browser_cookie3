# -*- coding: utf-8 -*-

import argparse
import browser_cookie3
import json
import sys


def parse_args(args=None):
    p = argparse.ArgumentParser(
        description='Extract browser cookies using browser_cookie3.',
        epilog='Exit status is 0 if cookie was found, 1 if not found, and 2 if errors occurred',
    )
    p.add_argument('-j', '--json', action='store_true',
                   help="Output JSON with all cookie details, rather than just the cookie's value")
    p.add_argument('domain')
    p.add_argument('name')

    g = p.add_argument_group('Browser selection')
    x = g.add_mutually_exclusive_group()
    x.add_argument('-a', '--all', dest='browser', action='store_const', const=None, default=None,
                   help="Try to load cookies from all supported browsers")
    for browser in browser_cookie3.all_browsers:
        x.add_argument('--' + browser.__name__, dest='browser', action='store_const', const=browser,
                       help="Load cookies from {} browser".format(browser.__name__.title()))
    g.add_argument('-f', '--cookie-file',
                   help="Use specific cookie file (default is to autodetect).")
    g.add_argument('-k', '--key-file',
                   help="Use specific key file (default is to autodetect).")
    g.add_argument('-p', '--profile',
                   help="Use specific profile name (e.g., 'Default', 'Profile 1', or Firefox profile name).")
    g.add_argument('-l', '--list-profiles', action='store_true',
                   help="List all available profiles for the specified browser and exit.")

    args = p.parse_args(args)

    if not args.browser and (args.cookie_file or args.key_file):
        p.error("Must specify a specific browser with --cookie-file or --key-file arguments")

    return p, args


def main(args=None):
    p, args = parse_args(args)

    # Handle list-profiles option
    if args.list_profiles:
        if not args.browser:
            p.error("Must specify a browser with --list-profiles (e.g., --chrome, --firefox)")
        
        # Map browser function to browser name
        browser_names = {
            browser_cookie3.chrome: 'chrome',
            browser_cookie3.arc: 'arc',
            browser_cookie3.chromium: 'chromium',
            browser_cookie3.opera: 'opera',
            browser_cookie3.opera_gx: 'opera_gx',
            browser_cookie3.brave: 'brave',
            browser_cookie3.edge: 'edge',
            browser_cookie3.vivaldi: 'vivaldi',
            browser_cookie3.firefox: 'firefox',
            browser_cookie3.librewolf: 'librewolf',
        }
        
        browser_name = browser_names.get(args.browser, 'unknown')
        try:
            profiles = browser_cookie3.list_profiles(browser_name)
            if profiles:
                for profile in profiles:
                    print(profile)
            else:
                print(f'No profiles found for {browser_name}', file=sys.stderr)
                raise SystemExit(1)
        except browser_cookie3.BrowserCookieError as e:
            p.error(e.args[0])
        return

    try:
        if args.browser:
            # Build kwargs for browser function
            browser_kwargs = {}
            if args.cookie_file:
                browser_kwargs['cookie_file'] = args.cookie_file
            if args.key_file:
                browser_kwargs['key_file'] = args.key_file
            if args.profile:
                browser_kwargs['profile_name'] = args.profile
            cj = args.browser(**browser_kwargs)
        else:
            cj = browser_cookie3.load(profile_name=args.profile if args.profile else None)
    except browser_cookie3.BrowserCookieError as e:
        p.error(e.args[0])

    for cookie in cj:
        if cookie.domain in (args.domain, '.' + args.domain) and cookie.name == args.name:
            if not args.json:
                print(cookie.value)
            else:
                print(json.dumps({k: v for k, v in vars(cookie).items()
                                  if v is not None and (k, v) != ('_rest', {})}))
            break
    else:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
