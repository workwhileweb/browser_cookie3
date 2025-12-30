# -*- coding: utf-8 -*-

import base64
import configparser
import contextlib
import glob
import http.cookiejar
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Union


if sys.platform.startswith('linux') or 'bsd' in sys.platform.lower():
    try:
        import jeepney
        from jeepney.io.blocking import open_dbus_connection
        USE_DBUS_LINUX = False
    except ImportError:
        import dbus
        USE_DBUS_LINUX = True


shadowcopy = None
if sys.platform == 'win32':
    try:
        import shadowcopy
    except ImportError:
        pass


# external dependencies
import lz4.block
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.Padding import unpad

__doc__ = 'Load browser cookies into a cookiejar'

CHROMIUM_DEFAULT_PASSWORD = b'peanuts'


class BrowserCookieError(Exception):
    pass


def _windows_group_policy_path():
    # we know that we're running under windows at this point so it's safe to do these imports
    from winreg import (HKEY_LOCAL_MACHINE, REG_EXPAND_SZ, REG_SZ,
                        ConnectRegistry, OpenKeyEx, QueryValueEx)
    try:
        root = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        policy_key = OpenKeyEx(root, r"SOFTWARE\Policies\Google\Chrome")
        user_data_dir, type_ = QueryValueEx(policy_key, "UserDataDir")
        if type_ == REG_EXPAND_SZ:
            user_data_dir = os.path.expandvars(user_data_dir)
        elif type_ != REG_SZ:
            return None
    except OSError:
        return None
    return os.path.join(user_data_dir, "Default", "Cookies")


# Code adapted slightly from https://github.com/Arnie97/chrome-cookies
def _crypt_unprotect_data(
        cipher_text=b'', entropy=b'', reserved=None, prompt_struct=None, is_key=False
):
    # we know that we're running under windows at this point so it's safe to try these imports
    import ctypes
    import ctypes.wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [
            ('cbData', ctypes.wintypes.DWORD),
            ('pbData', ctypes.POINTER(ctypes.c_char))
        ]

    blob_in, blob_entropy, blob_out = map(
        lambda x: DataBlob(len(x), ctypes.create_string_buffer(x)),
        [cipher_text, entropy, b'']
    )
    desc = ctypes.c_wchar_p()

    CRYPTPROTECT_UI_FORBIDDEN = 0x01

    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), ctypes.byref(
                desc), ctypes.byref(blob_entropy),
            reserved, prompt_struct, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(
                blob_out)
    ):
        raise RuntimeError('Failed to decrypt the cipher text with DPAPI')

    description = desc.value
    buffer_out = ctypes.create_string_buffer(int(blob_out.cbData))
    ctypes.memmove(buffer_out, blob_out.pbData, blob_out.cbData)
    map(ctypes.windll.kernel32.LocalFree, [desc, blob_out.pbData])
    if is_key:
        return description, buffer_out.raw
    else:
        return description, buffer_out.value


def _get_osx_keychain_password(osx_key_service, osx_key_user):
    """Retrieve password used to encrypt cookies from OSX Keychain"""

    cmd = ['/usr/bin/security', '-q', 'find-generic-password',
           '-w', '-a', osx_key_user, '-s', osx_key_service]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    out, err = proc.communicate()
    if proc.returncode != 0:
        return CHROMIUM_DEFAULT_PASSWORD     # default password, probably won't work
    return out.strip()


def _expand_win_path(path: Union[dict, str]):
    if not isinstance(path, dict):
        path = {'path': path, 'env': 'APPDATA'}
    return os.path.join(os.getenv(path['env'], ''), path['path'])


def _expand_paths_impl(paths: list, os_name: str):
    """Expands user paths on Linux, OSX, and windows"""

    os_name = os_name.lower()
    assert os_name in ['windows', 'osx', 'linux']

    if not isinstance(paths, list):
        paths = [paths]

    if os_name == 'windows':
        paths = map(_expand_win_path, paths)
    else:
        paths = map(os.path.expanduser, paths)

    for path in paths:
        # glob will return results in arbitrary order. sorted() is use to make output predictable.
        for i in sorted(glob.glob(path)):
            # can use return here without using `_expand_paths()` below.
            yield i
            # but using generator can be useful if we plan to parse all `Cookies` files later.


def _expand_paths(paths: list, os_name: str):
    return next(_expand_paths_impl(paths, os_name), None)


def _expand_paths_all(paths: list, os_name: str):
    """Expands paths and returns all matches as a list"""
    return list(_expand_paths_impl(paths, os_name))


def _normalize_genarate_paths_chromium(paths: Union[str, list], channel: Union[str, list] = None):
    channel = channel or ['']
    if not isinstance(channel, list):
        channel = [channel]
    if not isinstance(paths, list):
        paths = [paths]
    return paths, channel


def _genarate_nix_paths_chromium(paths: Union[str, list], channel: Union[str, list] = None):
    """Generate paths for chromium based browsers on *nix systems."""

    paths, channel = _normalize_genarate_paths_chromium(paths, channel)
    genararated_paths = []
    for chan in channel:
        for path in paths:
            genararated_paths.append(path.format(channel=chan))
    return genararated_paths


def _genarate_win_paths_chromium(paths: Union[str, list], channel: Union[str, list] = None):
    """Generate paths for chromium based browsers on windows"""

    paths, channel = _normalize_genarate_paths_chromium(paths, channel)
    genararated_paths = []
    for chan in channel:
        for path in paths:
            genararated_paths.append(
                {'env': 'APPDATA', 'path': '..\\Local\\' + path.format(channel=chan)})
            genararated_paths.append(
                {'env': 'LOCALAPPDATA', 'path': path.format(channel=chan)})
            genararated_paths.append(
                {'env': 'APPDATA', 'path': path.format(channel=chan)})
    return genararated_paths


def _text_factory(data):
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return data


class _JeepneyConnection:
    def __init__(self, object_path, bus_name, interface):
        self.__dbus_address = jeepney.DBusAddress(
            object_path, bus_name, interface)

    def __enter__(self):
        self.__connection = open_dbus_connection()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.__connection.close()

    def close(self):
        self.__connection.close()

    def call_method(self, method_name, signature=None, *args):
        method = jeepney.new_method_call(
            self.__dbus_address, method_name, signature, args)
        response = self.__connection.send_and_get_reply(method)
        if response.header.message_type == jeepney.MessageType.error:
            raise RuntimeError(response.body[0])
        return response.body[0] if len(response.body) == 1 else response.body


class _LinuxPasswordManager:
    """Retrieve password used to encrypt cookies from KDE Wallet or SecretService"""

    _APP_ID = 'browser-cookie3'

    def __init__(self, use_dbus):
        if use_dbus:
            self.__methods_map = {
                'kwallet': self.__get_kdewallet_password_dbus,
                'secretstorage': self.__get_secretstorage_item_dbus
            }
        else:
            self.__methods_map = {
                'kwallet': self.__get_kdewallet_password_jeepney,
                'secretstorage': self.__get_secretstorage_item_jeepney
            }

    def get_password(self, os_crypt_name):
        try:
            return self.__get_secretstorage_password(os_crypt_name)
        except RuntimeError:
            pass
        try:
            return self.__methods_map.get('kwallet')(os_crypt_name)
        except RuntimeError:
            pass
        # try default peanuts password, probably won't work
        return CHROMIUM_DEFAULT_PASSWORD

    def __get_secretstorage_password(self, os_crypt_name):
        schemas = ['chrome_libsecret_os_crypt_password_v2',
                   'chrome_libsecret_os_crypt_password_v1']
        for schema in schemas:
            try:
                return self.__methods_map.get('secretstorage')(schema, os_crypt_name)
            except RuntimeError:
                pass
        raise RuntimeError(f'Can not find secret for {os_crypt_name}')

    def __get_secretstorage_item_dbus(self, schema: str, application: str):
        with contextlib.closing(dbus.SessionBus()) as connection:
            try:
                secret_service = dbus.Interface(
                    connection.get_object(
                        'org.freedesktop.secrets', '/org/freedesktop/secrets', False),
                    'org.freedesktop.Secret.Service',
                )
            except dbus.exceptions.DBusException:
                raise RuntimeError(
                    "The name org.freedesktop.secrets was not provided by any .service files")
            object_path = secret_service.SearchItems({
                'xdg:schema': schema,
                'application': application,
            })
            object_path = list(filter(lambda x: len(x), object_path))
            if len(object_path) == 0:
                raise RuntimeError(f'Can not find secret for {application}')
            object_path = object_path[0][0]

            secret_service.Unlock([object_path])
            _, session = secret_service.OpenSession(
                'plain', dbus.String('', variant_level=1))
            _, _, secret, _ = secret_service.GetSecrets(
                [object_path], session)[object_path]
            return bytes(secret)

    def __get_kdewallet_password_dbus(self, os_crypt_name):
        folder = f'{os_crypt_name.capitalize()} Keys'
        key = f'{os_crypt_name.capitalize()} Safe Storage'
        with contextlib.closing(dbus.SessionBus()) as connection:
            try:
                kwalletd5_object = connection.get_object(
                    'org.kde.kwalletd5', '/modules/kwalletd5', False)
            except dbus.exceptions.DBusException:
                raise RuntimeError(
                    "The name org.kde.kwalletd5 was not provided by any .service files")
            kwalletd5 = dbus.Interface(kwalletd5_object, 'org.kde.KWallet')
            handle = kwalletd5.open(
                kwalletd5.networkWallet(), dbus.Int64(0), self._APP_ID)
            if not kwalletd5.hasFolder(handle, folder, self._APP_ID):
                kwalletd5.close(handle, False, self._APP_ID)
                raise RuntimeError(f'KDE Wallet folder {folder} not found.')
            password = kwalletd5.readPassword(
                handle, folder, key, self._APP_ID)
            kwalletd5.close(handle, False, self._APP_ID)
            return password.encode('utf-8')

    def __get_secretstorage_item_jeepney(self, schema, application):
        args = ['/org/freedesktop/secrets', 'org.freedesktop.secrets',
                'org.freedesktop.Secret.Service']
        with _JeepneyConnection(*args) as connection:
            object_path = connection.call_method(
                'SearchItems', 'a{ss}', {'xdg:schema': schema, 'application': application})
            object_path = list(filter(lambda x: len(x), object_path))
            if len(object_path) == 0:
                raise RuntimeError(f'Can not find secret for {application}')
            object_path = object_path[0][0]
            connection.call_method('Unlock', 'ao', [object_path])
            _, session = connection.call_method(
                'OpenSession', 'sv', 'plain', ('s', ''))
            _, _, secret, _ = connection.call_method(
                'GetSecrets', 'aoo', [object_path], session)[object_path]
            return secret

    def __get_kdewallet_password_jeepney(self, os_crypt_name):
        folder = f'{os_crypt_name.capitalize()} Keys'
        key = f'{os_crypt_name.capitalize()} Safe Storage'
        with _JeepneyConnection('/modules/kwalletd5', 'org.kde.kwalletd5', 'org.kde.KWallet') as connection:
            network_wallet = connection.call_method('networkWallet')
            handle = connection.call_method(
                'open', 'sxs', network_wallet, 0, self._APP_ID)
            has_folder = connection.call_method(
                'hasFolder', 'iss', handle, folder, self._APP_ID)
            if not has_folder:
                connection.call_method(
                    'close', 'ibs', handle, False, self._APP_ID)
                raise RuntimeError(f'KDE Wallet folder {folder} not found.')
            password = connection.call_method(
                'readPassword', 'isss', handle, folder, key, self._APP_ID)
            connection.call_method('close', 'ibs', handle, False, self._APP_ID)
            return password.encode('utf-8')


class _DatabaseConnetion():
    def __init__(self, database_file: os.PathLike, try_legacy_first: bool = False):
        self.__database_file = database_file
        self.__temp_cookie_file = None
        self.__connection = None
        self.__methods = [
            self.__sqlite3_connect_readonly,
        ]

        if try_legacy_first:
            self.__methods.insert(0, self.__get_connection_legacy)
        else:
            self.__methods.append(self.__get_connection_legacy)

        if shadowcopy:
            self.__methods.append(self.__get_connection_shadowcopy)

    def __enter__(self):
        return self.get_connection()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __check_connection_ok(self, connection):
        try:
            connection.cursor().execute('select 1 from sqlite_master')
            return True
        except sqlite3.OperationalError:
            return False

    def __sqlite3_connect_readonly(self):
        uri = Path(self.__database_file).absolute().as_uri()
        for options in ('?mode=ro', '?mode=ro&nolock=1', '?mode=ro&immutable=1'):
            try:
                con = sqlite3.connect(uri + options, uri=True)
            except sqlite3.OperationalError:
                continue
            if self.__check_connection_ok(con):
                return con

    def __get_connection_legacy(self):
        with tempfile.NamedTemporaryFile(suffix='.sqlite') as tf:
            self.__temp_cookie_file = tf.name
        try:
            shutil.copyfile(self.__database_file, self.__temp_cookie_file)
        except PermissionError:
            return
        con = sqlite3.connect(self.__temp_cookie_file)
        if self.__check_connection_ok(con):
            return con

    def __get_connection_shadowcopy(self):
        if not shadowcopy:
            raise RuntimeError("shadowcopy is not available")

        self.__temp_cookie_file = tempfile.NamedTemporaryFile(
            suffix='.sqlite').name
        shadowcopy.shadow_copy(self.__database_file, self.__temp_cookie_file)
        con = sqlite3.connect(self.__temp_cookie_file)
        if self.__check_connection_ok(con):
            return con

    def get_connection(self):
        if self.__connection:
            return self.__connection
        for method in self.__methods:
            con = method()
            if con is not None:
                self.__connection = con
                return con
        raise BrowserCookieError('Unable to read database file')

    def cursor(self):
        return self.connection().cursor()

    def close(self):
        if self.__connection:
            self.__connection.close()
        if self.__temp_cookie_file:
            try:
                os.remove(self.__temp_cookie_file)
            except Exception:
                pass


class ChromiumBased:
    """Super class for all Chromium based browsers"""

    # seconds from 1601-01-01T00:00:00Z to 1970-01-01T00:00:00Z
    UNIX_TO_NT_EPOCH_OFFSET = 11644473600

    def __init__(self, browser: str, cookie_file=None, domain_name="", key_file=None, profile_name=None, **kwargs):
        self.salt = b'saltysalt'
        self.iv = b' ' * 16
        self.length = 16
        self.browser = browser
        self.cookie_file = cookie_file
        self.domain_name = domain_name
        self.key_file = key_file
        self.profile_name = profile_name
        self.__add_key_and_cookie_file(**kwargs)

    def __add_key_and_cookie_file(self,
                                  linux_cookies=None, windows_cookies=None, osx_cookies=None,
                                  windows_keys=None, os_crypt_name=None, osx_key_service=None, osx_key_user=None):

        if sys.platform == 'darwin':
            password = _get_osx_keychain_password(
                osx_key_service, osx_key_user)
            iterations = 1003  # number of pbkdf2 iterations on mac
            self.v10_key = PBKDF2(password, self.salt, self.length, iterations)
            cookie_file = self.cookie_file or self.__find_cookie_file_with_profile(osx_cookies, 'osx')

        elif sys.platform.startswith('linux') or 'bsd' in sys.platform.lower():
            password = _LinuxPasswordManager(
                USE_DBUS_LINUX).get_password(os_crypt_name)
            iterations = 1
            self.v10_key = PBKDF2(CHROMIUM_DEFAULT_PASSWORD,
                                  self.salt, self.length, iterations)
            self.v11_key = PBKDF2(password, self.salt, self.length, iterations)

            # Due to a bug in previous version of chromium,
            # the key used to encrypt the cookies in some linux systems was empty
            # After the bug was fixed, old cookies are still encrypted with an empty key
            self.v11_empty_key = PBKDF2(
                b'', self.salt, self.length, iterations)

            cookie_file = self.cookie_file or self.__find_cookie_file_with_profile(
                linux_cookies, 'linux')

        elif sys.platform == "win32":
            key_file = self.key_file or _expand_paths(windows_keys, 'windows')

            if key_file:
                with open(key_file, 'rb') as f:
                    key_file_json = json.load(f)
                    key64 = key_file_json['os_crypt']['encrypted_key'].encode(
                        'utf-8')

                    # Decode Key, get rid of DPAPI prefix, unprotect data
                    keydpapi = base64.standard_b64decode(key64)[5:]
                    _, self.v10_key = _crypt_unprotect_data(
                        keydpapi, is_key=True)
            else:
                self.v10_key = None

            # get cookie file from APPDATA

            cookie_file = self.cookie_file

            if not cookie_file:
                if self.browser.lower() == 'chrome' and _windows_group_policy_path():
                    cookie_file = _windows_group_policy_path()
                else:
                    cookie_file = self.__find_cookie_file_with_profile(windows_cookies, 'windows')

        else:
            raise BrowserCookieError(
                "OS not recognized. Works on OSX, Windows, and Linux.")

        if not cookie_file:
            raise BrowserCookieError(
                'Failed to find cookies for {} browser'.format(self.browser))

        self.cookie_file = cookie_file

    def __find_cookie_file_with_profile(self, cookie_paths, os_name):
        """Find cookie file, optionally filtering by profile_name"""
        if not cookie_paths:
            return None
        
        # If profile_name is specified, try to find that specific profile
        if self.profile_name:
            # Replace Profile * pattern with the specific profile name
            specific_paths = []
            profile_name_lower = self.profile_name.lower()
            
            for path in cookie_paths:
                if 'Profile *' in path:
                    # Try multiple formats:
                    # 1. Exact profile name (e.g., "Profile 1")
                    # 2. Profile {name} if name doesn't start with "Profile "
                    # 3. Just the number if it's a number (e.g., "1" -> "Profile 1")
                    specific_paths.append(path.replace('Profile *', self.profile_name))
                    if not self.profile_name.startswith('Profile '):
                        specific_paths.append(path.replace('Profile *', f'Profile {self.profile_name}'))
                        # If it's just a number, also try "Profile {number}"
                        try:
                            int(self.profile_name)
                            specific_paths.append(path.replace('Profile *', f'Profile {self.profile_name}'))
                        except ValueError:
                            pass
                elif 'Default' in path:
                    if profile_name_lower == 'default':
                        specific_paths.append(path)
                    # Skip Default paths if looking for a specific non-default profile
                else:
                    # Keep other paths (might be useful for some browsers)
                    specific_paths.append(path)
            
            cookie_file = _expand_paths(specific_paths, os_name)
            if cookie_file:
                return cookie_file
        
        # If no profile_name specified or specific profile not found, use default behavior
        # This will find the first available cookie file (usually Default)
        return _expand_paths(cookie_paths, os_name)

    def __str__(self):
        return self.browser

    @classmethod
    def list_profiles(cls, browser: str, linux_cookies=None, windows_cookies=None, osx_cookies=None):
        """List all available profiles for this browser type"""
        profiles = []
        
        if sys.platform == 'darwin':
            cookie_paths = osx_cookies or []
        elif sys.platform.startswith('linux') or 'bsd' in sys.platform.lower():
            cookie_paths = linux_cookies or []
        elif sys.platform == "win32":
            cookie_paths = windows_cookies or []
        else:
            return profiles
        
        if not cookie_paths:
            return profiles
        
        # Find User Data directory by looking at cookie paths
        user_data_dirs = set()
        
        # Try to find existing cookie files to determine User Data location
        for path_template in cookie_paths:
            # Expand paths to find existing directories
            if sys.platform == 'win32':
                if isinstance(path_template, dict):
                    expanded_path = _expand_win_path(path_template)
                else:
                    continue
            else:
                expanded_path = os.path.expanduser(path_template)
            
            # Try glob pattern to find actual files
            if 'Profile *' in expanded_path or 'Default' in expanded_path:
                # Replace wildcards to find actual paths
                if 'Profile *' in expanded_path:
                    # Try to find all Profile directories
                    base_path = expanded_path.replace('Profile */Cookies', '').replace('Profile *\\Cookies', '')
                    if os.path.isdir(base_path):
                        try:
                            for item in os.listdir(base_path):
                                if item.startswith('Profile ') or item == 'Default':
                                    user_data_dirs.add(base_path)
                                    break
                        except (OSError, PermissionError):
                            pass
                elif 'Default' in expanded_path:
                    # Extract User Data directory
                    if 'User Data' in expanded_path:
                        user_data_idx = expanded_path.find('User Data')
                        if user_data_idx != -1:
                            user_data_dir = expanded_path[:user_data_idx + len('User Data')]
                            if os.path.isdir(user_data_dir):
                                user_data_dirs.add(user_data_dir)
                    else:
                        # Unix path - go up to find the directory containing Default
                        path_parts = expanded_path.split(os.sep)
                        for i in range(len(path_parts) - 1, 0, -1):
                            test_dir = os.sep.join(path_parts[:i])
                            if os.path.isdir(test_dir):
                                try:
                                    for item in os.listdir(test_dir):
                                        if item == 'Default' or item.startswith('Profile '):
                                            user_data_dirs.add(test_dir)
                                            break
                                except (OSError, PermissionError):
                                    pass
        
        # Now scan each User Data directory for profiles
        for user_data_dir in user_data_dirs:
            try:
                for item in os.listdir(user_data_dir):
                    item_path = os.path.join(user_data_dir, item)
                    if os.path.isdir(item_path):
                        # Check if it's a profile directory
                        if item == 'Default':
                            if 'Default' not in profiles:
                                profiles.append('Default')
                        elif item.startswith('Profile '):
                            profile_name = item
                            if profile_name not in profiles:
                                profiles.append(profile_name)
                        # Also check if it contains a Cookies file (might be a profile)
                        elif os.path.exists(os.path.join(item_path, 'Cookies')):
                            if item not in profiles:
                                profiles.append(item)
            except (OSError, PermissionError):
                continue
        
        return sorted(profiles)

    def load(self):
        """Load sqlite cookies into a cookiejar"""
        cj = http.cookiejar.CookieJar()

        with _DatabaseConnetion(self.cookie_file) as con:
            con.text_factory = _text_factory
            cur = con.cursor()
            has_integrity_check_for_cookie_domain = self._has_integrity_check_for_cookie_domain(cur)
            try:
                # chrome <=55
                cur.execute('SELECT host_key, path, secure, expires_utc, name, value, encrypted_value, is_httponly '
                            'FROM cookies WHERE host_key like ?;', ('%{}%'.format(self.domain_name),))
            except sqlite3.OperationalError:
                try:
                    # chrome >=56
                    cur.execute('SELECT host_key, path, is_secure, expires_utc, name, value, encrypted_value, is_httponly '
                                'FROM cookies WHERE host_key like ?;', ('%{}%'.format(self.domain_name),))
                except sqlite3.OperationalError as e:
                    if e.args[0].startswith(('no such table: ', 'file is not a database')):
                        raise BrowserCookieError('File {} is not a Chromium-based browser cookie file'.format(self.tmp_cookie_file))


            for item in cur.fetchall():
                # Per https://github.com/chromium/chromium/blob/main/base/time/time.h#L5-L7,
                # Chromium-based browsers store cookies' expiration timestamps as MICROSECONDS elapsed
                # since the Windows NT epoch (1601-01-01 0:00:00 GMT), or 0 for session cookies.
                #
                # http.cookiejar stores cookies' expiration timestamps as SECONDS since the Unix epoch
                # (1970-01-01 0:00:00 GMT, or None for session cookies.
                host, path, secure, expires_nt_time_epoch, name, value, enc_value, http_only = item
                if (expires_nt_time_epoch == 0):
                    expires = None
                else:
                    expires = (expires_nt_time_epoch / 1000000) - \
                        self.UNIX_TO_NT_EPOCH_OFFSET

                value = self._decrypt(value, enc_value, has_integrity_check_for_cookie_domain)
                c = create_cookie(host, path, secure, expires,
                                  name, value, http_only)
                cj.set_cookie(c)
        return cj

    @staticmethod
    def _has_integrity_check_for_cookie_domain(con):
        """Starting from version 24, the sha256 of the domain is prepended to the encrypted value
        of the cookie.

        See:
            - https://issues.chromium.org/issues/40185252
            - https://chromium-review.googlesource.com/c/chromium/src/+/5792044
            - https://chromium.googlesource.com/chromium/src/net/+/master/extras/sqlite/sqlite_persistent_cookie_store.cc#193
        """
        try:
            value, = con.execute('SELECT value FROM meta WHERE key = "version";').fetchone()
        except sqlite3.OperationalError:
            return False

        try:
            version = int(value)
        except ValueError:
            return False

        return version >= 24

    @staticmethod
    def _decrypt_windows_chromium(value, encrypted_value):

        if len(value) != 0:
            return value

        if encrypted_value == b"":
            return ""

        _, data = _crypt_unprotect_data(encrypted_value)
        assert isinstance(data, bytes)
        return data.decode()

    def _decrypt(self, value, encrypted_value, has_integrity_check_for_cookie_domain=False):
        """Decrypt encoded cookies"""

        if sys.platform == 'win32':
            try:
                return self._decrypt_windows_chromium(value, encrypted_value)

            # Fix for change in Chrome 80
            except RuntimeError:  # Failed to decrypt the cipher text with DPAPI
                if not self.v10_key:
                    raise RuntimeError(
                        'Failed to decrypt the cipher text with DPAPI and no AES key.')
                # Encrypted cookies should be prefixed with 'v10' according to the
                # Chromium code. Strip it off.
                encrypted_value = encrypted_value[3:]
                nonce, tag = encrypted_value[:12], encrypted_value[-16:]
                aes = AES.new(self.v10_key, AES.MODE_GCM, nonce=nonce)

                # will rise Value Error: MAC check failed byte if the key is wrong,
                # probably we did not got the key and used peanuts
                try:
                    data = aes.decrypt_and_verify(encrypted_value[12:-16], tag)
                except ValueError:
                    raise BrowserCookieError(
                        'Unable to get key for cookie decryption')
                if has_integrity_check_for_cookie_domain:
                    data = data[32:]
                return data.decode()

        if value or (encrypted_value[:3] not in [b'v11', b'v10']):
            return value

        # Encrypted cookies should be prefixed with 'v10' on mac,
        # 'v10' or 'v11' on Linux. Choose key based on this prefix.
        # Reference in chromium code: `OSCryptImpl::DecryptString` in
        # components/os_crypt/os_crypt_linux.cc
        if not hasattr(self, 'v11_key'):
            assert encrypted_value[:3] != b'v11', "v11 keys should only appear on Linux."
        keys = (self.v11_key, self.v11_empty_key) if encrypted_value[:3] == b'v11' else (
            self.v10_key,)
        encrypted_value = encrypted_value[3:]

        for key in keys:
            cipher = AES.new(key, AES.MODE_CBC, self.iv)

            # will rise Value Error: invalid padding byte if the key is wrong,
            # probably we did not got the key and used peanuts
            try:
                decrypted = unpad(cipher.decrypt(
                    encrypted_value), AES.block_size)
                if has_integrity_check_for_cookie_domain:
                    decrypted = decrypted[32:]
                return decrypted.decode('utf-8')
            except ValueError:
                pass
        raise BrowserCookieError('Unable to get key for cookie decryption')


class Chrome(ChromiumBased):
    """Class for Google Chrome"""

    def __init__(self, cookie_file=None, domain_name="", key_file=None, profile_name=None):
        args = {
            'linux_cookies': _genarate_nix_paths_chromium(
                [
                    '~/.config/google-chrome{channel}/Default/Cookies',
                    '~/.config/google-chrome{channel}/Profile */Cookies',
                    '~/.var/app/com.google.Chrome/config/google-chrome{channel}/Default/Cookies',
                    '~/.var/app/com.google.Chrome/config/google-chrome{channel}/Profile */Cookies'
                ],
                channel=['', '-beta', '-unstable']
            ),
            'windows_cookies': _genarate_win_paths_chromium(
                [
                    'Google\\Chrome{channel}\\User Data\\Default\\Cookies',
                    'Google\\Chrome{channel}\\User Data\\Default\\Network\\Cookies',
                    'Google\\Chrome{channel}\\User Data\\Profile *\\Cookies',
                    'Google\\Chrome{channel}\\User Data\\Profile *\\Network\\Cookies'
                ],
                channel=['', ' Beta', ' Dev']
            ),
            'osx_cookies': _genarate_nix_paths_chromium(
                [
                    '~/Library/Application Support/Google/Chrome{channel}/Default/Cookies',
                    '~/Library/Application Support/Google/Chrome{channel}/Profile */Cookies'
                ],
                channel=['', ' Beta', ' Dev']
            ),
            'windows_keys': _genarate_win_paths_chromium(
                'Google\\Chrome{channel}\\User Data\\Local State',
                channel=['', ' Beta', ' Dev']
            ),
            'os_crypt_name': 'chrome',
            'osx_key_service': 'Chrome Safe Storage',
            'osx_key_user': 'Chrome'
        }
        super().__init__(browser='Chrome', cookie_file=cookie_file,
                         domain_name=domain_name, key_file=key_file, profile_name=profile_name, **args)

    @classmethod
    def list_profiles(cls):
        """List all available Chrome profiles"""
        args = {
            'linux_cookies': _genarate_nix_paths_chromium(
                [
                    '~/.config/google-chrome{channel}/Default/Cookies',
                    '~/.config/google-chrome{channel}/Profile */Cookies',
                    '~/.var/app/com.google.Chrome/config/google-chrome{channel}/Default/Cookies',
                    '~/.var/app/com.google.Chrome/config/google-chrome{channel}/Profile */Cookies'
                ],
                channel=['', '-beta', '-unstable']
            ),
            'windows_cookies': _genarate_win_paths_chromium(
                [
                    'Google\\Chrome{channel}\\User Data\\Default\\Cookies',
                    'Google\\Chrome{channel}\\User Data\\Default\\Network\\Cookies',
                    'Google\\Chrome{channel}\\User Data\\Profile *\\Cookies',
                    'Google\\Chrome{channel}\\User Data\\Profile *\\Network\\Cookies'
                ],
                channel=['', ' Beta', ' Dev']
            ),
            'osx_cookies': _genarate_nix_paths_chromium(
                [
                    '~/Library/Application Support/Google/Chrome{channel}/Default/Cookies',
                    '~/Library/Application Support/Google/Chrome{channel}/Profile */Cookies'
                ],
                channel=['', ' Beta', ' Dev']
            )
        }
        return ChromiumBased.list_profiles('Chrome', **args)


class Arc(ChromiumBased):
    """Class for Arc"""

    def __init__(self, cookie_file=None, domain_name="", key_file=None, profile_name=None):
        args = {
            'osx_cookies': _genarate_nix_paths_chromium(
                [
                    '~/Library/Application Support/Arc/User Data/Default/Cookies',
                    '~/Library/Application Support/Arc/User Data/Profile */Cookies'
                ],
                channel=['']
            ),
            'os_crypt_name': 'chrome',
            'osx_key_service': 'Arc Safe Storage',
            'osx_key_user': 'Arc'
        }
        super().__init__(browser='Arc', cookie_file=cookie_file,
                         domain_name=domain_name, key_file=key_file, profile_name=profile_name, **args)

    @classmethod
    def list_profiles(cls):
        """List all available Arc profiles"""
        args = {
            'osx_cookies': _genarate_nix_paths_chromium(
                [
                    '~/Library/Application Support/Arc/User Data/Default/Cookies',
                    '~/Library/Application Support/Arc/User Data/Profile */Cookies'
                ],
                channel=['']
            )
        }
        return ChromiumBased.list_profiles('Arc', **args)


class Chromium(ChromiumBased):
    """Class for Chromium"""

    def __init__(self, cookie_file=None, domain_name="", key_file=None, profile_name=None):
        args = {
            'linux_cookies': [
                '~/.config/chromium/Default/Cookies',
                '~/.config/chromium/Profile */Cookies',
                '~/.var/app/org.chromium.Chromium/config/chromium/Default/Cookies',
                '~/.var/app/org.chromium.Chromium/config/chromium/Profile */Cookies'
            ],
            'windows_cookies': _genarate_win_paths_chromium(
                [
                    'Chromium\\User Data\\Default\\Cookies',
                    'Chromium\\User Data\\Default\\Network\\Cookies',
                    'Chromium\\User Data\\Profile *\\Cookies',
                    'Chromium\\User Data\\Profile *\\Network\\Cookies'
                ]
            ),
            'osx_cookies': [
                '~/Library/Application Support/Chromium/Default/Cookies',
                '~/Library/Application Support/Chromium/Profile */Cookies'
            ],
            'windows_keys': _genarate_win_paths_chromium(
                'Chromium\\User Data\\Local State'
            ),
            'os_crypt_name': 'chromium',
            'osx_key_service': 'Chromium Safe Storage',
            'osx_key_user': 'Chromium'
        }
        super().__init__(browser='Chromium', cookie_file=cookie_file,
                         domain_name=domain_name, key_file=key_file, profile_name=profile_name, **args)

    @classmethod
    def list_profiles(cls):
        """List all available Chromium profiles"""
        args = {
            'linux_cookies': [
                '~/.config/chromium/Default/Cookies',
                '~/.config/chromium/Profile */Cookies',
                '~/.var/app/org.chromium.Chromium/config/chromium/Default/Cookies',
                '~/.var/app/org.chromium.Chromium/config/chromium/Profile */Cookies'
            ],
            'windows_cookies': _genarate_win_paths_chromium(
                [
                    'Chromium\\User Data\\Default\\Cookies',
                    'Chromium\\User Data\\Default\\Network\\Cookies',
                    'Chromium\\User Data\\Profile *\\Cookies',
                    'Chromium\\User Data\\Profile *\\Network\\Cookies'
                ]
            ),
            'osx_cookies': [
                '~/Library/Application Support/Chromium/Default/Cookies',
                '~/Library/Application Support/Chromium/Profile */Cookies'
            ]
        }
        return ChromiumBased.list_profiles('Chromium', **args)


class Opera(ChromiumBased):
    """Class for Opera"""

    def __init__(self, cookie_file=None, domain_name="", key_file=None, profile_name=None):
        args = {
            'linux_cookies': [
                '~/.config/opera/Cookies',
                '~/.config/opera-beta/Cookies',
                '~/.config/opera-developer/Cookies',
                '~/.var/app/com.opera.Opera/config/opera/Cookies'
                '~/.var/app/com.opera.Opera/config/opera-beta/Cookies'
                '~/.var/app/com.opera.Opera/config/opera-developer/Cookies'
            ],
            'windows_cookies': _genarate_win_paths_chromium(
                [
                    'Opera Software\\Opera {channel}\\Cookies',
                    'Opera Software\\Opera {channel}\\Network\\Cookies'
                ],
                channel=['Stable', 'Next', 'Developer']
            ),
            'osx_cookies': [
                '~/Library/Application Support/com.operasoftware.Opera/Cookies',
                '~/Library/Application Support/com.operasoftware.OperaNext/Cookies',
                '~/Library/Application Support/com.operasoftware.OperaDeveloper/Cookies'
            ],
            'windows_keys': _genarate_win_paths_chromium(
                'Opera Software\\Opera {channel}\\Local State',
                channel=['Stable', 'Next', 'Developer']
            ),
            'os_crypt_name': 'chromium',
            'osx_key_service': 'Opera Safe Storage',
            'osx_key_user': 'Opera'
        }
        super().__init__(browser='Opera', cookie_file=cookie_file,
                         domain_name=domain_name, key_file=key_file, profile_name=profile_name, **args)

    @classmethod
    def list_profiles(cls):
        """List all available Opera profiles"""
        args = {
            'linux_cookies': [
                '~/.config/opera/Cookies',
                '~/.config/opera-beta/Cookies',
                '~/.config/opera-developer/Cookies',
                '~/.var/app/com.opera.Opera/config/opera/Cookies',
                '~/.var/app/com.opera.Opera/config/opera-beta/Cookies',
                '~/.var/app/com.opera.Opera/config/opera-developer/Cookies'
            ],
            'windows_cookies': _genarate_win_paths_chromium(
                [
                    'Opera Software\\Opera {channel}\\Cookies',
                    'Opera Software\\Opera {channel}\\Network\\Cookies'
                ],
                channel=['Stable', 'Next', 'Developer']
            ),
            'osx_cookies': [
                '~/Library/Application Support/com.operasoftware.Opera/Cookies',
                '~/Library/Application Support/com.operasoftware.OperaNext/Cookies',
                '~/Library/Application Support/com.operasoftware.OperaDeveloper/Cookies'
            ]
        }
        return ChromiumBased.list_profiles('Opera', **args)


class OperaGX(ChromiumBased):
    """Class for Opera GX"""

    def __init__(self, cookie_file=None, domain_name="", key_file=None, profile_name=None):
        args = {
            'linux_cookies': [],  # Not available on Linux
            'windows_cookies': _genarate_win_paths_chromium(
                [
                    'Opera Software\\Opera GX {channel}\\Cookies',
                    'Opera Software\\Opera GX {channel}\\Network\\Cookies'
                ],
                channel=['Stable']
            ),
            'osx_cookies': ['~/Library/Application Support/com.operasoftware.OperaGX/Cookies'],
            'windows_keys': _genarate_win_paths_chromium(
                'Opera Software\\Opera GX {channel}\\Local State',
                channel=['Stable']
            ),
            'os_crypt_name': 'chromium',
            'osx_key_service': 'Opera Safe Storage',
            'osx_key_user': 'Opera'
        }
        super().__init__(browser='Opera GX', cookie_file=cookie_file,
                         domain_name=domain_name, key_file=key_file, profile_name=profile_name, **args)

    @classmethod
    def list_profiles(cls):
        """List all available Opera GX profiles"""
        args = {
            'linux_cookies': [],  # Not available on Linux
            'windows_cookies': _genarate_win_paths_chromium(
                [
                    'Opera Software\\Opera GX {channel}\\Cookies',
                    'Opera Software\\Opera GX {channel}\\Network\\Cookies'
                ],
                channel=['Stable']
            ),
            'osx_cookies': ['~/Library/Application Support/com.operasoftware.OperaGX/Cookies']
        }
        return ChromiumBased.list_profiles('Opera GX', **args)


class Brave(ChromiumBased):
    def __init__(self, cookie_file=None, domain_name="", key_file=None, profile_name=None):
        args = {
            'linux_cookies': _genarate_nix_paths_chromium(
                [
                    '~/.config/BraveSoftware/Brave-Browser{channel}/Default/Cookies',
                    '~/.config/BraveSoftware/Brave-Browser{channel}/Profile */Cookies',
                    '~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser{channel}/Default/Cookies',
                    '~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser{channel}/Profile */Cookies'
                ],
                channel=['', '-Beta', '-Dev', '-Nightly']
            ),
            'windows_cookies': _genarate_win_paths_chromium(
                [
                    'BraveSoftware\\Brave-Browser{channel}\\User Data\\Default\\Cookies',
                    'BraveSoftware\\Brave-Browser{channel}\\User Data\\Default\\Network\\Cookies',
                    'BraveSoftware\\Brave-Browser{channel}\\User Data\\Profile *\\Cookies',
                    'BraveSoftware\\Brave-Browser{channel}\\User Data\\Profile *\\Network\\Cookies'
                ],
                channel=['', '-Beta', '-Dev', '-Nightly']
            ),
            'osx_cookies': _genarate_nix_paths_chromium(
                [
                    '~/Library/Application Support/BraveSoftware/Brave-Browser{channel}/Default/Cookies',
                    '~/Library/Application Support/BraveSoftware/Brave-Browser{channel}/Profile */Cookies'
                ],
                channel=['', '-Beta', '-Dev', '-Nightly']
            ),
            'windows_keys': _genarate_win_paths_chromium(
                'BraveSoftware\\Brave-Browser{channel}\\User Data\\Local State',
                channel=['', '-Beta', '-Dev', '-Nightly']
            ),
            'os_crypt_name': 'brave',
            'osx_key_service': 'Brave Safe Storage',
            'osx_key_user': 'Brave'
        }
        super().__init__(browser='Brave', cookie_file=cookie_file,
                         domain_name=domain_name, key_file=key_file, profile_name=profile_name, **args)

    @classmethod
    def list_profiles(cls):
        """List all available Brave profiles"""
        args = {
            'linux_cookies': _genarate_nix_paths_chromium(
                [
                    '~/.config/BraveSoftware/Brave-Browser{channel}/Default/Cookies',
                    '~/.config/BraveSoftware/Brave-Browser{channel}/Profile */Cookies',
                    '~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser{channel}/Default/Cookies',
                    '~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser{channel}/Profile */Cookies'
                ],
                channel=['', '-Beta', '-Dev', '-Nightly']
            ),
            'windows_cookies': _genarate_win_paths_chromium(
                [
                    'BraveSoftware\\Brave-Browser{channel}\\User Data\\Default\\Cookies',
                    'BraveSoftware\\Brave-Browser{channel}\\User Data\\Default\\Network\\Cookies',
                    'BraveSoftware\\Brave-Browser{channel}\\User Data\\Profile *\\Cookies',
                    'BraveSoftware\\Brave-Browser{channel}\\User Data\\Profile *\\Network\\Cookies'
                ],
                channel=['', '-Beta', '-Dev', '-Nightly']
            ),
            'osx_cookies': _genarate_nix_paths_chromium(
                [
                    '~/Library/Application Support/BraveSoftware/Brave-Browser{channel}/Default/Cookies',
                    '~/Library/Application Support/BraveSoftware/Brave-Browser{channel}/Profile */Cookies'
                ],
                channel=['', '-Beta', '-Dev', '-Nightly']
            )
        }
        return ChromiumBased.list_profiles('Brave', **args)


class Edge(ChromiumBased):
    """Class for Microsoft Edge"""

    def __init__(self, cookie_file=None, domain_name="", key_file=None, profile_name=None):
        args = {
            'linux_cookies': _genarate_nix_paths_chromium(
                [
                    '~/.config/microsoft-edge{channel}/Default/Cookies',
                    '~/.config/microsoft-edge{channel}/Profile */Cookies',
                    "~/.var/app/com.microsoft.Edge/config/microsoft-edge{channel}/Default/Cookies",
                    "~/.var/app/com.microsoft.Edge/config/microsoft-edge{channel}/Profile */Cookies",
                ],
                channel=['', '-beta', '-dev']
            ),
            'windows_cookies': _genarate_win_paths_chromium(
                [
                    'Microsoft\\Edge{channel}\\User Data\\Default\\Cookies',
                    'Microsoft\\Edge{channel}\\User Data\\Default\\Network\\Cookies',
                    'Microsoft\\Edge{channel}\\User Data\\Profile *\\Cookies',
                    'Microsoft\\Edge{channel}\\User Data\\Profile *\\Network\\Cookies'
                ],
                channel=['', ' Beta', ' Dev', ' SxS']
            ),
            'osx_cookies': _genarate_nix_paths_chromium(
                [
                    '~/Library/Application Support/Microsoft Edge{channel}/Default/Cookies',
                    '~/Library/Application Support/Microsoft Edge{channel}/Profile */Cookies'
                ],
                channel=['', ' Beta', ' Dev', ' Canary']
            ),
            'windows_keys': _genarate_win_paths_chromium(
                'Microsoft\\Edge{channel}\\User Data\\Local State',
                channel=['', ' Beta', ' Dev', ' SxS']
            ),
            'os_crypt_name': 'chromium',
            'osx_key_service': 'Microsoft Edge Safe Storage',
            'osx_key_user': 'Microsoft Edge'
        }
        super().__init__(browser='Edge', cookie_file=cookie_file,
                         domain_name=domain_name, key_file=key_file, profile_name=profile_name, **args)

    @classmethod
    def list_profiles(cls):
        """List all available Edge profiles"""
        args = {
            'linux_cookies': _genarate_nix_paths_chromium(
                [
                    '~/.config/microsoft-edge{channel}/Default/Cookies',
                    '~/.config/microsoft-edge{channel}/Profile */Cookies',
                    "~/.var/app/com.microsoft.Edge/config/microsoft-edge{channel}/Default/Cookies",
                    "~/.var/app/com.microsoft.Edge/config/microsoft-edge{channel}/Profile */Cookies",
                ],
                channel=['', '-beta', '-dev']
            ),
            'windows_cookies': _genarate_win_paths_chromium(
                [
                    'Microsoft\\Edge{channel}\\User Data\\Default\\Cookies',
                    'Microsoft\\Edge{channel}\\User Data\\Default\\Network\\Cookies',
                    'Microsoft\\Edge{channel}\\User Data\\Profile *\\Cookies',
                    'Microsoft\\Edge{channel}\\User Data\\Profile *\\Network\\Cookies'
                ],
                channel=['', ' Beta', ' Dev', ' SxS']
            ),
            'osx_cookies': _genarate_nix_paths_chromium(
                [
                    '~/Library/Application Support/Microsoft Edge{channel}/Default/Cookies',
                    '~/Library/Application Support/Microsoft Edge{channel}/Profile */Cookies'
                ],
                channel=['', ' Beta', ' Dev', ' Canary']
            )
        }
        return ChromiumBased.list_profiles('Edge', **args)


class Vivaldi(ChromiumBased):
    """Class for Vivaldi Browser"""

    def __init__(self, cookie_file=None, domain_name="", key_file=None, profile_name=None):
        args = {
            'linux_cookies': [
                '~/.config/vivaldi/Default/Cookies',
                '~/.config/vivaldi/Profile */Cookies',
                '~/.config/vivaldi-snapshot/Default/Cookies',
                '~/.config/vivaldi-snapshot/Profile */Cookies',
                '~/.var/app/com.vivaldi.Vivaldi/config/vivaldi/Default/Cookies',
                '~/.var/app/com.vivaldi.Vivaldi/config/vivaldi/Profile */Cookies'
            ],
            'windows_cookies': _genarate_win_paths_chromium(
                [
                    'Vivaldi\\User Data\\Default\\Cookies',
                    'Vivaldi\\User Data\\Default\\Network\\Cookies',
                    'Vivaldi\\User Data\\Profile *\\Cookies',
                    'Vivaldi\\User Data\\Profile *\\Network\\Cookies'
                ]
            ),
            'osx_cookies': [
                '~/Library/Application Support/Vivaldi/Default/Cookies',
                '~/Library/Application Support/Vivaldi/Profile */Cookies'
            ],
            'windows_keys': _genarate_win_paths_chromium(
                'Vivaldi\\User Data\\Local State'
            ),
            'os_crypt_name': 'chrome',
            'osx_key_service': 'Vivaldi Safe Storage',
            'osx_key_user': 'Vivaldi'
        }
        super().__init__(browser='Vivaldi', cookie_file=cookie_file,
                         domain_name=domain_name, key_file=key_file, profile_name=profile_name, **args)

    @classmethod
    def list_profiles(cls):
        """List all available Vivaldi profiles"""
        args = {
            'linux_cookies': [
                '~/.config/vivaldi/Default/Cookies',
                '~/.config/vivaldi/Profile */Cookies',
                '~/.config/vivaldi-snapshot/Default/Cookies',
                '~/.config/vivaldi-snapshot/Profile */Cookies',
                '~/.var/app/com.vivaldi.Vivaldi/config/vivaldi/Default/Cookies',
                '~/.var/app/com.vivaldi.Vivaldi/config/vivaldi/Profile */Cookies'
            ],
            'windows_cookies': _genarate_win_paths_chromium(
                [
                    'Vivaldi\\User Data\\Default\\Cookies',
                    'Vivaldi\\User Data\\Default\\Network\\Cookies',
                    'Vivaldi\\User Data\\Profile *\\Cookies',
                    'Vivaldi\\User Data\\Profile *\\Network\\Cookies'
                ]
            ),
            'osx_cookies': [
                '~/Library/Application Support/Vivaldi/Default/Cookies',
                '~/Library/Application Support/Vivaldi/Profile */Cookies'
            ]
        }
        return ChromiumBased.list_profiles('Vivaldi', **args)


class FirefoxBased:
    """Superclass for Firefox based browsers"""

    def __init__(self, browser_name, cookie_file=None, domain_name="", key_file=None, profile_name=None, **kwargs):
        self.browser_name = browser_name
        self.profile_name = profile_name
        self.cookie_file = cookie_file or self.__find_cookie_file(**kwargs)
        # current sessions are saved in sessionstore.js
        self.session_file = os.path.join(
            os.path.dirname(self.cookie_file), 'sessionstore.js')
        self.session_file_lz4 = os.path.join(os.path.dirname(
            self.cookie_file), 'sessionstore-backups', 'recovery.jsonlz4')
        # domain name to filter cookies by
        self.domain_name = domain_name

    def __str__(self):
        return self.browser_name

    @staticmethod
    def list_profiles(user_data_path):
        """List all available profiles from profiles.ini"""
        profiles = []
        config = configparser.ConfigParser()
        profiles_ini_path = glob.glob(os.path.join(
            user_data_path + '**', 'profiles.ini'))
        
        if not profiles_ini_path:
            return profiles
        
        profiles_ini_path = profiles_ini_path[0]
        config.read(profiles_ini_path, encoding="utf8")
        
        for section in config.sections():
            if section.startswith('Profile'):
                profile_name = config[section].get('Name', '')
                profile_path = config[section].get('Path', '')
                # Use name if available, otherwise use path
                display_name = profile_name if profile_name else profile_path
                if display_name and display_name not in profiles:
                    profiles.append(display_name)
        
        return sorted(profiles)

    @staticmethod
    def get_default_profile(user_data_path, profile_name=None):
        config = configparser.ConfigParser()
        profiles_ini_path = glob.glob(os.path.join(
            user_data_path + '**', 'profiles.ini'))
        fallback_path = user_data_path + '**'

        if not profiles_ini_path:
            return fallback_path

        profiles_ini_path = profiles_ini_path[0]
        config.read(profiles_ini_path, encoding="utf8")

        # If profile_name is specified, try to find that specific profile
        if profile_name:
            for section in config.sections():
                if section.startswith('Profile'):
                    # Check if this is the profile we're looking for
                    section_profile_name = config[section].get('Name', '')
                    section_profile_path = config[section].get('Path', '')
                    
                    # Match by name, path, or section number (e.g., "Profile0" -> "0")
                    section_number = section.replace('Profile', '') if section.startswith('Profile') else None
                    if (section_profile_name == profile_name or 
                        section_profile_path == profile_name or
                        section_number == profile_name or
                        section == profile_name):
                        absolute = config[section].get('IsRelative') == '0'
                        return section_profile_path if absolute else os.path.join(os.path.dirname(profiles_ini_path), section_profile_path)
            
            # If profile not found by name, raise an error
            raise BrowserCookieError(f'Profile "{profile_name}" not found in profiles.ini')

        # Default behavior: find the default profile
        profile_path = None
        for section in config.sections():
            if section.startswith('Install'):
                profile_path = config[section].get('Default')
                break
            # in ff 72.0.1, if both an Install section and one with Default=1 are present, the former takes precedence
            elif config[section].get('Default') == '1' and not profile_path:
                profile_path = config[section].get('Path')

        for section in config.sections():
            # the Install section has no relative/absolute info, so check the profiles
            if config[section].get('Path') == profile_path:
                absolute = config[section].get('IsRelative') == '0'
                return profile_path if absolute else os.path.join(os.path.dirname(profiles_ini_path), profile_path)

        return fallback_path

    def __expand_and_check_path(self, paths: Union[str, List[str], Dict[str, str], List[Dict[str, str]]]) -> str:
        """Expands a path to a list of paths and returns the first one that exists"""
        if not isinstance(paths, list):
            paths = [paths]
        for path in paths:
            if isinstance(path, dict):
                expanded = _expand_win_path(path)
            else:
                expanded = os.path.expanduser(path)
            if os.path.isdir(expanded):
                return expanded
        raise BrowserCookieError(
            f'Could not find {self.browser_name} profile directory')

    def __find_cookie_file(self, linux_data_dirs=None, windows_data_dirs=None, osx_data_dirs=None):
        cookie_files = []

        if sys.platform == 'darwin':
            user_data_path = self.__expand_and_check_path(osx_data_dirs)
        elif sys.platform.startswith('linux') or 'bsd' in sys.platform.lower():
            user_data_path = self.__expand_and_check_path(linux_data_dirs)
        elif sys.platform == 'win32':
            user_data_path = self.__expand_and_check_path(windows_data_dirs)
        else:
            raise BrowserCookieError(
                'Unsupported operating system: ' + sys.platform)

        profile_path = FirefoxBased.get_default_profile(user_data_path, self.profile_name)
        cookie_files = glob.glob(os.path.join(profile_path, 'cookies.sqlite')) \
            or cookie_files

        if cookie_files:
            return cookie_files[0]
        else:
            raise BrowserCookieError(
                f'Failed to find {self.browser_name} cookie file' + 
                (f' for profile "{self.profile_name}"' if self.profile_name else ''))

    @staticmethod
    def __create_session_cookie(cookie_json):
        return create_cookie(cookie_json.get('host', ''), cookie_json.get('path', ''),
                             cookie_json.get('secure', False), None,
                             cookie_json.get('name', ''), cookie_json.get(
                                 'value', ''),
                             cookie_json.get('httponly', False))

    def __add_session_cookies(self, cj):
        if not os.path.exists(self.session_file):
            return
        try:
            with open(self.session_file, 'rb') as file_obj:
                json_data = json.load(file_obj)
        except ValueError as e:
            print(f'Error parsing {self.browser_name} session JSON:', str(e))
        else:
            for window in json_data.get('windows', []):
                for cookie in window.get('cookies', []):
                    if self.domain_name == '' or self.domain_name in cookie.get('host', ''):
                        cj.set_cookie(
                            FirefoxBased.__create_session_cookie(cookie))

    def __add_session_cookies_lz4(self, cj):
        if not os.path.exists(self.session_file_lz4):
            return
        try:
            with open(self.session_file_lz4, 'rb') as file_obj:
                file_obj.read(8)
                json_data = json.loads(lz4.block.decompress(file_obj.read()))
        except ValueError as e:
            print(
                f'Error parsing {self.browser_name} session JSON LZ4:', str(e))
        else:
            for cookie in json_data.get('cookies', []):
                if self.domain_name == '' or self.domain_name in cookie.get('host', ''):
                    cj.set_cookie(FirefoxBased.__create_session_cookie(cookie))

    def load(self):
        cj = http.cookiejar.CookieJar()
        # firefoxbased seems faster with legacy mode
        with _DatabaseConnetion(self.cookie_file, True) as con:
            cur = con.cursor()
            try:
                cur.execute('select host, path, isSecure, expiry, name, value, isHttpOnly from moz_cookies '
                            'where host like ?', ('%{}%'.format(self.domain_name),))
            except sqlite3.DatabaseError as e:
                if e.args[0].startswith(('no such table: ', 'file is not a database')):
                    raise BrowserCookieError('File {} is not a Firefox cookie file'.format(self.tmp_cookie_file))
                raise

            for item in cur.fetchall():
                host, path, secure, expires, name, value, http_only = item
                c = create_cookie(host, path, secure, expires,
                                  name, value, http_only)
                cj.set_cookie(c)

        self.__add_session_cookies(cj)
        self.__add_session_cookies_lz4(cj)

        return cj


class Firefox(FirefoxBased):
    """Class for Firefox"""

    def __init__(self, cookie_file=None, domain_name="", key_file=None, profile_name=None):
        args = {
            'linux_data_dirs': [
                '~/snap/firefox/common/.mozilla/firefox',
                '~/.mozilla/firefox'
            ],
            'windows_data_dirs': [
                {'env': 'APPDATA', 'path': r'Mozilla\Firefox'},
                {'env': 'LOCALAPPDATA', 'path': r'Mozilla\Firefox'}
            ],
            'osx_data_dirs': [
                '~/Library/Application Support/Firefox'
            ]
        }
        super().__init__('Firefox', cookie_file, domain_name, key_file, profile_name, **args)

    @classmethod
    def list_profiles(cls):
        """List all available Firefox profiles"""
        args = {
            'linux_data_dirs': [
                '~/snap/firefox/common/.mozilla/firefox',
                '~/.mozilla/firefox'
            ],
            'windows_data_dirs': [
                {'env': 'APPDATA', 'path': r'Mozilla\Firefox'},
                {'env': 'LOCALAPPDATA', 'path': r'Mozilla\Firefox'}
            ],
            'osx_data_dirs': [
                '~/Library/Application Support/Firefox'
            ]
        }
        return cls._list_profiles_from_dirs(**args)

    @classmethod
    def _list_profiles_from_dirs(cls, linux_data_dirs=None, windows_data_dirs=None, osx_data_dirs=None):
        """Helper method to list profiles from data directories"""
        if sys.platform == 'darwin':
            data_dirs = osx_data_dirs or []
        elif sys.platform.startswith('linux') or 'bsd' in sys.platform.lower():
            data_dirs = linux_data_dirs or []
        elif sys.platform == 'win32':
            data_dirs = windows_data_dirs or []
        else:
            return []
        
        all_profiles = []
        for data_dir in data_dirs:
            try:
                if isinstance(data_dir, dict):
                    expanded = _expand_win_path(data_dir)
                else:
                    expanded = os.path.expanduser(data_dir)
                if os.path.isdir(expanded):
                    profiles = FirefoxBased.list_profiles(expanded)
                    all_profiles.extend(profiles)
            except (OSError, BrowserCookieError):
                continue
        return sorted(list(set(all_profiles)))


class LibreWolf(FirefoxBased):
    """Class for LibreWolf"""

    def __init__(self, cookie_file=None, domain_name="", key_file=None, profile_name=None):
        args = {
            'linux_data_dirs': [
                '~/snap/librewolf/common/.librewolf',
                '~/.librewolf'
            ],
            'windows_data_dirs': [
                {'env': 'APPDATA', 'path': 'librewolf'},
                {'env': 'LOCALAPPDATA', 'path': 'librewolf'}
            ],
            'osx_data_dirs': [
                '~/Library/Application Support/librewolf'
            ]
        }
        super().__init__('LibreWolf', cookie_file, domain_name, key_file, profile_name, **args)

    @classmethod
    def list_profiles(cls):
        """List all available LibreWolf profiles"""
        args = {
            'linux_data_dirs': [
                '~/snap/librewolf/common/.librewolf',
                '~/.librewolf'
            ],
            'windows_data_dirs': [
                {'env': 'APPDATA', 'path': 'librewolf'},
                {'env': 'LOCALAPPDATA', 'path': 'librewolf'}
            ],
            'osx_data_dirs': [
                '~/Library/Application Support/librewolf'
            ]
        }
        return Firefox._list_profiles_from_dirs(**args)


class Safari:
    """Class for Safari"""

    APPLE_TO_UNIX_TIME = 978307200
    NEW_ISSUE_URL = 'https://github.com/borisbabic/browser_cookie3/issues/new'
    NEW_ISSUE_MESSAGE = f'Page format changed.\nPlease create a new issue on: {NEW_ISSUE_URL}'
    safari_cookies = [
        '~/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies',
        '~/Library/Cookies/Cookies.binarycookies'
    ]

    def __init__(self, cookie_file=None, domain_name="", key_file=None, profile_name=None) -> None:
        self.__offset = 0
        self.__domain_name = domain_name
        self.__buffer = None
        self.__open_file(cookie_file)
        self.__parse_header()

    def __del__(self):
        if self.__buffer:
            self.__buffer.close()

    def __open_file(self, cookie_file):
        cookie_file = cookie_file or _expand_paths(self.safari_cookies, 'osx')
        if not cookie_file:
            raise BrowserCookieError('Can not find Safari cookie file')
        self.__buffer = open(cookie_file, 'rb')

    def __read_file(self, size: int, offset: int = None):
        if offset is not None:
            self.__offset = offset
        self.__buffer.seek(self.__offset)
        self.__offset += size
        return BytesIO(self.__buffer.read(size))

    def __parse_header(self):
        assert self.__buffer.read(4) == b'cook', 'Not a safari cookie file'
        self.__total_page = struct.unpack('>I', self.__buffer.read(4))[0]

        self.__page_sizes = []
        for _ in range(self.__total_page):
            self.__page_sizes.append(struct.unpack(
                '>I', self.__buffer.read(4))[0])

    @staticmethod
    def __read_until_null(file: BytesIO, decode: bool = True):
        data = []
        while True:
            byte = file.read(1)
            if byte == b'\x00':
                break
            data.append(byte)
        data = b''.join(data)
        if decode:
            data = data.decode('utf-8')
        return data

    def __parse_cookie(self, page: BytesIO, cookie_offset: int):
        page.seek(cookie_offset)
        # cookie size, keep it for future use and better understanding
        _ = struct.unpack('<I', page.read(4))[0]
        page.seek(4, 1)  # skip 4-bytes unknown data
        flags = struct.unpack('<I', page.read(4))[0]
        page.seek(4, 1)  # skip 4-bytes unknown data
        is_secure = bool(flags & 0x1)
        is_httponly = bool(flags & 0x4)

        host_offset = struct.unpack('<I', page.read(4))[0]
        name_offset = struct.unpack('<I', page.read(4))[0]
        path_offset = struct.unpack('<I', page.read(4))[0]
        value_offset = struct.unpack('<I', page.read(4))[0]
        comment_offset = struct.unpack('<I', page.read(4))[0]

        assert page.read(4) == b'\x00\x00\x00\x00', self.NEW_ISSUE_MESSAGE
        expiry_date = int(struct.unpack('<d', page.read(8))[
                          0] + self.APPLE_TO_UNIX_TIME)  # convert to unix time
        # creation time, keep it for future use and better understanding
        _ = int(struct.unpack('<d', page.read(8))[
            0] + self.APPLE_TO_UNIX_TIME)  # convert to unix time

        page.seek(cookie_offset + host_offset, 0)
        host = self.__read_until_null(page)
        page.seek(cookie_offset + name_offset, 0)
        name = self.__read_until_null(page)
        page.seek(cookie_offset + path_offset, 0)
        path = self.__read_until_null(page)
        page.seek(cookie_offset + value_offset, 0)
        value = self.__read_until_null(page)
        if comment_offset:
            page.seek(cookie_offset + comment_offset, 0)
            # comment, keep it for future use and better understanding
            _ = self.__read_until_null(page)

        return create_cookie(host, path, is_secure, expiry_date, name, value, is_httponly)

    def __domain_filter(self, cookie: http.cookiejar.Cookie):
        if not self.__domain_name:
            return True
        return self.__domain_name in cookie.domain

    def __parse_page(self, page_index: int):
        offset = 8 + self.__total_page * 4 + \
            sum(self.__page_sizes[:page_index])
        page = self.__read_file(self.__page_sizes[page_index], offset)
        assert page.read(4) == b'\x00\x00\x01\x00', self.NEW_ISSUE_MESSAGE
        n_cookies = struct.unpack('<I', page.read(4))[0]
        cookie_offsets = []
        for _ in range(n_cookies):
            cookie_offsets.append(struct.unpack('<I', page.read(4))[0])
        assert page.read(4) == b'\x00\x00\x00\x00', self.NEW_ISSUE_MESSAGE

        for offset in cookie_offsets:
            yield self.__parse_cookie(page, offset)

    def load(self):
        cj = http.cookiejar.CookieJar()
        for i in range(self.__total_page):
            for cookie in self.__parse_page(i):
                if self.__domain_filter(cookie):
                    cj.set_cookie(cookie)
        return cj


class Lynx:
    """Class for Lynx"""

    lynx_cookies = [
        '~/.lynx_cookies', # most systems, see lynx man page
        '~/cookies'        # MS-DOS
    ]

    def __init__(self, cookie_file=None, domain_name="", profile_name=None):
        self.cookie_file = _expand_paths(cookie_file or self.lynx_cookies, 'linux')
        self.domain_name = domain_name
        self.profile_name = profile_name

    def load(self):
        cj = http.cookiejar.CookieJar()
        if not self.cookie_file:
            raise BrowserCookieError('Cannot find Lynx cookie file')
        with open(self.cookie_file) as f:
            for line in f.read().splitlines():
                # documentation in source code of lynx, file src/LYCookie.c
                domain, domain_specified, path, secure, expires, name, value = \
                        [None if word == '' else word for word in line.split('\t')]
                domain_specified = domain_specified == 'TRUE'
                secure = secure == 'TRUE'
                if domain.find(self.domain_name) >= 0:
                    cookie = create_cookie(domain, path, secure, expires, name,
                            value, False)
                    cj.set_cookie(cookie)
        return cj


class W3m:
    """Class for W3m"""

    # see documentation in source code of w3m, file fm.h
    COO_USE = 1
    COO_SECURE = 2
    COO_DOMAIN = 4
    COO_PATH = 8
    COO_DISCARD = 16
    COO_OVERRIDE = 32
    w3m_cookies = [
        '~/.w3m/cookie'
    ]

    def __init__(self, cookie_file=None, domain_name="", profile_name=None):
        self.cookie_file = _expand_paths(cookie_file or self.w3m_cookies, 'linux')
        self.domain_name = domain_name
        self.profile_name = profile_name

    def load(self):
        cj = http.cookiejar.CookieJar()
        if not self.cookie_file:
            raise BrowserCookieError('Cannot find W3m cookie file')
        with open(self.cookie_file) as f:
            for line in f.read().splitlines():
                # see documentation in source code of w3m, file cookie.c
                url, name, value, expires, domain, path, flag, version, comment, \
                        port, comment_url = \
                        [None if word == '' else word for word in line.split('\t')]
                flag = int(flag)
                expires = int(expires)
                secure = bool(flag & self.COO_SECURE)
                domain_specified = bool(flag & self.COO_DOMAIN)
                path_specified = bool(flag & self.COO_PATH)
                discard = bool(flag & self.COO_DISCARD)
                if domain.find(self.domain_name) >= 0:
                    cookie = http.cookiejar.Cookie(version, name, value, port,
                            bool(port), domain, domain_specified,
                            domain.startswith('.'), path, path_specified, secure,
                            expires, discard, comment, comment_url, {})
                    cj.set_cookie(cookie)
        return cj


def create_cookie(host, path, secure, expires, name, value, http_only):
    """Shortcut function to create a cookie"""
    # HTTPOnly flag goes in _rest, if present (see https://github.com/python/cpython/pull/17471/files#r511187060)
    return http.cookiejar.Cookie(0, name, value, None, False, host, host.startswith('.'), host.startswith('.'), path,
                                 True, secure, expires, False, None, None,
                                 {'HTTPOnly': ''} if http_only else {})


def chrome(cookie_file=None, domain_name="", key_file=None, profile_name=None):
    """Returns a cookiejar of the cookies used by Chrome. Optionally pass in a
    domain name to only load cookies from the specified domain, and a profile_name
    to load cookies from a specific profile (e.g., "Default", "Profile 1")
    """
    return Chrome(cookie_file, domain_name, key_file, profile_name).load()


def arc(cookie_file=None, domain_name="", key_file=None, profile_name=None):
    """Returns a cookiejar of the cookies used by Arc. Optionally pass in a
    domain name to only load cookies from the specified domain, and a profile_name
    to load cookies from a specific profile (e.g., "Default", "Profile 1")
    """
    return Arc(cookie_file, domain_name, key_file, profile_name).load()


def chromium(cookie_file=None, domain_name="", key_file=None, profile_name=None):
    """Returns a cookiejar of the cookies used by Chromium. Optionally pass in a
    domain name to only load cookies from the specified domain, and a profile_name
    to load cookies from a specific profile (e.g., "Default", "Profile 1")
    """
    return Chromium(cookie_file, domain_name, key_file, profile_name).load()


def opera(cookie_file=None, domain_name="", key_file=None, profile_name=None):
    """Returns a cookiejar of the cookies used by Opera. Optionally pass in a
    domain name to only load cookies from the specified domain, and a profile_name
    to load cookies from a specific profile (e.g., "Default", "Profile 1")
    """
    return Opera(cookie_file, domain_name, key_file, profile_name).load()


def opera_gx(cookie_file=None, domain_name="", key_file=None, profile_name=None):
    """Returns a cookiejar of the cookies used by Opera GX. Optionally pass in a
    domain name to only load cookies from the specified domain, and a profile_name
    to load cookies from a specific profile (e.g., "Default", "Profile 1")
    """
    return OperaGX(cookie_file, domain_name, key_file, profile_name).load()


def brave(cookie_file=None, domain_name="", key_file=None, profile_name=None):
    """Returns a cookiejar of the cookies and sessions used by Brave. Optionally
    pass in a domain name to only load cookies from the specified domain, and a profile_name
    to load cookies from a specific profile (e.g., "Default", "Profile 1")
    """
    return Brave(cookie_file, domain_name, key_file, profile_name).load()


def edge(cookie_file=None, domain_name="", key_file=None, profile_name=None):
    """Returns a cookiejar of the cookies used by Microsoft Edge. Optionally pass in a
    domain name to only load cookies from the specified domain, and a profile_name
    to load cookies from a specific profile (e.g., "Default", "Profile 1")
    """
    return Edge(cookie_file, domain_name, key_file, profile_name).load()


def vivaldi(cookie_file=None, domain_name="", key_file=None, profile_name=None):
    """Returns a cookiejar of the cookies used by Vivaldi Browser. Optionally pass in a
    domain name to only load cookies from the specified domain, and a profile_name
    to load cookies from a specific profile (e.g., "Default", "Profile 1")
    """
    return Vivaldi(cookie_file, domain_name, key_file, profile_name).load()


def firefox(cookie_file=None, domain_name="", key_file=None, profile_name=None):
    """Returns a cookiejar of the cookies and sessions used by Firefox. Optionally
    pass in a domain name to only load cookies from the specified domain, and a profile_name
    to load cookies from a specific profile (profile name from profiles.ini)
    """
    return Firefox(cookie_file, domain_name, key_file, profile_name).load()


def librewolf(cookie_file=None, domain_name="", key_file=None, profile_name=None):
    """Returns a cookiejar of the cookies and sessions used by LibreWolf. Optionally
    pass in a domain name to only load cookies from the specified domain, and a profile_name
    to load cookies from a specific profile (profile name from profiles.ini)
    """
    return LibreWolf(cookie_file, domain_name, key_file, profile_name).load()


def safari(cookie_file=None, domain_name="", key_file=None, profile_name=None):
    """Returns a cookiejar of the cookies and sessions used by Safari. Optionally
    pass in a domain name to only load cookies from the specified domain.
    Note: Safari does not support multiple profiles.
    """
    return Safari(cookie_file, domain_name, key_file, profile_name).load()

def lynx(cookie_file=None, domain_name="", profile_name=None):
    """Returns a cookiejar of the cookies and sessions used by Lynx. Optionally
    pass in a domain name to only load cookies from the specified domain.
    Note: Lynx does not support multiple profiles.
    """
    return Lynx(cookie_file, domain_name, profile_name).load()


def w3m(cookie_file=None, domain_name="", profile_name=None):
    """Returns a cookiejar of the cookies and sessions used by W3m. Optionally
    pass in a domain name to only load cookies from the specified domain.
    Note: W3m does not support multiple profiles.
    """
    return W3m(cookie_file, domain_name, profile_name).load()

all_browsers = [chrome, chromium, opera, opera_gx, brave, edge, vivaldi, firefox, librewolf, safari, lynx, w3m, arc]

def list_chrome_profiles():
    """List all available Chrome profiles"""
    return Chrome.list_profiles()


def list_arc_profiles():
    """List all available Arc profiles"""
    return Arc.list_profiles()


def list_chromium_profiles():
    """List all available Chromium profiles"""
    return Chromium.list_profiles()


def list_opera_profiles():
    """List all available Opera profiles"""
    return Opera.list_profiles()


def list_opera_gx_profiles():
    """List all available Opera GX profiles"""
    return OperaGX.list_profiles()


def list_brave_profiles():
    """List all available Brave profiles"""
    return Brave.list_profiles()


def list_edge_profiles():
    """List all available Edge profiles"""
    return Edge.list_profiles()


def list_vivaldi_profiles():
    """List all available Vivaldi profiles"""
    return Vivaldi.list_profiles()


def list_firefox_profiles():
    """List all available Firefox profiles"""
    return Firefox.list_profiles()


def list_librewolf_profiles():
    """List all available LibreWolf profiles"""
    return LibreWolf.list_profiles()


def list_profiles(browser_name=None):
    """List profiles for a specific browser or all browsers
    
    Args:
        browser_name: Name of browser (e.g., 'chrome', 'firefox'). If None, lists profiles for all browsers.
    
    Returns:
        If browser_name is specified: list of profile names
        If browser_name is None: dict mapping browser names to lists of profiles
    """
    browser_map = {
        'chrome': list_chrome_profiles,
        'arc': list_arc_profiles,
        'chromium': list_chromium_profiles,
        'opera': list_opera_profiles,
        'opera_gx': list_opera_gx_profiles,
        'opera-gx': list_opera_gx_profiles,
        'brave': list_brave_profiles,
        'edge': list_edge_profiles,
        'vivaldi': list_vivaldi_profiles,
        'firefox': list_firefox_profiles,
        'librewolf': list_librewolf_profiles,
    }
    
    if browser_name:
        browser_name_lower = browser_name.lower().replace('-', '_')
        if browser_name_lower in browser_map:
            try:
                return browser_map[browser_name_lower]()
            except BrowserCookieError:
                return []
        return []
    else:
        # Return profiles for all browsers
        result = {}
        for name, func in browser_map.items():
            try:
                profiles = func()
                if profiles:
                    result[name] = profiles
            except BrowserCookieError:
                pass
        return result


def load(domain_name="", profile_name=None):
    """Try to load cookies from all supported browsers and return combined cookiejar
    Optionally pass in a domain name to only load cookies from the specified domain,
    and a profile_name to load cookies from a specific profile for each browser
    """
    cj = http.cookiejar.CookieJar()
    for cookie_fn in all_browsers:
        try:
            # Pass profile_name if the function accepts it
            if profile_name:
                try:
                    cookies = cookie_fn(domain_name=domain_name, profile_name=profile_name)
                except TypeError:
                    # Some browsers (like lynx, w3m) might not support profile_name
                    cookies = cookie_fn(domain_name=domain_name)
            else:
                cookies = cookie_fn(domain_name=domain_name)
            for cookie in cookies:
                cj.set_cookie(cookie)
        except BrowserCookieError:
            pass
    return cj


__all__ = ['BrowserCookieError', 'load', 'all_browsers', 'list_profiles',
           'list_chrome_profiles', 'list_arc_profiles', 'list_chromium_profiles',
           'list_opera_profiles', 'list_opera_gx_profiles', 'list_brave_profiles',
           'list_edge_profiles', 'list_vivaldi_profiles', 'list_firefox_profiles',
           'list_librewolf_profiles'] + all_browsers


if __name__ == '__main__':
    print(load())
