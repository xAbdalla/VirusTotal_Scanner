# VirusTotal Scanner
# Author: Abdalla Hamdy
# Github: https://github.com/xAbdalla

import os

#################################################################################
# YOU NEED TO INSERT YOUR OWN API KEYS AND CHAT ID HERE TO MAKE THE SCRIPT WORK #

# VirusTotal API key is required to scan files.
VT_API_KEY = os.environ.get('VT_API_KEY', 'PUT_YOUR_KEY_HERE')   # Get free one by signing up at https://www.virustotal.com

# Telegram bot token and chat ID are required to send alerts to your Telegram account.
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', 'PUT_YOUR_TOEKN_HERE')   # Get your token from @BotFather
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', 'PUT_YOUR_ID_HERE')    # Get your group chat ID from the Group URL (ex: -xxxxxxxxxx)
NO_SEND = False  # Set to True to disable sending alerts to Telegram

# Paths to monitor for malicious files. You can add relative or absolute paths and environment variables.
PATHS = [
    # Add your paths here (ex: r"path/to/scan_1", r"path/to/scan_2")
    r"test_scan",
    r'C:/Users/%USERNAME%/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup',
    ]
#################################################################################

#################################################################################
# Optional settings to customize the script behavior.

UPLOAD = True   # Set to True to upload files to VirusTotal for scanning if not found in the database

MALSHARE_API_KEY = os.environ.get('MALSHARE_API_KEY', 'PUT_YOUR_KEY_HERE')   # Get free one by signing up at https://malshare.com/register.php

# VirusTotal public API rate limit is 4 lookups/min, 500 lookups/day, 15.5K lookups/month
SCAN_INTERVAL = 0 # in minutes (0 for no interval and skip process check for old scans)
FOREVER = 0  # Set to 0 to scan forever, or set to a number to scan for that number of times (ex: 10)

# List of suspicious file extensions to check for
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta",
    ".scr", ".pif", ".msi", ".com", ".reg", ".docm", ".xlsm", ".pptm",
    ".jar", ".php", ".py", ".sh", ".ps1"
    ]

SKIP_PROCESS = False  # Set to True to skip checking the processes of the scanned files

HISTORY_LOG = True  # Set to False to disable saving the history of scanned files
LOGGING = True  # Set to False to disable logging the alerts to a file
DEBUG = False   # True for more detailed errors, Warning: may expose sensitive information
# Telegram message limit is 4096 characters, you can set the maximum number of messages to send per file
MAX_MSG = 1 # 0 for unlimited
#################################################################################

import os
import time
import json
import ctypes
import base64
import psutil
import hashlib
import requests
import datetime
import winshell
import argparse
import platform
import subprocess
from copy import deepcopy
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from importlib.util import find_spec
if find_spec('pypiwin32') and 'pypiwin32' in find_spec('pypiwin32').name:
    import win32evtlog  # type: ignore
if find_spec('rich') and 'rich' in find_spec('rich').name:
    from rich import print  # type: ignore


class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action):
        if not action.option_strings:
            return super()._format_action_invocation(action)

        parts = []
        if action.option_strings:
            parts.append(', '.join(action.option_strings))

        if action.nargs == 0:
            return ', '.join(parts)
        
        return ' '.join(parts)


def Parse_Args():
    global VT_API_KEY, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, PATHS
    global SCAN_INTERVAL, FOREVER, SUSPICIOUS_EXTENSIONS, DEBUG
    global MAX_MSG, UPLOAD, MALSHARE_API_KEY, NO_SEND, SKIP_PROCESS, HISTORY_LOG, LOGGING
    
    parser = argparse.ArgumentParser(description="VirusTotal Scanner by xAbdalla",
                                     epilog="Please follow GitHub for updates:https://github.com/xAbdalla/VirusTotal_Scanner",
                                     formatter_class=CustomHelpFormatter)
    parser.add_argument("-k", "--vt_api_key", help="VirusTotal API key (required)")
    parser.add_argument("-p", "--paths", help="Folders/Files paths to scan (required)", nargs="+")
    parser.add_argument("-t", "--t_bot_token", help="Telegram bot token")
    parser.add_argument("-c", "--t_chat_id", help="Telegram chat ID")
    parser.add_argument("-i", "--stop_interval", type=float, help="Stop Interval in minutes")
    parser.add_argument("-f", "--cycles", type=int, help="Number of scan cycles (0 for forever)")
    parser.add_argument("-m", "--max_msg", type=int, help="Maximum number of messages per file (0 for unlimited)")
    parser.add_argument("-e", "--sus_ext", help="Suspicious file extensions", nargs="+")
    parser.add_argument("--malshare_api_key", help="MalShare API key")
    parser.add_argument("--no_send", help="Do not send alerts to Telegram", action="store_true")
    parser.add_argument("--no_upload", help="Do not upload new files to VirusTotal", action="store_false")
    parser.add_argument("--skip_process", help="Skip checking the processes of old scanned files", action="store_true")
    parser.add_argument("--no_history", help="Do not cache the history of the scan", action="store_false")
    parser.add_argument("--no_log", help="Do not log the output to a file", action="store_false")
    parser.add_argument("--debug", help="Enable debug mode", action="store_true")
    args = parser.parse_args()
    
    args_dict = vars(args)
    
    if args_dict.get('vt_api_key') == None and not ("PUT" in VT_API_KEY):
        args_dict['vt_api_key'] = VT_API_KEY
    if args_dict.get('t_bot_token') == None and not ("PUT" in TELEGRAM_BOT_TOKEN):
        args_dict['t_bot_token'] = TELEGRAM_BOT_TOKEN
    if args_dict.get('t_chat_id') == None and not ("PUT" in TELEGRAM_CHAT_ID):
        args_dict['t_chat_id'] = TELEGRAM_CHAT_ID
    if args_dict.get('paths') == None and not (PATHS == []):
        args_dict['paths'] = PATHS
    if args_dict.get('malshare_api_key') == None and not ("PUT" in MALSHARE_API_KEY):
        args_dict['malshare_api_key'] = MALSHARE_API_KEY
    
    if args_dict.get('vt_api_key', None):
        if not (args_dict.get('vt_api_key', None) and
                ((args_dict.get('t_bot_token', None) and args_dict.get('t_chat_id', None)) or args_dict.get('no_send', False)) and
                args_dict.get('paths', None)):
            print("[X] VirusTotal API key, Telegram bot token, Telegram chat ID, and Paths are required to proceed.\n")
            parser.print_help()
            exit()
        
        if not args_dict.get('vt_api_key') == None:
            VT_API_KEY = args_dict.get('vt_api_key', "")
        else:
            VT_API_KEY = ""
        
        if not args_dict.get('t_bot_token') == None:
            TELEGRAM_BOT_TOKEN = args_dict.get('t_bot_token', "")
        else:
            TELEGRAM_BOT_TOKEN = ""
        
        if not args_dict.get('t_chat_id') == None:
            TELEGRAM_CHAT_ID = args_dict.get('t_chat_id', "")
        else:
            TELEGRAM_CHAT_ID = ""
        
        if not args_dict.get('paths') in [None, []]:
            PATHS = args_dict.get('paths', [])
        else:
            PATHS = []
        
        if not args_dict.get('malshare_api_key') == None:
            MALSHARE_API_KEY = args_dict.get('malshare_api_key', MALSHARE_API_KEY)
        else:
            MALSHARE_API_KEY = MALSHARE_API_KEY
        
        if not args_dict.get('stop_interval') == None:
            SCAN_INTERVAL = args_dict.get('stop_interval', SCAN_INTERVAL)
        else:
            SCAN_INTERVAL = SCAN_INTERVAL
        
        if not args_dict.get('cycles') == None:
            FOREVER = args_dict.get('cycles', FOREVER)
        else:
            FOREVER = FOREVER
        
        if SCAN_INTERVAL == 0.0 and FOREVER != 0:
            print(f"[X] To skip the scan interval (-i, --stop_interval {SCAN_INTERVAL}), set --cycles to 0.")
            parser.print_help()
            exit()
        
        if not args_dict.get('sus_ext') in [None, []]:
            SUSPICIOUS_EXTENSIONS = args_dict.get('sus_ext', SUSPICIOUS_EXTENSIONS)
        else:
            SUSPICIOUS_EXTENSIONS = SUSPICIOUS_EXTENSIONS
        
        if not args_dict.get('max_msg') == None:
            MAX_MSG = args_dict.get('max_msg', MAX_MSG)
        else:
            MAX_MSG = MAX_MSG
        
        SKIP_PROCESS = args_dict.get('skip_process', SKIP_PROCESS)
        HISTORY_LOG = args_dict.get('no_history', HISTORY_LOG)
        LOGGING = args_dict.get('no_log', LOGGING)
        NO_SEND = args_dict.get('no_send', NO_SEND)
        UPLOAD = args_dict.get('no_upload', UPLOAD)
        DEBUG = args_dict.get('debug', DEBUG)
        
        print("[+] Arguments parsed successfully.")
    
    else:
        print("[+] No arguments provided. Using the default values.")


def GUID():
    if platform.system() == "Windows":
        import wmi
        c = wmi.WMI()
        for system in c.Win32_ComputerSystemProduct():
            return system.UUID
    elif platform.system() == "Linux":
        if os.path.isfile('/sys/class/dmi/id/product_uuid'):
            with open('/sys/class/dmi/id/product_uuid') as f:
                return f.read().strip()
    elif platform.system() == "Darwin":
        uuid = subprocess.check_output(['system_profiler', 'SPHardwareDataType']).decode()
        for line in uuid.splitlines():
            if "UUID" in line:
                return line.split(": ")[1]
        return uuid.uuid1()
    else:
        return os.environ.get('USERNAME', '') + os.environ.get('COMPUTERNAME', '')


def Encrypt(source: str, key: str = str(GUID())+os.environ.get('USERNAME', '')):
    try:
        key = key.encode("utf-8")
        source = source.encode("utf-8")

        key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
        IV = Random.new().read(AES.block_size)  # generate IV
        encryptor = AES.new(key, AES.MODE_CBC, IV)
        padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
        source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
        data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
        data = base64.b64encode(data).decode("utf-8")
        return data
    except:
        return None


def Decrypt(source: str, key: str = str(GUID())+os.environ.get('USERNAME', '')):
    try:
        key = key.encode("utf-8")  # key must be bytes
        source = base64.b64decode(source.encode("utf-8"))

        key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
        IV = source[:AES.block_size]  # extract the IV from the beginning
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        data = decryptor.decrypt(source[AES.block_size:])  # decrypt
        padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
        if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
            return None  # if the padding is incorrect, this is not the correct key
        data = data[:-padding].decode("utf-8")
        return data
    except:
        return None


def Check_Vars():
    global VT_API_KEY, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, PATHS
    global SCAN_INTERVAL, FOREVER, SUSPICIOUS_EXTENSIONS, DEBUG
    global MAX_MSG, UPLOAD, MALSHARE_API_KEY, NO_SEND, SKIP_PROCESS, HISTORY_LOG, LOGGING
    
    if NO_SEND:
        TELEGRAM_BOT_TOKEN = "PUT"
        TELEGRAM_CHAT_ID = "PUT"
    
    if "PUT" in VT_API_KEY:
        VT_API_KEY = input("[+] Enter your VirusTotal API key: ").strip()
        if VT_API_KEY and Check_Vars():
            return True
        else:
            print("[X] VirusTotal API key is required to proceed.")
            exit()
    
    if "PUT" in TELEGRAM_BOT_TOKEN and not NO_SEND:
        TELEGRAM_BOT_TOKEN = input("[+] Enter your Telegram bot token (Enter \"No\" to not send telegram messages): ").strip()
        if TELEGRAM_BOT_TOKEN.lower() in ['no', 'n']: NO_SEND = True
        if TELEGRAM_BOT_TOKEN and Check_Vars():
            return True
        else:
            print("[X] Telegram bot token is required to proceed.")
            exit()
    
    if "PUT" in TELEGRAM_CHAT_ID and not NO_SEND:
        TELEGRAM_CHAT_ID = input("[+] Enter your Telegram chat ID: ").strip()
        if TELEGRAM_CHAT_ID and Check_Vars():
            return True
        else:
            print("[X] Telegram chat ID is required to proceed.")
            exit()
    
    if not VT_API_KEY:
        print("[X] VirusTotal API key is required to proceed.")
        exit()
    else:
        VT_API_KEY = os.path.expandvars(VT_API_KEY.strip())
        
    if not TELEGRAM_BOT_TOKEN:
        print("[X] Telegram bot token is required to proceed.")
        exit()
    else:
        TELEGRAM_BOT_TOKEN = os.path.expandvars(TELEGRAM_BOT_TOKEN.strip())

    if not TELEGRAM_CHAT_ID:
        print("[X] Telegram chat ID is required to proceed.")
        exit()
    else:
        TELEGRAM_CHAT_ID = os.path.expandvars(TELEGRAM_CHAT_ID.strip())

    if not PATHS:
        print("[X] No paths to scan. Please add some paths to scan.")
        exit()
    else:
        for i, path in enumerate(PATHS):
            # Replace environment variables in the path
            PATHS[i] = os.path.expandvars(path.strip()).replace("\\", "/")
    
    if "PUT" in MALSHARE_API_KEY: MALSHARE_API_KEY = ""
    else: MALSHARE_API_KEY = os.path.expandvars(MALSHARE_API_KEY.strip())
    
    try:
        FOREVER = int(FOREVER)
        if FOREVER < 0:
            raise
    except:
        print("[X] FOREVER (number of cycles) is not a valid integer number.")
        exit()
    
    try:
        SCAN_INTERVAL = float(SCAN_INTERVAL)
        if SCAN_INTERVAL < 0.0:
            raise
        if SCAN_INTERVAL == 0.0 and FOREVER != 0:
            print("[X] To skip the scan interval, set the <FOREVER> to 0.")
            exit()
    except:
        print("[X] Scan Interval is not a valid number of minutes.")
        exit()

    try:
        MAX_MSG = int(MAX_MSG)
        if MAX_MSG < 0:
            raise
    except:
        print("[X] MAX_MSG (maximum number of messages) is not a valid integer number.")
        exit()
    
    SUSPICIOUS_EXTENSIONS = list(set([str(ext).strip().lower() for ext in SUSPICIOUS_EXTENSIONS]))
    
    try:
        NO_SEND = bool(NO_SEND)
        UPLOAD = bool(UPLOAD)
        SKIP_PROCESS = bool(SKIP_PROCESS)
        HISTORY_LOG = bool(HISTORY_LOG)
        LOGGING = bool(LOGGING)
        DEBUG = bool(DEBUG)
    except:
        print("[X] Invalid value for one of the optional settings.")
        exit()
        
    if DEBUG:
        print("[+] Variables checked successfully.")
    return True


def Save_logs(message: str) -> bool:
    try:
        if LOGGING:
            with open("logs.txt", "a") as f:
                f.write(f"\n[+] Log Time: {datetime.datetime.now().strftime('%Y-%m-%d %I:%M:%S %p')}\n\n{message}\n\n{"="*100}\n")
        return True
    except Exception as e:
        print(f"[X] Error saving logs{f": {e}" if DEBUG else "."}")
        return False
    

def Save_Data(data: dict) -> bool:
    try:
        if HISTORY_LOG:
            with open("history.cache", "w") as f:
                f.write(Encrypt(json.dumps(data, separators=(',', ':'))))
        
        if LOGGING:
            data_copy = deepcopy(data)
            for key in data_copy.keys():
                del data_copy[key]['vt_check_again']
                
            with open("scanned_files.json", "w") as f:
                json.dump(data_copy, f, sort_keys=True, indent=4)
            
            del data_copy
        return True
    except Exception as e:
        print(f"[X] Error saving the history{f": {e}" if DEBUG else "."}")
        return False


def Load_Data() -> dict:
    if not os.path.exists("history.cache"):
        return {}
    
    try:
        if HISTORY_LOG:
            if DEBUG: print("[+] Loading data from file 'history.cache'")
            with open("history.cache", "r") as f:
                data = json.loads(Decrypt(f.read()))
            if DEBUG: print(f"[+] Data loaded successfully. ({len(data.keys())} records found)")
            return data
    except Exception as e:
        print(f"[X] Error loading the history{f": {e}" if DEBUG else "."}")
        return {}


def Get_SHA256(file_path: str) -> str:
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        print(f"[X] Error hashing the file '{file_path}'{f": {e}" if DEBUG else "."}")
        return ""


def Get_Valhalla(file_hash):
    if not file_hash:
        return False
    
    try:
        VALHALLA_URL = f"https://valhalla.nextron-systems.com/info/search?keyword={file_hash}"
        print("[+] Checking Valhalla Search")
        response = requests.get(VALHALLA_URL)
        if response.status_code == 200:
            if "results:" in response.text.lower() and "no results" not in response.text.lower():
                return VALHALLA_URL
    except Exception as e:
        if DEBUG: print(f"[X] Error querying Valhalla: {e}")
        pass
    return False


def Get_MalShare(file_hash: str) -> str|bool:
    FAKE_HEADERS = {
            'referer': 'https://www.google.com',
            'pragma': 'no-cache',
            'cache-control': 'no-cache',
            'sec-ch-ua': '"Chromium";v="88", "Google Chrome";v="88", ";Not A Brand";v="99"',
            'accept': 'application/json, text/plain, */*',
            'dnt': '1',
            'sec-ch-ua-mobile': '?0',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'accept-language': 'en-US,en;q=0.9,de-DE;q=0.8,de;q=0.7,es;q=0.6'
            }
    
    if not MALSHARE_API_KEY:
        return False
    
    try:
        print("[+] Checking MalShare Reports")
        MAL_API = f'https://malshare.com/api.php?api_key={MALSHARE_API_KEY}&action=details&hash={file_hash}'
        response = requests.get(MAL_API, timeout=15, headers=FAKE_HEADERS)
        if response.status_code == 200:
            return f"https://malshare.com/sample.php?action=detail&hash={file_hash}"
    except Exception as e:
        if DEBUG: print(f"[X] Error querying MalShare: {e}")
        pass
    return False


def Rescan_VT(file_hash: str) -> bool:
    rescan_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/analyse"
    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json",
        }
    
    try:
        response = requests.post(rescan_url, headers=headers)
        response_dict = response.json()
        
        if response.status_code == 200 and 'id' in response_dict.get('data', {}).keys():
            print(f"[+] Rescan requested successfully for the file. (Check the new scan results later)")
            return True
        
        elif response.status_code == 204:
            print(f"[X] VirusTotal API request failed with status code 204: Rate limit exceeded.")
            time.sleep(15)
        
        else:
            error_code = response_dict.get('error', {}).get('code', "")
            error_message = response_dict.get('error', {}).get('message', "")
            if DEBUG:
                print(f"[X] VirusTotal API request failed with status code {response.status_code} ({error_code}): {error_message}")
            else:
                print(f"[X] VirusTotal API request failed with error code: {error_code}")
                    
    except Exception as e:
        print(f"[X] Exception occurred while requesting rescan{f": {e}" if DEBUG else "."}")
    
    return False


def Get_VT_Report(file_hash: str) -> dict:
    global checked_files
    
    report_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json",
        }
    
    try:
        response = requests.get(report_url, headers=headers)
        response_dict = response.json()
        
        if response.status_code == 200:
            print(f"[+] Checking the results from VirusTotal database.")
            last_analysis = datetime.datetime.fromtimestamp(response_dict['data'].get('attributes', {}).get('last_analysis_date', 0))
            delta_from_now = datetime.datetime.now() - last_analysis
            is_old_scan = delta_from_now > datetime.timedelta(days=15)
            
            if is_old_scan:
                if delta_from_now.days == 19924:
                    print(f"[!] The analysis of the file is still in progress. Please check later.")
                    print(f"[+] Check the analysis URL: https://www.virustotal.com/gui/file/{file_hash}")
                else:
                    print(f"[!] Last scan at {last_analysis.strftime('%Y-%m-%d %I:%M:%S %p')} ({delta_from_now.days} days ago).")
                    print(f"[!] File was last scanned more than 15 days ago. Requesting rescan.")
                time.sleep(15)  # Wait for 15 seconds before request rescan
                if delta_from_now.days != 19924 and Rescan_VT(file_hash):
                    checked_files[file_hash]['vt_check_again'] = True
                else:
                    checked_files[file_hash]['vt_check_again'] = True
                    checked_files[file_hash]['vt_checked'] = False
                    return {}
                
            else:
                checked_files[file_hash]['vt_check_again'] = False
            
            checked_files[file_hash]['vt_checked'] = True
                
        elif response.status_code == 204:
            checked_files[file_hash]['vt_checked'] = False
            checked_files[file_hash]['vt_check_again'] = True
            print(f"[X] VirusTotal API request failed with status code 204: Rate limit exceeded.")
            time.sleep(15)
        
        elif response.status_code == 404 and response_dict.get('error', {}).get('code', "") == "NotFoundError":
            checked_files[file_hash]['vt_checked'] = False
            checked_files[file_hash]['vt_check_again'] = True
            print(f"[!] File Hash not found in VirusTotal database.")
            
        else:
            checked_files[file_hash]['vt_checked'] = False
            checked_files[file_hash]['vt_check_again'] = True
            error_code = response_dict.get('error', {}).get('code', "")
            error_message = response_dict.get('error', {}).get('message', "")
            if DEBUG:
                print(f"[X] VirusTotal API request failed with status code {response.status_code} ({error_code}): {error_message}")
            else:
                    print(f"[X] VirusTotal API request failed with error code: {error_code}")
        return response_dict
    
    except Exception as e:
        print(f"[X] Exception occurred while checking VirusTotal{f": {e}" if DEBUG else "."}")
    
    checked_files[file_hash]['vt_checked'] = False
    checked_files[file_hash]['vt_check_again'] = True
    return {}


def Upload_File_VT(file_path: str) -> dict:
    file_size = os.path.getsize(file_path) / 1024.0 / 1024.0  # in MB
    if file_size >= 200:
        print(f"[X] File '{os.path.basename(file_path)}' is too large to upload to VirusTotal (>200MB).")
        return {}
    
    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json",
        }
    
    if file_size < 32:
        upload_url = f"https://www.virustotal.com/api/v3/files"
    else:
        get_upload_url = f"https://www.virustotal.com/api/v3/files/upload_url"
        try:
            response = requests.get(get_upload_url, headers=headers)
            
            if response.status_code == 200 and 'data' in response.json().keys():
                upload_url = response.json()['data']
            else:
                error_code = response.json().get('error', {}).get('code', "")
                error_message = response.json().get('error', {}).get('message', "")
                if DEBUG:
                    print(f"[X] Failed to get upload URL from VirusTotal with status code {response.status_code} ({error_code}): {error_message}")
                else:
                    print(f"[X] Failed to get upload URL from VirusTotal with error code: {error_code}")
                return {}
            
        except Exception as e:
            print(f"[X] Exception occurred while getting upload URL from VirusTotal report{f": {e}" if DEBUG else "."}")
            return {}
    
    try:
        with open(file_path, "rb") as f:
            files = {'file': (os.path.basename(file_path), f)}
            response = requests.post(upload_url, files=files, headers=headers)
            
        if response.status_code == 200:
            analysis_id = response.json().get('data', {}).get('id', "")
            print(f"[+] File '{os.path.basename(file_path)}' uploaded successfully to VirusTotal for scanning{f". (Analysis ID: {analysis_id})" if DEBUG else "."}")
            try:
                while True:
                    time.sleep(15)  # Wait for the scan results
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                    analysis_response = requests.get(analysis_url, headers=headers)
                    if analysis_response.status_code == 200:
                        if analysis_response.json().get('data', {}).get('attributes', {}).get('status', "") == "completed":
                            file_sha256 = analysis_response.json().get('meta', {}).get('file_info', {}).get('sha256', "")
                            print(f"[+] File '{os.path.basename(file_path)}' scanned successfully by VirusTotal.")
                            break
                    
                if file_sha256:
                    response = Get_VT_Report(file_sha256)
                    return response
            except Exception as e:
                print(f"[X] Exception occurred while checking VirusTotal{f": {e}" if DEBUG else "."}")
        else:
            error_code = response.json().get('error', {}).get('code', "")
            error_message = response.json().get('error', {}).get('message', "")
            if DEBUG:
                print(f"[X] VirusTotal API request failed with status code {response.status_code} ({error_code}): {error_message}")
            else:
                print(f"[X] VirusTotal API request failed with error code: {error_code}")
                        
    except Exception as e:
        print(f"[X] Exception occurred while uploading file to VirusTotal{f": {e}" if DEBUG else "."}")
    
    return {}


def Send_TeleMessage(message: str) -> bool:
    if NO_SEND: return True
    
    message = message.replace("\nVirusTotal", "\nVT")
    message = message.replace("\\", "/")
    # message = message.replace("\n\n", "\n")
    message = message.replace("  ", " ")
    
    # Telegram message limit is 4096 characters
    counter = 0
    while len(message) > 4055:
        counter += 1
        if MAX_MSG and counter > MAX_MSG:
            return True
        
        if "\nProcess(es) Information" in message:
            index = message[:4055].rfind("\nProcess(es) Information")
            if (index+1 < len(message) and
                Send_TeleBot(f"⚠️ VirusTotal Scanner Alert{f" {counter}" if counter and MAX_MSG != 1 else ""} ⚠️\n\n```\n" + message[:index] + "```")):
                message = message[index+1:]
                continue
        
        message = message.replace("Process(es) Information:\n\n", "")
        if "\n Process " in message:
            index = message[:4055].find("\n Process ")
            if (index+1 < len(message) and
                Send_TeleBot(f"⚠️ VirusTotal Scanner Alert{f" {counter}" if counter else ""} ⚠️\n\n```\n" + message[:index] + "```")):
                message = message[index+1:]
                continue
        
        index = 4055
        if Send_TeleBot(f"⚠️ VirusTotal Scanner Alert{f" {counter}" if counter else ""} ⚠️\n\n```\n" + message[:index] + "```"):
            message = message[index:]
            continue
        return False
    else:
        if "\n Process " in message and not "Process(es) Information:" in message:
            counter += 1
            if MAX_MSG and counter > MAX_MSG:
                return True
            index = message.find("\n Process ")
            if (index+1 < len(message) and
                Send_TeleBot(f"⚠️ VirusTotal Scanner Alert{f" {counter}" if counter else ""} ⚠️\n\n```\n" + message[:index] + "```")):
                message = message[index+1:]
    
    if MAX_MSG and counter+1 > MAX_MSG:
        return True
    if message and Send_TeleBot(f"⚠️ VirusTotal Scanner Alert{f" {counter+1}" if counter else ""} ⚠️\n\n```\n" + message + "```"):
        return True
    return False


def Send_TeleBot(message: str) -> bool:
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage?parse_mode=MarkdownV2"
    data = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message,
        }
    
    try:
        response = requests.post(url, data=data)
        if response.status_code != 200:
            print(f"[X] Failed to send message to Telegram{f": {response.text}" if DEBUG else "."}")
            return False
        else:
            print(f"[+] Alert sent to Telegram successfully.")
            return True
    except Exception as e:
        print(f"[X] Exception occurred while sending alert to Telegram{f": {e}" if DEBUG else "."}")
    return False


def Get_Message(**kwargs) -> str:
    global checked_files
    
    filename = kwargs.get('filename', "Unknown")
    file_extension = kwargs.get('file_extension', "Unknown")
    file_path = kwargs.get('file_path', "Unknown")
    file_hash = kwargs.get('file_hash', "Unknown")
    
    vt_scan_date = kwargs.get('vt_scan_date', checked_files[file_hash].get('last_checked', "Unknown"))
    old_scan_date = ""
    if vt_scan_date != "Unknown" and not isinstance(vt_scan_date, str):
        date = datetime.datetime.fromtimestamp(vt_scan_date)
        if datetime.datetime.now() - date > datetime.timedelta(days=15):
            old_scan_date = " (Relatively old scan)"
        vt_scan_date = datetime.datetime.fromtimestamp(vt_scan_date).strftime("%Y-%m-%d %I:%M:%S %p")
    elif isinstance(vt_scan_date, datetime.datetime):
        vt_scan_date = vt_scan_date.strftime("%Y-%m-%d %I:%M:%S %p")
    checked_files[file_hash]['last_checked'] = vt_scan_date
    
    vt_reputation = kwargs.get('vt_reputation', "Unknown")
    vt_votes = kwargs.get('vt_votes', "Unknown")
    vt_url = kwargs.get('vt_url', "No Link")
    
    valhalla_url = kwargs.get('valhalla_url', False)
    malshare_url = kwargs.get('malshare_url', False)
    
    vt_malicious = kwargs.get('vt_malicious', 0)
    vt_suspicious = kwargs.get('vt_suspicious', 0)
    vt_undetected = kwargs.get('vt_undetected', 0)
    vt_harmless = kwargs.get('vt_harmless', 0)
    vt_failure = kwargs.get('vt_failure', 0)
    vt_unsupported = kwargs.get('vt_unsupported', 0)
    vt_total = kwargs.get('vt_total', 0)
    
    suspicious_ext = str(kwargs.get('suspicious_ext', False))
    alert_type = kwargs.get('alert_type', "Unknown")
    
    processes_info = kwargs.get('processes_info', [])
    
    message = []
    
    if not filename or not file_path or not file_hash:
        print("[X] ERROR: Missing required parameters to generate message.")
        return ""
    
    message.append(f"File Name: '{filename}'")
    message.append(f"Full Path: '{file_path}'")
    message.append(f"SHA256 Hash: {file_hash}")
    
    message.append("")
    if alert_type != "Unknown":
        message.append(f"Alert Type: {alert_type}")
        if suspicious_ext == "True":
            message.append(f"Suspicous Extension: {suspicious_ext} ({file_extension})")
        if checked_files[file_hash].get('vt_checked', False) and vt_url != "No Link":
            message.append(f"VirusTotal Last Scan Date: {vt_scan_date}{old_scan_date}")
            message.append(f"VirusTotal Reputation: {vt_reputation}")
            message.append(f"VirusTotal Votes: {vt_votes}")
            message.append(f"VirusTotal URL: {vt_url}")
            if vt_malicious or vt_suspicious:
                message.append(f"Virustotal Scan Details:")
                if vt_malicious: message.append(f"  Malicious: {vt_malicious}/{vt_total}")
                if vt_suspicious: message.append(f"  Suspicious: {vt_suspicious}/{vt_total}")
                if vt_undetected: message.append(f"  Undetected: {vt_undetected}/{vt_total}")
                if vt_harmless: message.append(f"  Harmless: {vt_harmless}/{vt_total}")
                if vt_failure: message.append(f"  Failure: {vt_failure}/{vt_total}")
                if vt_unsupported: message.append(f"  Unsupported: {vt_unsupported}/{vt_total}")
        elif 'http' in vt_url:
            message.append(f"Last Scan Date: {vt_scan_date}{old_scan_date}")
            message.append(f"VirusTotal URL: {vt_url}")
        else:
            message.append(f"Last Scan Date: {vt_scan_date}{old_scan_date}")
        
        if valhalla_url:
            message.append(f"Valhalla URL: {valhalla_url}")
        if malshare_url:
            message.append(f"MalShare URL: {malshare_url}")
    else:
        message.append("Alert Type: No Data")
        
    
    if processes_info:
        message.append("")
        message.append("Process(es) Information:")
        no_processes = len(processes_info)
        for i, process in enumerate(processes_info):
            message.append("")
            message.append(f"  Process {i+1}/{no_processes}:")
            message.append(f"    Status: {process['status']}")
            message.append(f"    Name: {process['name']} (PID: {process['pid']})")
            message.append(f"    User: {process['username']}")
            message.append(f"    Parent: {process['pname']} (PID: {process['ppid']})")
            message.append(f"    Process-Chain: {process['proc_chain']}")
            message.append(f"    Create Time: {process['create_time']} (Running Time: {process['running_time']})")
            message.append("")
            message.append(f"    Executable: '{process['exe']}'")
            message.append(f"    Current Working Directory: '{process['cwd']}'")
            message.append(f"    Cmdline: {process['cmdline']}")
            message.append("")
            
            if process['open_files']:
                message.append("    Open Files:")
                process['open_files'] = sorted(list(set(process['open_files'])))
                for ofile in process['open_files']:
                    message.append(f"      '{ofile}'")
                message.append("")
            else:
                message.append("    Open Files: No Files Opened")
                message.append("")
            
            if process['connections']:
                message.append("    Connections:")
                process['connections'] = sorted(list(set(process['connections'])))
                for connection in process['connections']:
                    message.append(f"      {connection}")
            else:
                message.append("    Connections: No Active Connections")
            if i+1 != no_processes: message.append("  " + ("-" * 25))
    
    else:
        message.append("")
        message.append("Process Information: No Process Associated")
    
    return "\n".join(message)


def Get_Process_Events_Win() -> dict:
    try:
        if platform.system() == "Windows" and ctypes.windll.shell32.IsUserAnAdmin():
            server = 'localhost'  # Name of the target computer to get event logs
            log_type = 'Security'
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            handle = win32evtlog.OpenEventLog(server, log_type)
            total = win32evtlog.GetNumberOfEventLogRecords(handle)

            events = {}
            while True:
                events_raw = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events_raw:
                    break
                for event in events_raw:
                    if event.EventID == 4688:  # Process creation event ID
                        event = event.StringInserts
                        pid = int(event[4].strip(), 16)
                        ppid = int(event[7].strip(), 16)
                        name = os.path.basename(event[5].strip())
                        if not name: name = "Non-existent process"
                        pname = os.path.basename(event[13].strip())
                        if not pname: pname = "Non-existent process"                        
                        events[pid] = {'name': name, 'pid': pid, 'pname': pname, 'ppid': ppid}

            win32evtlog.CloseEventLog(handle)
            return events
    except:
        pass
    return {}


def Get_Running_Process(executable_path: str) -> list[dict]:
    processes = []
    
    if not os.path.exists(executable_path) or not os.path.isfile(executable_path):
        return processes
    
    running_processes = psutil.process_iter()
    for proc in running_processes:
        try:
            proc = proc.as_dict()
            if proc['exe'] == executable_path:
                processes.append(proc)
            else:
                if proc['cmdline']:
                    for cmd in proc['cmdline']:
                        if os.path.isfile(cmd) and os.path.samefile(executable_path, cmd):
                            processes.append(proc)
                            break
                
                if proc['open_files']:
                    for ofile in proc['open_files']:
                        if os.path.isfile(ofile[0]) and os.path.samefile(executable_path, ofile[0]):
                            processes.append(proc)
                            break
                
        except:
            pass
    
    return processes


def Get_Process_Info(executable_path: str) -> list[dict]:
    processes_data = []
    print(f"[+] Checking running processes for '{os.path.basename(executable_path)}'")
    processes = Get_Running_Process(executable_path)
    if not processes: return processes_data
    
    events = Get_Process_Events_Win()
    for i, process in enumerate(processes):
        processes_data.append(dict())
        
        processes_data[-1]['name'] = process['name']
        processes_data[-1]['pid'] = process['pid']
        processes_data[-1]['exe'] = process['exe']
        processes_data[-1]['cwd'] = process['cwd']  # Current Working Directory
        processes_data[-1]['ppid'] = process['ppid']
        processes_data[-1]['status'] = process['status']
        processes_data[-1]['username'] = process['username'] if process['username'] else "SYSTEM"
        
        try:
            processes_data[-1]['pname'] = psutil.Process(process['pid']).parent().name()
        except:
            if process['ppid'] in events.keys():
                processes_data[-1]['pname'] = events[process['ppid']].get('name', "Non-existent process")
            else:
                processes_data[-1]['pname'] = "Non-existent process"
        
        cmdline = process['cmdline']
        if cmdline:
            for i, cmd in enumerate(cmdline):
                if os.path.exists(cmd):
                    cmdline[i] = f'"{cmd}"'
                elif " " in cmd and not (cmd.startswith(("'", '"')) and cmd.endswith(("'", '"'))):
                    cmdline[i] = f'"{cmd}"'
        else: cmdline = [f'"{process["exe"]}"']
        processes_data[-1]['cmdline'] = " ".join(cmdline)
        
        chain_pid = [processes_data[-1]['pid'], ]
        chain_name = [processes_data[-1]['name'], ]
        while True:
            try:
                parent = psutil.Process(chain_pid[-1]).parent()
                chain_pid.append(parent.pid)
                chain_name.append(parent.name())
                continue
            except:
                try:
                    p = psutil.Process(chain_pid[-1]).as_dict()
                    if p['ppid'] in events.keys():
                        chain_pid.append(p['ppid'])
                        chain_name.append(events[p['ppid']].get('name', "Non-existent process"))
                        break
                    else:
                        chain_pid.append(p.get('ppid', 'Unknown'))
                        chain_name.append("Non-existent process")
                        break
                except:
                    chain_pid.append('Unknown')
                    chain_name.append("Non-existent process")
                    break
        chain_pid = map(str, reversed(chain_pid))
        chain_name = map(str, reversed(chain_name))
        chain = [f"{n} ({p})" for n, p in zip(chain_name, chain_pid)]
        processes_data[-1]['proc_chain'] = " > ".join(chain)
        
        open_files = []
        if 'open_files' in process.keys() and process['open_files']:
            for ofile in process['open_files']:
                open_files.append(ofile[0])
        processes_data[-1]['open_files'] = open_files
        
        connections = []
        if process.get('connections', process.get('net_connections', [])):
            for con in process.get('connections', process.get('net_connections', [])):
                connections.append(f'{con[5]}\t{con[3][0]}:{con[3][1]}')
        processes_data[-1]['connections'] = connections
        
        create_time = datetime.datetime.fromtimestamp(process['create_time'])
        running_time = datetime.datetime.now() - create_time
        processes_data[-1]['create_time'] = create_time.strftime("%Y-%m-%d %I:%M:%S %p")
        processes_data[-1]['running_time'] = ":".join(str(running_time).split(".")[:-1])
    
    return processes_data


def Scan_Paths(paths: list[str] = []):
    global checked_files

    for i, path in enumerate(paths):
        checked_files = Load_Data()
        print(f"{"\n" if i==0 else ''}{'='*100}\n")
        
        no_paths = len(paths)
        if not os.path.exists(path) and not (os.path.isdir(path) or os.path.isfile(path)):
            print(f"[X] {i+1}/{no_paths} Path '{path}' does not exist. Skipping.")
            time.sleep(1)
            continue
        
        files = []
        if os.path.isfile(path):
            path = os.path.abspath(path).replace("\\", "/")
            files = [path, ]
        elif os.path.isdir(path):
            for root, dirs, filenames in os.walk(os.path.abspath(path)):
                for filename in filenames:
                    file_path = os.path.join(root, filename).replace("\\", "/")
                    files.append(file_path)
        else:
            print(f"[X] {i+1}/{no_paths} Invalid Path: '{path}'")
            time.sleep(1)
            continue
        
        if not files:
            print(f"[!] {i+1}/{no_paths} No files found in path: '{path}'")
            time.sleep(1)
            continue
                    
        no_files = len(files)
        vt_timer = datetime.datetime.now() - datetime.timedelta(seconds=15) # Initialize VirusTotal API timer
        print(f"[+] {i+1}/{no_paths} Checking Path: '{path}'")
        
        for j, file_path in enumerate(files):
            message_data = {}
            filename = os.path.basename(file_path)
            file_extension = os.path.splitext(filename)[1].lower()
            
            if SCAN_INTERVAL > 0: print(f"\n{i+1}: {j+1}/{no_files} Checking file: '{file_path}'")
            
            if file_extension == '.lnk':
                if winshell.shortcut(file_path).path: # type: ignore
                    file_path = winshell.shortcut(file_path).path # type: ignore
                    filename = os.path.basename(file_path)
                    file_extension = os.path.splitext(filename)[1].lower()
                    if SCAN_INTERVAL > 0: print(f"[!] File is a shortcut. Resolving to: '{file_path}'")
                else:
                    if SCAN_INTERVAL > 0: print(f"[X] Error resolving shortcut '{filename}'")
                    time.sleep(1)
                    continue
                    
            file_hash = Get_SHA256(file_path)
            
            message_data['filename'] = filename
            message_data['file_extension'] = file_extension
            message_data['file_path'] = file_path
            message_data['file_hash'] = file_hash
            
            if not file_hash:
                continue
            elif (SCAN_INTERVAL == 0 and
                  checked_files.get(file_hash, {}).get("notified", False) and
                  checked_files.get(file_hash, {}).get("vt_checked", False) and
                  not checked_files.get(file_hash, {}).get("vt_check_again", False)):
                print(f"[-] File '{filename}' scanned and notified before (Scan Result: {checked_files[file_hash]['scan_result']}), skipping the process check.")
                time.sleep(1)
                continue
            elif not (checked_files.get(file_hash, {}).get("notified", False) and
                      checked_files.get(file_hash, {}).get("vt_checked", False)) or checked_files.get(file_hash, {}).get("vt_check_again", False):
                print(f"[+] New file detected: '{filename}'")
                checked_files[file_hash] = {"notified": False,
                                            "vt_checked": False,
                                            "vt_check_again": False,
                                            "file_path": file_path.replace("\\", "/"),
                                            "scan_result": "Unknown",
                                            "last_checked": f"{datetime.datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")}"}
                
                if (datetime.datetime.now() - vt_timer).seconds < 15:
                    print(f"[!] VirusTotal API rate limit exceeded. Waiting for some time before checking again.")
                    time.sleep(15 - (datetime.datetime.now() - vt_timer).seconds)
                    vt_timer = datetime.datetime.now()
                
                vt_report = Get_VT_Report(file_hash)
                if UPLOAD and vt_report and vt_report.get('error', 0):
                    print(f"[+] Uploading file '{filename}' to VirusTotal for scanning.")
                    vt_report = Upload_File_VT(file_path)
                
                if file_extension in SUSPICIOUS_EXTENSIONS:
                    message_data['suspicious_ext'] = True
                    checked_files[file_hash]['scan_result'] = "Suspicious Extension"
                    message_data['alert_type'] = "Suspicious Extension"
                else:
                    message_data['suspicious_ext'] = False
                    checked_files[file_hash]['scan_result'] = "Clean File"
                    message_data['alert_type'] = "Clean File"
                
                if not vt_report and not checked_files[file_hash]['vt_checked'] and checked_files[file_hash]['vt_check_again']:
                    pass
                elif not vt_report:
                    print(f"[X] Error checking VirusTotal for '{filename}'.")
                elif not vt_report.get('data', 0):
                    print(f"[!] '{filename}' file not found in VirusTotal Database. Please enable <UPLOAD> to scan.")
                else:
                    vt_report = vt_report.get('data', {})
                    
                    last_analysis_stats = vt_report.get('attributes', {}).get('last_analysis_stats', {})
                    malicious = last_analysis_stats.get('malicious', 0)
                    suspicious = last_analysis_stats.get('suspicious', 0)
                    undetected = last_analysis_stats.get('undetected', 0)
                    harmless = last_analysis_stats.get('harmless', 0)
                    failure = last_analysis_stats.get('timeout', 0) + last_analysis_stats.get('confirmed-timeout', 0) + last_analysis_stats.get('failure', 0)
                    unsupported = last_analysis_stats.get('type-unsupported', 0)
                    total = 0
                    for num in last_analysis_stats.values():
                        total += int(num)
                        
                    message_data['vt_malicious'] = malicious
                    message_data['vt_suspicious'] = suspicious
                    message_data['vt_undetected'] = undetected
                    message_data['vt_harmless'] = harmless
                    message_data['vt_failure'] = failure
                    message_data['vt_unsupported'] = unsupported
                    message_data['vt_total'] = total
                    
                    checked_files[file_hash]['last_checked'] = f"{vt_report.get('attributes', {}).get('last_analysis_date', datetime.datetime.now().strftime("%Y-%m-%d %I:%M:%S %p"))}"
                    
                    message_data['vt_scan_date'] = vt_report.get('attributes', {}).get('last_analysis_date', "Unknown")
                    message_data['vt_reputation'] = f"{"Malicious" if malicious+suspicious else "Clean"} ({malicious+suspicious} / {total} scanners)"
                    message_data['vt_url'] = f"https://www.virustotal.com/gui/file/{vt_report.get('attributes', {}).get('sha256', "")}"
                    
                    vote_up = vt_report.get('attributes', {}).get('total_votes', {}).get('harmless', 0)
                    vt_down = vt_report.get('attributes', {}).get('total_votes', {}).get('malicious', 0)
                    message_data['vt_votes'] = f"{vote_up} Good - {vt_down} Bad"
                
                    if malicious+suspicious == 0:
                        if message_data['suspicious_ext']:
                            checked_files[file_hash]['scan_result'] = "Suspicious Extension"
                            message_data['alert_type'] = "Suspicious Extension"
                        else:
                            checked_files[file_hash]['scan_result'] = "Clean File"
                            message_data['alert_type'] = "Clean File"
                    else:
                        checked_files[file_hash]['scan_result'] = "Malicious File"
                        message_data['alert_type'] = "Malicious File"
                
                if 'http' not in checked_files[file_hash].get('valhalla_url', ""):
                    valhalla_url = Get_Valhalla(file_hash)
                    if valhalla_url:
                        message_data['valhalla_url'] = valhalla_url
                        checked_files[file_hash]['valhalla_url'] = valhalla_url
                elif 'http' in checked_files[file_hash].get('valhalla_url', ""):
                    message_data['valhalla_url'] = checked_files[file_hash].get('valhalla_url', "")
                
                if 'http' not in checked_files[file_hash].get('malshare_url', ""):
                    malshare_url = Get_MalShare(file_hash)
                    if malshare_url:
                        message_data['malshare_url'] = malshare_url
                        checked_files[file_hash]['malshare_url'] = malshare_url
                elif 'http' in checked_files[file_hash].get('malshare_url', ""):
                    message_data['malshare_url'] = checked_files[file_hash].get('malshare_url', "")
                
                processes_info = Get_Process_Info(file_path)
                message = Get_Message(processes_info= processes_info, **message_data)
                
                print(f"\n{message}\n")
                # checked_files[file_hash]['notified'] = True
                
                if message_data['alert_type'] != "Clean File" and Send_TeleMessage(message):
                    checked_files[file_hash]['notified'] = True
                elif message_data['alert_type'] == "Clean File":
                    print(f"[+] File '{filename}' is clean. No alert sent.")
                    checked_files[file_hash]['notified'] = True
                
            else:
                print(f"[-] File '{filename}' already scanned and notified before (Scan Result: {checked_files[file_hash]['scan_result']}).")
                
                message_data['vt_url'] = f"https://www.virustotal.com/gui/file/{file_hash}"
                
                valhalla_url = Get_Valhalla(file_hash)
                if valhalla_url:
                    message_data['valhalla_url'] = valhalla_url
                    checked_files[file_hash]['valhalla_url'] = valhalla_url
                
                malshare_url = Get_MalShare(file_hash)
                if malshare_url:
                    message_data['malshare_url'] = malshare_url
                    checked_files[file_hash]['malshare_url'] = malshare_url
                
                message_data['alert_type'] = checked_files[file_hash]['scan_result']
                if file_extension in SUSPICIOUS_EXTENSIONS:
                    message_data['suspicious_ext'] = True
                message_data['last_checked'] = checked_files[file_hash]['last_checked']
                if not SKIP_PROCESS:
                    processes_info = Get_Process_Info(file_path)
                else:
                    processes_info = []
                message = Get_Message(processes_info= processes_info, **message_data)
                
                print(f"\n{message}")
            
            print(f"{'\n' + ('-'*50) if j+1 != no_files else ''}")
            Save_Data(checked_files)
            Save_logs(message)


if __name__ == "__main__":
    Parse_Args()
    Check_Vars()
    
    # Change the current directory to the script directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    if not DEBUG: os.system('cls' if os.name == 'nt' else 'clear')
    
    print("[+][+][+] VirusTotal Scanner by xAbdalla [+][+][+]\n")
    print(f"[+] Monitoring the following paths:{f" (Upload Enabled)" if UPLOAD else ' (Upload Disabled)'}")
    for i, path in enumerate(PATHS):
        print(f"      {i+1}. '{path}'")
    print(f"[+] Suspicious Extensions: {', '.join(SUSPICIOUS_EXTENSIONS)}")
    print(f"[+] Stop Interval: {SCAN_INTERVAL} minutes")
    print(f"[+] Number of Cycles: {FOREVER if FOREVER else 'Forever'}")
    if MALSHARE_API_KEY: print(f"[+] MalShare API: Enabled")
    if NO_SEND:
        print(f"[+] Telegram Alert: Disabled.")
    else:
        print(f"[+] Telegram Alert: Enabled. ({MAX_MSG if MAX_MSG else 'Unlimited'} Msg/File)")
    try:
        if platform.system() == "Windows" and ctypes.windll.shell32.IsUserAnAdmin():
            print(f"[+] Running as Administrator. (Helps in getting more process information from Event Logs)")
        elif platform.system() != "Windows":
            pass
        else:
            # print(f"[X] No Administrator Privileges. (Some process information may not be available)")
            pass
    except:
        if platform.system() != "Windows":
            pass
        else:
            # print(f"[X] No Administrator Privileges. (Some process information may not be available)")
            pass
    
    print()
    print(f"[+] Press (Ctrl + C) to stop the script. (You may need to press it multiple times)")
    
    t1 = datetime.datetime.now()
    
    if FOREVER == 0:
        while True:
            t2 = datetime.datetime.now()
            Scan_Paths(PATHS)
            t3 = datetime.datetime.now()
            if SCAN_INTERVAL > 0:
                print(f"{'='*100}\n\n[+] Scan time: {".".join(str(t3-t2).split('.')[:-1])}")
            if SCAN_INTERVAL == 0: print()
            print(f"[+] Running time: {".".join(str(t3-t1).split('.')[:-1])}")
            if SCAN_INTERVAL > 0:
                print(f"[+] Sleeping for {SCAN_INTERVAL} minutes before scanning again. (Press Ctrl+C to skip the sleep)")
                try:
                    time.sleep(60 * SCAN_INTERVAL)
                except:
                    print("[+] Skipping the sleep.")
    elif FOREVER > 0:
        for i in range(FOREVER):
            t2 = datetime.datetime.now()
            Scan_Paths(PATHS)
            t3 = datetime.datetime.now()
            print(f"{'='*100}\n\n[+] Scanned {i+1}/{FOREVER} times.")
            print(f"[+] Scan time: {".".join(str(t3-t2).split('.')[:-1])}")
            print(f"[+] Running time: {".".join(str(t3-t1).split('.')[:-1])}")
            if i+1 != FOREVER:
                print(f"[+] Sleeping for {SCAN_INTERVAL} minutes before scanning again. (Press Ctrl+C to skip the sleep)")
                try:
                    time.sleep(60 * SCAN_INTERVAL)
                except:
                    print("[+] Skipping the sleep.")
        print("[+] Scanning completed.")
    else:
        print("[X] Invalid value for FOREVER. Please set it to 0 to scan forever, or set it to a number to scan for that number of times.")
