<img src="https://www.virustotal.com/gui/images/favicon.svg" align= "right" style="float: right;height: 65px" alt="icon"/>

# VirusTotal Scanner

![Static Badge](https://img.shields.io/badge/language-python-green)
[![Static Badge](https://img.shields.io/badge/license-MIT-blue)](https://github.com/xAbdalla/VirusTotal_Scanner?tab=MIT-1-ov-file#readme)
[![Static Badge](https://img.shields.io/badge/author-xAbdalla-red)](https://github.com/xAbdalla)

VirusTotal Scanner is a Python script that utilizes the [VirusTotal](https://www.virustotal.com/) API v3 to scan files for potential malware or suspicious behavior. It provides a brief summary of the scan results and also retrieves information about the running processes associated with the file. If the file is identified as malicious or suspicious, the script will send a notification message through a Telegram bot. This tool is designed to enhance the security and analysis of files by leveraging the capabilities of VirusTotal's extensive malware database and process monitoring features.

## Features
- Accept both folder and file paths.
- Accept relative or absolute paths and environment variables like `%USERNAME%` and `%TEMP%`.
- Scan the folder recursively and get all the files.
- Do not request another scan for already scanned and notified files.
- Can run forever and scan only new or modified files.
- Save logs of the scans in text and JSON files.
- Save the history cache in encrypted text to prevent any user modification.
- Quota-friendly, sending requests for the newly discovered files only.
- Can upload files (<200MB) if they are not in the VirusTotal database.
- Request to rescan/re-analyze the file if the last scan is too old (>=15 days).
- If the file is associated with any process as an executable or argument or opened in the device, it will include its information in the report and get its network connections.
- **For Windows Only** (Not Required): If the script has admin privileges, it could access the event logs and get process creation logs, which will help get some useful information in the scan report.
- Send a notification of the malicious/suspicious files to the Telegram chat.
- If for any reason the notification fails, it will scan and try to send it again in the next cycle.
- If the scan report is too long for one Telegram message, it will break it into several messages and send them. (You can specify the maximum number of messages per file.)
- You can make it go to sleep between cycles.
- You can modify the variables in the code and run it directly or pass them as arguments in the terminal.
- If there are any reports on [Valhalla](https://valhalla.nextron-systems.com/) or [MalShare](https://malshare.com/), it will provide you with the URL to the report page.



## Requirements
- Clone the repo:
  ```
  git clone https://github.com/xAbdalla/VirusTotal_Scanner.git
  cd VirusTotal_Scanner
  ```
- Create a new environment:
  ```
  python -m venv vt_env
  ```
- Activate the environment:
  - For Windows:
    ```
    vt_env\Scripts\activate
    ```
  - For macOS/Linux:
    ```
    source vt_env/bin/activate
    ```
- Install the required packages:
  ```
  pip install -r requirements.txt
  ```
  **Note:** If you decide not to create a new environment, make sure to uninstall these packages:
  ```
  pip uninstall crypto 
  pip uninstall pycrypto 
  ```

## Usage
- Sign up at [VirusTotal](https://www.virustotal.com) and get your API token.
- Create a Telegram Bot and get your Bot Token. You can do it from @BotFather by following these [instructions](https://core.telegram.org/bots/tutorial#obtain-your-bot-token) from Telegram.
- Create a new Telegram Group and add your Bot to it.
- Get the Telegram Group Chat ID:
  - Open Telegram Web in your browser.
  - Open the group chat.
  - You will see the URL of the chat, something like `https://web.telegram.org/k/#-0123456789`.
  - The pattern of the link is: `https://web.telegram.org/k/#{group_chat_id}`.
  - For example, `-0123456789` is the `group_chat_id`. Don't forget the `-` sign as it is part of the ID.
  - Now, let's try to send a message: `https://api.telegram.org/bot<BOT_TOKEN>/sendMessage?chat_id=<GROUP_CHAT_ID>&text=Bot_Says_Hello`.
  - When we set the bot token and chat ID correctly, the message `Bot_Says_Hello` should arrive in our group chat.
- These are sensitive data; do not share them with anyone. It's better to use environment variables to store them. These articles from PhoenixNAP may help you:
  - [Windows](https://phoenixnap.com/kb/windows-set-environment-variable)
  - [Linux](https://phoenixnap.com/kb/linux-set-environment-variable)
  - [macOS](https://phoenixnap.com/kb/set-environment-variable-mac)
  
  If you decide to save them as environment variables, please save them as follows:
  ```
  VT_API_KEY
  TELEGRAM_BOT_TOKEN
  TELEGRAM_CHAT_ID
  ```
- `SCAN_INTERVAL` is the time that the script will sleep between cycles (in minutes).
- `FOREVER`/CYCLES is the number of times that the script will walk through paths to scan any new/modified files and the file processes. (`0` means that the script will not stop scanning for changes.)
- If you set `SCAN_INTERVAL` to `0` and `FOREVER`/CYCLES to `0`, the script will never stop or sleep, continuously scanning for changes in the paths. However, it will skip checking the processes associated with the scanned and notified files. **(Default)**
- Any files with `SUSPICIOUS_EXTENSIONS` will be notified in the Telegram chat even if the VirusTotal report says they are clean files.
- Some files are associated with many processes, generating large report texts for the Telegram message, which is limited to 4096 characters. The script will break the report into multiple messages. `MAX_MSG` is the maximum number of messages per file report that will be sent. **(Default is `1` message.)**

### Running the script
You have three options:

#### 1. Run the script without any modifications
```
python ./VTv3_Scanner.py
[+] Enter your VirusTotal API key:
[+] Enter your Telegram bot token:
[+] Enter your Telegram chat ID:
```
It will ask you to input only the required values to work and use the default for the rest:
```python
PATHS = [r"test_scan", r'C:/Users/%USERNAME%/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup']

UPLOAD = True
SCAN_INTERVAL = 0
FOREVER = 0
MAX_MSG = 1

SUSPICIOUS_EXTENSIONS = [".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".scr", ".pif", ".msi", ".com", ".reg", ".docm", ".xlsm", ".pptm", ".jar", ".php", ".py", ".sh", ".ps1"]

MALSHARE_API_KEY = %MALSHARE_API_KEY%
```

#### 2. Write the required values in the script file
Open the script file with any text editor and edit these variables at the beginning of the script.

- Required Values:
  ```python
  VT_API_KEY = "PUT_YOUR_KEY_HERE"
  TELEGRAM_BOT_TOKEN = "PUT_YOUR_TOKEN_HERE"
  TELEGRAM_CHAT_ID = "PUT_YOUR_ID_HERE"

  PATHS = ["path/to/scan_1", "path/to/scan_2", ...]
  ```
  **Note**: If you used environment variables to store `VT_API_KEY`, `TELEGRAM_BOT_TOKEN`, and `TELEGRAM_CHAT_ID` as mentioned above, you don't have to edit them in the script file.

- Optional Values:
  ```python
  UPLOAD = <True|False>
  SCAN_INTERVAL = <float_number>
  FOREVER = <integer_number>
  MAX_MSG = <integer_number>
  SUSPICIOUS_EXTENSIONS = ['.exe', '.py', '.sh', ...]
  MALSHARE_API_KEY = "PUT_YOUR_KEY_HERE"
  ```

#### 3. Input the values as arguments in the terminal
You can use `-h` or `--help` to assist you with the parameters:
```
python ./VTv3_Scanner.py -k VT_API_KEY -t T_BOT_TOKEN -c T_CHAT_ID -p PATH_1 [PATH_2 ...] [--malshare_api_key MALSHARE_API_KEY] [-i STOP_INTERVAL] [-f CYCLES] [-m MAX_MSG] [-e SUS_EXT_1 [SUS_EXT_2 ...]] [--no_upload] [--debug]

options:
  -h, --help            Show this help message and exit
  -k, --vt_api_key      VirusTotal API key (required)
  -t, --t_bot_token     Telegram bot token (required)
  -c, --t_chat_id       Telegram chat ID (required)
  -p, --paths           Relative or absolute or environment variable paths are accepted to scan (required)
  -i, --stop_interval   Stop Interval in minutes (0 for no interval and skip process check for old scans)
  -f, --cycles          Number of cycles to scan (0 for forever)
  -m, --max_msg         Maximum number of messages to send per file (0 for unlimited)
  -e, --sus_ext         Suspicious file extensions
  --malshare_api_key    MalShare API key (optional)
  --no_upload           Do not upload files to VirusTotal for scanning if they do not exist
  --debug               Enable debug mode
```

## Screenshots
- Clean File
  <p align= "center" style="text-align: center"><img src="res/img/Clean.png" alt="Clean"></p>
- Malicious File
  <p align= "center" style="text-align: center"><img src="res/img/Malicious.png" alt="Malicious"></p>
- Suspicious Extension File
  <p align= "center" style="text-align: center"><img src="res/img/Suspicious.png" alt="Suspicious"></p>
- Old Scanned Files
  <p align= "center" style="text-align: center"><img src="res/img/Old.png" alt="Old"></p>
- New File that doesn't exist in the VirusTotal database (Upload enabled)
  <p align= "center" style="text-align: center"><img src="res/img/New.png" alt="New"></p>
- Telegram Alert Messages
  <p align= "center" style="text-align: center"><img src="res/img/Telegram.png" alt="Telegram"></p>

## Similar Projects
- [munin](https://github.com/Neo23x0/munin/tree/master) by Neo23x0
- [Startup_Guard](https://github.com/mohabye/Startup_Guard) by mohabye

## Contributing
Feel free to contribute to this project by forking it and submitting a [pull request](https://github.com/xAbdalla/VirusTotal_Scanner/compare) if you have any idea how to make this app better. If you find any bug, please [create an issue](https://github.com/xAbdalla/VirusTotal_Scanner/issues/new).