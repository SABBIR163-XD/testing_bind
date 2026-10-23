#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# FF BIND MANAGER v3.0 - Owner: SABBIR AHMED (Reference Style)

import requests
import os
import sys
import json
import time
import urllib.parse
import base64
import hashlib
import urllib3
import types
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
#  INLINED PROTOBUF DEFINITIONS
# ============================================================
_sym_db = _symbol_database.Default()

_MLP_DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x13MajorLoginReq.proto"\xfa\n\n\nMajorLogin\x12\x12\n\nevent_time\x18\x03 \x01(\t'
    b'\x12\x11\n\tgame_name\x18\x04 \x01(\t\x12\x13\n\x0bplatform_id\x18\x05 \x01(\x05'
    b'\x12\x16\n\x0e\x63lient_version\x18\x07 \x01(\t\x12\x17\n\x0fsystem_software\x18\x08 \x01(\t'
    b'\x12\x17\n\x0fsystem_hardware\x18\t \x01(\t\x12\x18\n\x10telecom_operator\x18\n \x01(\t'
    b'\x12\x14\n\x0cnetwork_type\x18\x0b \x01(\t\x12\x14\n\x0cscreen_width\x18\x0c \x01(\r'
    b'\x12\x15\n\rscreen_height\x18\r \x01(\r\x12\x12\n\nscreen_dpi\x18\x0e \x01(\t'
    b'\x12\x19\n\x11processor_details\x18\x0f \x01(\t\x12\x0e\n\x06memory\x18\x10 \x01(\r'
    b'\x12\x14\n\x0cgpu_renderer\x18\x11 \x01(\t\x12\x13\n\x0bgpu_version\x18\x12 \x01(\t'
    b'\x12\x18\n\x10unique_device_id\x18\x13 \x01(\t\x12\x11\n\tclient_ip\x18\x14 \x01(\t'
    b'\x12\x10\n\x08language\x18\x15 \x01(\t\x12\x0f\n\x07open_id\x18\x16 \x01(\t'
    b'\x12\x14\n\x0copen_id_type\x18\x17 \x01(\t\x12\x13\n\x0b\x64\x65vice_type\x18\x18 \x01(\t'
    b"\x12'\n\x10memory_available\x18\x19 \x01(\x0b\x32\r.GameSecurity"
    b'\x12\x14\n\x0c\x61\x63\x63\x65ss_token\x18\x1d \x01(\t\x12\x17\n\x0fplatform_sdk_id\x18\x1e \x01(\x05'
    b'\x12\x1a\n\x12network_operator_a\x18) \x01(\t\x12\x16\n\x0enetwork_type_a\x18* \x01(\t'
    b'\x12\x1c\n\x14\x63lient_using_version\x18\x39 \x01(\t\x12\x1e\n\x16\x65xternal_storage_total\x18< \x01(\x05'
    b'\x12"\n\x1a\x65xternal_storage_available\x18= \x01(\x05\x12\x1e\n\x16internal_storage_total\x18> \x01(\x05'
    b'\x12"\n\x1ainternal_storage_available\x18? \x01(\x05\x12#\n\x1bgame_disk_storage_available\x18@ \x01(\x05'
    b'\x12\x1f\n\x17game_disk_storage_total\x18\x41 \x01(\x05\x12%\n\x1d\x65xternal_sdcard_avail_storage\x18\x42 \x01(\x05'
    b'\x12%\n\x1d\x65xternal_sdcard_total_storage\x18\x43 \x01(\x05\x12\x10\n\x08login_by\x18I \x01(\x05'
    b'\x12\x14\n\x0clibrary_path\x18J \x01(\t\x12\x12\n\nreg_avatar\x18L \x01(\x05'
    b'\x12\x15\n\rlibrary_token\x18M \x01(\t\x12\x14\n\x0c\x63hannel_type\x18N \x01(\x05'
    b'\x12\x10\n\x08\x63pu_type\x18O \x01(\x05\x12\x18\n\x10\x63pu_architecture\x18Q \x01(\t'
    b'\x12\x1b\n\x13\x63lient_version_code\x18S \x01(\t\x12\x14\n\x0cgraphics_api\x18V \x01(\t'
    b'\x12\x1d\n\x15supported_astc_bitset\x18W \x01(\r\x12\x1a\n\x12login_open_id_type\x18X \x01(\x05'
    b'\x12\x18\n\x10\x61nalytics_detail\x18Y \x01(\x0c\x12\x14\n\x0cloading_time\x18\\ \x01(\r'
    b'\x12\x17\n\x0frelease_channel\x18] \x01(\t\x12\x12\n\nextra_info\x18^ \x01(\t'
    b'\x12 \n\x18\x61ndroid_engine_init_flag\x18_ \x01(\r\x12\x0f\n\x07if_push\x18\x61 \x01(\x05'
    b'\x12\x0e\n\x06is_vpn\x18\x62 \x01(\x05\x12\x1c\n\x14origin_platform_type\x18\x63 \x01(\t'
    b'\x12\x1d\n\x15primary_platform_type\x18\x64 \x01(\t'
    b'"5\n\x0cGameSecurity\x12\x0f\n\x07version\x18\x06 \x01(\x05'
    b'\x12\x14\n\x0chidden_value\x18\x08 \x01(\x04\x62\x06proto3'
)

_MLP_GLOBALS = {}
_builder.BuildMessageAndEnumDescriptors(_MLP_DESCRIPTOR, _MLP_GLOBALS)
_builder.BuildTopDescriptorsAndMessages(_MLP_DESCRIPTOR, 'MajorLoginReq_pb2', _MLP_GLOBALS)
if _descriptor._USE_C_DESCRIPTORS == False:
    _MLP_DESCRIPTOR._options = None
    _MLP_GLOBALS['_MAJORLOGIN']._serialized_start = 24
    _MLP_GLOBALS['_MAJORLOGIN']._serialized_end = 1426
    _MLP_GLOBALS['_GAMESECURITY']._serialized_start = 1428
    _MLP_GLOBALS['_GAMESECURITY']._serialized_end = 1481

mLpB = types.SimpleNamespace(
    **{k: v for k, v in _MLP_GLOBALS.items() if not k.startswith('_')}
)

_MLR_DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x13MajorLoginRes.proto"\x87\x05\n\rMajorLoginRes\x12\x12\n\naccount_id\x18\x01 \x01(\x03'
    b'\x12\x13\n\x0block_region\x18\x02 \x01(\t\x12\x13\n\x0bnoti_region\x18\x03 \x01(\t'
    b'\x12\x11\n\tip_region\x18\x04 \x01(\t\x12\x19\n\x11\x61gora_environment\x18\x05 \x01(\t'
    b'\x12\x19\n\x11new_active_region\x18\x06 \x01(\t\x12\r\n\x05token\x18\x08 \x01(\t'
    b'\x12\x0b\n\x03ttl\x18\t \x01(\x05\x12\x12\n\nserver_url\x18\n \x01(\t'
    b'\x12\x16\n\x0e\x65mulator_score\x18\x0c \x01(\x03'
    b'\x12\x32\n\tblacklist\x18\r \x01(\x0b\x32\x1f.MajorLoginRes.BlacklistInfoRes'
    b'\x12\x31\n\nqueue_info\x18\x0f \x01(\x0b\x32\x1d.MajorLoginRes.LoginQueueInfo'
    b'\x12\x0e\n\x06tp_url\x18\x10 \x01(\t\x12\x15\n\rapp_server_id\x18\x11 \x01(\x03'
    b'\x12\x0f\n\x07\x61no_url\x18\x12 \x01(\t\x12\x0f\n\x07ip_city\x18\x13 \x01(\t'
    b'\x12\x16\n\x0eip_subdivision\x18\x14 \x01(\t\x12\x0b\n\x03kts\x18\x15 \x01(\x03'
    b'\x12\n\n\x02\x61k\x18\x16 \x01(\x0c\x12\x0b\n\x03\x61iv\x18\x17 \x01(\x0c'
    b'\x1aQ\n\x10\x42lacklistInfoRes\x12\x12\n\nban_reason\x18\x01 \x01(\x05'
    b'\x12\x17\n\x0f\x65xpire_duration\x18\x02 \x01(\x03\x12\x10\n\x08\x62\x61n_time\x18\x03 \x01(\x03'
    b'\x1a\x66\n\x0eLoginQueueInfo\x12\r\n\x05\x41llow\x18\x01 \x01(\x08'
    b'\x12\x16\n\x0equeue_position\x18\x02 \x01(\x03\x12\x16\n\x0eneed_wait_secs\x18\x03 \x01(\x03'
    b'\x12\x15\n\rqueue_is_full\x18\x04 \x01(\x08\x62\x06proto3'
)

_MLR_GLOBALS = {}
_builder.BuildMessageAndEnumDescriptors(_MLR_DESCRIPTOR, _MLR_GLOBALS)
_builder.BuildTopDescriptorsAndMessages(_MLR_DESCRIPTOR, 'MajorLoginRes_pb2', _MLR_GLOBALS)
if _descriptor._USE_C_DESCRIPTORS == False:
    _MLR_DESCRIPTOR._options = None
    _MLR_GLOBALS['_MAJORLOGINRES']._serialized_start = 24
    _MLR_GLOBALS['_MAJORLOGINRES']._serialized_end = 671
    _MLR_GLOBALS['_MAJORLOGINRES_BLACKLISTINFORES']._serialized_start = 486
    _MLR_GLOBALS['_MAJORLOGINRES_BLACKLISTINFORES']._serialized_end = 567
    _MLR_GLOBALS['_MAJORLOGINRES_LOGINQUEUEINFO']._serialized_start = 569
    _MLR_GLOBALS['_MAJORLOGINRES_LOGINQUEUEINFO']._serialized_end = 671

mLrPb = types.SimpleNamespace(
    **{k: v for k, v in _MLR_GLOBALS.items() if not k.startswith('_')}
)


# ============================================================
#  COLORS — REFERENCE STYLE
# ============================================================
class Colors:
    GREEN   = '\x1b[1;92m'
    RED     = '\x1b[1;91m'
    YELLOW  = '\x1b[1;93m'
    BLUE    = '\x1b[1;94m'
    CYAN    = '\x1b[1;96m'
    MAGENTA = '\x1b[1;95m'
    WHITE   = '\x1b[1;97m'
    ORANGE  = '\x1b[38;5;208m'
    PURPLE  = '\x1b[38;2;150;80;200m'
    TOXIC   = '\x1b[38;2;170;200;0m'
    BOLD    = '\033[1m'
    RESET   = '\033[0m'
    GOLD    = '\x1b[38;5;220m'

LINE = f"{Colors.WHITE}════════════════════════════════════════════════════{Colors.RESET}"


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def show_logo():
    logo = f"""{Colors.GREEN}
███████╗███████╗    ██████╗ ██╗███╗   ██╗██████╗
██╔════╝██╔════╝    ██╔══██╗██║████╗  ██║██╔══██╗
█████╗  █████╗      ██████╔╝██║██╔██╗ ██║██║  ██║
██╔══╝  ██╔══╝      ██╔══██╗██║██║╚██╗██║██║  ██║
██║     ██║         ██████╔╝██║██║ ╚████║██████╔╝
╚═╝     ╚═╝         ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═════╝ {Colors.YELLOW}SABBIR AHMED{Colors.RESET}"""
    print(logo)
    print(LINE)
    print(f"{Colors.RED}({Colors.GREEN}‒{Colors.RED}){Colors.WHITE}{Colors.GREEN} Developer : {Colors.WHITE}SABBIR AHMED{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}‒{Colors.RED}){Colors.WHITE}{Colors.GREEN} Tool Name : {Colors.WHITE}FF Bind Manager{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}‒{Colors.RED}){Colors.WHITE}{Colors.GREEN} Version   : {Colors.CYAN}v3.0 Enhanced{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}‒{Colors.RED}){Colors.WHITE}{Colors.GREEN} Features  : {Colors.WHITE}Bind | Unbind | History | JWT{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}‒{Colors.RED}){Colors.WHITE}{Colors.GREEN} Options   : {Colors.WHITE}11 Working Modules{Colors.RESET}")
    print(LINE)


def draw_header(subtitle=""):
    clear_screen()
    show_logo()
    if subtitle:
        print(f"{Colors.RED}({Colors.GREEN}>{Colors.RED}){Colors.WHITE}{Colors.GREEN} {subtitle}{Colors.RESET}")
        print(LINE)
    print()


def input_prompt(msg):
    return input(f"{Colors.RED}({Colors.GREEN}•{Colors.RED}){Colors.WHITE}{Colors.GREEN} {msg} : {Colors.RESET}").strip()


def print_step(current, total, msg):
    print(f"{Colors.RED}({Colors.GREEN}>{Colors.RED}){Colors.WHITE}{Colors.GREEN} [{current}/{total}] {msg}{Colors.RESET}")


def print_success(msg):
    print(f"{Colors.RED}({Colors.GREEN}√{Colors.RED}){Colors.WHITE}{Colors.GREEN} {msg}{Colors.RESET}")


def print_error(msg):
    print(f"{Colors.RED}({Colors.GREEN}×{Colors.RED}){Colors.WHITE}{Colors.YELLOW} {msg}{Colors.RESET}")


def print_info(msg):
    print(f"{Colors.RED}({Colors.GREEN}‒{Colors.RED}){Colors.WHITE}{Colors.GREEN} {msg}{Colors.RESET}")


def print_warning(msg):
    print(f"{Colors.RED}({Colors.GREEN}!{Colors.RED}){Colors.WHITE}{Colors.YELLOW} {msg}{Colors.RESET}")


def print_section(title):
    print(f"{Colors.RED}({Colors.GREEN}>{Colors.RED}){Colors.WHITE}{Colors.CYAN} {title}{Colors.RESET}")


def print_result_box(title, lines):
    print(f"{Colors.RED}({Colors.GREEN}>{Colors.RED}){Colors.WHITE}{Colors.GREEN} {title}{Colors.RESET}")
    for line in lines:
        print(f"{Colors.RED}({Colors.GREEN}‒{Colors.RED}){Colors.WHITE}{Colors.GREEN} {line}{Colors.RESET}")


def wait_for_enter():
    print(LINE)
    input(f"{Colors.RED}({Colors.GREEN}•{Colors.RED}){Colors.WHITE}{Colors.GREEN} Press Enter To Return ... {Colors.RESET}")


def format_response(response_text, title="API Response"):
    try:
        parsed = json.loads(response_text)
        result_code = parsed.get("result")
        if result_code == 0:
            print_success(f"{title}: SUCCESS")
            return True
        elif result_code is not None:
            error_msg = parsed.get("error", "Unknown error")
            print_error(f"{title}: FAILED (Code: {result_code} | {error_msg})")
            return False
        else:
            print_info(f"{title}: Completed (No result code)")
            return True
    except Exception:
        if '"result": 0' in response_text.replace(" ", ""):
            print_success(f"{title}: SUCCESS")
            return True
        else:
            print_error(f"{title}: Unrecognized response")
            return False


def convert_seconds(s):
    d, h = divmod(s, 86400)
    h, m = divmod(h, 3600)
    m, s = divmod(m, 60)
    return f"{d}D {h}H {m}M {s}S"


PLATFORM_MAP = {
    1: "Garena", 3: "Facebook", 4: "Guest", 5: "VK",
    6: "Huawei", 7: "Apple", 8: "Google", 10: "GameCenter / Line",
    11: "X (Twitter)", 13: "Apple ID", 28: "Line", 35: "TikTok"
}


# ============================================================
#  OPTION 01: CHECK BIND INFO (Multi-endpoint email scanner)
# ============================================================
def check_bind_info(access_token=None, show_raw=False):
    if not access_token:
        access_token = input_prompt("Enter Access Token")

    print_info("Fetching player info from Garena...")

    try:
        player_url = f"https://api-otrss.garena.com/support/callback/?access_token={access_token}"
        p_res = requests.get(player_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15, allow_redirects=True)
        parsed_url = urllib.parse.urlparse(p_res.url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        uid = query_params.get("account_id", ["Unknown"])[0]
        nickname = query_params.get("nickname", ["Unknown"])[0]
        region = query_params.get("region", ["Unknown"])[0]
        print_result_box("PLAYER INFORMATION", [
            f"UID       : {uid}",
            f"Nickname  : {nickname}",
            f"Region    : {region}",
        ])
    except Exception as e:
        print_error(f"Failed to fetch player details: {e}")

    print_info("Probing bind info across multiple endpoints (searching for full email)...")

    email_full = None
    email_masked = None
    email_to_be = "None"
    countdown_human = "0D 0H 0M 0S"
    result_code = None
    raw_data = {}
    source_info = ""

    UAS = [
        "GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)",
        "GarenaMSDK/4.0.30",
        "GarenaMSDK/4.0.20P9(iPhone 14; iOS 16; en; US;)",
        "GarenaMSDK/4.0.18P9(OPPO A57 ;Android 8;en;US;)",
    ]

    FIELD_NAMES = [
        "email", "email_full", "full_email", "email_unmasked", "recovery_email",
        "recovery_email_full", "raw_email", "unmasked_email", "real_email",
        "bound_email", "email_address", "user_email", "account_email", "mail",
        "bind_email", "display_email", "original_email", "true_email", "email_display"
    ]

    def probe(data, url):
        nonlocal email_full, email_masked, email_to_be, countdown_human, result_code, raw_data, source_info
        if not raw_data and isinstance(data, dict):
            raw_data = data
        if not isinstance(data, dict):
            return

        def scan(obj, path=""):
            nonlocal email_full, email_masked, source_info
            if isinstance(obj, dict):
                for field in FIELD_NAMES:
                    val = obj.get(field)
                    if val and isinstance(val, str) and "@" in val:
                        if "*" in val:
                            if email_masked is None:
                                email_masked = val
                        else:
                            if email_full is None:
                                email_full = val
                                source_info = f"{url} [{path}{field}]"
                                print_success(f"Full email FOUND via '{path}{field}'!")
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        scan(v, f"{path}{k}.")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    scan(item, f"{path}[{i}].")

        scan(data)

        if isinstance(data, dict):
            if data.get("email_to_be") and email_to_be == "None":
                email_to_be = data["email_to_be"]
            if "request_exec_countdown" in data and countdown_human == "0D 0H 0M 0S":
                countdown_human = convert_seconds(data["request_exec_countdown"])
            if "result" in data and result_code is None:
                result_code = data["result"]

    # Attempt 1: bind:get_bind_info with multiple UAs
    for ua in UAS:
        if email_full: break
        try:
            r = requests.get(
                "https://100067.connect.garena.com/game/account_security/bind:get_bind_info",
                params={'app_id': "100067", 'access_token': access_token},
                headers={'User-Agent': ua, 'Connection': 'Keep-Alive'}, timeout=15
            )
            if r.status_code == 200:
                probe(r.json(), "bind:get_bind_info")
        except:
            continue

    # Attempt 2: send_otp probe (response may leak target email)
    if not email_full and email_masked:
        try:
            r = requests.post(
                "https://100067.connect.garena.com/game/account_security/bind:send_otp",
                headers={"User-Agent": "GarenaMSDK/4.0.30",
                         "Content-Type": "application/x-www-form-urlencoded"},
                data={'email': email_masked, 'locale': 'en_PK', 'region': 'PK',
                      'app_id': '100067', 'access_token': access_token}, timeout=15
            )
            if r.status_code == 200:
                probe(r.json(), "bind:send_otp")
        except:
            pass

    # Attempt 3: oauth/token/inspect
    if not email_full:
        try:
            r = requests.get("https://100067.connect.garena.com/oauth/token/inspect",
                             params={'token': access_token},
                             headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
            if r.status_code == 200:
                probe(r.json(), "oauth/inspect")
        except:
            pass

    # Attempt 4: reward inspect
    if not email_full:
        try:
            r = requests.get("https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/",
                             headers={'access-token': access_token, 'user-agent': 'Mozilla/5.0'},
                             timeout=10, verify=False)
            if r.status_code == 200:
                probe(r.json(), "reward/inspect")
        except:
            pass

    # Attempt 5: platform info
    if not email_full:
        try:
            r = requests.get("https://100067.connect.garena.com/bind/app/platform/info/get",
                             params={'access_token': access_token},
                             headers={'User-Agent': "GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)"},
                             timeout=10)
            if r.status_code == 200:
                probe(r.json(), "platform/info")
        except:
            pass

    # Attempt 6: cancel_request (may echo current email)
    if not email_full:
        try:
            r = requests.post(
                "https://100067.connect.garena.com/game/account_security/bind:cancel_request",
                headers={"User-Agent": "GarenaMSDK/4.0.30",
                         "Content-Type": "application/x-www-form-urlencoded"},
                data={'app_id': "100067", 'access_token': access_token}, timeout=10
            )
            if r.status_code == 200:
                probe(r.json(), "cancel_request")
        except:
            pass

    # Build result
    lines = []
    if email_full:
        lines.append(f"Current Email : {email_full}")
        lines.append(f"Source        : {source_info}")
    elif email_masked:
        lines.append(f"Current Email : {email_masked}")
        lines.append(f"Note          : Garena masks email server-side (OB55+)")
        lines.append(f"Full Email    : Not available via any public API")
    else:
        lines.append(f"Current Email : None")

    lines.append(f"Pending Email : {email_to_be}")
    if email_to_be != "None":
        lines.append(f"Countdown     : {countdown_human}")

    if result_code is None:
        if email_full or email_masked or email_to_be != "None":
            lines.append("Status        : SUCCESS")
        else:
            lines.append("Status        : NO DATA")
    elif result_code == 0:
        lines.append("Status        : SUCCESS")
    else:
        lines.append(f"Status        : FAILED (Code: {result_code})")

    print_result_box("BIND INFORMATION", lines)

    if show_raw:
        print_info("Raw Response (debug):")
        print(json.dumps(raw_data, indent=2))


def bind_info():
    draw_header("CHECK BIND INFO")
    access_token = input_prompt("Enter Access Token")
    print("")
    check_bind_info(access_token, show_raw=False)
    wait_for_enter()


# ============================================================
#  OPTION 02: BIND EMAIL
# ============================================================
def bind_email():
    draw_header("BIND EMAIL")

    access_token = input_prompt("Enter Access Token")
    print("")
    check_bind_info(access_token, show_raw=False)
    print("")
    email = input_prompt("Enter Email to bind")

    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }

    print_step(1, 3, f"Sending OTP to {email}...")
    send_otp_url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
    send_otp_data = {
        "email": email, "locale": "en_PK", "region": "PK",
        "app_id": "100067", "access_token": access_token
    }
    resp_send = requests.post(send_otp_url, headers=headers, data=send_otp_data)
    if not format_response(resp_send.text, "Send OTP"):
        return wait_for_enter()

    otp = input_prompt("Enter OTP received in email")

    print_step(2, 3, "Verifying OTP...")
    verify_url = "https://100067.connect.garena.com/game/account_security/bind:verify_otp"
    verify_data = {
        "app_id": "100067", "access_token": access_token, "email": email,
        "code": otp, "otp": otp, "type": "1"
    }
    resp_verify = requests.post(verify_url, headers=headers, data=verify_data)
    if not format_response(resp_verify.text, "Verify OTP"):
        return wait_for_enter()

    verifier_token = ""
    try:
        verifier_token = resp_verify.json().get("verifier_token", "")
    except:
        pass

    if not verifier_token:
        print_error("Could not auto-extract verifier_token")
        verifier_token = input_prompt("Please enter verifier_token manually")
    else:
        print_success("Verifier Token extracted!")

    security_code = input_prompt("Set 6-digit security code")

    hashed_sec = hashlib.sha256(security_code.encode('utf-8')).hexdigest()
    print_info(f"Security code hashed: {hashed_sec[:16]}...")

    print_step(3, 3, "Creating bind request...")
    bind_url = "https://100067.connect.garena.com/game/account_security/bind:create_bind_request"
    bind_data = {
        "email": email, "app_id": "100067", "access_token": access_token,
        "verifier_token": verifier_token, "secondary_password": hashed_sec
    }
    resp_bind = requests.post(bind_url, headers=headers, data=bind_data)
    format_response(resp_bind.text, "Final Bind Request")

    wait_for_enter()


# ============================================================
#  OPTION 03: UNBIND EMAIL
# ============================================================
def unbind_email():
    draw_header("UNBIND EMAIL")

    print(f"{Colors.RED}({Colors.GREEN}1{Colors.RED}){Colors.WHITE}{Colors.GREEN} UNBIND VIA OTP{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}2{Colors.RED}){Colors.WHITE}{Colors.GREEN} UNBIND VIA SECURITY CODE{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}0{Colors.RED}){Colors.WHITE}{Colors.GREEN} CANCEL & GO BACK{Colors.RESET}")
    print(LINE)

    choice = input_prompt("Select Method")
    if choice == "0":
        return
    if choice not in ["1", "2"]:
        print_error("Invalid option!")
        return wait_for_enter()

    access_token = input_prompt("Enter Access Token")
    print("")
    check_bind_info(access_token, show_raw=False)

    try:
        url_info = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info"
        info_payload = {'app_id': "100067", 'access_token': access_token}
        r_info = requests.get(url_info, params=info_payload,
                              headers={'User-Agent': "GarenaMSDK/4.0.30"}, timeout=10)
        email = r_info.json().get("email", "")
    except:
        email = ""

    if not email:
        print_error("No bound email found!")
        return wait_for_enter()

    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }

    identity_token = None

    if choice == "1":
        print_step(1, 3, f"Sending OTP to {email}...")
        send_otp_url = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
        send_otp_data = {"email": email, "locale": "en_PK", "region": "PK",
                         "app_id": "100067", "access_token": access_token}
        resp = requests.post(send_otp_url, headers=headers, data=send_otp_data)
        format_response(resp.text, "Send OTP")

        otp = input_prompt(f"Enter OTP from {email}")

        print_step(2, 3, "Verifying Identity...")
        verify_url = "https://100067.connect.garena.com/game/account_security/bind:verify_identity"
        verify_data = {"email": email, "app_id": "100067",
                       "access_token": access_token, "otp": otp}
        resp = requests.post(verify_url, headers=headers, data=verify_data)
        format_response(resp.text, "Verify Identity")

        try:
            identity_token = resp.json().get("identity_token")
        except:
            pass
        step_final = 3
    else:
        sec_code = input_prompt("Enter 6-digit Security Code")
        hashed_sec = hashlib.sha256(sec_code.encode('utf-8')).hexdigest()

        print_step(1, 2, "Verifying via Security Code...")
        verify_url = "https://100067.connect.garena.com/game/account_security/bind:verify_identity"
        verify_data = {"email": email, "app_id": "100067",
                       "access_token": access_token, "secondary_password": hashed_sec}
        resp = requests.post(verify_url, headers=headers, data=verify_data)
        format_response(resp.text, "Verify Identity")

        try:
            identity_token = resp.json().get("identity_token")
        except:
            pass
        step_final = 2

    if not identity_token:
        print_error("Identity verification failed!")
        return wait_for_enter()

    print_success("Identity Token Extracted!")
    total_steps = 3 if choice == "1" else 2
    print_step(step_final, total_steps, "Creating Unbind Request...")
    unbind_url = "https://100067.connect.garena.com/game/account_security/bind:create_unbind_request"
    unbind_data = {"app_id": "100067", "access_token": access_token,
                   "identity_token": identity_token}
    resp = requests.post(unbind_url, headers=headers, data=unbind_data)
    format_response(resp.text, "Unbind Request")

    wait_for_enter()


# ============================================================
#  OPTION 04: CHANGE BIND EMAIL
# ============================================================
def change_bind_email():
    draw_header("CHANGE BIND EMAIL")

    print(f"{Colors.RED}({Colors.GREEN}1{Colors.RED}){Colors.WHITE}{Colors.GREEN} CHANGE VIA OTP{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}2{Colors.RED}){Colors.WHITE}{Colors.GREEN} CHANGE VIA SECURITY CODE{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}0{Colors.RED}){Colors.WHITE}{Colors.GREEN} CANCEL & GO BACK{Colors.RESET}")
    print(LINE)

    choice = input_prompt("Select Method")
    if choice == "0":
        return
    if choice not in ["1", "2"]:
        print_error("Invalid option!")
        return wait_for_enter()

    access_token = input_prompt("Enter Access Token")
    print("")
    check_bind_info(access_token, show_raw=False)

    try:
        url_info = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info"
        info_payload = {'app_id': "100067", 'access_token': access_token}
        r_info = requests.get(url_info, params=info_payload,
                              headers={'User-Agent': "GarenaMSDK/4.0.30"}, timeout=10)
        old_email = r_info.json().get("email", "")
    except:
        old_email = ""

    if not old_email:
        print_error("No current bound email found!")
        return wait_for_enter()

    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }

    identity_token = None
    total_steps = 5 if choice == "1" else 4
    current_step = 1

    if choice == "1":
        print_step(current_step, total_steps, f"Sending OTP to {old_email}...")
        url_send = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
        data = {"email": old_email, "locale": "en_PK", "region": "PK",
                "app_id": "100067", "access_token": access_token}
        r = requests.post(url_send, headers=headers, data=data)
        format_response(r.text, "Send Old Email OTP")
        current_step += 1

        otp_old = input_prompt(f"Enter OTP from {old_email}")

        print_step(current_step, total_steps, "Verifying Old Email Identity...")
        url_verify = "https://100067.connect.garena.com/game/account_security/bind:verify_identity"
        data = {"email": old_email, "app_id": "100067",
                "access_token": access_token, "otp": otp_old}
        r = requests.post(url_verify, headers=headers, data=data)
        format_response(r.text, "Verify Identity")
        current_step += 1

        try:
            identity_token = r.json().get("identity_token")
        except:
            pass
    else:
        sec_code = input_prompt("Enter 6-digit Security Code")
        hashed_sec = hashlib.sha256(sec_code.encode('utf-8')).hexdigest()

        print_step(current_step, total_steps, "Verifying via Security Code...")
        url_verify = "https://100067.connect.garena.com/game/account_security/bind:verify_identity"
        data = {"email": old_email, "app_id": "100067",
                "access_token": access_token, "secondary_password": hashed_sec}
        r = requests.post(url_verify, headers=headers, data=data)
        format_response(r.text, "Verify Identity")
        current_step += 1

        try:
            identity_token = r.json().get("identity_token")
        except:
            pass

    if not identity_token:
        print_error("Identity verification failed!")
        return wait_for_enter()
    print_success("Identity Token Extracted!")

    new_email = input_prompt("Enter New Email")

    print_step(current_step, total_steps, f"Sending OTP to {new_email}...")
    url_send = "https://100067.connect.garena.com/game/account_security/bind:send_otp"
    data = {"email": new_email, "locale": "en_PK", "region": "PK",
            "app_id": "100067", "access_token": access_token}
    r = requests.post(url_send, headers=headers, data=data)
    format_response(r.text, "Send New Email OTP")
    current_step += 1

    otp_new = input_prompt(f"Enter OTP from {new_email}")

    print_step(current_step, total_steps, "Verifying New Email OTP...")
    url_verify_otp = "https://100067.connect.garena.com/game/account_security/bind:verify_otp"
    data = {"email": new_email, "app_id": "100067",
            "access_token": access_token, "otp": otp_new}
    r = requests.post(url_verify_otp, headers=headers, data=data)
    format_response(r.text, "Verify OTP")
    current_step += 1

    verifier_token = None
    try:
        verifier_token = r.json().get("verifier_token")
    except:
        pass

    if not verifier_token:
        print_error("No verifier token received!")
        return wait_for_enter()
    print_success("Verifier Token Extracted!")

    print_step(current_step, total_steps, "Creating Rebind Request...")
    url_rebind = "https://100067.connect.garena.com/game/account_security/bind:create_rebind_request"
    data = {"identity_token": identity_token, "email": new_email,
            "app_id": "100067", "verifier_token": verifier_token,
            "access_token": access_token}
    r = requests.post(url_rebind, headers=headers, data=data)
    format_response(r.text, "Rebind Request")

    wait_for_enter()


# ============================================================
#  OPTION 05: CANCEL BIND REQUEST
# ============================================================
def cancel_bind():
    draw_header("CANCEL BIND REQUEST")

    access_token = input_prompt("Enter Access Token")
    print("")
    check_bind_info(access_token, show_raw=False)

    print_step(1, 1, "Creating Cancel Request...")
    url = "https://100067.connect.garena.com/game/account_security/bind:cancel_request"
    headers = {
        "User-Agent": "GarenaMSDK/4.0.30",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }
    data = {"app_id": "100067", "access_token": access_token}
    response = requests.post(url, headers=headers, data=data)
    format_response(response.text, "Cancel Request")

    wait_for_enter()


# ============================================================
#  OPTION 06: EAT TO ACCESS TOKEN
# ============================================================
def eat_to_access_token():
    draw_header("EAT TO ACCESS TOKEN")

    user_input = input_prompt("Enter EAT Token OR Full EAT URL")

    eat_token = None
    if "http" in user_input or "?" in user_input:
        parsed_url = urllib.parse.urlparse(user_input)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        if 'eat' in query_params:
            eat_token = query_params['eat'][0]
    else:
        eat_token = user_input.strip()

    if not eat_token:
        print_error("Could not find EAT token in input.")
        return wait_for_enter()

    print_step(1, 1, "Contacting Server & Following Redirects...")

    api_url = f"https://api-otrss.garena.com/support/callback/?access_token={eat_token}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36"
    }

    try:
        response = requests.get(api_url, headers=headers, allow_redirects=True, timeout=15)
        parsed_final = urllib.parse.urlparse(response.url)
        final_params = urllib.parse.parse_qs(parsed_final.query)

        if 'access_token' in final_params:
            access_token = final_params['access_token'][0]
            account_id = final_params.get('account_id', ['Unknown'])[0]
            nickname = final_params.get('nickname', ['Unknown'])[0]
            region = final_params.get('region', ['Unknown'])[0]

            print_result_box("SUCCESS - TOKEN RESOLVED", [
                f"Nickname     : {urllib.parse.unquote(nickname)}",
                f"Account ID   : {account_id}",
                f"Region       : {region}",
            ])
            print(f"{Colors.RED}({Colors.GREEN}>{Colors.RED}){Colors.WHITE}{Colors.GREEN} ACCESS TOKEN{Colors.RESET}")
            print(f"{Colors.RED}({Colors.GREEN}‒{Colors.RED}){Colors.WHITE}{Colors.GOLD}{access_token}{Colors.RESET}\n")
        else:
            print_error("Access token not found in redirect.")
            print_warning("The EAT token might be expired or invalid.")
            print_info(f"Final URL: {response.url[:100]}")
    except Exception as e:
        print_error(f"Failed to resolve EAT: {e}")

    wait_for_enter()


# ============================================================
#  OPTION 07: GET LOGIN HISTORY
# ============================================================
def read_varint(data, offset):
    res = 0
    shift = 0
    while True:
        if offset >= len(data):
            break
        b = data[offset]
        offset += 1
        res |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return res, offset


def parse_record(data):
    rec = {}
    offset = 0
    while offset < len(data):
        try:
            tag, offset = read_varint(data, offset)
            wt, f = tag & 7, tag >> 3
            if wt == 0:
                val, offset = read_varint(data, offset)
                if f == 1:
                    rec['ts'] = val
                elif f == 2:
                    rec['ram'] = val
                else:
                    rec[f'field_{f}'] = val
            elif wt == 2:
                length, offset = read_varint(data, offset)
                val = data[offset:offset + length]
                offset += length
                if f == 3:
                    rec['dev'] = val.decode(errors='ignore')
                elif f == 4:
                    rec['arch'] = val.decode(errors='ignore')
                else:
                    rec[f'bytes_{f}'] = val
            elif wt == 1:
                offset += 8
            elif wt == 5:
                offset += 4
            else:
                break
        except:
            break
    return rec


def parse_history_protobuf(data):
    records = []
    offset = 0
    while offset < len(data):
        try:
            tag, offset = read_varint(data, offset)
            wt, f = tag & 7, tag >> 3
            if wt == 0:
                val, offset = read_varint(data, offset)
            elif wt == 2:
                length, offset = read_varint(data, offset)
                val = data[offset:offset + length]
                offset += length
                if f == 1:
                    records.append(parse_record(val))
            elif wt == 1:
                offset += 8
            elif wt == 5:
                offset += 4
            else:
                break
        except:
            break
    return records


def login_history():
    draw_header("GET LOGIN HISTORY")

    token = input_prompt("Enter Access Token OR Game JWT Token")
    if not token:
        print_error("Token cannot be blank.")
        return wait_for_enter()

    jwt_token = None

    if token.startswith("ey") and "." in token:
        jwt_token = token
        print_success("Detected valid JWT Token.")
    else:
        print_step(1, 2, "Resolving Open ID from Access Token...")
        oId = None

        try:
            r = requests.get(
                f"https://100067.connect.garena.com/oauth/token/inspect?token={token}",
                headers={"User-Agent": "Mozilla/5.0"}, timeout=8).json()
            oId = r.get("open_id")
        except:
            pass

        if not oId:
            try:
                uid_headers = {"access-token": token, "user-agent": "Mozilla/5.0"}
                uid_res = requests.get(
                    "https://prod-api.reward.ff.garena.com/redemption/api/auth/inspect_token/",
                    headers=uid_headers, verify=False, timeout=8).json()
                uid = uid_res.get("uid")
                if uid:
                    openid_res = requests.post(
                        "https://topup.pk/api/auth/player_id_login",
                        json={"app_id": 100067, "login_id": str(uid)},
                        verify=False, timeout=8).json()
                    oId = openid_res.get("open_id")
            except:
                pass

        if not oId:
            print_error("Failed to extract Open ID. Token may be invalid.")
            return wait_for_enter()

        print_success(f"Open ID: {oId}")
        print_step(2, 2, "Bypassing MajorLogin via Protobufs...")

        platforms = [8, 3, 4, 6]
        for p_type in platforms:
            pl = build_majorlogin(token, oId, p_type)
            try:
                mLhDr = {
                    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-S908E Build/TP1A.220624.014)",
                    "Connection": "Keep-Alive", "Accept-Encoding": "gzip",
                    "Content-Type": "application/octet-stream", "Expect": "100-continue",
                    "X-GA": "v1 1", "X-Unity-Version": "2018.4.11f1", "ReleaseVersion": "OB52"
                }
                x = requests.post("https://loginbp.ggpolarbear.com/MajorLogin",
                                  headers=mLhDr, data=pl, timeout=12, verify=False)
                if x.status_code == 200:
                    res = mLrPb.MajorLoginRes()
                    parse_ok = False
                    try:
                        decrypted = dec(x.content)
                        res.ParseFromString(decrypted)
                        parse_ok = True
                    except:
                        try:
                            res.ParseFromString(x.content)
                            parse_ok = True
                        except:
                            continue
                    if parse_ok and res.token:
                        jwt_token = res.token
                        print_success(f"JWT Generated via Platform ID {p_type}!")
                        break
            except:
                continue

        if not jwt_token:
            print_error("MajorLogin failed across all platforms.")
            return wait_for_enter()

    try:
        payload_b64 = jwt_token.split('.')[1]
        payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload_b64).decode('utf-8'))

        name = urllib.parse.unquote(decoded.get("nickname", "Unknown"))
        uid = decoded.get("account_id", "Unknown")
        region = decoded.get("lock_region", "Unknown")
        p_id = decoded.get("external_type", 0)
        platform = PLATFORM_MAP.get(p_id, f"Unknown ({p_id})")

        print_result_box("PLAYER INFO", [
            f"Account Name : {name}",
            f"Account ID   : {uid}",
            f"Platform     : {platform}",
            f"Region       : {region}",
        ])
    except:
        pass

    print_info("Fetching Login History Records...")
    hH = {
        "Expect": "100-continue", "Authorization": f"Bearer {jwt_token}",
        "X-Unity-Version": "2018.4.11f1", "X-GA": "v1 1", "ReleaseVersion": "OB52",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)",
        "Host": "client.ind.freefiremobile.com", "Connection": "close"
    }

    try:
        r = requests.post("https://client.ind.freefiremobile.com/GetLoginHistory",
                          headers=hH, data=enc(b""), timeout=15, verify=False)
        if r.status_code != 200:
            print_error(f"History Request Failed: HTTP {r.status_code}")
            return wait_for_enter()

        try:
            d = dec(r.content)
        except Exception as e:
            print_error(f"Decryption failed: {e}")
            print_warning("Response format may have changed")
            return wait_for_enter()

        records = parse_history_protobuf(d)

        print_section("LOGIN HISTORY")

        if not records:
            print_warning("No login history records found.")
        else:
            print_info(f"Total records: {len(records)}\n")
            for i, rec in enumerate(records, 1):
                ts_raw = rec.get('ts', 0)
                try:
                    date_str = datetime.fromtimestamp(ts_raw).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    date_str = "Invalid"

                dev = rec.get('dev', 'Unknown')
                arch = rec.get('arch', 'Unknown')
                ram = rec.get('ram', 0)

                print_result_box(f"RECORD #{i}", [
                    f"Timestamp : {ts_raw}",
                    f"Date      : {date_str}",
                    f"Device    : {dev}",
                    f"Arch      : {arch}",
                    f"RAM       : {ram} MB",
                ])
    except Exception as e:
        print_error(f"Error: {e}")

    wait_for_enter()


# ============================================================
#  OPTION 08: CHECK BOUND ACCOUNTS
# ============================================================
def check_bound_accounts():
    draw_header("PLATFORM BIND INFO")

    access_token = input_prompt("Enter Access Token")
    if not access_token:
        print_error("Token cannot be blank.")
        return wait_for_enter()

    print_info("Fetching platform bind data...")

    url = "https://100067.connect.garena.com/bind/app/platform/info/get"
    params = {"access_token": access_token}
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)",
        "Connection": "Keep-Alive", "Accept-Encoding": "gzip"
    }

    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        if response.status_code != 200:
            print_error(f"Failed (HTTP {response.status_code})")
            return wait_for_enter()

        d = response.json()
        bounded = d.get("bounded_accounts", [])
        available = d.get("available_platforms", [])

        print_section("PLATFORM BINDS")

        if not bounded:
            print_warning("No third-party platforms currently bound.")
        else:
            bound_lines = []
            for p_id in bounded:
                p_name = PLATFORM_MAP.get(p_id, f"Unknown ({p_id})")
                bound_lines.append(f"{p_name}")
            print_result_box("BOUND ACCOUNTS", bound_lines)

        if available:
            avail_lines = [f"{PLATFORM_MAP.get(p, f'Unknown ({p})')}" for p in available]
            print_result_box("AVAILABLE PLATFORMS", avail_lines)

    except Exception as e:
        print_error(f"Error: {e}")

    wait_for_enter()


# ============================================================
#  OPTION 09: ACCESS TOKEN TO JWT
# ============================================================
def access_to_jwt():
    draw_header("ACCESS TOKEN TO JWT")

    token = input_prompt("Enter Access Token")
    if not token:
        print_error("Token cannot be blank.")
        return wait_for_enter()

    print_step(1, 1, "Connecting to JWT API Server...")

    url = f"https://acesstojwt-sigma.vercel.app/token?access_token={token}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    try:
        response = requests.get(url, headers=headers, timeout=20)

        if response.status_code == 200:
            raw_text = response.text.strip()
            jwt_token = None

            try:
                data = json.loads(raw_text)
                if isinstance(data, dict):
                    if "token" in data:
                        jwt_token = data["token"]
                    elif "jwt" in data:
                        jwt_token = data["jwt"]
                    elif "access_token" in data and data.get("access_token", "").startswith("ey"):
                        jwt_token = data["access_token"]
            except Exception:
                if raw_text.startswith("ey"):
                    jwt_token = raw_text

            if jwt_token and jwt_token.startswith("eyJ"):
                print_result_box("JWT GENERATED", [
                    f"Type   : Game JWT",
                    f"Length : {len(jwt_token)} chars",
                ])
                print(f"{Colors.RED}({Colors.GREEN}>{Colors.RED}){Colors.WHITE}{Colors.GREEN} JWT TOKEN{Colors.RESET}")
                print(f"{Colors.RED}({Colors.GREEN}‒{Colors.RED}){Colors.WHITE}{jwt_token}{Colors.RESET}\n")
            else:
                print_error("Invalid JWT received from server.")
                if jwt_token:
                    print_warning(f"Got unexpected format: {jwt_token[:60]}...")
                else:
                    print_warning(f"Raw response: {raw_text[:120]}")
        else:
            print_error(f"Server Error (HTTP {response.status_code})")
            print_warning("External API may be down. Try again later.")

    except Exception as e:
        print_error(f"Connection Failed: {e}")
        print_warning("External API may be unreachable.")

    wait_for_enter()


# ============================================================
#  OPTION 10: PLAYER OWNER DETAILS (multi-endpoint email scan)
# ============================================================
def player_owner_details():
    draw_header("PLAYER OWNER DETAILS")

    access_token = input_prompt("Enter Access Token")
    if not access_token:
        print_error("Token cannot be blank.")
        return wait_for_enter()

    uid = "Unknown"
    nickname = "Unknown"
    region = "Unknown"
    platform = "Unknown"
    bind_status = "Unknown"
    bind_email = "None"
    email_full_flag = False

    print_step(1, 3, "Fetching player information...")
    try:
        player_url = f"https://api-otrss.garena.com/support/callback/?access_token={access_token}"
        p_res = requests.get(player_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15, allow_redirects=True)
        parsed_url = urllib.parse.urlparse(p_res.url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        uid = query_params.get("account_id", ["Unknown"])[0]
        nickname = urllib.parse.unquote(query_params.get("nickname", ["Unknown"])[0])
        region = query_params.get("region", ["Unknown"])[0]
        print_success("Player info fetched")
    except Exception as e:
        print_error(f"Failed to fetch player info: {e}")

    print_step(2, 3, "Fetching bind status (multi-endpoint)...")
    email_full = None
    email_masked = None
    UAS = [
        "GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)",
        "GarenaMSDK/4.0.30",
        "GarenaMSDK/4.0.20P9(iPhone 14; iOS 16; en; US;)",
    ]
    FIELD_NAMES = [
        "email", "email_full", "full_email", "email_unmasked", "recovery_email",
        "raw_email", "unmasked_email", "real_email", "bound_email", "email_address",
        "user_email", "account_email", "mail", "bind_email", "display_email"
    ]
    try:
        for ua in UAS:
            r = requests.get(
                "https://100067.connect.garena.com/game/account_security/bind:get_bind_info",
                params={'app_id': "100067", 'access_token': access_token},
                headers={'User-Agent': ua}, timeout=15
            )
            if r.status_code != 200: continue
            data = r.json()
            for field in FIELD_NAMES:
                val = data.get(field)
                if val and isinstance(val, str) and "@" in val:
                    if "*" in val:
                        if email_masked is None: email_masked = val
                    else:
                        if email_full is None:
                            email_full = val
                            print_success(f"Full email via '{field}'!")
            if email_full: break

        if email_full:
            bind_status = "Bound"
            bind_email = email_full
            email_full_flag = True
        elif email_masked:
            bind_status = "Bound"
            bind_email = email_masked
        else:
            bind_status = "Not Bound"
            bind_email = "None"
        print_success("Bind status fetched")
    except Exception as e:
        print_error(f"Failed to fetch bind status: {e}")

    print_step(3, 3, "Fetching platform info...")
    try:
        url = "https://100067.connect.garena.com/bind/app/platform/info/get"
        r = requests.get(url, params={"access_token": access_token},
                         headers={"User-Agent": "GarenaMSDK/4.0.19P9(Redmi Note 5 ;Android 9;en;US;)"},
                         timeout=10)
        if r.status_code == 200:
            d = r.json()
            bounded = d.get("bounded_accounts", [])
            if bounded:
                platform = ", ".join([PLATFORM_MAP.get(p, f"Unknown ({p})") for p in bounded])
            else:
                platform = "None"
            print_success("Platform info fetched")
    except Exception as e:
        print_error(f"Failed to fetch platform info: {e}")

    print("")
    lines = [
        f"UID           : {uid}",
        f"Nickname      : {nickname}",
        f"Region        : {region}",
        f"Platform      : {platform}",
        f"Bind Status   : {bind_status}",
        f"Bind Email    : {bind_email}",
    ]
    if email_masked and not email_full_flag:
        lines.append(f"Email Note    : Garena masks email server-side (OB55+)")
    lines.append(f"Creation Date : Not Available (API Does Not Expose)")

    print_result_box("PLAYER OWNER DETAILS", lines)
    wait_for_enter()


# ============================================================
#  OPTION 11: ACCESS TOKEN TO BAN
# ============================================================
def ban_account():
    draw_header("BAN ACCOUNT (DANGER)")

    print_warning("WARNING: This will PERMANENTLY BAN the account!")
    print_warning("Use with extreme caution.")
    print("")

    confirm = input_prompt("Type 'YES' to confirm ban")
    if confirm.upper() != "YES":
        print_info("Cancelled.")
        return wait_for_enter()

    token = input_prompt("Enter Access Token")
    if not token:
        print_error("Token cannot be blank.")
        return wait_for_enter()

    print_step(1, 1, "Sending Ban Request to API Server...")

    url = f"https://toji-api-jwt.vercel.app/ban?token={token}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    try:
        response = requests.get(url, headers=headers, timeout=25)

        if response.status_code == 200:
            raw_text = response.text.strip()
            try:
                parsed_json = json.loads(raw_text)
                lines = [f"{k} : {v}" for k, v in parsed_json.items()]
                print_result_box("BAN RESPONSE", lines)
            except Exception:
                print_result_box("BAN RESPONSE", [raw_text[:50]])
        else:
            print_error(f"Server Error (HTTP {response.status_code})")
            print_warning(f"Response: {response.text[:120]}")

    except Exception as e:
        print_error(f"Connection Failed: {e}")
        print_warning("External API may be down.")

    wait_for_enter()


# ============================================================
#  CRYPTO HELPERS
# ============================================================
AeSkEy = b'Yg&tc%DEuh6%Zc^8'
AeSiV = b'6oyZDr22E3ychjM%'


def enc(d):
    return AES.new(AeSkEy, AES.MODE_CBC, AeSiV).encrypt(pad(d, 16))


def dec(d):
    return unpad(AES.new(AeSkEy, AES.MODE_CBC, AeSiV).decrypt(d), 16)


def build_majorlogin(tok, open_id, p_type):
    m = mLpB.MajorLogin()
    m.event_time = str(datetime.now())[:-7]
    m.game_name = "free fire"
    m.platform_id = p_type
    m.client_version = "1.120.1"
    m.system_software = "Android OS 9 / API-28"
    m.system_hardware = "Handheld"
    m.telecom_operator = "Verizon"
    m.network_type = "WIFI"
    m.screen_width = 1920
    m.screen_height = 1080
    m.screen_dpi = "280"
    m.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    m.memory = 3003
    m.gpu_renderer = "Adreno (TM) 640"
    m.gpu_version = "OpenGL ES 3.1 v1.46"
    m.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    m.client_ip = "223.191.51.89"
    m.language = "en"
    m.open_id = open_id
    m.open_id_type = str(p_type)
    m.device_type = "Handheld"
    m.access_token = tok
    m.platform_sdk_id = 1
    m.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    m.login_by = 3
    m.channel_type = 3
    m.cpu_type = 2
    m.cpu_architecture = "64"
    m.client_version_code = "2019118695"
    m.login_open_id_type = p_type
    m.origin_platform_type = str(p_type)
    m.primary_platform_type = str(p_type)
    return enc(m.SerializeToString())


# ============================================================
#  MENU & DISPATCH
# ============================================================
def show_menu():
    draw_header()

    print(f"{Colors.RED}({Colors.GREEN}1{Colors.RED}){Colors.WHITE}{Colors.GREEN}  CHECK BIND INFO{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}2{Colors.RED}){Colors.WHITE}{Colors.GREEN}  BIND EMAIL{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}3{Colors.RED}){Colors.WHITE}{Colors.GREEN}  UNBIND EMAIL{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}4{Colors.RED}){Colors.WHITE}{Colors.GREEN}  CHANGE BIND EMAIL{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}5{Colors.RED}){Colors.WHITE}{Colors.GREEN}  CANCEL BIND REQUEST{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}6{Colors.RED}){Colors.WHITE}{Colors.GREEN}  EAT TO ACCESS TOKEN{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}7{Colors.RED}){Colors.WHITE}{Colors.GREEN}  GET LOGIN HISTORY{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}8{Colors.RED}){Colors.WHITE}{Colors.GREEN}  CHECK BOUND ACCOUNTS{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}9{Colors.RED}){Colors.WHITE}{Colors.GREEN}  ACCESS TOKEN TO JWT{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}10{Colors.RED}){Colors.WHITE}{Colors.GREEN} PLAYER OWNER DETAILS{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}11{Colors.RED}){Colors.WHITE}{Colors.GREEN} ACCESS TOKEN TO BAN{Colors.RESET}")
    print(f"{Colors.RED}({Colors.GREEN}0{Colors.RED}){Colors.WHITE}{Colors.GREEN}  EXIT{Colors.RESET}")
    print(LINE)
    print()


def main():
    _dispatch = {
        "1": bind_info,            "01": bind_info,
        "2": bind_email,           "02": bind_email,
        "3": unbind_email,         "03": unbind_email,
        "4": change_bind_email,    "04": change_bind_email,
        "5": cancel_bind,          "05": cancel_bind,
        "6": eat_to_access_token,  "06": eat_to_access_token,
        "7": login_history,        "07": login_history,
        "8": check_bound_accounts, "08": check_bound_accounts,
        "9": access_to_jwt,        "09": access_to_jwt,
        "10": player_owner_details,
        "11": ban_account,
    }

    while True:
        show_menu()
        choice = input_prompt("Select Option").strip().lstrip("0") or "0"

        if choice in ("0", "00"):
            clear_screen()
            print(f"{Colors.RED}({Colors.GREEN}√{Colors.RED}){Colors.WHITE}{Colors.GREEN} Safely Exited. Goodbye!{Colors.RESET}\n")
            sys.exit(0)

        fn = _dispatch.get(choice)
        if fn:
            fn()
        else:
            print(f"{Colors.RED}({Colors.GREEN}×{Colors.RED}){Colors.WHITE}{Colors.YELLOW} Invalid option [{choice}]{Colors.RESET}\n")
            time.sleep(1.2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}({Colors.GREEN}√{Colors.RED}){Colors.WHITE}{Colors.GREEN} Exited cleanly.{Colors.RESET}\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}({Colors.GREEN}×{Colors.RED}){Colors.WHITE}{Colors.YELLOW} Fatal: {e}{Colors.RESET}")
        input(f"{Colors.RED}({Colors.GREEN}•{Colors.RED}){Colors.WHITE}{Colors.GREEN} Press Enter to exit ... {Colors.RESET}")