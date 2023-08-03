from time import sleep
import requests
import base64
import subprocess
import logging
import socket
import json
from urllib import parse
import os

from urllib3.exceptions import NewConnectionError

from src.plebvpn_common.types import *

logging.basicConfig(level=logging.DEBUG)
logging.getLogger().setLevel(level=logging.DEBUG)

# url = "https://192.168.1.212:8000"
# url = "https://0.0.0.0:8000"
FORCE_SSL_VERIFICATION = True  # Change to True in production to avoid self-signed certs
PLEB_SECRET_FILE = "/home/admin/pleb-vpn/pleb-vpn.secret"
OVPN_CONFIG_FILE = "/home/admin/plebvpn.conf"

# TODO: change username to node's pubkey when testing is done
import random
username = f"satoshi{random.randrange(1000000, 90000000)}"
payload = NewAccountReq(port=0, pubkey="abcdef", name=username)

# Gotta catch 'em all!
CONNECTION_ERRORS = (NewConnectionError, ConnectionRefusedError, OSError, ConnectionError)


def __sanitize_pleberror_response(resp_text):
    try:
        _err = json.loads(resp_text)['detail']
    except json.decoder.JSONDecodeError:
        _err = PlebError.UNKNOWN
    return _err


def _get_plebvpn_secret():
    with open(PLEB_SECRET_FILE, 'r') as secret:
        return secret.read()


def _save_plebvpn_secret(_bytes):
    with open(PLEB_SECRET_FILE, 'w') as secret:
        secret.write(_bytes)
    os.chmod(PLEB_SECRET_FILE, 0o600)


def _save_ovpn_file(ovpn_config_bytes):
    with open(OVPN_CONFIG_FILE, 'wb') as ovpn_file:
        text = base64.b64decode(ovpn_config_bytes)
        ovpn_file.write(text)


def check_account_availability(url: str, name: str):
    req = CheckAccountReq(name=name)
    endpoint = "/check_account_availability"
    try:
        response = requests.post(parse.urljoin(url, endpoint), json=req.dict(), verify=FORCE_SSL_VERIFICATION)
    except CONNECTION_ERRORS:
        return PlebError.NO_CONNECTION

    if response.status_code == 200:
        return PlebError.SUCCESS
    else:
        logging.debug(f"Could not request account {name}. Account already exists?")
        _err = __sanitize_pleberror_response(response.text)
        return _err


def request_new_account(url):
    endpoint = "/request_account"

    try:
        response = requests.post(parse.urljoin(url, endpoint), json=payload.dict(), verify=FORCE_SSL_VERIFICATION)
    except CONNECTION_ERRORS:
        return PlebError.NO_CONNECTION

    logging.info("Requesting a new account..")

    if response.status_code == 201:
        logging.info("Account requested successfully!")
        logging.debug(response.json())
        _save_plebvpn_secret(response.json()['secret'])
        _save_ovpn_file(response.json()['ovpn_bytes'])

        _err = PlebError.SUCCESS
    else:
        logging.debug(f"Error requesting account. Status code: {response.status_code}")
        logging.debug(f"Error requesting account. Content: {response.text}")

        _err = __sanitize_pleberror_response(response.text)

        # We've already negotiated ports, so this shouldn't happen, but it's worth checking anyway.
        if _err == PlebError.BAD_PORT:
            logging.error(f"Port {payload.port} already in use")
        elif _err == PlebError.ACCOUNT_ALREADY_EXISTS:
            logging.error(f"User {payload.name} already in use")
        elif _err == PlebError.UNKNOWN:
            logging.error("Unknown error")

    return _err


def request_ovpn_config(_url: str, _name: str):
    """Used for downloading an openvpn profile for an account that already exists."""
    endpoint = "/request_ovpn_config"
    try:
        req = OpenVPNReq(url=_url, name=_name, secret=_get_plebvpn_secret())
    except Exception as e:
        logging.exception(e)
        return PlebError.INVALID_CREDENTIALS
    try:
        response = requests.post(parse.urljoin(_url, endpoint), json=req.dict(), verify=FORCE_SSL_VERIFICATION)
    except CONNECTION_ERRORS:
        return PlebError.NO_CONNECTION

    if response.status_code == 200:
        logging.info("Ovpn file requested successfully!")
        logging.debug(response.json())
        ovpn_config_bytes = response.json()['ovpn_bytes']
        _save_ovpn_file(ovpn_config_bytes)

    else:
        logging.debug(f"Error requesting ovpn config. Status code: {response.status_code}")
        logging.debug(f"Error requesting ovpn config. Content: {response.text}")
        _err = __sanitize_pleberror_response(response.text)
        return _err


def negotiate_ports(url):
    """Find a port that is available for both server and client
    @returns: PlebError.BAD_PORT if no port is found.
    @returns: (int) port number if a good port is found"""
    endpoint = "/request_port"

    logging.info("Negotiating ports..")

    # Let's only try 50 times.. if we can't agree on a port by then, something is probably very wrong.
    MAX_RETRIES = 50
    for x in range(MAX_RETRIES):
        with socket.socket() as sock:
            sock.bind(('', 0))  # Gets a random free port
            _port = sock.getsockname()[1]

            logging.debug(f"Requesting port {_port}")

            try:
                response = requests.post(parse.urljoin(url, endpoint), json=PortReq(port=_port).dict(),
                                         verify=FORCE_SSL_VERIFICATION)
            except CONNECTION_ERRORS:
                return PlebError.NO_CONNECTION

        if response.status_code == 200:
            logging.info(f"Successfully negotiated port {_port}")
            return _port

        _err = __sanitize_pleberror_response(response.text)
        if _err == PlebError.BAD_PORT:
            sleep(0.1)  # In case something goes very wrong, don't DDoS the server.
            continue

    return PlebError.BAD_PORT


def get_public_ip():
    proc = subprocess.Popen("curl https://api.ipify.org".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        logging.error(f"Could not get IP address. curl output: {stderr}")
        return PlebError.NO_CONNECTION

    return stdout.decode()


def test_vpn():
    """Unused and untested. For now, the bulk of the work is done in vpn-install.sh in plebvpn repo"""
    # Determine our real public IP
    real_ip_addr = get_public_ip()
    if real_ip_addr is PlebError.NO_CONNECTION:
        logging.error("No internet connection. Bailing.")
        return

    logging.info(f"IP: {real_ip_addr}")

    # Enable VPN (TODO)

    # Attempt to get VPN ip address
    vpn_ip_addr = get_public_ip()

    # compare IPs
    if vpn_ip_addr == real_ip_addr:
        logging.error("IP Leak! OpenVPN connection failed!!")


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    import argparse
    from enum import Enum

    class Actions(Enum):
        CREATE_ACCOUNT = "create_account"
        DOWNLOAD_VPN_CONF = "download_vpn_config"
        CHECK_ACCOUNT_EXISTS = "check_account_exists"

    parser = argparse.ArgumentParser(prog="PlebVPN", description="A VPN for your Lightning Node!")

    parser.add_argument('-a ', '--action', choices=[e.value for e in Actions],
                        help="What do?")
    parser.add_argument('-s', '--server', required=True, help="Domain or IP:Port of PlebVPN server to connect to.")
    args = parser.parse_args()

    if args.action == Actions.CREATE_ACCOUNT.value:
        if check_account_availability(args.server, username) == PlebError.ACCOUNT_ALREADY_EXISTS:
            logging.error("Account name already exists.")
            exit(PlebError.ACCOUNT_ALREADY_EXISTS)
        port = negotiate_ports(args.server)
        if port == PlebError.BAD_PORT:
            logging.error("Could not negotiate a good LND port with the server. Bailing.")
            exit(PlebError.BAD_PORT)

        payload.port = port
        err = request_new_account(args.server)
        if err is not PlebError.SUCCESS:
            exit(err)

    elif args.action == Actions.DOWNLOAD_VPN_CONF.value:
        logging.info("Downloading VPN configuration..")
        err = request_ovpn_config(args.server, username)
        if err is not PlebError.SUCCESS:
            exit(err)

    elif args.action == Actions.CHECK_ACCOUNT_EXISTS.value:
        err = check_account_availability(args.server, username)
        if err is not PlebError.SUCCESS:
            logging.info("Account already exists")
            exit(err)
