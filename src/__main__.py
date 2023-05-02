from time import sleep
import requests
import base64
import subprocess
import logging
import socket
import json
from urllib import parse

from src.plebvpn_common.types import *

logging.basicConfig(level=logging.DEBUG)
logging.getLogger().setLevel(level=logging.DEBUG)

# url = "https://192.168.1.212:8000"
# url = "https://0.0.0.0:8000"
FORCE_SSL_VERIFICATION = False  # Change to True in production to avoid self-signed certs

payload = NewAccountReq(port=0, pubkey="abcdef", name="dickbutt26")


def __sanitize_pleberror_response(resp_text):
    try:
        err = json.loads(resp_text)['detail']
    except json.decoder.JSONDecodeError:
        err = PlebError.UNKNOWN
    return err


def request_new_account(url):
    endpoint = "/request_account"
    response = requests.post(parse.urljoin(url, endpoint), json=payload.dict(), verify=FORCE_SSL_VERIFICATION)

    logging.info("Requesting a new account..")

    if response.status_code == 201:
        logging.info("Account requested successfully!")
        logging.debug(response.json())
    else:
        logging.debug(f"Error requesting account. Status code: {response.status_code}")
        logging.debug(f"Error requesting account. Content: {response.text}")

        err = __sanitize_pleberror_response(response.text)

        # We've already negotiated ports, so this shouldn't happen, but it's worth checking anyway.
        if err == PlebError.BAD_PORT:
            logging.error(f"Port {payload.port} already in use")
        elif err == PlebError.ACCOUNT_ALREADY_EXISTS:
            logging.error(f"User {payload.name} already in use")
        elif err == PlebError.UNKNOWN:
            logging.error("Unknown error")


def request_ovpn_config(url):
    # TODO: Remove need for sending name a second time. Server should be able to return the config based on LN login
    endpoint = "/request_ovpn_config"
    response = requests.post(parse.urljoin(url, endpoint), json=payload.dict(), verify=FORCE_SSL_VERIFICATION)

    if response.status_code == 200:
        logging.info("Ovpn file requested successfully!")
        logging.debug(response.json()[0])
        logging.debug(response.json()[1])
        config_bytes = base64.b64decode(response.json()[1])
        logging.debug(config_bytes)

        with open("/home/admin/plebvpn.conf", 'wb') as ovpn_file:
            ovpn_file.write(config_bytes)
    else:
        logging.debug(f"Error requesting ovpn config. Status code: {response.status_code}")
        logging.debug(f"Error requesting ovpn config. Content: {response.text}")
        err = __sanitize_pleberror_response(response.text)


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

            response = requests.post(parse.urljoin(url, endpoint), json=PortReq(port=_port).dict(),
                                     verify=FORCE_SSL_VERIFICATION)

        if response.status_code == 200:
            logging.info(f"Successfully negotiated port {_port}")
            return _port

        err = __sanitize_pleberror_response(response.text)
        if err == PlebError.BAD_PORT:
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

    # Determine our real public IP
    real_ip_addr = get_public_ip()
    if real_ip_addr is PlebError.NO_CONNECTION:
        logging.error("No internet connection. Bailing.")
        return

    logging.info(f"IP: {real_ip_addr}")

    # Enable VPN

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

    parser = argparse.ArgumentParser(prog="PlebVPN", description="A VPN for your Lightning Node!")

    parser.add_argument('-a ', '--action', choices=[e.value for e in Actions],
                        help="What do?")
    parser.add_argument('-s', '--server', required=True, help="Domain or IP:Port of PlebVPN server to connect to.")
    args = parser.parse_args()

    if args.action == Actions.CREATE_ACCOUNT.value:
        port = negotiate_ports(args.server)
        if port == PlebError.BAD_PORT:
            logging.error("Could not negotiate a good LND port with the server. Bailing.")
            exit(1)

        payload.port = port
        request_new_account(args.server)
        # request_ovpn_config(args.server)

    elif args.action == Actions.DOWNLOAD_VPN_CONF.value:
        print("Downloading VPN configuration")

    # request_new_account()
    # request_ovpn_config()
    # test_vpn()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
