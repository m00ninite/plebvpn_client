import requests
import base64
import subprocess
import logging

#url = "http://172.18.0.2:8000"
url = "https://0.0.0.0:8000"
FORCE_SSL_VERIFICATION=False  # Change to True in production to avoid self-signed certs

payload = {
    "port": 6969,
    "pubkey": "abcdef",
    "name": "dickbutt7"
}


def request_new_account():
    endpoint = "/request_account"
    response = requests.post(url+endpoint, json=payload, verify=FORCE_SSL_VERIFICATION)

    if response.status_code == 200:
        print("Account requested successfully!")
        print(response.json())
    else:
        print("Error requesting account. Status code:", response.status_code)


def request_ovpn_config():
    # TODO: Remove need for sending name a second time. Server should be able to return the config based on LN login
    endpoint = "/request_ovpn_config"
    response = requests.post(url+endpoint, json=payload, verify=FORCE_SSL_VERIFICATION)

    if response.status_code == 200:
        print("Account requested successfully!")
        print(response.json()[1])
        config_bytes = base64.b64decode(response.json()[1])
        print(config_bytes)

        with open("/etc/openvpn/plebvpn.conf", 'wb') as ovpn_file:
            ovpn_file.write(config_bytes)
    else:
        print("Error requesting account. Status code:", response.status_code)


def get_public_ip():
    proc = subprocess.Popen("curl https://api.ipify.org".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if proc.returncode is not 0:
        logging.error(f"Could not get IP address. curl output: {stderr}")
        return Pleb


def test_vpn():


    real_ip_addr = stdout.decode()  # Our public IP address, sans VPN

    # Enable vpn
# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    request_new_account()
    request_ovpn_config()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
