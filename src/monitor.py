import logging
import requests
import re
import os
from datetime import datetime
import threading
import time

logging.basicConfig(
    encoding="utf-8",
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

def get_env(key, fallback):
    env = os.getenv(key, default=fallback)
    return env


def get_local_ip():
    url = f"{get_env('NETWATCH_COLLECTOR_URL', 'https://api.netwatch.team')}/check_ip"
    for attempt in range(50):
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                local_ip = response.json().get("ip")
                logging.info(f"Got the following local IP: {local_ip}")
                return local_ip

            logging.error(f"[!] Got a non 200 status code from the netwatch backend: {response.status_code}, message: {response.text}")

        except requests.RequestException as e:
            logging.error(f"[!] Got a request exception while trying to get the local IP: {e}")

        except Exception as e:
            logging.error(f"[!] Got an exception while trying to get the local IP: {e}")

        time.sleep(10)

    logging.error("[!] The system was unable to get the local IP. Sensor can not work without local IP => Exit with code 1")
    exit(1)


def submit_attack(ip, user, password, evidence, ATTACKPOD_LOCAL_IP):
    json = {"source_ip": ip,
            "destination_ip": ATTACKPOD_LOCAL_IP,
            "username":user,
            "password":password,
            "attack_timestamp": datetime.now().isoformat(),
            "evidence":evidence,
            "attack_type": "SSH_BRUTE_FORCE",
            }


    url = f"{get_env('NETWATCH_COLLECTOR_URL', '')}/add_attack"
    headers = {"authorization": get_env("NETWATCH_COLLECTOR_AUTHORIZATION", "")}

    for attempt in range(5):
        try:
            response = requests.post(url, json=json, headers=headers, timeout=5)
            if response.status_code == 200:
                logging.info(f"Reported the following JSON to the NetWatch collector: {json}")
                return

            logging.error(f"[!] Got a non 200 status code from the collector: {response.status_code} with message: {response.text}")

        except requests.RequestException as e:
            logging.error(f"[!] Got a request exception while submitting the attack: {e}")

        except Exception as e:
            logging.error(f"[!] Got an exception while submitting the attack: {e}")


def run_sshd():
    while True:
        os.system("/sbin/sshd -D -E /var/log/ssh.log")


def reap_children():
    while True:
        try:
            siginfo = os.waitid(os.P_ALL, 0, os.WEXITED|os.WNOHANG)
        except ChildProcessError:
            pass

        if siginfo is not None:
            logging.debug(f"Process {siginfo.si_pid} reaped")
        time.sleep(1)


def rotate_sshd_keys():
    os.system("rm -f /etc/ssh/ssh_host_*")
    os.system("ssh-keygen -t rsa -b 2048 -f /etc/ssh/ssh_host_rsa_key -N ''")
    os.system("ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key -N ''")

if __name__ == '__main__':
    logging.info("[+] Starting NetWatch Attackpod")
    logging.info("[+] Getting local ip")

    if os.getenv("ATTACK_POD_IP") is not None:
        ATTACKPOD_LOCAL_IP = get_env("ATTACK_POD_IP","")
    else:
        ATTACKPOD_LOCAL_IP = get_local_ip()
    
    logging.info("[+] Got the local ip of {} for the AttackPod".format(ATTACKPOD_LOCAL_IP))

    logging.info("[+] Rotating SSHD Keys")
    rotate_sshd_keys()

    logging.info("[+] Starting SSHD")
    sshd_thread = threading.Thread(target=run_sshd, args=())
    sshd_thread.start()

    logging.info("[+] Starting child reaper")
    reaper_thread = threading.Thread(target=reap_children, args=())
    reaper_thread.start()

    with open("/var/log/ssh.log", 'r') as logfile:
        logfile.seek(0, os.SEEK_END)

        ip = ""
        user = ""
        password = ""
        evidence = ""

        while True:
            # read last line of file
            line = logfile.readline()
            # sleep if file hasn't been updated
            if not line:
                time.sleep(0.1)
                continue

            logging.debug("Captured a new line from sshd: {}".format(line))
            output = re.findall("Login attempt by username '(.*)', password '(.*)', from ip '(\d.*)'", line)

            if len(output) == 1:
                # if the regex has a match it's the patched debug message

                if ip != "":
                    # If we have two matches after each other we submit the first one to not miss one, even if we don't have the evidence of the first one
                    submit_attack(ip, user, password, evidence, ATTACKPOD_LOCAL_IP)
                    ip = ""
                    user = ""
                    password = ""
                    evicence = ""

                user = output[0][0]
                password = output[0][1]
                ip = output[0][2]
            else:
                # If we don't have a regex match and we have a match of the "ip" in the line it is likely the "official" logline
                if ip in line and "Failed" in line:
                    evidence = line
                    submit_attack(ip, user, password, evidence, ATTACKPOD_LOCAL_IP)

                    ip = ""
                    user = ""
                    password = ""
                    evidence = ""
