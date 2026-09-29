#!/usr/bin/env python3
"""Catch the U-Boot autoboot window on the control board (test factory U-Boot,
BOOTDELAY=3), clear the TPM through the platform hierarchy, then boot on.
Everything read from the console is logged."""
import serial, sys, time

LOG = sys.argv[1]
ser = serial.Serial("/dev/ttyACM0", 115200, timeout=0.1)
log = open(LOG, "wb")
buf = b""

def pump(sec):
    global buf
    end = time.time() + sec
    while time.time() < end:
        d = ser.read(4096)
        if d:
            log.write(d); log.flush(); buf += d

def wait_for(pats, sec):
    global buf
    end = time.time() + sec
    while time.time() < end:
        pump(0.1)
        for p in pats:
            if p in buf:
                return p
    return None

def cmd(c, sec=6):
    global buf
    buf = b""
    ser.write(c.encode() + b"\r")
    wait_for([b"=> ", b"U-Boot> "], sec)
    pump(0.3)

print("waiting for autoboot (reboot the board now)", flush=True)
hit = wait_for([b"Hit any key", b"autoboot"], 600)
if not hit:
    print("no autoboot prompt seen"); sys.exit(1)
for _ in range(10):
    ser.write(b" "); time.sleep(0.05)
if not wait_for([b"=> ", b"U-Boot> "], 5):
    print("no prompt"); sys.exit(1)
print("at U-Boot prompt", flush=True)
cmd("tpm2 init")
cmd("tpm2 startup TPM2_SU_CLEAR")
cmd("tpm2 info")
cmd("tpm2 clear TPM2_RH_PLATFORM", 20)
ser.write(b"boot\r")
pump(120)
print("done", flush=True)
