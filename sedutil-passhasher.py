#!/usr/bin/python3
# - but should work in python 2.7 as well.
#
#   Copyright 2019 Michal Gawlik
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

"""
Script which prepares hashed password file for sed-opal-unlocker.

Compatible with sedutil-cli password hashing, allows using sed-opal-unlocker
with drive initialized without sedutil's -n option which disables hashing.
"""

import sys
import getpass
import fcntl
import ctypes
import hashlib


def read_sata_disk_serial(dev):
    """Read hard drive model, serial and firmware version using SATA/IDE interface."""
    HDIO_GET_IDENTITY = 0x030d
    buf = ctypes.create_string_buffer(b'\x00', 512)

    with open(dev, "rb") as fd:
        ret = fcntl.ioctl(fd, HDIO_GET_IDENTITY, buf, True)

    if ret != 0:
        raise Exception("HDIO_GET_IDENTITY failed!")

    serial = buf[20:40]
    model = buf[54:94]
    fw = buf[46:54]
    return serial, model, fw


def read_nvme_disk_serial(dev):
    """Read hard drive model, serial and firmware version using NVME interface."""
    class NVMEAdminCmd(ctypes.Structure):
        _pack_ = 1
        _fields_ = [('opcode', ctypes.c_uint8),
                    ('flags', ctypes.c_uint8),
                    ('rsvd1', ctypes.c_uint16),
                    ('nsid', ctypes.c_uint32),
                    ('cdw2', ctypes.c_uint32),
                    ('cdw3', ctypes.c_uint32),
                    ('metadata', ctypes.c_uint64),
                    ('addr', ctypes.c_uint64),
                    ('metadata_len', ctypes.c_uint32),
                    ('data_len', ctypes.c_uint32),
                    ('cdw10', ctypes.c_uint32),
                    ('cdw11', ctypes.c_uint32),
                    ('cdw12', ctypes.c_uint32),
                    ('cdw13', ctypes.c_uint32),
                    ('cdw14', ctypes.c_uint32),
                    ('cdw15', ctypes.c_uint32),
                    ('timeout_ms', ctypes.c_uint32),
                    ('result', ctypes.c_uint32)]

    NVME_IOCTL_ADMIN_CMD = 0xc0484e41
    buf = ctypes.create_string_buffer(b'\x00', 4096)
    cmd = NVMEAdminCmd(opcode=0x06,  # NVME_IDENTIFY
                       addr=ctypes.addressof(buf),
                       data_len=4096,
                       cdw10=1)

    with open(dev, "rb") as fd:
        ret = fcntl.ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd, True)

    if ret != 0:
        raise Exception("NVME_IOCTL_ADMIN_CMD failed!")

    serial = buf[4:24]
    model = buf[24:64]
    fw = buf[64:72]
    return serial, model, fw


def main():
    """Main module function implementing script body."""
    if len(sys.argv) != 3:
        print("Usage: {} <disk_path> <output_passwordhash_file_path>".format(sys.argv[0]))
        return 0

    dev = sys.argv[1]
    out = sys.argv[2]

    # Read disk serial number which is needed to salt the password hash.
    # On the wire, the serial number is 20 byte string, out of which some store
    # the serial, and the rest is usually padded with spaces. But some drives
    # seems to use right-padding, others do left-padding. I guess there exists
    # disks with non-space padding as well... But since this padding also salts
    # the hash and tools like hdparm/smartctl cuts it, we can't count on them
    # and have to read the serial ourselves.
    print("Checking {}...".format(dev))
    try:
        if 'nvm' in dev:
            serial, model, fw = read_nvme_disk_serial(dev)
        else:
            serial, model, fw = read_sata_disk_serial(dev)
    except Exception as e:
        print("Failed to read disk serial: {!s}".format(e))
        return 1

    # print drive identification and ask kindly for the password
    print("Found {!s} with firmware {!s} and serial {!r}".format(model.decode('utf8').strip(),
                                                                 fw.decode('utf8').strip(),
                                                                 serial))

    print("Password hash will be written into {}".format(out))
    password = getpass.getpass("Enter SED password for {} (CTRL+C to quit): ".format(dev))

    # hash it using the same settings sedutil-cli uses
    hashed = hashlib.pbkdf2_hmac('sha1', password.encode('utf8'), serial, 75000, 32)

    # finally, save it to a file, with some magic number allowing
    # sed-opal-unlocker to recognize this as a binary hash file, which should
    # not be mangled in any way.
    try:
        with open(out, 'wb') as f:
            f.write(b'\x00\x84\x11\xf8\x9a\x0f\x30\x93')
            f.write(hashed)
    except EnvironmentError as e:
        print("Failed to write hashed password to {}: {!s}".format(out, e))
        return 1
    else:
        print("Hashed password saved! Protect that file properly (chown/chmod at least).")
        return 0


if __name__ == '__main__':
    sys.exit(main())
