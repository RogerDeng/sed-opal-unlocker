# sed-opal-unlocker

Micro-utility for unlocking TCG-OPAL encrypted disks, utilizing CONFIG_BLK_SED_OPAL interface introduced in kernel 4.11. Also allows saving password in the running kernel for S3 Sleep support, cause it was a cheap feature to have. Based on Kyle Manna's [opalctl](https://github.com/kylemanna/opalctl) nano-utility.


### Background

I'm using this tool to unlock non-boot disk from custom initramfs, loaded from EFI partition sitting on another non-opal-encrypted drive. The machine is headless, cannot boot from NVME and the password is provided on an USB key, so the standard [sedutil](https://github.com/Drive-Trust-Alliance/sedutil) Pre-Boot Authentication image is not an option.


### Features

- unlocking / locking TCG-OPAL compatible Self-Encrypting Drives
- turning off MBR shadowing after unlocking
- saving drive password into the Linux kernel (unlock support when the system is waking from S3 sleep)
- reads password from a separate file
- supports password hashing used by sedutil-cli via separate one-time-use script
- supports SATA and NVME disks


### What this utility cannot do

- cannot unlock system drive (unless you create a custom Pre-Boot Authentication image with it; however s3save operation is supported when drive gets unlocked with sedutil's PBA image)
- password cannot be read interactively, nor from cmdline argument
- will not work with CONFIG_BLK_SED_OPAL=n kernel (and is Linux only, but this should be obvious now)


### Building

Just:

```
    make
```

If you need a static binary:

```
    make STATIC=1
```


### Usage

```
    sed-opal-unlocker <operation> <disk_path> <password_file_path>
```

Where:
- `<operation>` is one of: lock, unlock, MBRunshadow, s3save
- `<disk_path>` is device path, eg. /dev/sda, /dev/nvme0n1, etc.
- `<password_file_path>` is path to file containing the disk password

Operation specifies what the tool should do:
- `lock`: lock the drive. Useful mainly for testing.
- `unlock`: unlock the drive. The main feature of this tool.
- `MBRunshadow`: disable MBR shadow image. Use after unlock when the disk has been configured to shadow MBR (see below).
- `s3save`: store password in the Linux kernel for enabling drive unlock after S3 sleep.

When the disk has been initialized with sedutil-cli without using its `-n` option, the password which is send to the disk is a hash calculated using PKBDF2 algorithm from plain text password and the disk serial for salting. In order to use such password with `sed-opal-unlocker`, all you need to do is to store the hashed password in the password file. Fortunately, there's a Python script which will do this for you.

```
    sedutil-passhasher.py <disk_path> <output_passwordhash_file_path>
```

You need to call this script once, as root, cause it reads serial number from the disk needed to salt the password for hashing. Plaintext password is entered on script standard input. Hashed password (with some magic value for file type recognition) is written to the output file specified by second argument. Note that the file will be overwritten when it exists.


### Bonus: disk initialization notes

The most helpful information source for me was [Self-Encrypting Drives](https://wiki.archlinux.org/index.php/Self-Encrypting_Drives) article on Archlinux wiki. Another source worth looking at is [sedutil wiki](https://github.com/Drive-Trust-Alliance/sedutil/wiki).

Despite I'm encrypting non-root (secondary) disk, I still prefer to enable MBR shadowing and filling it with zeros. Otherwise when kernel boots and tries to read partition table while the disk is still locked, scary looking IO errors are generated, and disk also saves them in some SMART error counter.

**Please note that tinkering with your drive may cause data loss. It's best to work with an empty drive, so you lose nothing when screwing up. Otherwise, HAVE A BACKUP.**

**Do not execute this for your root drive. It won't boot without a proper PBA image.**

**In all the following examples, replace /dev/disk with proper path (like /dev/sda or /dev/nvme0n1), and "password1234" with your real password.** Non-indented line represents command to be executed, following indented lines are its example output.


1. Initial setup

```
sedutil-cli --initialsetup password1234 /dev/disk
    takeOwnership complete
    Locking SP Activate Complete
    LockingRange0 disabled
    LockingRange0 set to RW
    MBRDone set on
    MBRDone set on
    MBREnable set on
    Initial setup of TPer complete on /dev/disk
```

2. Clear MBR shadow image

(sedutil-cli requires a file to load, therefore first we need to create image filled with zeros. Copying takes a while and it's better not to interrupt it - disk may hang, stop responding and require a power-cycle to recover. The disk may also come with empty PBA already, but I think it's better to write it explicitly.)

```
dd if=/dev/zero of=/tmp/zeros.img bs=1M count=128
    128+0 records in
    128+0 records out
    134217728 bytes (134 MB, 128 MiB) copied, 0,0430394 s, 3,1 GB/s

sedutil-cli --loadPBAimage password1234 /tmp/zeros.img /dev/disk
    Writing PBA to /dev/disk
    ...
    19381540 of 134217728 14% blk=61334
    ...
    112363888 of 134217728 83% blk=61334
    ...
    134217728 of 134217728 100% blk=18936
    PBA image  /tmp/zeros.img written to /dev/disk
```

3. Ensure MBR shadowing is enabled

```
sedutil-cli --setMBREnable on password1234 /dev/disk
    MBRDone set on
    MBREnable set on
```

4. Enable global locking range

```
sedutil-cli --enableLockingRange 0 password1234 /dev/disk
    LockingRange0 enabled ReadLocking,WriteLocking
```

5. Now your drive is configured. It will lock itself after a power cycle. Do it now.

6. After the power cycle, your drive will be locked and empty shadow MBR will be presented. You may verify it:

```
sedutil-cli --query /dev/disk
    ...
    Locking function (0x0002)
        Locked = Y, LockingEnabled = Y, LockingSupported = Y, MBRDone = N, MBREnabled = Y, MediaEncrypt = Y
    ...

sedutil-cli --listLockingRanges password1234 /dev/disk
    Locking Range Configuration for /dev/disk
    LR0 Begin 0 for 0
                RLKEna = Y  WLKEna = Y  RLocked = Y  WLocked = Y
    ...

hexdump -C /dev/disk -n 512
    00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    *
    00000200
```

7. Prepare hashed password file (if you preferred non-hashed password and added `-n` to sedutil-cli calls, skip this step and just write plaintext password to the password file)

```
cd sed-opal-unlocker
./sedutil-passhasher.py /dev/disk /somewhere/safe/mypassword.secret
    Checking /dev/disk...
    Found DISK MODEL with firmware FW_VER and serial b'1234567890           '
    Password hash will be written into /somewhere/safe/mypassword.secret
    Enter SED password for /dev/disk (CTRL+C to quit): <enter password1234>
    Hashed password saved! Protect that file properly (chown/chmod at least).

chmod 400 /somewhere/safe/mypassword.secret
chown root:root /somewhere/safe/mypassword.secret
```

8. a) Now, finally, use the sed-opal-unlocker to unlock the drive:

```
cd sed-opal-unlocker
./sed-opal-unlocker unlock /dev/disk /somewhere/safe/mypassword.secret
./sed-opal-unlocker MBRunshadow /dev/disk /somewhere/safe/mypassword.secret
```

If no errors were printed, it worked! Check yourself with commands from step 6.

8. b) If you're interested as well (or only) in S3 sleep support:

```
cd sed-opal-unlocker
./sed-opal-unlocker s3save /dev/disk /somewhere/safe/mypassword.secret
```

9. You may put 8a / 8b commands in some initialization scripts, initramfs, etc. Writing a `.service` file should be fairly trivial. Good luck!
