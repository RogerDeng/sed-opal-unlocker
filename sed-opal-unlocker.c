/**
 * Micro frontend to Linux Kernel SED TCG OPAL userspace interface
 * (CONFIG_BLK_SED_OPAL introduced in kernel 4.11.)
 *
 * Copyright      2017 Kyle Manna
 * Copyright 2018-2019 Michal Gawlik
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mem_zeroize.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <endian.h>
#include <termios.h>

#include <linux/sed-opal.h>

#ifdef ENCRYPTED_PASSWORDS
#include <argon2.h>
#endif


static void help(const char *banner)
{
	if (banner)
		puts(banner);
	printf("Usage:\n");
	printf("\tsed-opal-unlocker <operation> <disk_path> <password_file_path>\n");
	printf("\n");
	printf("Where:\n");
	printf("\t<operation> is one of: lock, unlock, MBRunshadow, s3save\n");
	printf("\t<disk_path> is device path, ex. /dev/sda, /dev/nvme0n1, etc.\n");
	printf("\t<password_file_path> is path to file containing the admin1 password\n");
#ifdef ENCRYPTED_PASSWORDS
	printf("\t                     If encrypted using relevant sedutil-passhasher.py option,\n");
	printf("\t                     passphrase for unlocking is expected on stdin.\n");
#endif
	printf("\n");
	printf("Note: when using DTA sedutil-cli to initialize the drive without disabling\n");
	printf("      password hashing (-n option), you should use sedutil-passhasher.py\n");
	printf("      companion script to prepare hashed password file. See README for details.\n");
}


#ifdef ENCRYPTED_PASSWORDS
static int decrypt_password(uint8_t *passwd, int passwd_len)
{
	struct {
		uint8_t  magic[8];
		uint32_t t_cost;
		uint32_t m_cost;
		uint32_t parallelism;
		uint8_t  salt_type;
		uint8_t  salt_init[11];
		uint8_t  data[];
	} *decoded = (void*)passwd;
	struct termios term, save;
	int ret = -1;
	int i, n, passphr_len, salt_len, data_len;
	uint8_t salt[64];
	uint8_t xor_key[256];
	char passphrase[256];
	char *pp;

	/* prepare salt, if some DMI data is required */
	memcpy(salt, decoded->salt_init, sizeof(decoded->salt_init));
	salt_len = sizeof(decoded->salt_init);
	if (decoded->salt_type == 's' || decoded->salt_type == 'u')
	{
		const char *fpath = (decoded->salt_type == 's') ?
			"/sys/devices/virtual/dmi/id/product_serial" :
			"/sys/devices/virtual/dmi/id/product_uuid";
		FILE *fp = fopen(fpath, "rb");
		if (!fp)
		{
			fprintf(stderr, "Failed to decrypt password file: failed to open %s\n", fpath);
			goto exit;
		}
		n = fread(&salt[salt_len], 1, 32, fp);
		fclose(fp);
		while (n > 0 && salt[salt_len + n - 1] == '\n')
			n--;
		salt_len += n;
	}
	else if (decoded->salt_type != 'r')
	{
		fprintf(stderr, "Failed to decrypt password file: bad salt type %d\n", decoded->salt_type);
		goto exit;
	}

	/* read passphrase */
	if (isatty(STDIN_FILENO))
	{
		printf("Please enter key unlock passphrase: ");
		fflush(stdout);
		/* turn off the echo */
		if (tcgetattr(STDIN_FILENO, &term) < 0)
		{
			fprintf(stderr, "Failed to decrypt password file: unable to disable terminal echo #1\n");
			goto exit;
		}
		save = term;
		term.c_lflag &= ~ECHO;
		if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) < 0)
		{
			fprintf(stderr, "Failed to decrypt password file: unable to disable terminal echo #2\n");
			goto exit;
		}
	}
	pp = fgets(passphrase, sizeof(passphrase), stdin);
	if (isatty(STDIN_FILENO))
	{
		printf("\n");
		tcsetattr(STDIN_FILENO, TCSANOW, &save);
	}
	if (pp != passphrase)
	{
		fprintf(stderr, "Failed to decrypt password file: unable to read passphrase\n");
		goto exit;
	}
	passphr_len = strlen(passphrase);
	while (passphr_len > 0 && passphrase[passphr_len - 1] == '\n')
		passphr_len--;

	/* hash it! */
	decoded->t_cost = le32toh(decoded->t_cost);
	decoded->m_cost = le32toh(decoded->m_cost);
	decoded->parallelism = le32toh(decoded->parallelism);
	data_len = passwd_len - sizeof(*decoded);
	n = argon2id_hash_raw(decoded->t_cost, decoded->m_cost, decoded->parallelism,
			passphrase, passphr_len, salt, salt_len, xor_key, data_len);
	if (n < 0)
	{
		fprintf(stderr, "Failed to decrypt password file: argon2id failed with error code %d\n", n);
		goto exit;
	}

	/* xor to "decrypt" password */
	for (i = 0; i < data_len; i++)
		passwd[i] = xor_key[i] ^ decoded->data[i];

	ret = passwd_len - sizeof(*decoded);
exit:
	mem_zeroize(xor_key, sizeof(xor_key));
	mem_zeroize(passphrase, sizeof(passphrase));
	return ret;
}
#endif  /* ENCRYPTED_PASSWORDS */


int main(int argc, char* argv[])
{
	int ret = 1;
	int mode = -1;
	int fd = -1;
	char buf[64];
	int passwd_len = 0;
	uint8_t passwd[OPAL_KEY_MAX];  // note: maybe not-NULL-terminated
	struct opal_lock_unlock lk_unlk;
	struct opal_mbr_data mbr_data;

	// Parse arguments
	if (argc < 4)
		help("Not enough arguments!");
	else if (strcmp(argv[1], "lock") == 0)
		mode = 0;
	else if (strcmp(argv[1], "unlock") == 0)
		mode = 1;
	else if (strcmp(argv[1], "s3save") == 0)
		mode = 2;
	else if (strcmp(argv[1], "MBRunshadow") == 0)
		mode = 3;
	else
		help("Invalid <operation>!");
	if (mode < 0)
		return 1;

	const char *dev = argv[2];
	const char *passfile = argv[3];

	// Load password
	fd = open(passfile, O_RDONLY);
	if (fd < 0)
	{
		snprintf(buf, sizeof(buf), "Failed to open %s", passfile);
		perror(buf);
		goto exit;
	}
	passwd_len = read(fd, passwd, sizeof(passwd));
	if (passwd_len < 0)
	{
		snprintf(buf, sizeof(buf), "Failed load password from %s", passfile);
		perror(buf);
		goto cleanup;
	}
	close(fd);

	// If this is binary file produced by sedutil-passhasher.py, strip leading magic number.
	// If binary and encrypted, request passphrase and decrypt.
	// Otherwise trim terminating newline (any flavor) when present.
	if (passwd_len == 40 && memcmp(passwd, "\x00\x84\x11\xf8\x9a\x0f\x30\x93", 8) == 0)
	{
		passwd_len = 32;
		memmove(passwd, passwd + 8, passwd_len);
	}
	else if (passwd_len > 32 && memcmp(passwd, "\x00\x84\x11\xf8\xb5\xf8\x43\x88", 8) == 0)
	{
#ifdef ENCRYPTED_PASSWORDS
		passwd_len = decrypt_password(passwd, passwd_len);
		if (passwd_len <= 0)
			goto exit;
#else
		fprintf(stderr, "Encrypted passwords not supported! Please compile with ENCRYPTED_PASSWORDS=1.\n");
		goto exit;
#endif
	}
	else
	{
		if (passwd[passwd_len - 1] == '\n')
			passwd_len--;
		if (passwd[passwd_len - 1] == '\r')
			passwd_len--;
	}

	// Open the device
	fd = open(dev, O_WRONLY);
	if (fd < 0)
	{
		snprintf(buf, sizeof(buf), "Failed to open %s", dev);
		perror(buf);
		goto exit;
	}

	if (mode < 3)
	{
		// Create necessary structure and zerofill it, just in case
		memset(&lk_unlk, 0, sizeof(struct opal_lock_unlock));

		// Lock or unlock OPAL drive for read and write
		lk_unlk.l_state = (mode == 0) ? OPAL_LK : OPAL_RW;
		// Don't use single user mode
		lk_unlk.session.sum = 0;
		// Identify as admin1
		lk_unlk.session.who = OPAL_ADMIN1;
		// 0 locking range (global range)
		lk_unlk.session.opal_key.lr = 0;
		// Copy key
		memcpy(lk_unlk.session.opal_key.key, passwd, passwd_len);
		// Set key size
		lk_unlk.session.opal_key.key_len = passwd_len;

		// Lock/unlock as requested
		if (mode < 2)
		{
			ret = ioctl(fd, IOC_OPAL_LOCK_UNLOCK, &lk_unlk);
			if (ret != 0)
			{
				snprintf(buf, sizeof(buf), "Failed to ioctl(%s, IOC_OPAL_LOCK_UNLOCK, ...)", dev);
				if (errno == 0)
					errno = EINVAL;
				perror(buf);
				goto cleanup;
			}
		}
		// Save password for S3 when requested
		else if (mode == 2)
		{
			ret = ioctl(fd, IOC_OPAL_SAVE, &lk_unlk);
			if (ret != 0)
			{
				snprintf(buf, sizeof(buf), "Failed to ioctl(%s, IOC_OPAL_SAVE, ...)", dev);
				perror(buf);
				goto cleanup;
			}
		}
	}
	else if (mode == 3)
	{
		memset(&mbr_data, 0, sizeof(struct opal_mbr_data));

		// Set MBRDone = Y
		// NOTE: due to kernel API, this also sets MBREnabled = Y... but this should not hurt,
		// cause MBRunshadow is expected to be called only when MBREnabled = Y already.
		mbr_data.enable_disable = 1;
		// 0 locking range (global range)
		mbr_data.key.lr = 0;
		// Copy key
		memcpy(mbr_data.key.key, passwd, passwd_len);
		// Set key size
		mbr_data.key.key_len = passwd_len;

		ret = ioctl(fd, IOC_OPAL_ENABLE_DISABLE_MBR, &mbr_data);
		if (ret != 0)
		{
			snprintf(buf, sizeof(buf), "Failed to ioctl(%s, IOC_OPAL_ENABLE_DISABLE_MBR, ...)", dev);
			if (errno == 0)
				errno = EINVAL;
			perror(buf);
			goto cleanup;
		}
	}

cleanup:
	close(fd);
exit:
	mem_zeroize(&mbr_data, sizeof(mbr_data));
	mem_zeroize(&lk_unlk, sizeof(lk_unlk));
	mem_zeroize(passwd, sizeof(passwd));
	mem_zeroize(buf, sizeof(buf));
	return !!ret;
}
