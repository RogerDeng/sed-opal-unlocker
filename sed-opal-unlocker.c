/**
 * Micro frontend to Linux Kernel SED TCG OPAL userpace interface
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>

#include <linux/sed-opal.h>


void help(const char *banner)
{
	if (banner)
		puts(banner);
	printf("Usage:\n");
	printf("\tsed-opal-unlocker <operation> <disk_path> <password_file_path>\n");
	printf("\n");
	printf("Where:\n");
	printf("\t<operation> is one of: lock, unlock, s3save, unlock+s3save\n");
	printf("\t<disk_path> is device path, ex. /dev/sda, /dev/nvme0n1, etc.\n");
	printf("\t<password_file_path> is path to file containing the admin1 password\n");
	printf("\n");
	printf("Note: when using DTA sedutil-cli to initialize the drive, you need to use its\n");
	printf("      -n option to disable password hashing, otherwise this utility won't work.\n");
}

int main(int argc, char* argv[])
{
	int ret = 1;
	int mode = -1;
	int fd = -1;
	char buf[64];
	int passwd_len = 0;
	uint8_t passwd[OPAL_KEY_MAX];  // note: maybe not-NULL-terminated

	// Parse arguments
	if (argc < 4)
		help("Not enough arguments!");
	else if (strcmp(argv[1], "lock") == 0)
		mode = 0;
	else if (strcmp(argv[1], "unlock") == 0)
		mode = 1;
	else if (strcmp(argv[1], "s3save") == 0)
		mode = 2;
	else if (strcmp(argv[1], "unlock+s3save") == 0)
		mode = 3;
	else
		help("Invalid <operation>!");
	if (mode < 0)
		return 0;

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

	// Trim terminating newline (any flavor) when present
	if (passwd[passwd_len - 1] == '\n')
		passwd_len--;
	if (passwd[passwd_len - 1] == '\r')
		passwd_len--;

	// Open the device
	fd = open(dev, O_WRONLY);
	if (fd < 0)
	{
		snprintf(buf, sizeof(buf), "Failed to open %s", dev);
		perror(buf);
		goto exit;
	}

	// Create necessary structure and zerofill it, just in case
	struct opal_lock_unlock lk_unlk;
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
	if (mode != 2)
	{
		ret = ioctl(fd, IOC_OPAL_LOCK_UNLOCK, &lk_unlk);
		if (ret != 0)
		{
			snprintf(buf, sizeof(buf), "Failed to ioctl(%s, IOC_OPAL_LOCK_UNLOCK, ...)", dev);
			perror(buf);
			goto cleanup;
		}
	}

	// Save password for S3 when requested
	if (mode >= 2)
	{
		ret = ioctl(fd, IOC_OPAL_SAVE, &lk_unlk);
		if (ret != 0)
		{
			snprintf(buf, sizeof(buf), "Failed to ioctl(%s, IOC_OPAL_SAVE, ...)", dev);
			perror(buf);
			goto cleanup;
		}
	}

cleanup:
	close(fd);
exit:
	return !!ret;
}
