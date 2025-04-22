#include "config.h"
#include "password.h"
#include "pwfile.h"

#include <swadbcrypt.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    int rc = Config_init(argc, argv);
    if (rc > 0) return EXIT_SUCCESS;
    if (rc < 0) return EXIT_FAILURE;

    rc = EXIT_FAILURE;
    Password *pw = 0;
    PwFile *pwf = PwFile_create(Config_path(), Config_mode() == CM_APPEND);
    if (!pwf) goto done;

    if (Config_mode() == CM_DELETE)
    {
	if (PwFile_deleteEntry(pwf, Config_user()) == 0
		&& PwFile_write(pwf) == 0)
	{
	    fprintf(stderr, "Deleted user %s from %s.\n",
		    Config_user(), Config_path());
	    rc = EXIT_SUCCESS;
	}
	goto done;
    }

    PwEntry *entry = 0;
    if (Config_mode() == CM_APPEND)
    {
	entry = PwFile_addEntry(pwf, Config_user());
    }
    else if (Config_mode() == CM_EDIT)
    {
	entry = PwFile_entry(pwf, Config_user(), 0);
    }
    if (!entry) goto done;

    pw = Password_read(Config_user(), Config_method() == CPM_STDIN);
    if (!pw) goto done;
    char *hash = PwEntry_hash(entry);
    if (swad_bcrypt_hash(hash, BCRYPT_HASHSZ, Config_cost(),
		Password_str(pw)) < 0)
    {
	fputs("Error hashing password. This is most likely a bug!\n", stderr);
	goto done;
    }
    if (Config_type() == CHT_APACHE ||
	    (Config_type() == CHT_DEFAULT &&
	     PwEntry_hashType(entry) == HT_BCRYPT_APACHE))
    {
	hash[2] = 'y';
    }

    if (Config_name()) PwEntry_setName(entry, Config_name());
    if (PwFile_write(pwf) < 0) goto done;

    if (Config_mode() == CM_APPEND)
    {
	fprintf(stderr, "Added user %s to %s.\n",
		Config_user(), Config_path());
    }
    else
    {
	fprintf(stderr, "Changed password for %s in %s.\n",
		Config_user(), Config_path());
    }
    rc = EXIT_SUCCESS;

done:
    Password_destroy(pw);
    PwFile_destroy(pwf);
    return rc;
}

