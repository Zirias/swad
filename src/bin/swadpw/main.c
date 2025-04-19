#include "config.h"
#include "password.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    int rc = Config_init(argc, argv);
    if (rc > 0) return EXIT_SUCCESS;
    if (rc < 0) return EXIT_FAILURE;

    Password *pw = Password_read(Config_user(), Config_method() == CPM_STDIN);
    Password_destroy(pw);

    return EXIT_SUCCESS;
}
