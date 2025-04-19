#include "config.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    int rc = Config_init(argc, argv);
    if (rc > 0) return EXIT_SUCCESS;
    if (rc < 0) return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
