#ifndef SWADPW_CONFIG_H
#define SWADPW_CONFIG_H

typedef enum ConfigMode
{
    CM_EDIT,
    CM_APPEND,
    CM_DELETE
} ConfigMode;

typedef enum ConfigPwMethod
{
    CPM_TERM,
    CPM_STDIN
} ConfigPwMethod;

typedef enum ConfigHashType
{
    CHT_DEFAULT,
    CHT_OPENBSD,
    CHT_APACHE
} ConfigHashType;

int Config_init(int argc, char **argv);
ConfigMode Config_mode(void);
ConfigPwMethod Config_method(void);
ConfigHashType Config_type(void);
int Config_cost(void);
const char *Config_path(void);
const char *Config_user(void);
const char *Config_name(void);

#endif
