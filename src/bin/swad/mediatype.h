#ifndef SWAD_MEDIATYPE_H
#define SWAD_MEDIATYPE_H

#include <poser/decl.h>

typedef enum MediaCategory
{
    MC_NONE	= 0,
    MC_TEXT	= 1,
    MC_IMAGE	= 2
} MediaCategory;

typedef enum MediaType
{
    MT_NONE	= 0,
    MT_TEXT	= (MC_TEXT<<8) | 1,
    MT_HTML	= (MC_TEXT<<8) | 2,
    MT_CSS	= (MC_TEXT<<8) | 3,
    MT_PNG	= (MC_IMAGE<<8) | 1,
    MT_GIF	= (MC_IMAGE<<8) | 2
} MediaType;

#define MediaType_category(t) ((t)>>8)

const char *MediaType_str(MediaType self) ATTR_CONST;

#endif
