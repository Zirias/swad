#undef DEF_WEAK
#define DEF_WEAK(x) struct dummy_ ## x
#undef WRAP
#define WRAP(x) x
#define u_int32_t uint32_t
#define u_int16_t uint16_t
#define u_int8_t uint8_t
