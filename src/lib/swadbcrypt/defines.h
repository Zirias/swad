#undef DEF_WEAK
#define DEF_WEAK(x) struct dummy_ ## x
#undef WRAP
#define WRAP(x) x
