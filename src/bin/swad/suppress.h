#ifndef SWAD_SUPPRESS_H
#define SWAD_SUPPRESS_H

#if defined(__clang__)
#  define swad___compiler clang
#  define swad___unknown swad___suppress(-Wunknown-warning-option)
#elif defined(__GNUC__)
#  define swad___compiler GCC
#  define swad___unknown swad___suppress(-Wpragmas)
#endif
#ifdef swad___compiler
#  define swad___pragma(x) _Pragma(#x)
#  define swad___diagprag1(x,y) swad___pragma(x diagnostic y)
#  define swad___diagprag(x) swad___diagprag1(swad___compiler, x)
#  define swad___suppress1(x) swad___diagprag(ignored x)
#  define swad___suppress(x) swad___suppress1(#x)
#  define SUPPRESS(x) swad___diagprag(push) \
    swad___unknown swad___suppress(-W##x)
#  define ENDSUPPRESS swad___diagprag(pop)
#else
#  define SUPPRESS(x)
#  define ENDSUPPRESS
#endif

#endif
