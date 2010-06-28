#ifndef UTIL_H
#define UTIL_H
/*
 * Wrappers around strtoull/strtoll that are safer and easier to
 * use.  For tests and assumptions, see internal_tests.c.
 *
 * str   a NULL-terminated base decimal 10 unsigned integer
 * out   out parameter, if conversion succeeded
 *
 * returns true if conversion succeeded.
 */

#ifndef PUBLIC

#if defined (__SUNPRO_C) && (__SUNPRO_C >= 0x550)
#define PUBLIC __global
#elif defined __GNUC__
#define PUBLIC __attribute__ ((visibility("default")))
#else
#define PUBLIC
#endif

#endif

#ifdef __cplusplus
extern "C" {
#endif

PUBLIC bool safe_strtoull(const char *str, uint64_t *out);
PUBLIC bool safe_strtoll(const char *str, int64_t *out);
PUBLIC bool safe_strtoul(const char *str, uint32_t *out);
PUBLIC bool safe_strtol(const char *str, int32_t *out);
PUBLIC bool safe_strtof(const char *str, float *out);

#ifndef HAVE_HTONLL
PUBLIC extern uint64_t htonll(uint64_t);
PUBLIC extern uint64_t ntohll(uint64_t);
#endif

#ifdef __GCC
# define __gcc_attribute__ __attribute__
#else
# define __gcc_attribute__(x)
#endif

/**
 * Vararg variant of perror that makes for more useful error messages
 * when reporting with parameters.
 *
 * @param fmt a printf format
 */
PUBLIC void vperror(const char *fmt, ...)
    __gcc_attribute__ ((format (printf, 1, 2)));

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif
