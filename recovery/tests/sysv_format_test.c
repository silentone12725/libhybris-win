/* Unit test for hybris/common/sysv_format.h: compares sh_vformat against the
 * host libc's snprintf.  Native Linux build:
 *   gcc -O2 -Wall -I../../hybris/common sysv_format_test.c -o sysv_format_test && ./sysv_format_test
 */
#include "sysv_format.h"
#include <stdlib.h>

static int g_fail, g_n;

static int ours(char *b, size_t n, const char *fmt, ...)
{
    sh_va ap;
    __builtin_sysv_va_start(ap, fmt);
    int r = sh_vformat(b, n, fmt, ap);
    __builtin_sysv_va_end(ap);
    return r;
}

#define CHECK(fmt, ...) do { \
    char a[256], b[256]; memset(a, 'X', sizeof a); memset(b, 'X', sizeof b); \
    int ra = snprintf(a, sizeof a, fmt, __VA_ARGS__); \
    int rb = ours(b, sizeof b, fmt, __VA_ARGS__); \
    g_n++; \
    if (ra != rb || strcmp(a, b)) { g_fail++; printf("FAIL %-22s glibc=[%s](%d) ours=[%s](%d)\n", fmt, a, ra, b, rb); } \
} while (0)

int main(void)
{
    int x = 7;
    CHECK("%d", 42);               CHECK("%i", -42);            CHECK("%u", 4000000000u);
    CHECK("%5d|", 42);             CHECK("%-5d|", 42);          CHECK("%05d", 42);
    CHECK("%+d", 42);              CHECK("% d", 42);            CHECK("%.5d", 42);
    CHECK("%8.5d|", 42);           CHECK("%x", 255);            CHECK("%#x", 255);
    CHECK("%X", 48879);            CHECK("%#X", 48879);         CHECK("%o", 8);
    CHECK("%#o", 8);               CHECK("%ld", 123456789012L); CHECK("%lld", -123456789012LL);
    CHECK("%lu", 18446744073709551615UL); CHECK("%llx", 0xdeadbeefcafeULL);
    CHECK("%zu", (size_t)99);      CHECK("%zd", (ssize_t)-99);  CHECK("%jd", (intmax_t)5);
    CHECK("%td", (ptrdiff_t)-5);   CHECK("%hhd", 300);          CHECK("%hd", 70000);
    CHECK("%hhu", 300);            CHECK("%hu", 70000);         CHECK("%c", 'a');
    CHECK("%5c|", 'a');            CHECK("%-5c|", 'a');         CHECK("%s", "hello");
    CHECK("%10s|", "hello");       CHECK("%-10s|", "hello");    CHECK("%.3s", "hello");
    CHECK("%10.3s|", "hello");     CHECK("%-10.3s|", "hello");  CHECK("%s", (char *)NULL);
    CHECK("%.0s|", "hello");       CHECK("%*d", 6, 42);         CHECK("%-*d|", 6, 42);
    CHECK("%*d", -6, 42);          CHECK("%.*s", 2, "hello");   CHECK("%*.*s|", 8, 3, "hello");
    CHECK("%.*s", -1, "hello");    CHECK("%f", 3.14159);        CHECK("%.2f", 3.14159);
    CHECK("%10.2f|", 3.14159);     CHECK("%-10.2f|", 3.14159);  CHECK("%e", 12345.678);
    CHECK("%E", 12345.678);        CHECK("%g", 0.0001234);      CHECK("%G", 1e20);
    CHECK("%+.3f", 2.5);           CHECK("%08.3f", -2.5);       CHECK("%.0f", 2.5);
    CHECK("%Lf", (long double)1.5L); CHECK("%.1Lf", (long double)2.25L);
    CHECK("%%", 0);                CHECK("100%% of %d", 5);     CHECK("%p", (void *)&x);
    CHECK("a%db%sc%fd", 1, "two", 3.0);
    CHECK("%d %d %d %d %d %d %d %d", 1, 2, 3, 4, 5, 6, 7, 8);
    CHECK("%s %s %s %s %s %s %s", "a", "b", "c", "d", "e", "f", "g");
    CHECK("%d %f %d %f %s %lld %f", 1, 1.5, 2, 2.5, "s", 3LL, 3.5);
    CHECK("%.10d|%-12ld|%+5hd", 5, 6L, (short)7);
    CHECK("no conversions", 0);

    /* truncation: return value is the untruncated length; buffer NUL-terminated */
    { char a[8], b[8]; int ra = snprintf(a, sizeof a, "%s", "0123456789"); int rb = ours(b, sizeof b, "%s", "0123456789");
      g_n++; if (ra != rb || strcmp(a, b)) { g_fail++; printf("FAIL truncate glibc=[%s](%d) ours=[%s](%d)\n", a, ra, b, rb); } }
    { char a[1] = {'Q'}, b[1] = {'Q'}; int ra = snprintf(a, 1, "%d", 12345); int rb = ours(b, 1, "%d", 12345);
      g_n++; if (ra != rb || a[0] != b[0]) { g_fail++; printf("FAIL cap1 glibc=%d ours=%d\n", ra, rb); } }
    { char b[4] = {'Q','Q','Q','Q'}; int rb = ours(b, 0, "%d", 12345);
      g_n++; if (rb != 5 || b[0] != 'Q') { g_fail++; printf("FAIL cap0 rb=%d b0=%c\n", rb, b[0]); } }
    /* unbounded (sprintf) */
    { char a[64], b[64]; int ra = sprintf(a, "%s-%d-%.2f", "x", 9, 1.234); int rb = ours(b, (size_t)-1, "%s-%d-%.2f", "x", 9, 1.234);
      g_n++; if (ra != rb || strcmp(a, b)) { g_fail++; printf("FAIL unbounded glibc=[%s] ours=[%s]\n", a, b); } }

    printf("%d checks, %d failures\n", g_n, g_fail);
    return g_fail ? 1 : 0;
}
