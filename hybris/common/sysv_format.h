/*
 * sysv_format.h — printf-family formatter that consumes a System V va_list.
 *
 * Guest (Android x86-64) code passes variadic arguments and va_list objects in
 * the System V AMD64 layout.  The Windows CRT's vsnprintf expects the Microsoft
 * layout (a plain char*), so handing a SysV va_list to it reads garbage.  This
 * formatter walks the format string itself, pulls each argument out of the SysV
 * list with the compiler's own va_arg, and delegates only the per-argument
 * conversion to the host snprintf.
 *
 * Pure C: builds on Windows (MinGW) and natively on Linux, where the unit test
 * in recovery/tests/sysv_format_test.c exercises it against glibc.
 */
#ifndef HYBRIS_SYSV_FORMAT_H
#define HYBRIS_SYSV_FORMAT_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef __builtin_sysv_va_list sh_va;

typedef struct {
    char *out;
    size_t cap;   /* total buffer size including the NUL; (size_t)-1 = unbounded */
    size_t len;   /* characters that would have been written (C99 return value) */
} sh_sink;

static void sh_emit(sh_sink *s, const char *p, size_t n)
{
    if (s->cap && s->cap != (size_t)-1) {
        if (s->len < s->cap - 1) {
            size_t room = s->cap - 1 - s->len;
            memcpy(s->out + s->len, p, n < room ? n : room);
        }
    } else if (s->cap == (size_t)-1) {
        memcpy(s->out + s->len, p, n);
    }
    s->len += n;
}

static void sh_pad(sh_sink *s, char c, size_t n)
{
    char buf[64];
    memset(buf, c, sizeof buf);
    while (n) {
        size_t k = n < sizeof buf ? n : sizeof buf;
        sh_emit(s, buf, k);
        n -= k;
    }
}

/* Returns the length the full output would have (excluding the NUL). */
static int sh_vformat(char *out, size_t cap, const char *fmt, sh_va ap)
{
    sh_sink s = { out, cap, 0 };
    if (!fmt) fmt = "";

    for (const char *p = fmt; *p; ) {
        if (*p != '%') {
            const char *q = p;
            while (*q && *q != '%') q++;
            sh_emit(&s, p, (size_t)(q - p));
            p = q;
            continue;
        }
        p++;
        if (*p == '%') { sh_emit(&s, "%", 1); p++; continue; }

        char flags[8]; int nf = 0;
        for (;; p++) {
            if (*p == '-' || *p == '+' || *p == ' ' || *p == '#' || *p == '0') {
                if (nf < 7) flags[nf++] = *p;
            } else if (*p == '\'') {
                /* thousands grouping: not supported by the host CRT, ignore */
            } else break;
        }
        flags[nf] = 0;
        int left = strchr(flags, '-') != NULL;

        long width = -1;
        if (*p == '*') {
            int w = __builtin_va_arg(ap, int);
            if (w < 0) { left = 1; if (nf < 7) { flags[nf++] = '-'; flags[nf] = 0; } w = -w; }
            width = w; p++;
        } else if (*p >= '0' && *p <= '9') {
            width = 0;
            while (*p >= '0' && *p <= '9') { width = width * 10 + (*p - '0'); if (width > 1000) width = 1000; p++; }
        }

        long prec = -1;
        if (*p == '.') {
            p++; prec = 0;
            if (*p == '*') { int pr = __builtin_va_arg(ap, int); prec = pr < 0 ? -1 : pr; p++; }
            else while (*p >= '0' && *p <= '9') { prec = prec * 10 + (*p - '0'); if (prec > 1000) prec = 1000; p++; }
        }

        int lm = 0; /* 0 none, 1 hh, 2 h, 3 l, 4 ll/z/j/t (64-bit), 5 L */
        for (;; p++) {
            if (*p == 'h') lm = (lm == 2) ? 1 : 2;
            else if (*p == 'l') lm = (lm == 3) ? 4 : 3;
            else if (*p == 'z' || *p == 'j' || *p == 't') lm = 4;
            else if (*p == 'q') lm = 4;
            else if (*p == 'L') lm = 5;
            else break;
        }

        char conv = *p;
        if (!conv) break;
        p++;

        char spec[48]; char tmp[1100];
        switch (conv) {
        case 'd': case 'i': case 'u': case 'o': case 'x': case 'X': {
            int is64 = (lm == 3 || lm == 4);    /* SysV long is 64-bit */
            int64_t sv = 0; uint64_t uv = 0;
            if (conv == 'd' || conv == 'i') sv = is64 ? __builtin_va_arg(ap, int64_t) : (int64_t)__builtin_va_arg(ap, int);
            else uv = is64 ? __builtin_va_arg(ap, uint64_t) : (uint64_t)__builtin_va_arg(ap, unsigned int);
            if (lm == 1 && (conv == 'd' || conv == 'i')) sv = (signed char)sv;
            else if (lm == 2 && (conv == 'd' || conv == 'i')) sv = (short)sv;
            else if (lm == 1) uv = (unsigned char)uv;
            else if (lm == 2) uv = (unsigned short)uv;
            int n = snprintf(spec, sizeof spec, "%%%s%s%s%s", flags,
                             width >= 0 ? "*" : "", prec >= 0 ? ".*" : "", "ll");
            (void)n;
            size_t sl = strlen(spec);
            spec[sl] = conv; spec[sl + 1] = 0;
            int r;
            if (width >= 0 && prec >= 0) r = (conv == 'd' || conv == 'i') ? snprintf(tmp, sizeof tmp, spec, (int)width, (int)prec, (long long)sv) : snprintf(tmp, sizeof tmp, spec, (int)width, (int)prec, (unsigned long long)uv);
            else if (width >= 0)         r = (conv == 'd' || conv == 'i') ? snprintf(tmp, sizeof tmp, spec, (int)width, (long long)sv) : snprintf(tmp, sizeof tmp, spec, (int)width, (unsigned long long)uv);
            else if (prec >= 0)          r = (conv == 'd' || conv == 'i') ? snprintf(tmp, sizeof tmp, spec, (int)prec, (long long)sv) : snprintf(tmp, sizeof tmp, spec, (int)prec, (unsigned long long)uv);
            else                         r = (conv == 'd' || conv == 'i') ? snprintf(tmp, sizeof tmp, spec, (long long)sv) : snprintf(tmp, sizeof tmp, spec, (unsigned long long)uv);
            if (r > 0) sh_emit(&s, tmp, (size_t)(r < (int)sizeof tmp ? r : (int)sizeof tmp - 1));
            break;
        }
        case 'c': {
            int c = __builtin_va_arg(ap, int);
            char ch = (char)c;
            size_t w = width > 1 ? (size_t)width : 1;
            if (!left) sh_pad(&s, ' ', w - 1);
            sh_emit(&s, &ch, 1);
            if (left) sh_pad(&s, ' ', w - 1);
            break;
        }
        case 's': {
            const char *str = __builtin_va_arg(ap, const char *);
            if (!str) str = "(null)";
            size_t n = 0;
            if (prec >= 0) { while (n < (size_t)prec && str[n]) n++; } else n = strlen(str);
            size_t w = width > 0 ? (size_t)width : 0;
            if (!left && w > n) sh_pad(&s, ' ', w - n);
            sh_emit(&s, str, n);
            if (left && w > n) sh_pad(&s, ' ', w - n);
            break;
        }
        case 'p': {
            void *ptr = __builtin_va_arg(ap, void *);
            char hex[32];
            int r = snprintf(hex, sizeof hex, "0x%llx", (unsigned long long)(uintptr_t)ptr);
            size_t n = (size_t)r;
            size_t w = width > 0 ? (size_t)width : 0;
            if (!left && w > n) sh_pad(&s, ' ', w - n);
            sh_emit(&s, hex, n);
            if (left && w > n) sh_pad(&s, ' ', w - n);
            break;
        }
        case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A': {
            double d = (lm == 5) ? (double)__builtin_va_arg(ap, long double) : __builtin_va_arg(ap, double);
#ifdef SH_FMT_TRACE
            { static int on = -1; if (on < 0) on = getenv("ADAM_FMT_TRACE") != NULL;
              if (on) { union { double d; unsigned long long u; } cv = { d }; fprintf(stderr, "[fmt] %%%c arg=%g bits=%016llx fmt=%.60s\n", conv, d, cv.u, fmt); fflush(stderr); } }
#endif
            snprintf(spec, sizeof spec, "%%%s%s%s%c", flags, width >= 0 ? "*" : "", prec >= 0 ? ".*" : "", conv);
            int r;
            if (width >= 0 && prec >= 0) r = snprintf(tmp, sizeof tmp, spec, (int)width, (int)prec, d);
            else if (width >= 0)         r = snprintf(tmp, sizeof tmp, spec, (int)width, d);
            else if (prec >= 0)          r = snprintf(tmp, sizeof tmp, spec, (int)prec, d);
            else                         r = snprintf(tmp, sizeof tmp, spec, d);
            if (r > 0) sh_emit(&s, tmp, (size_t)(r < (int)sizeof tmp ? r : (int)sizeof tmp - 1));
            break;
        }
        case 'n': {
            (void)__builtin_va_arg(ap, void *);   /* %n is not honoured: unsafe and unused */
            break;
        }
        default: {
            /* Unknown conversion: reproduce it literally rather than lose sync. */
            char lit[2] = { '%', conv };
            sh_emit(&s, lit, 2);
            break;
        }
        }
    }

    if (s.cap == (size_t)-1) s.out[s.len] = 0;
    else if (s.cap) s.out[s.len < s.cap ? s.len : s.cap - 1] = 0;
    return (int)s.len;
}

#endif /* HYBRIS_SYSV_FORMAT_H */
