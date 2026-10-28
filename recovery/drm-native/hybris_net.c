/*
 * hybris_net.c — Winsock shim for the Android (bionic) networking symbols that
 * libcurl / libssl / libstoreservicescore import (socket, connect, send, recv,
 * getaddrinfo, poll, …).  On Linux these were raw Linux syscalls that worked
 * natively; on Windows there is no such syscall layer, so route them to Winsock
 * and translate the bionic<->Windows differences:
 *   - socket fd space (Winsock SOCKET handle vs bionic int fd)
 *   - AF_INET6 value (bionic 10 vs Windows 23) and sockaddr_in6 family field
 *   - struct addrinfo layout (ai_addr/ai_canonname are swapped; ai_addrlen size)
 *   - setsockopt/getsockopt level and option-name constants
 *   - poll()/ioctl()/fcntl() flag constants
 *   - errno values (guest code compares against bionic errno numbers)
 *
 * Every hook entry point is sysv_abi: the guest calls them with the SysV AMD64
 * ABI.  Built as a NATIVE source (no windows_core_compat.h force-include), so
 * winsock2.h can be included cleanly before windows.h.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>

#define SV __attribute__((sysv_abi))

/* ── bionic errno values (the guest compares against these) ───────────────── */
#define B_EINTR 4
#define B_EBADF 9
#define B_EAGAIN 11
#define B_EACCES 13
#define B_EFAULT 14
#define B_EINVAL 22
#define B_EPIPE 32
#define B_EADDRINUSE 98
#define B_EADDRNOTAVAIL 99
#define B_ENETUNREACH 101
#define B_ECONNRESET 104
#define B_EISCONN 106
#define B_ENOTCONN 107
#define B_ETIMEDOUT 110
#define B_ECONNREFUSED 111
#define B_EHOSTUNREACH 113
#define B_EALREADY 114
#define B_EINPROGRESS 115
#define B_ENOTSOCK 88
#define B_EMSGSIZE 90
#define B_ENOSYS 38

static int wsa2errno(int w) {
  switch (w) {
    case WSAEINTR: return B_EINTR;
    case WSAEBADF: return B_EBADF;
    case WSAEWOULDBLOCK: return B_EAGAIN;
    case WSAEINPROGRESS: return B_EINPROGRESS;
    case WSAEALREADY: return B_EALREADY;
    case WSAENOTSOCK: return B_ENOTSOCK;
    case WSAEFAULT: return B_EFAULT;
    case WSAEMSGSIZE: return B_EMSGSIZE;
    case WSAEACCES: return B_EACCES;
    case WSAEADDRINUSE: return B_EADDRINUSE;
    case WSAEADDRNOTAVAIL: return B_EADDRNOTAVAIL;
    case WSAENETUNREACH: return B_ENETUNREACH;
    case WSAECONNRESET: return B_ECONNRESET;
    case WSAEISCONN: return B_EISCONN;
    case WSAENOTCONN: return B_ENOTCONN;
    case WSAETIMEDOUT: return B_ETIMEDOUT;
    case WSAECONNREFUSED: return B_ECONNREFUSED;
    case WSAEHOSTUNREACH: return B_EHOSTUNREACH;
    case WSAEINVAL: return B_EINVAL;
    default: return B_EINVAL;
  }
}
static void set_wsa_errno(void) { errno = wsa2errno(WSAGetLastError()); }

/* ── socket fd table: map a synthetic int fd to a Winsock SOCKET ──────────── */
#define NETFD_BASE 256
#define NETFD_MAX  2048
static struct { SOCKET s; int used; int nonblock; } g_sox[NETFD_MAX];
static CRITICAL_SECTION g_sox_cs;
static volatile LONG g_sox_init = 0;

static void net_ready(void) {
  if (g_sox_init == 2) return;
  LONG prev = InterlockedCompareExchange(&g_sox_init, 1, 0);
  if (prev == 0) {
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);
    InitializeCriticalSection(&g_sox_cs);
    g_sox_init = 2;
  } else {
    while (g_sox_init != 2) SwitchToThread();
  }
}
static int sox_alloc(SOCKET s) {
  EnterCriticalSection(&g_sox_cs);
  for (int i = 0; i < NETFD_MAX; i++) {
    if (!g_sox[i].used) {
      g_sox[i].used = 1; g_sox[i].s = s; g_sox[i].nonblock = 0;
      LeaveCriticalSection(&g_sox_cs);
      return NETFD_BASE + i;
    }
  }
  LeaveCriticalSection(&g_sox_cs);
  return -1;
}
static SOCKET sox_get(int fd) {
  if (fd < NETFD_BASE || fd >= NETFD_BASE + NETFD_MAX) return INVALID_SOCKET;
  int i = fd - NETFD_BASE;
  return g_sox[i].used ? g_sox[i].s : INVALID_SOCKET;
}

#define AUXFD_BASE 0x50000000
#define AUXFD_MAX  128
#define AUXEP_MAX  256
#define AUX_EPOLL  1
#define AUX_EVENTFD 2
#define AUX_TIMERFD 3
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3
#define EPOLLIN 0x001
#define EPOLLOUT 0x004
#define EPOLLERR 0x008
#define EPOLLHUP 0x010
#define EPOLLRDHUP 0x2000
#define EFD_NONBLOCK 0x800
#define TFD_NONBLOCK 0x800
#define TFD_TIMER_ABSTIME 1
struct b_epoll_event { uint32_t events; uint32_t pad; uint64_t data; };
struct b_timespec { int64_t tv_sec; int64_t tv_nsec; };
struct b_itimerspec { struct b_timespec it_interval; struct b_timespec it_value; };
struct aux_item { int used; int fd; uint32_t events; uint64_t data; };
struct aux_fd { int used; int kind; uint64_t counter; uint64_t due_ms; uint64_t interval_ms; struct aux_item items[AUXEP_MAX]; };
static struct aux_fd g_aux[AUXFD_MAX];
static uint64_t now_ms(void) { return (uint64_t)GetTickCount64(); }
static int aux_index(int fd) { return fd >= AUXFD_BASE && fd < AUXFD_BASE + AUXFD_MAX ? fd - AUXFD_BASE : -1; }
static struct aux_fd *aux_get(int fd) { int i=aux_index(fd); return i>=0 && g_aux[i].used ? &g_aux[i] : NULL; }
static uint64_t now_ms(void);
int SV _net_eventfd_write(int fd, uint64_t value);
/* Auxiliary descriptors are declared below; forward-declare the lookup for fd routing. */
struct aux_fd;
static struct aux_fd *aux_get(int fd);
/* Called from windows_hook_table.c's close/read/write/fcntl to route socket fds. */
int SV _net_is_fd(int fd) {
  return (fd >= NETFD_BASE && fd < NETFD_BASE + NETFD_MAX && g_sox[fd - NETFD_BASE].used) || aux_get(fd) != NULL;
}

/* ── address-family / sockaddr translation (bionic <-> Windows) ───────────── */
#define B_AF_INET6 10
#define W_AF_INET6 23
/* Copy a bionic sockaddr into a Windows one, translating the AF_INET6 value.
 * IPv4 (AF_INET=2) is identical on both; IPv6 only differs in the family int. */
static void sa_b2w(const void *src, int len, struct sockaddr_storage *dst, int *dlen) {
  if (len > (int)sizeof(*dst)) len = (int)sizeof(*dst);
  memcpy(dst, src, len);
  unsigned short fam = *(unsigned short *)dst;
  if (fam == B_AF_INET6) *(unsigned short *)dst = W_AF_INET6;
  *dlen = len;
}
static void sa_w2b(void *buf, int *len) {
  if (!buf || !len || *len < 2) return;
  unsigned short fam = *(unsigned short *)buf;
  if (fam == W_AF_INET6) *(unsigned short *)buf = B_AF_INET6;
}
static int af_b2w(int af) { return af == B_AF_INET6 ? W_AF_INET6 : af; }
static int af_w2b(int af) { return af == W_AF_INET6 ? B_AF_INET6 : af; }

/* ── core socket calls ────────────────────────────────────────────────────── */
int SV _net_socket(int domain, int type, int protocol) {
  net_ready();
  /* bionic may OR SOCK_CLOEXEC(02000000)/SOCK_NONBLOCK(04000) into type. */
  int nb = (type & 04000) ? 1 : 0;
  int wtype = type & ~(02000000 | 04000);
  SOCKET s = socket(af_b2w(domain), wtype, protocol);
  if (s == INVALID_SOCKET) { set_wsa_errno(); fprintf(stderr, "[net] socket failed errno=%d\n", errno); return -1; }
  int fd = sox_alloc(s);
  if (fd < 0) { closesocket(s); errno = B_EINVAL; return -1; }
  if (nb) { unsigned int on = 1; ioctlsocket(s, FIONBIO, &on); g_sox[fd - NETFD_BASE].nonblock = 1; }
  fprintf(stderr, "[net] socket domain=%d type=%d -> fd=%d\n", domain, type, fd);
  return fd;
}
int SV _net_connect(int fd, const void *addr, int alen) {
  fprintf(stderr, "[net] connect enter fd=%d alen=%d\n", fd, alen);
  SOCKET s = sox_get(fd);
  if (s == INVALID_SOCKET) { errno = B_EBADF; return -1; }
  struct sockaddr_storage ss; int wlen;
  sa_b2w(addr, alen, &ss, &wlen);
  if (connect(s, (struct sockaddr *)&ss, wlen) == 0) { fprintf(stderr, "[net] connect fd=%d ok\n", fd); return 0; }
  set_wsa_errno(); fprintf(stderr, "[net] connect fd=%d failed errno=%d wsa=%d\n", fd, errno, WSAGetLastError());
  return -1;
}
long SV _net_send(int fd, const void *buf, size_t n, int flags) {
  SOCKET s = sox_get(fd);
  if (s == INVALID_SOCKET) { errno = B_EBADF; return -1; }
  int r = send(s, (const char *)buf, (int)n, flags & ~0x4000 /* strip MSG_NOSIGNAL */);
  if (r == SOCKET_ERROR) { set_wsa_errno(); fprintf(stderr, "[net] send fd=%d n=%zu failed errno=%d\n", fd, n, errno); return -1; }
  fprintf(stderr, "[net] send fd=%d n=%zu -> %d\n", fd, n, r);
  return r;
}
long SV _net_recv(int fd, void *buf, size_t n, int flags) {
  SOCKET s = sox_get(fd);
  if (s == INVALID_SOCKET) { errno = B_EBADF; return -1; }
  int r = recv(s, (char *)buf, (int)n, flags);
  if (r == SOCKET_ERROR) { set_wsa_errno(); fprintf(stderr, "[net] recv fd=%d n=%zu failed errno=%d\n", fd, n, errno); return -1; }
  fprintf(stderr, "[net] recv fd=%d n=%zu -> %d\n", fd, n, r);
  return r;
}
long SV _net_sendto(int fd, const void *buf, size_t n, int flags, const void *addr, int alen) {
  fprintf(stderr, "[net] sendto enter fd=%d n=%zu alen=%d\n", fd, n, alen);
  SOCKET s = sox_get(fd);
  if (s == INVALID_SOCKET) { errno = B_EBADF; return -1; }
  int r;
  if (addr && alen) {
    struct sockaddr_storage ss; int wlen; sa_b2w(addr, alen, &ss, &wlen);
    r = sendto(s, (const char *)buf, (int)n, flags & ~0x4000, (struct sockaddr *)&ss, wlen);
  } else {
    r = send(s, (const char *)buf, (int)n, flags & ~0x4000);
  }
  if (r == SOCKET_ERROR) { set_wsa_errno(); fprintf(stderr, "[net] sendto fd=%d failed errno=%d wsa=%d\n", fd, errno, WSAGetLastError()); return -1; }
  fprintf(stderr, "[net] sendto fd=%d -> %d\n", fd, r);
  return r;
}
long SV _net_recvfrom(int fd, void *buf, size_t n, int flags, void *addr, int *alen) {
  fprintf(stderr, "[net] recvfrom enter fd=%d n=%zu\n", fd, n);
  SOCKET s = sox_get(fd);
  if (s == INVALID_SOCKET) { errno = B_EBADF; return -1; }
  int wlen = (addr && alen) ? *alen : 0;
  int r = recvfrom(s, (char *)buf, (int)n, flags, (struct sockaddr *)addr, addr ? &wlen : NULL);
  if (r == SOCKET_ERROR) { set_wsa_errno(); fprintf(stderr, "[net] recvfrom fd=%d failed errno=%d wsa=%d\n", fd, errno, WSAGetLastError()); return -1; }
  fprintf(stderr, "[net] recvfrom fd=%d -> %d\n", fd, r);
  if (addr && alen) { sa_w2b(addr, &wlen); *alen = wlen; }
  return r;
}
int SV _net_shutdown(int fd, int how) {
  SOCKET s = sox_get(fd);
  if (s == INVALID_SOCKET) { errno = B_EBADF; return -1; }
  if (shutdown(s, how) == 0) return 0;
  set_wsa_errno(); return -1;
}
int SV _net_getpeername(int fd, void *addr, int *alen) {
  SOCKET s = sox_get(fd);
  if (s == INVALID_SOCKET) { errno = B_EBADF; return -1; }
  int wlen = alen ? *alen : 0;
  if (getpeername(s, (struct sockaddr *)addr, &wlen) != 0) { set_wsa_errno(); return -1; }
  sa_w2b(addr, &wlen); if (alen) *alen = wlen; return 0;
}
int SV _net_getsockname(int fd, void *addr, int *alen) {
  SOCKET s = sox_get(fd);
  if (s == INVALID_SOCKET) { errno = B_EBADF; return -1; }
  int wlen = alen ? *alen : 0;
  if (getsockname(s, (struct sockaddr *)addr, &wlen) != 0) { set_wsa_errno(); return -1; }
  sa_w2b(addr, &wlen); if (alen) *alen = wlen; return 0;
}

/* ── setsockopt / getsockopt: translate level + option name ───────────────── */
#define B_SOL_SOCKET 1
static int opt_b2w(int level, int optname, int *wlevel, int *wopt) {
  if (level == B_SOL_SOCKET) {
    *wlevel = SOL_SOCKET;
    switch (optname) {
      case 1:  *wopt = SO_DEBUG; return 1;
      case 2:  *wopt = SO_REUSEADDR; return 1;
      case 3:  *wopt = SO_TYPE; return 1;
      case 4:  *wopt = SO_ERROR; return 1;
      case 5:  *wopt = SO_DONTROUTE; return 1;
      case 6:  *wopt = SO_BROADCAST; return 1;
      case 7:  *wopt = SO_SNDBUF; return 1;
      case 8:  *wopt = SO_RCVBUF; return 1;
      case 9:  *wopt = SO_KEEPALIVE; return 1;
      case 10: *wopt = SO_OOBINLINE; return 1;
      case 13: *wopt = SO_LINGER; return 1;
      case 20: *wopt = SO_RCVTIMEO; return 1;
      case 21: *wopt = SO_SNDTIMEO; return 1;
      default: return 0; /* unknown SOL_SOCKET option -> no-op */
    }
  }
  /* IPPROTO_TCP(6), IPPROTO_IP(0), IPPROTO_IPV6(41) have matching values and
   * the common option names (TCP_NODELAY=1, IPV6_V6ONLY=…) line up on Windows. */
  *wlevel = level; *wopt = optname; return 1;
}
int SV _net_setsockopt(int fd, int level, int optname, const void *val, int len) {
  SOCKET s = sox_get(fd);
  if (s == INVALID_SOCKET) { errno = B_EBADF; return -1; }
  int wl, wo;
  if (!opt_b2w(level, optname, &wl, &wo)) return 0; /* ignore unknown opts */
  if (setsockopt(s, wl, wo, (const char *)val, len) == 0) return 0;
  /* Non-fatal: many options curl sets are best-effort. Report success unless
   * the socket is clearly bad. */
  int w = WSAGetLastError();
  if (w == WSAENOTSOCK || w == WSAEBADF) { errno = wsa2errno(w); return -1; }
  return 0;
}
int SV _net_getsockopt(int fd, int level, int optname, void *val, int *len) {
  fprintf(stderr, "[net] getsockopt fd=%d level=%d opt=%d\n", fd, level, optname);
  SOCKET s = sox_get(fd);
  if (s == INVALID_SOCKET) { errno = B_EBADF; return -1; }
  int wl, wo;
  if (!opt_b2w(level, optname, &wl, &wo)) { if (len && *len >= 4) *(int *)val = 0; return 0; }
  int wlen = len ? *len : 0;
  if (getsockopt(s, wl, wo, (char *)val, &wlen) != 0) { set_wsa_errno(); return -1; }
  /* SO_ERROR returns a WSA error code; translate to a bionic errno value. */
  if (level == B_SOL_SOCKET && optname == 4 && val && wlen >= 4)
    *(int *)val = wsa2errno(*(int *)val);
  if (len) *len = wlen;
  return 0;
}

/* ── ioctl / fcntl (non-blocking) ─────────────────────────────────────────── */
int SV _net_ioctl(int fd, unsigned long req, void *arg) {
  fprintf(stderr, "[net] ioctl fd=%d req=%lu\n", fd, req);
  if (!_net_is_fd(fd)) return 0; /* non-socket ioctl: ignore */
  SOCKET s = sox_get(fd);
  if (s == INVALID_SOCKET) { errno = B_EBADF; return -1; }
  unsigned int v = (arg ? *(unsigned int *)arg : 0);
  if (req == 0x5421 /* bionic FIONBIO */) {
    if (ioctlsocket(s, FIONBIO, &v) != 0) { set_wsa_errno(); return -1; }
    g_sox[fd - NETFD_BASE].nonblock = v ? 1 : 0;
    return 0;
  }
  if (req == 0x541b /* bionic FIONREAD */) {
    if (ioctlsocket(s, FIONREAD, &v) != 0) { set_wsa_errno(); return -1; }
    if (arg) *(unsigned int *)arg = (unsigned int)v;
    return 0;
  }
  return 0;
}
/* F_GETFL=3, F_SETFL=4; bionic O_NONBLOCK=0x800. Returns fcntl result, or -2 if
 * the command is not one we handle (caller falls back to its default). */
int SV _net_fcntl(int fd, int cmd, int arg) {
  fprintf(stderr, "[net] fcntl fd=%d cmd=%d arg=%d\n", fd, cmd, arg);
  if (aux_get(fd)) return 0;
  if (!_net_is_fd(fd)) return -2;
  int i = fd - NETFD_BASE;
  if (cmd == 3 /* F_GETFL */) return g_sox[i].nonblock ? 0x800 : 0;
  if (cmd == 4 /* F_SETFL */) {
    unsigned int on = (arg & 0x800) ? 1 : 0;
    ioctlsocket(g_sox[i].s, FIONBIO, &on);
    g_sox[i].nonblock = on ? 1 : 0;
    return 0;
  }
  if (cmd == 2 /* F_SETFD (FD_CLOEXEC) */ || cmd == 1 /* F_GETFD */) return 0;
  return 0;
}
long SV _net_read(int fd, void *buf, size_t n) {
  struct aux_fd *a=aux_get(fd); if(a && a->kind==AUX_EVENTFD){ if(n<8){errno=B_EINVAL;return -1;} if(a->counter==0){errno=B_EAGAIN;return -1;} *(uint64_t*)buf=a->counter;a->counter=0;return 8; }
  if(a && a->kind==AUX_TIMERFD){ if(n<8){errno=B_EINVAL;return -1;} if(!a->due_ms||now_ms()<a->due_ms){errno=B_EAGAIN;return -1;} *(uint64_t*)buf=1;a->due_ms=a->interval_ms?now_ms()+a->interval_ms:0;return 8; }
  return _net_recv(fd, buf, n, 0);
}
long SV _net_write(int fd, const void *buf, size_t n) { struct aux_fd*a=aux_get(fd); if(a&&a->kind==AUX_EVENTFD){if(n<8){errno=B_EINVAL;return -1;}return _net_eventfd_write(fd,*(const uint64_t*)buf);} return _net_send(fd, buf, n, 0); }
int SV _net_close(int fd) {
  struct aux_fd *a=aux_get(fd); if(a){EnterCriticalSection(&g_sox_cs);a->used=0;LeaveCriticalSection(&g_sox_cs);return 0;}
  if (!_net_is_fd(fd)) { errno = B_EBADF; return -1; }
  int i = fd - NETFD_BASE;
  EnterCriticalSection(&g_sox_cs);
  SOCKET s = g_sox[i].s; g_sox[i].used = 0; g_sox[i].s = INVALID_SOCKET;
  LeaveCriticalSection(&g_sox_cs);
  closesocket(s);
  return 0;
}

/* ── poll -> WSAPoll (translate fd and event flags) ───────────────────────── */
struct b_pollfd { int fd; short events; short revents; };
#define B_POLLIN 0x0001
#define B_POLLPRI 0x0002
#define B_POLLOUT 0x0004
#define B_POLLERR 0x0008
#define B_POLLHUP 0x0010
#define B_POLLNVAL 0x0020
int SV _net_poll(void *fds_, unsigned long nfds, int timeout) {
  fprintf(stderr, "[net] poll nfds=%lu timeout=%d\n", nfds, timeout);
  struct b_pollfd *fds = (struct b_pollfd *)fds_;
  if (nfds == 0) { Sleep(timeout > 0 ? timeout : 0); return 0; }
  WSAPOLLFD *wf = (WSAPOLLFD *)calloc(nfds, sizeof(WSAPOLLFD));
  if (!wf) { errno = B_EINVAL; return -1; }
  for (unsigned long i = 0; i < nfds; i++) {
    wf[i].fd = sox_get(fds[i].fd);
    short ev = 0;
    if (fds[i].events & B_POLLIN)  ev |= POLLRDNORM;
    if (fds[i].events & B_POLLOUT) ev |= POLLWRNORM;
    wf[i].events = ev;
    wf[i].revents = 0;
  }
  int r = WSAPoll(wf, (ULONG)nfds, timeout);
  if (r == SOCKET_ERROR) { set_wsa_errno(); free(wf); return -1; }
  for (unsigned long i = 0; i < nfds; i++) {
    short rv = 0;
    if (wf[i].revents & (POLLRDNORM | POLLRDBAND)) rv |= B_POLLIN;
    if (wf[i].revents & POLLWRNORM)                rv |= B_POLLOUT;
    if (wf[i].revents & POLLERR)  rv |= B_POLLERR;
    if (wf[i].revents & POLLHUP)  rv |= B_POLLHUP;
    if (wf[i].revents & POLLNVAL) rv |= B_POLLNVAL;
    fds[i].revents = rv;
  }
  free(wf);
  return r;
}

/* ── getaddrinfo / freeaddrinfo (translate struct layout + AF value) ──────── */
struct b_addrinfo {
  int ai_flags;       /* 0  */
  int ai_family;      /* 4  */
  int ai_socktype;    /* 8  */
  int ai_protocol;    /* 12 */
  uint32_t ai_addrlen;/* 16 */
  /* 4 bytes pad      (20) */
  void *ai_addr;      /* 24 (struct sockaddr*) */
  char *ai_canonname; /* 32 */
  void *ai_next;      /* 40 */
};                    /* 48 */

int SV _net_getaddrinfo(const char *node, const char *service, const void *hints_, void **res) {
  net_ready();
  const struct b_addrinfo *bh = (const struct b_addrinfo *)hints_;
  struct addrinfo whints; struct addrinfo *whintsp = NULL;
  if (bh) {
    memset(&whints, 0, sizeof whints);
    whints.ai_flags = bh->ai_flags;
    whints.ai_family = af_b2w(bh->ai_family);
    whints.ai_socktype = bh->ai_socktype;
    whints.ai_protocol = bh->ai_protocol;
    whintsp = &whints;
  }
  struct addrinfo *wres = NULL;
  int rc = getaddrinfo(node, service, whintsp, &wres);
  fprintf(stderr, "[net] getaddrinfo node=%s service=%s -> %d\n", node?node:"", service?service:"", rc);
  if (rc != 0) { return rc; /* EAI_* codes are largely common */ }
  /* Translate the Windows list into a bionic-layout list. */
  struct b_addrinfo *head = NULL, *tail = NULL;
  for (struct addrinfo *w = wres; w; w = w->ai_next) {
    struct b_addrinfo *b = (struct b_addrinfo *)calloc(1, sizeof(*b));
    if (!b) break;
    b->ai_flags = w->ai_flags;
    b->ai_family = af_w2b(w->ai_family);
    b->ai_socktype = w->ai_socktype;
    b->ai_protocol = w->ai_protocol;
    b->ai_addrlen = (uint32_t)w->ai_addrlen;
    if (w->ai_addr && w->ai_addrlen) {
      b->ai_addr = malloc(w->ai_addrlen);
      if (b->ai_addr) {
        memcpy(b->ai_addr, w->ai_addr, w->ai_addrlen);
        int l = (int)w->ai_addrlen; sa_w2b(b->ai_addr, &l);
      }
    }
    if (w->ai_canonname) {
      size_t L = strlen(w->ai_canonname) + 1;
      b->ai_canonname = (char *)malloc(L);
      if (b->ai_canonname) memcpy(b->ai_canonname, w->ai_canonname, L);
    }
    if (!head) head = b; else tail->ai_next = b;
    tail = b;
  }
  freeaddrinfo(wres);
  *res = head;
  return 0;
}
void SV _net_freeaddrinfo(void *res) {
  struct b_addrinfo *b = (struct b_addrinfo *)res;
  while (b) {
    struct b_addrinfo *n = (struct b_addrinfo *)b->ai_next;
    free(b->ai_addr);
    free(b->ai_canonname);
    free(b);
    b = n;
  }
}

/* ── inet_pton / inet_ntop (translate AF) ─────────────────────────────────── */
int SV _net_inet_pton(int af, const char *src, void *dst) {
  net_ready();
  return InetPtonA(af_b2w(af), src, dst);
}
const char *SV _net_inet_ntop(int af, const void *src, char *dst, unsigned int sz) {
  net_ready();
  return InetNtopA(af_b2w(af), (void *)src, dst, sz);
}

/* ── rarely-needed by a client; provide safe behaviour ────────────────────── */
int SV _net_bind(int fd, const void *addr, int alen) {
  SOCKET s = sox_get(fd);
  if (s == INVALID_SOCKET) { errno = B_EBADF; return -1; }
  struct sockaddr_storage ss; int wlen; sa_b2w(addr, alen, &ss, &wlen);
  if (bind(s, (struct sockaddr *)&ss, wlen) == 0) return 0;
  set_wsa_errno(); return -1;
}
int SV _net_listen(int fd, int backlog) {
  SOCKET s = sox_get(fd);
  if (s == INVALID_SOCKET) { errno = B_EBADF; return -1; }
  if (listen(s, backlog) == 0) return 0;
  set_wsa_errno(); return -1;
}
int SV _net_accept(int fd, void *addr, int *alen) {
  SOCKET s = sox_get(fd);
  if (s == INVALID_SOCKET) { errno = B_EBADF; return -1; }
  int wlen = (addr && alen) ? *alen : 0;
  SOCKET a = accept(s, (struct sockaddr *)addr, addr ? &wlen : NULL);
  if (a == INVALID_SOCKET) { set_wsa_errno(); return -1; }
  if (addr && alen) { sa_w2b(addr, &wlen); *alen = wlen; }
  int nfd = sox_alloc(a);
  if (nfd < 0) { closesocket(a); errno = B_EINVAL; return -1; }
  return nfd;
}
int SV _net_socketpair(int d, int t, int p, int sv[2]) {
  (void)d; (void)t; (void)p; (void)sv;
  errno = B_ENOSYS; return -1; /* curl falls back when unavailable */
}
unsigned int SV _net_if_nametoindex(const char *name) {
  (void)name; /* iphlpapi dependency not needed by the client path */
  return 0;
}


/* select() uses a fixed 1024-bit Linux fd_set, so synthetic socket IDs must
 * remain inside that range. Translate the guest bitsets to WSAPoll. */
struct b_timeval { int64_t tv_sec; int64_t tv_usec; };
static int fdset_has(const unsigned char *set, int fd){ return set && fd>=0 && fd<1024 && (set[fd>>3] & (1u<<(fd&7))); }
static void fdset_put(unsigned char *set, int fd){ if(set&&fd>=0&&fd<1024)set[fd>>3]|=(unsigned char)(1u<<(fd&7)); }
static void fdset_zero(unsigned char *set){ if(set) memset(set,0,128); }
int SV _net_select(int nfds, void *rset_, void *wset_, void *xset_, const void *tv_){
  fprintf(stderr, "[net] select nfds=%d\n", nfds);
  unsigned char *rset=(unsigned char*)rset_, *wset=(unsigned char*)wset_, *xset=(unsigned char*)xset_;
  struct b_timeval tv; int timeout=-1;
  if(tv_){ memcpy(&tv,tv_,sizeof tv); timeout=(int)(tv.tv_sec*1000+tv.tv_usec/1000); if(timeout<0)timeout=0; }
  WSAPOLLFD wf[NETFD_MAX]; int map[NETFD_MAX], wn=0;
  unsigned char rin[128], win[128], xin[128];
  if(rset){memcpy(rin,rset,128);fdset_zero(rset);} else memset(rin,0,128);
  if(wset){memcpy(win,wset,128);fdset_zero(wset);} else memset(win,0,128);
  if(xset){memcpy(xin,xset,128);fdset_zero(xset);} else memset(xin,0,128);
  for(int fd=0;fd<nfds && fd<1024;fd++){
    if(!_net_is_fd(fd)) continue; SOCKET so=sox_get(fd); if(so==INVALID_SOCKET)continue;
    short ev=0; if(rset_ && fdset_has(rin,fd))ev|=POLLRDNORM; if(wset_ && fdset_has(win,fd))ev|=POLLWRNORM; if(xset_ && fdset_has(xin,fd))ev|=POLLERR;
    if(ev){wf[wn].fd=so;wf[wn].events=ev;wf[wn].revents=0;map[wn]=fd;wn++;}
  }
  int ready=wn?WSAPoll(wf,(ULONG)wn,timeout):(timeout>0?(Sleep((DWORD)timeout),0):0); if(ready==SOCKET_ERROR){set_wsa_errno();return -1;} int out=0;
  for(int i=0;i<wn;i++) if(wf[i].revents){int fd=map[i];if(rset_&&wf[i].revents&(POLLRDNORM|POLLERR|POLLHUP)){fdset_put((unsigned char*)rset_,fd);out++;}if(wset_&&wf[i].revents&POLLWRNORM)fdset_put((unsigned char*)wset_,fd);if(xset_&&wf[i].revents&POLLERR)fdset_put((unsigned char*)xset_,fd);}
  return out;
}

/* ── epoll/eventfd/timerfd compatibility ───────────────────────────────── */
static int aux_alloc(int kind) {
  net_ready(); EnterCriticalSection(&g_sox_cs);
  for (int i=0;i<AUXFD_MAX;i++) if (!g_aux[i].used) {
    memset(&g_aux[i],0,sizeof g_aux[i]); g_aux[i].used=1; g_aux[i].kind=kind;
    LeaveCriticalSection(&g_sox_cs); return AUXFD_BASE+i;
  }
  LeaveCriticalSection(&g_sox_cs); errno=B_EINVAL; return -1;
}
int SV _net_epoll_create(int size) { (void)size; int r=aux_alloc(AUX_EPOLL); fprintf(stderr,"[net] epoll_create -> %d\n",r); return r; }
int SV _net_epoll_create1(int flags) { (void)flags; int r=aux_alloc(AUX_EPOLL); fprintf(stderr,"[net] epoll_create1 -> %d\n",r); return r; }
int SV _net_epoll_ctl(int epfd, int op, int fd, const void *event_) {
  fprintf(stderr,"[net] epoll_ctl epfd=%d op=%d fd=%d\n",epfd,op,fd);
  struct aux_fd *a=aux_get(epfd); if(!a || a->kind!=AUX_EPOLL){errno=B_EBADF;return -1;}
  const struct b_epoll_event *ev=(const struct b_epoll_event *)event_;
  EnterCriticalSection(&g_sox_cs);
  int found=-1, freei=-1;
  for(int i=0;i<AUXEP_MAX;i++){ if(a->items[i].used && a->items[i].fd==fd) found=i; if(!a->items[i].used && freei<0) freei=i; }
  if(op==EPOLL_CTL_DEL){ if(found<0){LeaveCriticalSection(&g_sox_cs);errno=B_EBADF;return -1;} a->items[found].used=0; }
  else if(op==EPOLL_CTL_ADD){ if(found>=0||freei<0){LeaveCriticalSection(&g_sox_cs);errno=B_EINVAL;return -1;} a->items[freei].used=1;a->items[freei].fd=fd;a->items[freei].events=ev?ev->events:0;a->items[freei].data=ev?ev->data:0; }
  else if(op==EPOLL_CTL_MOD){ if(found<0){LeaveCriticalSection(&g_sox_cs);errno=B_EBADF;return -1;} a->items[found].events=ev?ev->events:0;a->items[found].data=ev?ev->data:0; }
  else { LeaveCriticalSection(&g_sox_cs); errno=B_EINVAL; return -1; }
  LeaveCriticalSection(&g_sox_cs); return 0;
}
static short ep_events_to_poll(uint32_t e){ short p=0; if(e&EPOLLIN)p|=POLLRDNORM; if(e&EPOLLOUT)p|=POLLWRNORM; return p; }
static uint32_t poll_to_ep_events(short e){ uint32_t r=0; if(e&(POLLRDNORM|POLLRDBAND))r|=EPOLLIN; if(e&POLLWRNORM)r|=EPOLLOUT; if(e&POLLERR)r|=EPOLLERR; if(e&POLLHUP)r|=EPOLLHUP; if(e&POLLNVAL)r|=EPOLLERR; return r; }
int SV _net_epoll_wait(int epfd, void *events_, int maxevents, int timeout) {
  fprintf(stderr,"[net] epoll_wait epfd=%d max=%d timeout=%d\n",epfd,maxevents,timeout);
  struct aux_fd *a=aux_get(epfd); if(!a||a->kind!=AUX_EPOLL||!events_||maxevents<=0){errno=B_EINVAL;return -1;}
  struct b_epoll_event *out=(struct b_epoll_event*)events_;
  WSAPOLLFD wf[AUXEP_MAX]; int wi[AUXEP_MAX]; int wn=0; uint64_t now=now_ms();
  EnterCriticalSection(&g_sox_cs);
  for(int i=0;i<AUXEP_MAX;i++) if(a->items[i].used){
    struct aux_fd *child=aux_get(a->items[i].fd);
    if(child && child->kind==AUX_EVENTFD && child->counter>0){ if(wn<maxevents){out[wn].events=EPOLLIN;out[wn].pad=0;out[wn].data=a->items[i].data;wn++;} continue; }
    if(child && child->kind==AUX_TIMERFD && child->due_ms && now>=child->due_ms){ if(wn<maxevents){out[wn].events=EPOLLIN;out[wn].pad=0;out[wn].data=a->items[i].data;wn++;} continue; }
    SOCKET s=sox_get(a->items[i].fd); if(s!=INVALID_SOCKET && wn<maxevents){ wf[wn].fd=s;wf[wn].events=ep_events_to_poll(a->items[i].events);wf[wn].revents=0;wi[wn]=i;wn++; }
  }
  LeaveCriticalSection(&g_sox_cs);
  int r=0;
  if(wn>0){ r=WSAPoll(wf,(ULONG)wn,timeout); if(r==SOCKET_ERROR){set_wsa_errno();return -1;} }
  else if(timeout!=0) Sleep(timeout>0?(DWORD)timeout:0);
  if(r<=0) return 0;
  int outn=0; for(int j=0;j<wn && outn<maxevents;j++) if(wf[j].revents){ int i=wi[j]; out[outn].events=poll_to_ep_events(wf[j].revents);out[outn].pad=0;out[outn].data=a->items[i].data;outn++; }
  return outn;
}
int SV _net_eventfd(unsigned int initval, int flags){ (void)flags; int fd=aux_alloc(AUX_EVENTFD); fprintf(stderr,"[net] eventfd init=%u -> %d\n",initval,fd); struct aux_fd*a=aux_get(fd); if(a)a->counter=initval; return fd; }
int SV _net_eventfd_write(int fd, uint64_t value){ struct aux_fd*a=aux_get(fd); if(!a||a->kind!=AUX_EVENTFD){errno=B_EBADF;return -1;} EnterCriticalSection(&g_sox_cs);a->counter+=value;LeaveCriticalSection(&g_sox_cs);return 0; }
int SV _net_timerfd_create(int clockid, int flags){ (void)clockid;(void)flags; int r=aux_alloc(AUX_TIMERFD); fprintf(stderr,"[net] timerfd_create -> %d\n",r); return r; }
int SV _net_timerfd_settime(int fd, int flags, const void *newv, void *oldv){ (void)flags;(void)oldv; struct aux_fd*a=aux_get(fd); const struct b_itimerspec*t=(const struct b_itimerspec*)newv; if(!a||a->kind!=AUX_TIMERFD||!t){errno=B_EINVAL;return -1;} uint64_t d=(uint64_t)(t->it_value.tv_sec*1000 + t->it_value.tv_nsec/1000000); a->interval_ms=(uint64_t)(t->it_interval.tv_sec*1000+t->it_interval.tv_nsec/1000000); a->due_ms=d?(now_ms()+d):0; return 0; }
int SV _net_ppoll(void *fds, unsigned long nfds, const void *timeout, const void *sigmask){ (void)sigmask; int ms=-1; if(timeout){const struct b_timespec*t=(const struct b_timespec*)timeout;ms=(int)(t->tv_sec*1000+t->tv_nsec/1000000);} return _net_poll(fds,nfds,ms); }
