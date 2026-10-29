/* Windows stress test for the pthread mutex / cond / semaphore hooks in windows_hook_table.c.
 * Loads libhybris-core.dll and calls the hooks through the System V ABI, from real Windows threads.
 *   gcc -O1 -o sync_smoke.exe sync_smoke.c && ./sync_smoke.exe
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#define SYSV __attribute__((sysv_abi))
#undef ETIMEDOUT
#define ETIMEDOUT 110   /* the guest (bionic) value */
typedef void *(*resolver_t)(const char *, const char *);
static resolver_t resolve;
static int g_fail, g_n;
#define CHECK(cond, what) do { g_n++; if (!(cond)) { g_fail++; printf("FAIL  %s\n", what); } } while (0)

static int (SYSV *mlock_)(void *), (SYSV *munlock_)(void *), (SYSV *mtry)(void *), (SYSV *mtimed)(void *, const struct timespec *);
static int (SYSV *minit)(void *, const void *);
static int (SYSV *cinit)(void *, const void *), (SYSV *cdestroy)(void *), (SYSV *csig)(void *), (SYSV *cbc)(void *);
static int (SYSV *cwait)(void *, void *), (SYSV *ctwait)(void *, void *, const struct timespec *);
static int (SYSV *sinit)(void *, int, unsigned), (SYSV *spost)(void *), (SYSV *swait)(void *), (SYSV *stwait)(void *, const struct timespec *), (SYSV *sdestroy)(void *);

static void *R(const char *n) { void *f = resolve(n, "sync"); if (!f) { g_n++; g_fail++; printf("FAIL  %s not hooked\n", n); } return f; }
static void rt_after(struct timespec *ts, long ms) { clock_gettime(CLOCK_REALTIME, ts); ts->tv_sec += ms / 1000; ts->tv_nsec += (ms % 1000) * 1000000L; if (ts->tv_nsec >= 1000000000L) { ts->tv_sec++; ts->tv_nsec -= 1000000000L; } }

/* 1. contention */
static char g_mtx[40]; static volatile long g_count;
static DWORD WINAPI inc_thread(LPVOID p) { (void)p; for (int i = 0; i < 20000; i++) { mlock_(g_mtx); long v = g_count; if (i % 997 == 0) Sleep(0); g_count = v + 1; munlock_(g_mtx); } return 0; }

/* 2. producer / consumer ping-pong */
static char pc_m[40], pc_c[48]; static volatile int pc_turn, pc_done;
static DWORD WINAPI pong_thread(LPVOID p) { (void)p; for (int i = 0; i < 5000; i++) { mlock_(pc_m); while (pc_turn != 1) cwait(pc_c, pc_m); pc_turn = 0; csig(pc_c); munlock_(pc_m); } pc_done = 1; return 0; }

/* 3. holder for timedlock */
static char h_m[40]; static HANDLE h_go, h_release;
static DWORD WINAPI hold_thread(LPVOID p) { (void)p; mlock_(h_m); SetEvent(h_go); WaitForSingleObject(h_release, 5000); munlock_(h_m); return 0; }

/* 4. cond signalled after a delay while waiting on a fut-future deadline */
static char f_m[40], f_c[48]; static volatile int f_flag;
static DWORD WINAPI signal_later(LPVOID p) { (void)p; Sleep(60); mlock_(f_m); f_flag = 1; cbc(f_c); munlock_(f_m); return 0; }

/* 5. sem */
static char s_s[32];
static DWORD WINAPI post_later(LPVOID p) { (void)p; Sleep(60); spost(s_s); return 0; }

/* 6. waiters vs destroy */
static char d_m[40], d_c[48]; static volatile int d_go, d_woke;
static DWORD WINAPI d_waiter(LPVOID p) { (void)p; mlock_(d_m); while (!d_go) cwait(d_c, d_m); munlock_(d_m); InterlockedIncrement((volatile LONG *)&d_woke); return 0; }

int main(void)
{
    HMODULE m = LoadLibraryA("libhybris-core.dll");
    if (!m) { printf("cannot load libhybris-core.dll (%lu)\n", GetLastError()); return 2; }
    resolve = (resolver_t)GetProcAddress(m, "hybris_get_hooked_symbol");
    if (!resolve) return 2;
    mlock_ = R("pthread_mutex_lock"); munlock_ = R("pthread_mutex_unlock"); mtry = R("pthread_mutex_trylock");
    mtimed = R("pthread_mutex_timedlock"); minit = R("pthread_mutex_init");
    cinit = R("pthread_cond_init"); cdestroy = R("pthread_cond_destroy"); csig = R("pthread_cond_signal"); cbc = R("pthread_cond_broadcast");
    cwait = R("pthread_cond_wait"); ctwait = R("pthread_cond_timedwait");
    sinit = R("sem_init"); spost = R("sem_post"); swait = R("sem_wait"); stwait = R("sem_timedwait"); sdestroy = R("sem_destroy");
    if (g_fail) return 1;

    /* contention */
    HANDLE th[8];
    for (int i = 0; i < 8; i++) th[i] = CreateThread(NULL, 0, inc_thread, NULL, 0, NULL);
    CHECK(WaitForMultipleObjects(8, th, TRUE, 60000) == WAIT_OBJECT_0, "8 contending threads finish");
    CHECK(g_count == 8 * 20000, "mutex gives mutual exclusion");
    for (int i = 0; i < 8; i++) CloseHandle(th[i]);

    /* recursion, trylock, unlock errors */
    char r[40] = {0};
    CHECK(mlock_(r) == 0 && mlock_(r) == 0, "recursive lock");
    CHECK(munlock_(r) == 0 && munlock_(r) == 0, "recursive unlock");
    CHECK(munlock_(r) == EPERM, "unlock of an unlocked mutex -> EPERM");
    CHECK(mtry(r) == 0 && mtry(r) == 0 && munlock_(r) == 0 && munlock_(r) == 0, "trylock recursion");

    /* timedlock */
    h_go = CreateEventA(NULL, FALSE, FALSE, NULL); h_release = CreateEventA(NULL, FALSE, FALSE, NULL);
    HANDLE ht = CreateThread(NULL, 0, hold_thread, NULL, 0, NULL);
    WaitForSingleObject(h_go, 5000);
    struct timespec ts; rt_after(&ts, 80); DWORD t0 = GetTickCount();
    int rc = mtimed(h_m, &ts); DWORD dt = GetTickCount() - t0;
    CHECK(rc == ETIMEDOUT && dt >= 70 && dt < 1000, "timedlock honours its timeout");
    CHECK(mtry(h_m) == EBUSY, "trylock on a held mutex -> EBUSY");
    SetEvent(h_release); WaitForSingleObject(ht, 5000); CloseHandle(ht);
    rt_after(&ts, 500); CHECK(mtimed(h_m, &ts) == 0 && munlock_(h_m) == 0, "timedlock succeeds on a free mutex");

    /* ping-pong */
    HANDLE pt = CreateThread(NULL, 0, pong_thread, NULL, 0, NULL);
    for (int i = 0; i < 5000; i++) { mlock_(pc_m); pc_turn = 1; csig(pc_c); while (pc_turn != 0) cwait(pc_c, pc_m); munlock_(pc_m); }
    CHECK(WaitForSingleObject(pt, 20000) == WAIT_OBJECT_0 && pc_done, "5000 cond ping-pongs, no lost wakeup");
    CloseHandle(pt);

    /* fut-future absolute deadline must wait, not time out at once */
    HANDLE st = CreateThread(NULL, 0, signal_later, NULL, 0, NULL);
    struct timespec fut; clock_gettime(CLOCK_REALTIME, &fut); fut.tv_sec = INT64_MAX / 4;
    mlock_(f_m); t0 = GetTickCount(); rc = 0;
    while (!f_flag && rc == 0) rc = ctwait(f_c, f_m, &fut);
    dt = GetTickCount() - t0; munlock_(f_m);
    CHECK(rc == 0 && f_flag && dt >= 40 && dt < 2000, "fut-future deadline waits for the signal");
    WaitForSingleObject(st, 5000); CloseHandle(st);

    /* short timeout expires */
    rt_after(&ts, 80); mlock_(f_m); t0 = GetTickCount(); rc = ctwait(f_c, f_m, &ts); dt = GetTickCount() - t0; munlock_(f_m);
    CHECK(rc == ETIMEDOUT && dt >= 70 && dt < 1000, "timedwait times out");
    /* past deadline */
    rt_after(&ts, -5); ts.tv_sec -= 1; mlock_(f_m); rc = ctwait(f_c, f_m, &ts); munlock_(f_m);
    CHECK(rc == ETIMEDOUT, "past deadline -> ETIMEDOUT");

    /* semaphores */
    CHECK(sinit(s_s, 0, 0) == 0, "sem_init");
    HANDLE pl = CreateThread(NULL, 0, post_later, NULL, 0, NULL);
    t0 = GetTickCount(); CHECK(swait(s_s) == 0 && GetTickCount() - t0 >= 40, "sem_wait blocks until post");
    WaitForSingleObject(pl, 5000); CloseHandle(pl);
    rt_after(&ts, 60); errno = 0; CHECK(stwait(s_s, &ts) == -1 && errno == ETIMEDOUT, "sem_timedwait times out");
    spost(s_s); spost(s_s); CHECK(swait(s_s) == 0 && swait(s_s) == 0, "sem counts");
    CHECK(sdestroy(s_s) == 0, "sem_destroy");

    /* destroy right after a broadcast, with sleepers */
    for (int round = 0; round < 200; round++) {
        memset(d_m, 0, sizeof d_m); memset(d_c, 0, sizeof d_c); d_go = 0; d_woke = 0;
        HANDLE w[4]; for (int i = 0; i < 4; i++) w[i] = CreateThread(NULL, 0, d_waiter, NULL, 0, NULL);
        Sleep(round % 3);
        mlock_(d_m); d_go = 1; cbc(d_c); munlock_(d_m);
        cdestroy(d_c);
        WaitForMultipleObjects(4, w, TRUE, 5000); for (int i = 0; i < 4; i++) CloseHandle(w[i]);
        if (d_woke != 4) { CHECK(0, "all waiters woke before destroy completed"); break; }
    }
    CHECK(1, "cond_destroy after broadcast survived 200 rounds");

    printf("%d checks, %d failures\n", g_n, g_fail);
    return g_fail ? 1 : 0;
}
