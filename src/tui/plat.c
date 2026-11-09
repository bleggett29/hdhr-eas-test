/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * plat.c - portability layer for HDHR EAS Test (Linux/Unix and Windows). GPLv3.
 */
#include "plat.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#  include <direct.h>
#  include <io.h>
#  include <process.h>
#  include <shellapi.h>
#else
#  include <fcntl.h>
#  include <limits.h>
#  include <pwd.h>
#  include <signal.h>
#  include <sys/select.h>
#  include <sys/statvfs.h>
#  include <sys/time.h>
#  include <sys/wait.h>
#endif

/* ------------------------------------------------------------------ */
void plat_init(void) {
#ifdef _WIN32
    static bool done = false;
    if (!done) {
        WSADATA w;
        WSAStartup(MAKEWORD(2, 2), &w);
        done = true;
    }
#else
    signal(SIGPIPE, SIG_IGN);
#endif
}

/* ------------------------------------------------------------------ */
/* Paths                                                               */
/* ------------------------------------------------------------------ */
static void slashes(char *s) {
#ifdef _WIN32
    for (; *s; s++) if (*s == '\\') *s = '/';
#else
    (void)s;
#endif
}

const char *plat_home(void) {
    static char home[1024];
    if (home[0]) return home;
#ifdef _WIN32
    const char *h = getenv("USERPROFILE");
    if (!h || !*h) h = getenv("HOMEPATH");
    snprintf(home, sizeof(home), "%s", h && *h ? h : "C:/");
#else
    const char *h = getenv("HOME");
    if (!h || !*h) {
        struct passwd *pw = getpwuid(getuid());
        h = pw ? pw->pw_dir : "/tmp";
    }
    snprintf(home, sizeof(home), "%s", h);
#endif
    slashes(home);
    return home;
}

const char *plat_config_base(void) {
    static char base[1024];
    if (base[0]) return base;
#ifdef _WIN32
    const char *a = getenv("APPDATA");
    if (a && *a) snprintf(base, sizeof(base), "%s", a);
    else snprintf(base, sizeof(base), "%s/AppData/Roaming", plat_home());
#else
    const char *x = getenv("XDG_CONFIG_HOME");
    if (x && *x) snprintf(base, sizeof(base), "%s", x);
    else snprintf(base, sizeof(base), "%s/.config", plat_home());
#endif
    slashes(base);
    return base;
}

static bool is_absolute(const char *p) {
    if (p[0] == '/' || p[0] == '\\') return true;
#ifdef _WIN32
    if (isalpha((unsigned char)p[0]) && p[1] == ':') return true;
#endif
    return false;
}

/* "~/x" -> home/x. A relative path ("eas2026") is also taken as relative to
 * home, not to whatever folder the program happened to start in: background
 * processes run from the home folder (see plat_spawn), so this keeps every
 * process agreeing on where the files are. */
void plat_expand_home(const char *in, char *out, size_t n) {
    if (in[0] == '~' && (in[1] == '/' || in[1] == '\\' || in[1] == '\0'))
        snprintf(out, n, "%s%s", plat_home(), in + 1);
    else if (in[0] && !is_absolute(in))
        snprintf(out, n, "%s/%s", plat_home(), in);
    else
        snprintf(out, n, "%s", in);
    slashes(out);
}

static int mkdir1(const char *p) {
#ifdef _WIN32
    return _mkdir(p);
#else
    return mkdir(p, 0755);
#endif
}

int plat_mkdir_p(const char *path) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    slashes(tmp);
    size_t L = strlen(tmp);
    while (L > 1 && tmp[L - 1] == '/') tmp[--L] = '\0';
    char *start = tmp + 1;
#ifdef _WIN32
    if (isalpha((unsigned char)tmp[0]) && tmp[1] == ':') start = tmp + 3;   /* C:/ */
    else if (tmp[0] == '/' && tmp[1] == '/') {                              /* //server/share/ */
        char *p = strchr(tmp + 2, '/');
        p = p ? strchr(p + 1, '/') : NULL;
        start = p ? p + 1 : tmp + L;
    }
#endif
    for (char *p = start; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir1(tmp) < 0 && errno != EEXIST && !plat_is_dir(tmp)) return -1;
            *p = '/';
        }
    }
    if (mkdir1(tmp) < 0 && errno != EEXIST && !plat_is_dir(tmp)) return -1;
    return 0;
}

int plat_exe_path(char *out, size_t n) {
#ifdef _WIN32
    char buf[MAX_PATH * 2];
    DWORD L = GetModuleFileNameA(NULL, buf, sizeof(buf));
    if (L == 0 || L >= sizeof(buf)) return -1;
    snprintf(out, n, "%s", buf);
    slashes(out);
    return 0;
#else
    char buf[PATH_MAX];
    ssize_t L = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (L <= 0) return -1;
    buf[L] = '\0';
    snprintf(out, n, "%s", buf);
    return 0;
#endif
}

int plat_exe_dir(char *out, size_t n) {
    if (plat_exe_path(out, n) < 0) return -1;
    char *s = strrchr(out, '/');
    if (s) *s = '\0';
    return 0;
}

bool plat_is_file(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFREG;
}

bool plat_is_dir(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR;
}

bool plat_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

long long plat_file_size(const char *path) {
#ifdef _WIN32
    struct __stat64 st;
    if (_stat64(path, &st) != 0) return -1;
    return (long long)st.st_size;
#else
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long long)st.st_size;
#endif
}

int plat_rename_replace(const char *from, const char *to) {
#ifdef _WIN32
    return MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED) ? 0 : -1;
#else
    return rename(from, to);
#endif
}

double plat_free_bytes(const char *path) {
    char dir[1024];
    plat_expand_home(path, dir, sizeof(dir));
    for (;;) {
        if (plat_is_dir(dir)) {
#ifdef _WIN32
            ULARGE_INTEGER avail;
            if (GetDiskFreeSpaceExA(dir, &avail, NULL, NULL)) return (double)avail.QuadPart;
            return -1;
#else
            struct statvfs v;
            if (statvfs(dir, &v) == 0) return (double)v.f_bavail * (double)v.f_frsize;
            return -1;
#endif
        }
        char *s = strrchr(dir, '/');
        if (!s) return -1;
        if (s == dir) { dir[1] = '\0'; continue; }
#ifdef _WIN32
        if (s == dir + 2 && dir[1] == ':') { dir[3] = '\0'; if (!plat_is_dir(dir)) return -1; continue; }
#endif
        *s = '\0';
    }
}

/* ------------------------------------------------------------------ */
/* Time                                                                */
/* ------------------------------------------------------------------ */
void plat_sleep_ms(int ms) {
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) { /* keep sleeping unless asked to stop */ break; }
#endif
}

void plat_localtime(time_t t, struct tm *out) {
#ifdef _WIN32
    localtime_s(out, &t);
#else
    localtime_r(&t, out);
#endif
}

/* ------------------------------------------------------------------ */
/* Network                                                             */
/* ------------------------------------------------------------------ */
void plat_sock_close(plat_sock_t s) {
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

int plat_sock_set_nonblock(plat_sock_t s) {
#ifdef _WIN32
    u_long one = 1;
    return ioctlsocket(s, FIONBIO, &one) == 0 ? 0 : -1;
#else
    int fl = fcntl(s, F_GETFL, 0);
    return fcntl(s, F_SETFL, fl | O_NONBLOCK);
#endif
}

static int wait_sock(plat_sock_t s, int timeout_ms, bool write) {
    fd_set fs, es;
    FD_ZERO(&fs);
    FD_ZERO(&es);
    FD_SET(s, &fs);
    FD_SET(s, &es);
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    int r = select((int)s + 1, write ? NULL : &fs, write ? &fs : NULL, &es, timeout_ms < 0 ? NULL : &tv);
    if (r > 0 && FD_ISSET(s, &es) && !FD_ISSET(s, &fs)) return -1;
    return r;
}

int plat_wait_readable(plat_sock_t s, int timeout_ms) { return wait_sock(s, timeout_ms, false); }

bool plat_sock_would_block(void) {
#ifdef _WIN32
    int e = WSAGetLastError();
    return e == WSAEWOULDBLOCK || e == WSAEINTR;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}

const char *plat_sock_error(void) {
#ifdef _WIN32
    static char buf[64];
    snprintf(buf, sizeof(buf), "socket error %d", WSAGetLastError());
    return buf;
#else
    return strerror(errno);
#endif
}

plat_sock_t plat_tcp_connect(const char *ip, int port, int timeout_ms, char *err, size_t errlen) {
    plat_init();
    plat_sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == PLAT_BAD_SOCK) { snprintf(err, errlen, "socket(): %s", plat_sock_error()); return PLAT_BAD_SOCK; }
    int rcvbuf = 8 * 1024 * 1024;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (const char *)&rcvbuf, sizeof(rcvbuf));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        snprintf(err, errlen, "bad IP address '%s'", ip);
        plat_sock_close(s);
        return PLAT_BAD_SOCK;
    }
    plat_sock_set_nonblock(s);
    int rc = connect(s, (struct sockaddr *)&sa, sizeof(sa));
    if (rc < 0) {
#ifdef _WIN32
        bool pending = WSAGetLastError() == WSAEWOULDBLOCK;
#else
        bool pending = errno == EINPROGRESS;
#endif
        if (!pending) { snprintf(err, errlen, "connect: %s", plat_sock_error()); plat_sock_close(s); return PLAT_BAD_SOCK; }
        if (wait_sock(s, timeout_ms, true) <= 0) {
            snprintf(err, errlen, "connect: no answer from %s:%d", ip, port);
            plat_sock_close(s);
            return PLAT_BAD_SOCK;
        }
        int soerr = 0;
        socklen_t sl = sizeof(soerr);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &sl);
        if (soerr) {
            snprintf(err, errlen, "connect: %s refused (%d)", ip, soerr);
            plat_sock_close(s);
            return PLAT_BAD_SOCK;
        }
    }
    return s;
}

int plat_local_ip_towards(const char *ip, char *out, size_t n) {
    plat_init();
    plat_sock_t s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == PLAT_BAD_SOCK) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(65001);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1 || connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        plat_sock_close(s);
        return -1;
    }
    struct sockaddr_in me;
    socklen_t ml = sizeof(me);
    int r = getsockname(s, (struct sockaddr *)&me, &ml);
    plat_sock_close(s);
    if (r < 0) return -1;
    if (!inet_ntop(AF_INET, &me.sin_addr, out, (socklen_t)n)) return -1;
    return strcmp(out, "0.0.0.0") ? 0 : -1;
}

int plat_lan_ip(char *out, size_t n) {
    /* A UDP "connect" sends nothing; it just picks the interface the OS would use. */
    if (plat_local_ip_towards("192.168.1.1", out, n) == 0) return 0;
    if (plat_local_ip_towards("10.0.0.1", out, n) == 0) return 0;
    if (plat_local_ip_towards("8.8.8.8", out, n) == 0) return 0;
    snprintf(out, n, "localhost");
    return -1;
}

/* ------------------------------------------------------------------ */
/* Processes                                                           */
/* ------------------------------------------------------------------ */
plat_pid_t plat_getpid(void) {
#ifdef _WIN32
    return (plat_pid_t)GetCurrentProcessId();
#else
    return (plat_pid_t)getpid();
#endif
}

bool plat_pid_alive(plat_pid_t pid) {
    if (pid <= 0) return false;
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) return false;
    DWORD code = 0;
    BOOL ok = GetExitCodeProcess(h, &code);
    CloseHandle(h);
    return ok && code == STILL_ACTIVE;
#else
    if (kill((pid_t)pid, 0) == 0) {
        /* a zombie child of ours still "exists" - reap and report dead */
        int st;
        if (waitpid((pid_t)pid, &st, WNOHANG) == (pid_t)pid) return false;
        return true;
    }
    return errno == EPERM;
#endif
}

#ifdef _WIN32
/* Quote one argument for CreateProcess' command line. */
static void append_arg(char *cmd, size_t n, const char *a) {
    size_t L = strlen(cmd);
    if (L) { if (L + 1 < n) { cmd[L++] = ' '; cmd[L] = '\0'; } }
    bool quote = !*a || strpbrk(a, " \t\"") != NULL;
    if (!quote) { snprintf(cmd + L, n - L, "%s", a); return; }
    if (L + 1 < n) { cmd[L++] = '"'; }
    int bs = 0;
    for (const char *p = a; *p && L + 4 < n; p++) {
        if (*p == '\\') { bs++; cmd[L++] = '\\'; continue; }
        if (*p == '"') { for (int i = 0; i < bs + 1 && L + 2 < n; i++) cmd[L++] = '\\'; }
        bs = 0;
        cmd[L++] = *p;
    }
    for (int i = 0; i < bs && L + 2 < n; i++) cmd[L++] = '\\';
    if (L + 1 < n) cmd[L++] = '"';
    cmd[L] = '\0';
}
#endif

bool plat_find_program(const char *name, char *out, size_t n) {
    if (strchr(name, '/')
#ifdef _WIN32
        || strchr(name, '\\')
#endif
       ) {
        if (plat_is_file(name)) { snprintf(out, n, "%s", name); return true; }
        return false;
    }
    const char *path = getenv("PATH");
    if (!path) return false;
    char buf[8192];
    snprintf(buf, sizeof(buf), "%s", path);
#ifdef _WIN32
    const char *sep = ";";
    const char *exts[] = { "", ".exe", ".bat", ".cmd", NULL };
#else
    const char *sep = ":";
    const char *exts[] = { "", NULL };
#endif
    char *save = NULL;
    for (char *d = strtok_r(buf, sep, &save); d; d = strtok_r(NULL, sep, &save)) {
        for (int i = 0; exts[i]; i++) {
            char p[2048];
            snprintf(p, sizeof(p), "%s/%s%s", d, name, exts[i]);
#ifdef _WIN32
            if (plat_is_file(p)) { snprintf(out, n, "%s", p); return true; }
#else
            if (plat_is_file(p) && access(p, X_OK) == 0) { snprintf(out, n, "%s", p); return true; }
#endif
        }
    }
    return false;
}

plat_pid_t plat_spawn(const char *const argv[], const char *logfile, bool append, bool detached) {
    return plat_spawn_ex(argv, logfile, append, detached, false);
}

/* show = the program has its own window (ffplay); otherwise it runs hidden */
plat_pid_t plat_spawn_ex(const char *const argv[], const char *logfile, bool append, bool detached, bool show) {
#ifdef _WIN32
    char cmd[8192] = "";
    for (int i = 0; argv[i]; i++) append_arg(cmd, sizeof(cmd), argv[i]);
    char prog[2048];
    const char *app = NULL;
    if (plat_find_program(argv[0], prog, sizeof(prog))) app = prog;

    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE hout = INVALID_HANDLE_VALUE;
    if (logfile) {
        hout = CreateFileA(logfile, append ? FILE_APPEND_DATA : GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                           append ? OPEN_ALWAYS : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    } else {
        hout = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    }
    HANDLE hin = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | (show ? 0 : STARTF_USESHOWWINDOW);
    si.wShowWindow = SW_HIDE;
    si.hStdInput = hin;
    si.hStdOutput = hout;
    si.hStdError = hout;
    PROCESS_INFORMATION pi;
    DWORD flags = CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT;
    if (detached) flags |= CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB;

    /* Hand the child ONLY its stdin/stdout handles. Without this list Windows
     * passes every inheritable handle the GUI has open, and a long-lived child
     * (the web server) would keep those files - and folders - locked. */
    STARTUPINFOEXA six;
    memset(&six, 0, sizeof(six));
    six.StartupInfo = si;
    six.StartupInfo.cb = sizeof(six);
    HANDLE inherit[2];
    int ninh = 0;
    if (hin != INVALID_HANDLE_VALUE) inherit[ninh++] = hin;
    if (hout != INVALID_HANDLE_VALUE) inherit[ninh++] = hout;
    SIZE_T asz = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &asz);
    LPPROC_THREAD_ATTRIBUTE_LIST al = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, asz);
    bool have_list = al && InitializeProcThreadAttributeList(al, 1, 0, &asz) &&
                     (ninh == 0 || UpdateProcThreadAttribute(al, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                                             inherit, ninh * sizeof(HANDLE), NULL, NULL));
    if (have_list) six.lpAttributeList = al;
    else flags &= ~EXTENDED_STARTUPINFO_PRESENT;
    BOOL inh = ninh > 0;

    /* Start in the home folder, never in the program's folder: a child's
     * current directory locks that folder against deletion while it runs. */
    const char *cwd = plat_home();
    LPSTARTUPINFOA psi = have_list ? &six.StartupInfo : &si;
    BOOL ok = CreateProcessA(app, cmd, NULL, NULL, inh, flags, NULL, cwd, psi, &pi);
    if (!ok && detached) {   /* breakaway not allowed in some job objects */
        flags &= ~CREATE_BREAKAWAY_FROM_JOB;
        ok = CreateProcessA(app, cmd, NULL, NULL, inh, flags, NULL, cwd, psi, &pi);
    }
    if (have_list) DeleteProcThreadAttributeList(al);
    if (al) HeapFree(GetProcessHeap(), 0, al);
    if (hout != INVALID_HANDLE_VALUE) CloseHandle(hout);
    if (hin != INVALID_HANDLE_VALUE) CloseHandle(hin);
    if (!ok) return -1;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (plat_pid_t)pi.dwProcessId;
#else
    (void)show;
    int pfd[2] = { -1, -1 };
    if (detached && pipe(pfd) < 0) return -1;
    pid_t a = fork();
    if (a < 0) return -1;
    if (a == 0) {
        if (chdir(plat_home()) != 0) { int r = chdir("/"); (void)r; }   /* don't pin the program's folder */
        if (detached) {
            setsid();
            pid_t b = fork();
            if (b != 0) {
                if (b > 0) { int pid = (int)b; ssize_t w = write(pfd[1], &pid, sizeof(pid)); (void)w; }
                _exit(0);
            }
            close(pfd[0]);
            close(pfd[1]);
        }
        int nul = open("/dev/null", O_RDONLY);
        int fd = logfile ? open(logfile, O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC), 0644)
                         : open("/dev/null", O_WRONLY);
        if (nul >= 0) { dup2(nul, 0); close(nul); }
        if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
        for (int k = 3; k < 1024; k++) close(k);
        signal(SIGHUP, SIG_IGN);
        signal(SIGPIPE, SIG_DFL);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    if (!detached) return (plat_pid_t)a;
    close(pfd[1]);
    int gpid = -1;
    ssize_t r = read(pfd[0], &gpid, sizeof(gpid));
    close(pfd[0]);
    waitpid(a, NULL, 0);
    return r == (ssize_t)sizeof(gpid) ? (plat_pid_t)gpid : -1;
#endif
}

int plat_wait(plat_pid_t pid, int timeout_ms) {
#ifdef _WIN32
    HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) return -1;
    DWORD w = WaitForSingleObject(h, timeout_ms < 0 ? INFINITE : (DWORD)timeout_ms);
    if (w == WAIT_TIMEOUT) { CloseHandle(h); return -2; }
    DWORD code = 0;
    GetExitCodeProcess(h, &code);
    CloseHandle(h);
    return (int)code;
#else
    int st = 0;
    if (timeout_ms < 0) {
        while (waitpid((pid_t)pid, &st, 0) < 0) { if (errno != EINTR) return -1; }
    } else {
        int waited = 0;
        for (;;) {
            pid_t r = waitpid((pid_t)pid, &st, WNOHANG);
            if (r == (pid_t)pid) break;
            if (r < 0 && errno != EINTR) return -1;
            if (waited >= timeout_ms) return -2;
            plat_sleep_ms(20);
            waited += 20;
        }
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128;
#endif
}

int plat_terminate(plat_pid_t pid) {
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (!h) return -1;
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    return ok ? 0 : -1;
#else
    return kill((pid_t)pid, SIGTERM);
#endif
}

int plat_run_capture(const char *cmd, char *out, size_t n) {
    if (out && n) out[0] = '\0';
#ifdef _WIN32
    /* like _popen("cmd /c ..."), but with no console window flashing up */
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    HANDLE nul = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = nul;
    si.hStdOutput = wr;
    si.hStdError = wr;
    size_t L = strlen(cmd) + 32;
    char *line = malloc(L);
    if (!line) { CloseHandle(rd); CloseHandle(wr); if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul); return -1; }
    snprintf(line, L, "cmd.exe /c %s", cmd);
    PROCESS_INFORMATION pi;
    BOOL ok = CreateProcessA(NULL, line, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, plat_home(), &si, &pi);
    free(line);
    CloseHandle(wr);
    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    if (!ok) { CloseHandle(rd); return -1; }
    size_t used = 0;
    char buf[512];
    DWORD got;
    while (ReadFile(rd, buf, sizeof(buf), &got, NULL) && got > 0) {
        if (out && used + 1 < n) {
            size_t c = got < n - 1 - used ? got : n - 1 - used;
            memcpy(out + used, buf, c);
            used += c;
            out[used] = '\0';
        }
    }
    CloseHandle(rd);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)code;
#else
    FILE *p = popen(cmd, "r");
    if (!p) return -1;
    size_t used = 0;
    char buf[512];
    size_t got;
    while ((got = fread(buf, 1, sizeof(buf), p)) > 0) {
        if (out && used + 1 < n) {
            size_t c = got < n - 1 - used ? got : n - 1 - used;
            memcpy(out + used, buf, c);
            used += c;
            out[used] = '\0';
        }
    }
    int rc = pclose(p);
    return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
#endif
}

/* ------------------------------------------------------------------ */
/* Desktop                                                             */
/* ------------------------------------------------------------------ */
int plat_open_uri(const char *what) {
#ifdef _WIN32
    char w[2048];
    snprintf(w, sizeof(w), "%s", what);
    if (strncmp(w, "http", 4) != 0) for (char *p = w; *p; p++) if (*p == '/') *p = '\\';
    HINSTANCE r = ShellExecuteA(NULL, "open", w, NULL, NULL, SW_SHOWNORMAL);
    return (INT_PTR)r > 32 ? 0 : -1;
#else
    const char *argv[] = { "xdg-open", what, NULL };
    return plat_spawn(argv, NULL, false, true) > 0 ? 0 : -1;
#endif
}

void plat_keep_awake(bool on) {
#ifdef _WIN32
    SetThreadExecutionState(on ? (ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED) : ES_CONTINUOUS);
#else
    (void)on;   /* Linux boxes used for this normally don't sleep; see README */
#endif
}

char *plat_strcasestr(const char *h, const char *n) {
    size_t L = strlen(n);
    if (!L) return (char *)h;
    for (; *h; h++) {
        size_t i = 0;
        while (i < L && h[i] && tolower((unsigned char)h[i]) == tolower((unsigned char)n[i])) i++;
        if (i == L) return (char *)h;
    }
    return NULL;
}
