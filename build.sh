#!/usr/bin/env bash
set -euo pipefail

# byedpi-x360 — fully self-contained build of a DashLaunch plugin.
# Everything needed (sources + tools) is generated/downloaded here.

BASE=0x91500000
PPC=powerpc-linux-gnu

echo "== tools =="
curl -fsSL -o elf2xex.py https://raw.githubusercontent.com/xenosworks/xsdk/main/tools/elf2xex.py
curl -fsSL -o gen_imports.py https://raw.githubusercontent.com/xenosworks/xsdk/main/tools/gen_imports.py
curl -fsSL -o xsdk_plugin.ld https://raw.githubusercontent.com/xenosworks/xsdk/main/src/xsdk_plugin.ld

# The generic assembler rejects some PPC mnemonics: emit raw opcodes instead.
python3 - <<'PY'
p = 'gen_imports.py'
s = open(p).read()
s = s.replace('"\\tmtctr\\tr11",', '"\\t.long\\t0x7D6903A6",')
s = s.replace('"\\tbctr",', '"\\t.long\\t0x4E800420",')
open(p, 'w').write(s)
PY

echo "== sources =="
cat > imports.txt <<'EOF'
xboxkrnl.exe  0x0CF  NtClose
xboxkrnl.exe  0x0D2  NtCreateFile
xboxkrnl.exe  0x0FF  NtWriteFile
xboxkrnl.exe  0x14D  _vsnprintf
xboxkrnl.exe  0x05A  KeDelayExecutionThread
xboxkrnl.exe  0x195  XexGetModuleHandle
xboxkrnl.exe  0x197  XexGetProcedureAddress
EOF

cat > plugin.c <<'EOF'
#include <stdint.h>
#include <stdarg.h>

typedef void *HANDLE;
typedef uint32_t NTSTATUS;
typedef uint32_t ULONG;
typedef uint16_t USHORT;

typedef struct { USHORT Length, MaximumLength; char *Buffer; } ANSI_STRING;
typedef struct { ANSI_STRING *ObjectName; void *RootDirectory; } OBJECT_ATTRIBUTES;
typedef struct { NTSTATUS Status; ULONG Information; } IO_STATUS_BLOCK;

NTSTATUS XexGetModuleHandle(const char *module_name, HANDLE *module);
NTSTATUS XexGetProcedureAddress(HANDLE module, uint32_t ordinal, void **address);
NTSTATUS NtCreateFile(HANDLE *file, ULONG access, const OBJECT_ATTRIBUTES *attributes,
                      IO_STATUS_BLOCK *status, void *allocation, ULONG file_attributes,
                      ULONG share, ULONG disposition, ULONG options);
NTSTATUS NtWriteFile(HANDLE file, void *event, void *apc, void *context,
                     IO_STATUS_BLOCK *status, const void *buffer, ULONG length,
                     void *byte_offset, void *key);
NTSTATUS NtClose(HANDLE handle);
NTSTATUS _vsnprintf(char *buffer, uint32_t count, const char *format, va_list args);
NTSTATUS KeDelayExecutionThread(uint8_t processor_mode, uint8_t alertable, int64_t *interval);

static HANDLE log_handle;

static void log_open(void)
{
    static char name[] = "\\Device\\Harddisk0\\Partition1\\byedpi.log";
    ANSI_STRING string = { (USHORT)(sizeof(name) - 1), (USHORT)sizeof(name), name };
    OBJECT_ATTRIBUTES attributes = { &string, 0 };
    IO_STATUS_BLOCK status;
    NtCreateFile(&log_handle, 0x40000000 | 0x00100000, &attributes, &status, 0,
                 0x80, 0x01, 3, 0x20);
}

static void log_line(const char *format, ...)
{
    if (!log_handle) return;
    char line[256];
    va_list args;
    va_start(args, format);
    int32_t n = _vsnprintf(line, sizeof(line) - 1, format, args);
    va_end(args);
    if (n < 0) n = 0;
    line[n++] = '\n';
    IO_STATUS_BLOCK status;
    int64_t end = -1;
    NtWriteFile(log_handle, 0, 0, 0, &status, line, (ULONG)n, &end, 0);
}

static void copy_bytes(void *dst, const void *src, uint32_t n)
{
    uint8_t *d = dst; const uint8_t *s = src;
    while (n--) *d++ = *s++;
}

#define PPC_LIS(r, i)   (0x3C000000u | ((uint32_t)(r) << 21) | ((i) & 0xFFFFu))
#define PPC_ORI(rA,rB,i)(0x60000000u | ((uint32_t)(rA) << 21) | ((uint32_t)(rB) << 16) | ((i) & 0xFFFFu))
#define PPC_MTCTR(r)    (0x7C0903A6u | ((uint32_t)(r) << 21))
#define PPC_BCTR        (0x4E800420u)

static void flush_icache(void *address, uint32_t size)
{
    uint32_t a = ((uint32_t)address) & ~31u;
    uint32_t e = (((uint32_t)address) + size + 31u) & ~31u;
    for (; a < e; a += 32)
        __asm__ volatile ("dcbst 0,%0\n\tsync\n\ticbi 0,%0\n\tisync" : : "r"(a) : "memory");
}

typedef struct { void *target; uint32_t original[4]; uint32_t trampoline[8]; } HOOK;
static HOOK hook_send, hook_connect;

static void build_jump(uint32_t out[4], uint32_t address)
{
    out[0] = PPC_LIS(12, (address >> 16) & 0xFFFFu);
    out[1] = PPC_ORI(12, 12, address & 0xFFFFu);
    out[2] = PPC_MTCTR(12);
    out[3] = PPC_BCTR;
}

static void install(HOOK *h, void *target, void *handler)
{
    h->target = target;
    copy_bytes(h->original, target, 16);
    copy_bytes(h->trampoline, h->original, 16);
    build_jump(h->trampoline + 4, (uint32_t)target + 16);
    uint32_t patch[4];
    build_jump(patch, (uint32_t)handler);
    copy_bytes(target, patch, 16);
    flush_icache(target, 16);
    flush_icache(h->trampoline, 32);
}

typedef int (*PFN_SEND)(uint32_t, uint32_t, const char *, int, int);
typedef int (*PFN_CONNECT)(uint32_t, uint32_t, const void *, int);
typedef int (*PFN_SOCKOPT)(uint32_t, uint32_t, int, int, const char *, int);

static PFN_SOCKOPT real_setsockopt;
static uint32_t fragments;

static int call_send(uint32_t c, uint32_t s, const char *b, int l, int f)
{
    return ((PFN_SEND)(void *)hook_send.trampoline)(c, s, b, l, f);
}
static int call_connect(uint32_t c, uint32_t s, const void *n, int l)
{
    return ((PFN_CONNECT)(void *)hook_connect.trampoline)(c, s, n, l);
}

static int tls_hello(const uint8_t *p, int len)
{
    if (len < 6) return 0;
    return p[0] == 0x16 && p[1] == 0x03 && p[5] == 0x01 ? 1 : 0;
}

static int find_bytes(const unsigned char *hay, int hlen, const char *needle)
{
    int nlen = 0;
    while (needle[nlen]) nlen++;
    if (!nlen || nlen > hlen) return -1;
    for (int i = 0; i <= hlen - nlen; i++) {
        int j = 0;
        while (j < nlen && hay[i + j] == (unsigned char)needle[j]) j++;
        if (j == nlen) return i;
    }
    return -1;
}

static int hooked_send(uint32_t caller, uint32_t s, const char *buf, int len, int flags)
{
    if (!buf || len <= 16) return call_send(caller, s, buf, len, flags);
    if (!tls_hello((const uint8_t *)buf, len)) return call_send(caller, s, buf, len, flags);

    /* ByeByeDPI style: fake ClientHello with a mangled SNI at low TTL, then the
       real ClientHello with its TLS record split just before the SNI field. */
    unsigned char fake[2048];
    int n = len;
    if (n > (int)sizeof(fake)) n = (int)sizeof(fake);
    copy_bytes(fake, buf, (uint32_t)n);

    static const char *domains[] = {
        "youtubei.googleapis.com", "googlevideo.com", "www.youtube.com",
        "youtube.com", "googleapis.com", "google.com"
    };
    int sni = -1;
    for (unsigned d = 0; d < sizeof(domains)/sizeof(domains[0]); d++) {
        int pos;
        while ((pos = find_bytes(fake, n, domains[d])) >= 0) {
            if (sni < 0 || pos < sni) sni = pos;
            int k = 0;
            while (domains[d][k]) k++;
            for (int j = 0; j < k; j++) fake[pos + j] = 'a';
        }
    }

    int low_ttl = 8;
    int normal_ttl = 64;
    if (real_setsockopt) {
        real_setsockopt(caller, s, 0, 2, (const char *)&low_ttl, 4);
        call_send(caller, s, (const char *)fake, n, flags);
        real_setsockopt(caller, s, 0, 2, (const char *)&normal_ttl, 4);
    }

    /* --tlsrec -5+s: insert a new TLS record header 5 bytes before the SNI. */
    unsigned char real[2056];
    int split = sni - 5;
    if (split > 16 && split < len - 5 && len + 5 <= (int)sizeof(real)) {
        copy_bytes(real, buf, (uint32_t)split);
        int first_record_len = split - 5;
        real[3] = (unsigned char)(first_record_len >> 8);
        real[4] = (unsigned char)(first_record_len & 0xFF);
        real[split]     = 0x16;
        real[split + 1] = buf[1];
        real[split + 2] = buf[2];
        int second_record_len = len - split;
        real[split + 3] = (unsigned char)(second_record_len >> 8);
        real[split + 4] = (unsigned char)(second_record_len & 0xFF);
        copy_bytes(real + split + 5, buf + split, (uint32_t)(len - split));
        call_send(caller, s, (const char *)real, len + 5, flags);
    } else {
        call_send(caller, s, buf, len, flags);
    }

    fragments++;
    if (fragments < 5) log_line("tlsrec s=%u len=%d sni=%d total=%u", s, len, sni, fragments);
    return len;
}

static int hooked_connect(uint32_t caller, uint32_t s, const void *name, int namelen)
{
    return call_connect(caller, s, name, namelen);
}

uint32_t xsdk_plugin_entry(void *module, uint32_t reason, void *reserved)
{
    (void)module; (void)reserved;
    if (reason != 1) return 1;

    log_open();
    log_line("byedpi-x360: start");

    HANDLE xam;
    void *p_send, *p_connect, *p_setsockopt;
    if (XexGetModuleHandle("xam.xex", &xam) ||
        XexGetProcedureAddress(xam, 22, &p_send) ||
        XexGetProcedureAddress(xam, 12, &p_connect) ||
        XexGetProcedureAddress(xam, 7, &p_setsockopt)) {
        log_line("resolve failed");
        return 1;
    }
    real_setsockopt = (PFN_SOCKOPT)p_setsockopt;

    install(&hook_send, p_send, (void *)hooked_send);
    install(&hook_connect, p_connect, (void *)hooked_connect);
    log_line("hooks installed");
    return 1;
}
EOF

echo "== compile =="
mkdir -p build imports_gen
python3 gen_imports.py imports.txt imports_gen

$PPC-gcc -O2 -nostdlib -ffreestanding -fno-builtin \
    -msoft-float -mno-altivec \
    -c plugin.c -o build/plugin.o

for f in imports_gen/*.S; do
    $PPC-gcc -c "$f" -o "build/$(basename "$f" .S).o"
done

echo "== link =="
$PPC-ld -T xsdk_plugin.ld --defsym=xsdk_plugin_base=$BASE \
    -o build/plugin.elf build/*.o

echo "== pack =="
python3 elf2xex.py build/plugin.elf build/byedpi.xex --dll $BASE
ls -l build/byedpi.xex
