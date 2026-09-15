/* tapprobe2 — does source-bound traffic actually enter our TAP adapter?
 *
 * The whole userspace tunnel design rests on one assumption (measured once with
 * Find-NetRoute, but never observed at the wire): when an app binds to a modem's
 * source IP and sends out, Windows delivers the frame INTO that interface's TAP,
 * where a tun2socks could pick it up. This proves it at the wire before we spend
 * days on the tunnel engine.
 *
 * For number N it: finds the adapter holding 192.168.N.100, opens its TAP,
 * forces media-connected, then from a socket bound to 192.168.N.100 sends a few
 * UDP packets to 8.8.8.8:53 while a reader thread prints whatever the TAP
 * receives. Expected: an ARP "who-has 192.168.N.1" (the OS trying to resolve the
 * gateway on the TAP) — that alone proves traffic is being steered into the
 * adapter. If nothing arrives, source routing did not deliver here.
 *
 * Build: zig cc -target x86_64-windows-gnu -O2 -o tapprobe2.exe \
 *          adapter/tapprobe2.c -liphlpapi -lws2_32
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winioctl.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>

#define TAP_CONTROL_CODE(req,method) CTL_CODE(FILE_DEVICE_UNKNOWN, req, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_SET_MEDIA_STATUS   TAP_CONTROL_CODE(6, METHOD_BUFFERED)

static volatile LONG g_arp = 0, g_ip = 0, g_frames = 0;
static int g_n;

static HANDLE open_tap_for_ip(unsigned wantip)
{
    ULONG sz = 0;
    IP_ADAPTER_ADDRESSES *aa, *p;
    char guid[64] = {0};
    HANDLE h = INVALID_HANDLE_VALUE;

    GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_DNS_SERVER|GAA_FLAG_SKIP_MULTICAST, NULL, NULL, &sz);
    if (!sz) return h;
    aa = (IP_ADAPTER_ADDRESSES*)malloc(sz);
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_DNS_SERVER|GAA_FLAG_SKIP_MULTICAST, NULL, aa, &sz) == NO_ERROR) {
        for (p = aa; p; p = p->Next) {
            IP_ADAPTER_UNICAST_ADDRESS *u;
            for (u = p->FirstUnicastAddress; u; u = u->Next) {
                struct sockaddr_in *s = (struct sockaddr_in*)u->Address.lpSockaddr;
                if (s->sin_family == AF_INET && ntohl(s->sin_addr.S_un.S_addr) == wantip) {
                    strncpy(guid, p->AdapterName, sizeof(guid)-1);
                }
            }
        }
    }
    free(aa);
    if (!guid[0]) { printf("no adapter holds that IP\n"); return h; }

    {
        char path[128];
        snprintf(path, sizeof(path), "\\\\.\\Global\\%s.tap", guid);
        h = CreateFileA(path, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_SYSTEM, NULL);
        if (h == INVALID_HANDLE_VALUE)
            printf("open %s failed err %lu\n", path, GetLastError());
        else
            printf("opened TAP %s\n", path);
    }
    return h;
}

static DWORD WINAPI reader(LPVOID arg)
{
    HANDLE h = (HANDLE)arg;
    unsigned char buf[2048];
    DWORD n;
    while (ReadFile(h, buf, sizeof(buf), &n, NULL) && n >= 14) {
        unsigned short eth = (buf[12] << 8) | buf[13];
        InterlockedIncrement(&g_frames);
        if (eth == 0x0806 && n >= 28) {            /* ARP */
            unsigned tip = (buf[38]<<24)|(buf[39]<<16)|(buf[40]<<8)|buf[41];
            InterlockedIncrement(&g_arp);
            if (g_arp <= 4)
                printf("  ARP who-has %u.%u.%u.%u  from %02x:%02x:%02x:%02x:%02x:%02x\n",
                       (tip>>24)&255,(tip>>16)&255,(tip>>8)&255,tip&255,
                       buf[6],buf[7],buf[8],buf[9],buf[10],buf[11]);
        } else if (eth == 0x0800 && n >= 34) {      /* IPv4 */
            unsigned dip = (buf[30]<<24)|(buf[31]<<16)|(buf[32]<<8)|buf[33];
            InterlockedIncrement(&g_ip);
            if (g_ip <= 6)
                printf("  IPv4 -> %u.%u.%u.%u  proto %d\n",
                       (dip>>24)&255,(dip>>16)&255,(dip>>8)&255,dip&255, buf[23]);
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    WSADATA wsa;
    HANDLE tap, th;
    ULONG on = 1;
    DWORD ret = 0;
    int i;
    SOCKET s;
    struct sockaddr_in src, dst;
    unsigned base;

    if (argc < 2) { printf("usage: tapprobe2 <N>\n"); return 1; }
    g_n = atoi(argv[1]);
    base = 0xC0A80000u | ((unsigned)g_n << 8);       /* 192.168.N.0 */
    WSAStartup(MAKEWORD(2,2), &wsa);

    tap = open_tap_for_ip(base | 100u);              /* 192.168.N.100 */
    if (tap == INVALID_HANDLE_VALUE) return 2;

    if (!DeviceIoControl(tap, TAP_IOCTL_SET_MEDIA_STATUS, &on, sizeof(on), &on, sizeof(on), &ret, NULL))
        printf("set media status failed err %lu\n", GetLastError());

    th = CreateThread(NULL, 0, reader, tap, 0, NULL);

    /* send source-bound traffic that should be steered into this adapter */
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    memset(&src, 0, sizeof(src));
    src.sin_family = AF_INET;
    src.sin_addr.S_un.S_addr = htonl(base | 100u);
    if (bind(s, (struct sockaddr*)&src, sizeof(src)) != 0)
        printf("bind 192.168.%d.100 failed err %d\n", g_n, WSAGetLastError());
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.S_un.S_addr = htonl(0x08080808u);   /* 8.8.8.8 */
    dst.sin_port = htons(53);

    printf("sending 6 source-bound packets 192.168.%d.100 -> 8.8.8.8:53 ...\n", g_n);
    for (i = 0; i < 6; i++) {
        const char *msg = "probe";
        sendto(s, msg, 5, 0, (struct sockaddr*)&dst, sizeof(dst));
        Sleep(500);
    }
    Sleep(1500);

    printf("\n==== frames=%ld  ARP=%ld  IPv4=%ld ====\n", (long)g_frames, (long)g_arp, (long)g_ip);
    if (g_arp || g_ip) printf("VERDICT: traffic ENTERS the TAP — userspace tunnel is viable.\n");
    else               printf("VERDICT: nothing arrived — source routing did NOT deliver here.\n");

    CloseHandle(tap);           /* unblocks the reader */
    (void)th;
    WSACleanup();
    return 0;
}
