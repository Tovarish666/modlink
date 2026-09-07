/* modlink-agent — конфигурация lwIP.
 *
 * Режим NO_SYS: без операционной системы, без потоков внутри стека. Весь lwIP
 * крутится в одном потоке-петле, который читает кадры из TAP и раз в тик дёргает
 * таймеры. Это самый простой корректный режим — блокировок нет вообще, а значит
 * нет и целого класса гонок, которые в многопоточном lwIP ловятся месяцами. */
#ifndef MODLINK_LWIPOPTS_H
#define MODLINK_LWIPOPTS_H

#define NO_SYS                      1
#define SYS_LIGHTWEIGHT_PROT        0
#define LWIP_NETCONN                0   /* API последовательного доступа не нужен */
#define LWIP_SOCKET                 0   /* сокеты BSD тоже: работаем через raw API */

/* --- протоколы --- */
#define LWIP_IPV4                   1
#define LWIP_IPV6                   0
#define LWIP_TCP                    1
#define LWIP_UDP                    1   /* нужен для DNS */
#define LWIP_ICMP                   1
#define LWIP_RAW                    0
#define LWIP_DHCP                   0   /* адреса раздаём сами */
#define LWIP_AUTOIP                 0
#define LWIP_IGMP                   0
#define LWIP_DNS                    0   /* резолвим не мы, а удалённая сторона */
#define LWIP_ARP                    1
#define LWIP_ETHERNET               1

/* --- память ---
 * 40 адаптеров по одному netif; счётчики рассчитаны на десятки одновременных
 * соединений на каждый, а не на тысячи. */
#define MEM_LIBC_MALLOC             0
#define MEMP_MEM_MALLOC             0
#define MEM_ALIGNMENT               4
#define MEM_SIZE                    (512 * 1024)
#define MEMP_NUM_PBUF               512
#define MEMP_NUM_TCP_PCB            256
#define MEMP_NUM_TCP_PCB_LISTEN     8
#define MEMP_NUM_TCP_SEG            512
#define MEMP_NUM_UDP_PCB            32
#define MEMP_NUM_SYS_TIMEOUT        16
#define PBUF_POOL_SIZE              512
#define PBUF_POOL_BUFSIZE           1600   /* кадр Ethernet целиком */

/* --- TCP ---
 * Окно побольше умолчания: канал за прокси имеет заметную задержку (у модема
 * пинг около 35 мс), и на маленьком окне скорость упирается в RTT, а не в LTE. */
#define TCP_MSS                     1460
#define TCP_WND                     (32 * TCP_MSS)
#define TCP_SND_BUF                 (32 * TCP_MSS)
#define TCP_SND_QUEUELEN            ((4 * TCP_SND_BUF) / TCP_MSS)
#define LWIP_TCP_KEEPALIVE          1
#define TCP_LISTEN_BACKLOG          1

/* --- прочее --- */
#define LWIP_NETIF_STATUS_CALLBACK  0
#define LWIP_NETIF_LINK_CALLBACK    0
#define LWIP_NETIF_HOSTNAME         0
#define LWIP_NETIF_API              0
#define LWIP_STATS                  0
#define LWIP_CHECKSUM_CTRL_PER_NETIF 0
#define LWIP_SINGLE_NETIF           0   /* по одному netif на модем */
#define IP_FORWARD                  0
#define LWIP_NETIF_LOOPBACK         0

/* Отладка выключена целиком: включается точечно при разборе полётов. */
#define LWIP_DEBUG                  0

#endif
