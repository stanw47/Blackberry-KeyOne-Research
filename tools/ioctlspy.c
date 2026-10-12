#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <dlfcn.h>
#include <sys/ioctl.h>

typedef int (*ioctl_fn)(int, unsigned long, ...);
static ioctl_fn real_ioctl = 0;

struct bulk { unsigned int ep, len, timeout; void *data; };
struct ctrl { unsigned char bRequestType, bRequest; unsigned short wValue, wIndex, wLength; unsigned int timeout; void *data; };
struct setintf { unsigned int interface, altsetting; };

int ioctl(int fd, unsigned long req, ...)
{
    va_list ap; va_start(ap, req);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    if (!real_ioctl) real_ioctl = (ioctl_fn)dlsym(RTLD_NEXT, "ioctl");

    if (((req >> 8) & 0xff) == 'U') {
        unsigned int nr = req & 0xff;
        if (nr == 2 && arg) { /* BULK */
            struct bulk *b = (struct bulk *)arg;
            fprintf(stderr, "[spy] BULK ep=0x%02x len=%u timeout=%u", b->ep, b->len, b->timeout);
            if (b->data && !(b->ep & 0x80) && b->len < 256) {
                unsigned char *d = (unsigned char *)b->data;
                fprintf(stderr, " data=\"");
                for (unsigned int i = 0; i < b->len; i++) fputc((d[i] >= 32 && d[i] < 127) ? d[i] : '.', stderr);
                fprintf(stderr, "\"");
            }
            fprintf(stderr, "\n");
        } else if (nr == 0 && arg) { /* CONTROL */
            struct ctrl *c = (struct ctrl *)arg;
            fprintf(stderr, "[spy] CTRL bmReqType=0x%02x bReq=0x%02x wValue=0x%04x wIndex=0x%04x wLen=%u\n",
                    c->bRequestType, c->bRequest, c->wValue, c->wIndex, c->wLength);
        } else if (nr == 4 && arg) { /* SETINTERFACE */
            struct setintf *s = (struct setintf *)arg;
            fprintf(stderr, "[spy] SETINTERFACE if=%u alt=%u\n", s->interface, s->altsetting);
        } else if (nr == 15 || nr == 16 || nr == 21) { /* CLAIM/RELEASE/CLEAR_HALT */
            unsigned int *v = (unsigned int *)arg;
            const char *n = nr == 15 ? "CLAIM" : nr == 16 ? "RELEASE" : "CLEAR_HALT";
            fprintf(stderr, "[spy] %s %u\n", n, v ? *v : 0);
        } else {
            fprintf(stderr, "[spy] USBDEVFS nr=%u req=0x%lx\n", nr, req);
        }
    }
    int ret = real_ioctl(fd, req, arg);
    if (((req >> 8) & 0xff) == 'U' && (req & 0xff) == 2 && arg) {
        struct bulk *b = (struct bulk *)arg;
        if (b->ep & 0x80) {
            fprintf(stderr, "[spy] BULK-IN ep=0x%02x ret=%d", b->ep, ret);
            if (ret > 0 && b->data) {
                unsigned char *d = (unsigned char *)b->data;
                int n = ret > 96 ? 96 : ret;
                fprintf(stderr, " data=\"");
                for (int i = 0; i < n; i++) fputc((d[i] >= 32 && d[i] < 127) ? d[i] : '.', stderr);
                fprintf(stderr, "\"");
            }
            fprintf(stderr, "\n");
        }
    }
    return ret;
}
