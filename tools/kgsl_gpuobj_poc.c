/*
 * kgsl_gpuobj_poc.c - SAFE groundwork for the chain: allocate a GPU buffer,
 * mmap it, query it, free it (rbtree grooming primitives). Non-destructive.
 *
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_gpuobj_poc kgsl_gpuobj_poc.c
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

struct kgsl_gpumem_alloc_id{ u32 id; u32 flags; u64 size; u64 mmapsize; u64 gpuaddr; u64 pad[2]; };
#define IOCTL_GPUMEM_ALLOC_ID IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x34,sizeof(struct kgsl_gpumem_alloc_id))
struct kgsl_gpumem_free_id{ u32 id; u32 pad; };
#define IOCTL_GPUMEM_FREE_ID IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x35,sizeof(struct kgsl_gpumem_free_id))

void _start(void){
    long fd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    out("[*] open = ");outdec(fd);out("\n");
    if(fd<0){sys3(SYS_exit,1,0,0);return;}

    struct kgsl_gpumem_alloc_id a;
    for(u64 i=0;i<sizeof(a);i++)((u8*)&a)[i]=0;
    a.size=0x1000; a.flags=0;
    long r=sys3(SYS_ioctl,fd,IOCTL_GPUMEM_ALLOC_ID,(s64)&a);
    out("[*] GPUMEM_ALLOC_ID ret=");outdec(r); out(" id=");outdec(a.id);
    out(" gpuaddr=");outhex(a.gpuaddr); out(" mmapsize=");outhex(a.mmapsize); out(" flags=");outhex(a.flags); out("\n");
    if(r!=0||a.id==0){ out("[!] alloc failed\n"); sys3(SYS_exit,1,0,0); return; }

    s64 m=sys6(SYS_mmap,0,a.mmapsize? a.mmapsize:0x1000,3,1,fd,(s64)a.gpuaddr);
    out("[*] mmap(offset=gpuaddr) = ");outhex((u64)m);out("\n");
    if(m>0){ volatile unsigned char*p=(volatile unsigned char*)m; p[0]=0x41; out("[*] wrote mapping OK, readback=");outhex(p[0]);out("\n"); }

    struct kgsl_gpumem_free_id f; f.id=a.id; f.pad=0;
    r=sys3(SYS_ioctl,fd,IOCTL_GPUMEM_FREE_ID,(s64)&f);
    out("[*] GPUMEM_FREE_ID ret=");outdec(r);out("\n");
    out("[*] done (safe)\n");
    sys3(SYS_close,fd,0,0);
    sys3(SYS_exit,0,0,0);
}
