/*
 * kgsl_gpu_submit.c - stage 0: validate GPU command submission from shell.
 * Submits one IB with two CP_MEM_WRITE ops targeting a user GPU buffer and
 * reads the result back from the CPU (after cache maintenance).
 *
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_gpu_submit kgsl_gpu_submit.c
 */
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64; typedef long s64;
#define SYS_openat 56
#define SYS_ioctl 29
#define SYS_write 64
#define SYS_exit 93
#define SYS_close 57
#define SYS_mmap 222
#define SYS_sched_yield 124
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

struct kgsl_drawctxt_create{u32 flags;u32 drawctxt_id;};
#define IOCTL_DRAWCTXT_CREATE IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x13,sizeof(struct kgsl_drawctxt_create))
struct kgsl_gpumem_alloc_id{u32 id;u32 flags;u64 size;u64 mmapsize;u64 gpuaddr;u64 pad[2];};
#define IOCTL_GPUMEM_ALLOC_ID IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x34,sizeof(struct kgsl_gpumem_alloc_id))
struct kgsl_gpumem_free_id{u32 id;u32 pad;};
#define IOCTL_GPUMEM_FREE_ID IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x35,sizeof(struct kgsl_gpumem_free_id))
struct kgsl_command_object{u64 offset;u64 gpuaddr;u64 size;u32 flags;u32 id;};
struct kgsl_gpu_command{u64 flags;u64 cmdlist;u32 cmdsize;u32 numcmds;u64 objlist;u32 objsize;u32 numobjs;u64 synclist;u32 syncsize;u32 numsyncs;u32 context_id;u32 timestamp;};
#define IOCTL_GPU_COMMAND IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x4A,sizeof(struct kgsl_gpu_command))
#define KGSL_CMDLIST_IB 0x1u
#define CP_NOP 0x10u
#define CP_MEM_WRITE 0x3du

static u32 parity(u32 v){v^=v>>4;v^=v>>8;v^=v>>12;v^=v>>16;v^=v>>20;v^=v>>24;v^=v>>28;return (0x9669u>>(v&0xf))&1u;}
static u32 pkt7(u32 op,u32 cnt){return 0x70000000u|(cnt&0x3fffu)|(parity(cnt)<<15)|((op&0x7fu)<<16)|(parity(op)<<23);}
static void dc_civac(void*p,u64 len){u64 a=(u64)p&~63ull,b=((u64)p+len+63)&~63ull;for(;a<b;a+=64)asm volatile("dc civac, %0"::"r"(a):"memory");asm volatile("dsb ish":::"memory");}

static long alloc_id(long fd,u64 size,u32*id,u64*gpu,u64*mmapsz){
    struct kgsl_gpumem_alloc_id a; for(u64 i=0;i<sizeof(a);i++)((u8*)&a)[i]=0;
    a.size=size; a.flags=0;
    long r=sys3(SYS_ioctl,fd,IOCTL_GPUMEM_ALLOC_ID,(s64)&a);
    if(r==0){*id=a.id;*gpu=a.gpuaddr;*mmapsz=a.mmapsize?a.mmapsize:size;}
    return r;
}
void _start(void){
    out("[*] kgsl_gpu_submit: stage 0\n");
    long fd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    out("[1] open = ");outdec(fd);out("\n");
    if(fd<0){sys3(SYS_exit,1,0,0);return;}

    struct kgsl_drawctxt_create dc; dc.flags=0x12u; dc.drawctxt_id=0; /* PREAMBLE|NO_GMEM_ALLOC (0x10|0x02) */
    long r=sys3(SYS_ioctl,fd,IOCTL_DRAWCTXT_CREATE,(s64)&dc);
    out("[2] DRAWCTXT_CREATE ret=");outdec(r);out(" id=");outdec(dc.drawctxt_id);out("\n");
    if(r||!dc.drawctxt_id){sys3(SYS_exit,1,0,0);return;}

    u32 cid,cid_id; u64 cgpu,cmz;
    r=alloc_id(fd,0x1000,&cid_id,&cgpu,&cmz);
    out("[3] alloc CMD ret=");outdec(r);out(" id=");outdec(cid_id);out(" gpu=");outhex(cgpu);out(" mmapsz=");outhex(cmz);out("\n");
    u32 oid; u64 ogpu,omz;
    r=alloc_id(fd,0x1000,&oid,&ogpu,&omz);
    out("[4] alloc OUT ret=");outdec(r);out(" id=");outdec(oid);out(" gpu=");outhex(ogpu);out(" mmapsz=");outhex(omz);out("\n");
    if(!cid_id||!oid){sys3(SYS_exit,1,0,0);return;}

    s64 cmap=sys6(SYS_mmap,0,cmz,3,1,fd,(s64)((u64)cid_id<<12));
    s64 omap=sys6(SYS_mmap,0,omz,3,1,fd,(s64)((u64)oid<<12));
    out("[5] mmap CMD=");outhex((u64)cmap);out(" OUT=");outhex((u64)omap);out("\n");
    if(cmap<=0||omap<=0){sys3(SYS_exit,1,0,0);return;}

    u32*c=(u32*)cmap; u32*d=(u32*)omap;
    d[0]=0; d[1]=0;
    c[0]=pkt7(CP_MEM_WRITE,3); c[1]=(u32)ogpu; c[2]=(u32)(ogpu>>32); c[3]=0x42424242;
    c[4]=pkt7(CP_MEM_WRITE,3); c[5]=(u32)(ogpu+4); c[6]=(u32)((ogpu+4)>>32); c[7]=0x43434343;
    c[8]=pkt7(CP_NOP,1); c[9]=0;
    dc_civac(c,40);

    struct kgsl_command_object cmd; cmd.offset=0; cmd.gpuaddr=cgpu; cmd.size=40; cmd.flags=KGSL_CMDLIST_IB; cmd.id=cid_id;
    struct kgsl_gpu_command gc; for(u64 i=0;i<sizeof(gc);i++)((u8*)&gc)[i]=0;
    gc.cmdlist=(u64)&cmd; gc.cmdsize=sizeof(cmd); gc.numcmds=1;
    gc.context_id=dc.drawctxt_id; gc.timestamp=1;
    r=sys3(SYS_ioctl,fd,IOCTL_GPU_COMMAND,(s64)&gc);
    out("[6] GPU_COMMAND ret=");outdec(r);out("\n");

    u32 v0=0,v1=0; int ok=0;
    for(int i=0;i<2000;i++){
        dc_civac(d,8);
        v0=d[0]; v1=d[1];
        if(v0==0x42424242u&&v1==0x43434343u){ok=1;break;}
        sys3(SYS_sched_yield,0,0,0);
    }
    out("[7] readback d0=");outhex(v0);out(" d1=");outhex(v1);
    out(ok?"  <== GPU COMMANDS WORK\n":"  (not written; see dmesg)\n");

    struct kgsl_gpumem_free_id f; f.id=cid_id; f.pad=0; sys3(SYS_ioctl,fd,IOCTL_GPUMEM_FREE_ID,(s64)&f);
    f.id=oid; sys3(SYS_ioctl,fd,IOCTL_GPUMEM_FREE_ID,(s64)&f);
    sys3(SYS_close,fd,0,0);
    sys3(SYS_exit,0,0,0);
}
