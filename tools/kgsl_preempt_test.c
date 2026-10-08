/*
 * kgsl_preempt_test.c - S3.2: does a high-priority rb0 batch preempt a long
 * user IB running on the lowest-priority rb3?
 *
 *  victim (rb3, prio 12): IB of N MEM_WRITE ops  OUT[1..N] = i   (long, busy)
 *  preemptor (rb0, prio 1): tiny IB  OUT[0] = 0xB0B0
 *
 * Poll OUT[0] while the victim runs.  If 0xB0B0 appears while OUT[last] has
 * not reached its final value -> preemption happened mid-IB.
 *
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_preempt_test kgsl_preempt_test.c
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
#define CP_MEM_WRITE 0x3du
#define NW 200000u          /* victim MEM_WRITEs */
#define OUTSZ (0x1000u + NW*4u)

static u32 parity(u32 v){v^=v>>4;v^=v>>8;v^=v>>12;v^=v>>16;v^=v>>20;v^=v>>24;v^=v>>28;return (0x9669u>>(v&0xf))&1u;}
static u32 pkt7(u32 op,u32 cnt){return 0x70000000u|(cnt&0x3fffu)|(parity(cnt)<<15)|((op&0x7fu)<<16)|(parity(op)<<23);}
static void dc_civac(void*p,u64 len){u64 a=(u64)p&~63ull,b=((u64)p+len+63)&~63ull;for(;a<b;a+=64)asm volatile("dc civac, %0"::"r"(a):"memory");asm volatile("dsb ish":::"memory");}
static long gfd; static u32*outp; static u64 out_gpu;
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
static long submit(u32 ctx,u32 cmdid,u64 cmdgpu,u32*d, u32 n,u32 ts){
    dc_civac(d,n*4);
    struct kgsl_command_object co; co.offset=0; co.gpuaddr=cmdgpu; co.size=n*4; co.flags=KGSL_CMDLIST_IB; co.id=cmdid;
    struct kgsl_gpu_command gc; for(u64 i=0;i<sizeof(gc);i++)((u8*)&gc)[i]=0;
    gc.cmdlist=(u64)&co; gc.cmdsize=sizeof(co); gc.numcmds=1; gc.context_id=ctx; gc.timestamp=ts;
    return sys3(SYS_ioctl,gfd,IOCTL_GPU_COMMAND,(s64)&gc);
}
static u32*mw(u32*n,u64 addr,u32 val){ n[0]=pkt7(CP_MEM_WRITE,3); n[1]=(u32)addr; n[2]=(u32)(addr>>32); n[3]=val; return n+4; }
void _start(void){
    out("[*] kgsl_preempt_test S3.2\n");
    gfd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    if(gfd<0){out("[!] open\n");sys3(SYS_exit,1,0,0);return;}
    struct kgsl_drawctxt_create d;
    d.flags=0xC012u; d.drawctxt_id=0; u32 cv;
    if(sys3(SYS_ioctl,gfd,IOCTL_DRAWCTXT_CREATE,(s64)&d)){out("[!] ctx v\n");sys3(SYS_exit,1,0,0);return;} cv=d.drawctxt_id;
    d.flags=0x1012u; d.drawctxt_id=0; u32 cp;
    if(sys3(SYS_ioctl,gfd,IOCTL_DRAWCTXT_CREATE,(s64)&d)){out("[!] ctx p\n");sys3(SYS_exit,1,0,0);return;} cp=d.drawctxt_id;
    out("[1] victim ctx(rb3)=");outdec(cv);out(" preemptor ctx(rb0)=");outdec(cp);out("\n");

    u32 vid; u64 vgpu; u32*vcmd;
    if(alloc_buf(0x1000+NW*16,&vid,&vgpu,&vcmd)){out("[!] vcmd\n");sys3(SYS_exit,1,0,0);return;}
    u32 pid; u64 pgpu; u32*pcmd;
    if(alloc_buf(0x1000,&pid,&pgpu,&pcmd)){out("[!] pcmd\n");sys3(SYS_exit,1,0,0);return;}
    u32 oid; if(alloc_buf(OUTSZ,&oid,&out_gpu,&outp)){out("[!] out\n");sys3(SYS_exit,1,0,0);return;}
    out("[2] vcmd=");outhex(vgpu);out(" pcmd=");outhex(pgpu);out(" out=");outhex(out_gpu);out("\n");

    /* build victim: NW MEM_WRITEs OUT[1+i] = i+1 */
    u32 k=0;
    for(u32 i=0;i<NW;i++){ k=(u32)(mw(&vcmd[k],out_gpu+4*(i+1),i+1)-vcmd); }
    dc_civac(vcmd,k*4);
    outp[0]=0; dc_civac(outp,8);

    /* preemptor: OUT[0] = 0xB0B0 */
    u32 q=0; q=(u32)(mw(&pcmd[q],out_gpu,0xB0B0u)-pcmd);
    dc_civac(pcmd,q*4);

    long rv=submit(cv,vid,vgpu,vcmd,k,80);
    /* immediately submit preemptor */
    long rp=submit(cp,pid,pgpu,pcmd,q,81);
    out("[3] victim submit ret=");outdec(rv);out(" preemptor submit ret=");outdec(rp);out("\n");

    /* poll: did OUT[0] appear while victim incomplete? sample OUT[5000] instantly */
    int seen=0; u32 mid=0; int polls=0;
    for(int i=0;i<200000;i++){
        dc_civac(outp,64);
        if(outp[0]==0xB0B0u){
            seen=1;
            dc_civac((u8*)outp+5000*4,64);
            mid=outp[5000];
            break;
        }
        polls++;
    }
    dc_civac(outp,OUTSZ);
    out("[4] preemptor marker seen=");outdec(seen);out(" after polls=");outdec(polls);out(" mid-sample OUT[5000]=");outhex(mid);out("\n");
    out("[5] victim first=");outhex(outp[1]);out(" last=");outhex(outp[NW]);out("\n");
    if(seen && mid<5000) out("[6] PREEMPTION CONFIRMED (marker landed while victim < 5000)\n");
    else if(seen) out("[6] marker seen; victim already past 5000 (no mid-IB proof)\n");
    else out("[6] marker not seen\n");
    out("[*] done\n");
    sys3(SYS_close,gfd,0,0);
    sys3(SYS_exit,0,0,0);
}
