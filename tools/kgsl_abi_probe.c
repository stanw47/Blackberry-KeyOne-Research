/*
 * kgsl_abi_probe.c - brute-force KGSL ioctl ABI discovery (non-destructive).
 * Scans ioctl nr x size x dir for anything the driver recognizes, and probes
 * GETPROPERTY. Prints only interesting results. No exploitation.
 * Build: zig cc -target aarch64-linux-musl -nostdlib -static -ffreestanding -fno-builtin -O2 -Wl,-e,_start -o kgsl_abi_probe kgsl_abi_probe.c
 */
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64; typedef long s64;
#define SYS_openat 56
#define SYS_ioctl 29
#define SYS_write 64
#define SYS_exit 93
static inline s64 sys3(long n,s64 a,s64 b,s64 c){register s64 x0 __asm__("x0")=a;register s64 x1 __asm__("x1")=b;register s64 x2 __asm__("x2")=c;register s64 x8 __asm__("x8")=n;__asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x8):"memory");return x0;}
static inline s64 sys4(long n,s64 a,s64 b,s64 c,s64 d){register s64 x0 __asm__("x0")=a;register s64 x1 __asm__("x1")=b;register s64 x2 __asm__("x2")=c;register s64 x3 __asm__("x3")=d;register s64 x8 __asm__("x8")=n;__asm__ volatile("svc #0":"+r"(x0):"r"(x1),"r"(x2),"r"(x3),"r"(x8):"memory");return x0;}
static int slen(const char*s){int n=0;while(s[n])n++;return n;}
static void out(const char*s){sys3(SYS_write,1,(s64)s,slen(s));}
static void outhex(u64 v){char b[19];b[0]='0';b[1]='x';for(int i=0;i<16;i++){int n=(v>>((15-i)*4))&0xf;b[2+i]=n<10?'0'+n:'a'+n-10;}b[18]=0;out(b);}
static void outdec(s64 v){char b[24];int i=23;b[i--]=0;int neg=v<0;if(neg)v=-v;if(v==0)b[i--]='0';while(v>0){b[i--]='0'+(v%10);v/=10;}if(neg)b[i--]='-';out(&b[i+1]);}
#define MKCMD(dir,t,nr,sz) (((dir)<<30)|((sz)<<16)|((t)<<8)|(nr))
void _start(void){
 long fd=sys4(SYS_openat,-100,(s64)"/dev/kgsl-3d0",2,0);
 out("[*] open=");outdec(fd);out("\n");
 if(fd<0){sys3(SYS_exit,1,0,0);return;}
 static u8 buf[1024];
 unsigned sizes[8]={0,8,16,24,32,40,48,56};
 out("[*] scanning cmd space (magic 0x09, dir 3) for non-EINVAL/ENOTTY:\n");
 for(u32 nr=0;nr<0x100;nr++){
  for(int si=0;si<8;si++){
   u32 sz=sizes[si];
   for(int i=0;i<1024;i++)buf[i]=0;
   u32 cmd=MKCMD(3,9,nr,sz);
   long r=sys3(SYS_ioctl,fd,cmd,(s64)buf);
   if(r!=-22 && r!=-25 && r!=-515 && r!=-14){
    out("  nr=");outhex(nr);out(" sz=");outdec(sz);out(" cmd=");outhex(cmd);out(" ret=");outdec(r);out("\n");
   }
  }
 }
 out("[*] GETPROPERTY matrix (nr=2):\n");
 for(u32 t=0;t<8;t++){
  for(u32 s=0;s<64;s+=8){
   for(int i=0;i<1024;i++)buf[i]=0;
   u8 gp[32]; for(int k=0;k<32;k++)gp[k]=0;
   *(u32*)&gp[0]=t; *(u64*)&gp[8]=(u64)buf; *(u64*)&gp[16]=(u64)s;
   long r=sys3(SYS_ioctl,fd,MKCMD(3,9,2,0x18),(s64)gp);
   if(r==0){ out("  OK type=");outdec(t);out(" size=");outdec(s);out(" d0=");outhex(*(u64*)&buf[0]);out(" d1=");outhex(*(u64*)&buf[8]);out("\n"); }
  }
 }
 out("[*] done\n");
 sys3(SYS_exit,0,0,0);
}
