/**
 * kernel_jwt.h — JWT HS256 爆破 OpenCL kernel(hashcat 风格寄存器流水线重写版)。
 *
 * 参照 hashcat inc_hash_sha256.cl/.h 的手工优化结构:
 * - SHA-256 轮函数宏全展开,消息驻留 16 个具名 u32 寄存器(与 w0_t..wf_t 同款);
 * - Ch/Maj 用 bitselect 形式(NV 上映射为单条 LOP3);
 * - HMAC 全程 u32 字运算:ipad/opad 直接以字为单位 XOR 构建,零字节数组、零动态下标;
 * - 候选生成摊薄(hashcat Loops 同款):每 work-item 只做一次混合进制除法反解,
 *   内层 loopN 个候选用"递增+进位"推进,且仅重建受影响的密钥字;
 * - 消息块由 host 预填充并预字节交换为 BE u32,__constant 存放,按字加载;
 * - 期望签名同样预打包为 8 个 BE u32,直接字比较。
 */
#pragma once

namespace jose::gpu {

inline const char* JWT_KERNEL_SRC = R"CLC(
// SHA-256 K 常量
__constant uint K256[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

#define ROTR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

#define S0(x) (ROTR32(x,2) ^ ROTR32(x,13) ^ ROTR32(x,22))
#define S1(x) (ROTR32(x,6) ^ ROTR32(x,11) ^ ROTR32(x,25))
#define s0(x) (ROTR32(x,7) ^ ROTR32(x,18) ^ ((x)>>3))
#define s1(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ ((x)>>10))
// hashcat inc_hash_sha256.h 同款 bitselect 形式(NV LOP3)
#define CH(x,y,z)  bitselect((z),(y),(x))
#define MAJ(x,y,z) bitselect((x),(y),((x)^(z)))

// 单步(hashcat SHA256_STEP_S 结构)
#define RSTEP(a,b,c,d,e,f,g,h,w,i) \
{ \
  h += S1(e) + CH(e,f,g) + K256[i] + (w); \
  d += h; \
  h += S0(a) + MAJ(a,b,c); \
}

// 16 步:操作 W0..Wf(调用处作用域内的具名 u32 变量)
#define STEP16(i) \
  RSTEP(a,b,c,d,e,f,g,h, W0, (i)+ 0); \
  RSTEP(h,a,b,c,d,e,f,g, W1, (i)+ 1); \
  RSTEP(g,h,a,b,c,d,e,f, W2, (i)+ 2); \
  RSTEP(f,g,h,a,b,c,d,e, W3, (i)+ 3); \
  RSTEP(e,f,g,h,a,b,c,d, W4, (i)+ 4); \
  RSTEP(d,e,f,g,h,a,b,c, W5, (i)+ 5); \
  RSTEP(c,d,e,f,g,h,a,b, W6, (i)+ 6); \
  RSTEP(b,c,d,e,f,g,h,a, W7, (i)+ 7); \
  RSTEP(a,b,c,d,e,f,g,h, W8, (i)+ 8); \
  RSTEP(h,a,b,c,d,e,f,g, W9, (i)+ 9); \
  RSTEP(g,h,a,b,c,d,e,f, Wa, (i)+10); \
  RSTEP(f,g,h,a,b,c,d,e, Wb, (i)+11); \
  RSTEP(e,f,g,h,a,b,c,d, Wc, (i)+12); \
  RSTEP(d,e,f,g,h,a,b,c, Wd, (i)+13); \
  RSTEP(c,d,e,f,g,h,a,b, We, (i)+14); \
  RSTEP(b,c,d,e,f,g,h,a, Wf, (i)+15);

// 消息扩展:w[i] = w[i-16] + s0(w[i-15]) + w[i-7] + s1(w[i-2])(原地滚动)
#define EXP16() \
  W0 += s1(We) + W9 + s0(W1); \
  W1 += s1(Wf) + Wa + s0(W2); \
  W2 += s1(W0) + Wb + s0(W3); \
  W3 += s1(W1) + Wc + s0(W4); \
  W4 += s1(W2) + Wd + s0(W5); \
  W5 += s1(W3) + We + s0(W6); \
  W6 += s1(W4) + Wf + s0(W7); \
  W7 += s1(W5) + W0 + s0(W8); \
  W8 += s1(W6) + W1 + s0(W9); \
  W9 += s1(W7) + W2 + s0(Wa); \
  Wa += s1(W8) + W3 + s0(Wb); \
  Wb += s1(W9) + W4 + s0(Wc); \
  Wc += s1(Wa) + W5 + s0(Wd); \
  Wd += s1(Wb) + W6 + s0(We); \
  We += s1(Wc) + W7 + s0(Wf); \
  Wf += s1(Wd) + W8 + s0(W0);

// 声明 16 个具名消息字并从 src(数组/指针,常量下标)加载
#define DECL_W(src) \
  uint W0=(src)[0], W1=(src)[1], W2=(src)[2], W3=(src)[3]; \
  uint W4=(src)[4], W5=(src)[5], W6=(src)[6], W7=(src)[7]; \
  uint W8=(src)[8], W9=(src)[9], Wa=(src)[10], Wb=(src)[11]; \
  uint Wc=(src)[12], Wd=(src)[13], We=(src)[14], Wf=(src)[15];

// 同上,但逐字异或常量(opad = ipad ^ 0x6a6a6a6a,0x36^0x5c=0x6a)
#define DECL_WXOR(src,x) \
  uint W0=(src)[0]^(x), W1=(src)[1]^(x), W2=(src)[2]^(x), W3=(src)[3]^(x); \
  uint W4=(src)[4]^(x), W5=(src)[5]^(x), W6=(src)[6]^(x), W7=(src)[7]^(x); \
  uint W8=(src)[8]^(x), W9=(src)[9]^(x), Wa=(src)[10]^(x), Wb=(src)[11]^(x); \
  uint Wc=(src)[12]^(x), Wd=(src)[13]^(x), We=(src)[14]^(x), Wf=(src)[15]^(x);

// 单块 SHA-256 压缩:W0..Wf 已就位,st 累加。全展开,寄存器驻留。
#define TRANSFORM(st) \
{ \
  uint a=(st)[0],b=(st)[1],c=(st)[2],d=(st)[3],e=(st)[4],f=(st)[5],g=(st)[6],h=(st)[7]; \
  STEP16(0); \
  EXP16(); STEP16(16); \
  EXP16(); STEP16(32); \
  EXP16(); STEP16(48); \
  (st)[0]+=a; (st)[1]+=b; (st)[2]+=c; (st)[3]+=d; \
  (st)[4]+=e; (st)[5]+=f; (st)[6]+=g; (st)[7]+=h; \
}

#define IV8 {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}

// HMAC-SHA256 核心:ip/op 为 16 字 ipad/opad 块(寄存器),msgW 为 __constant BE 字。
// 内层终块 = inner摘要(8字) || 0x80 || 0... || 768bit(0x300),全部为字常量。
#define HMAC256_CORE(dg) \
{ \
  uint st[8] = IV8; \
  { DECL_W(ip) TRANSFORM(st); } \
  for (int b = 0; b < nBlocks; b++) { \
    __constant uint *mp = msgW + (uint)b * 16; \
    DECL_W(mp) TRANSFORM(st); \
  } \
  uint so[8] = IV8; \
  { DECL_WXOR(ip, 0x6a6a6a6au) TRANSFORM(so); } \
  { \
    uint W0=st[0],W1=st[1],W2=st[2],W3=st[3],W4=st[4],W5=st[5],W6=st[6],W7=st[7]; \
    uint W8=0x80000000u,W9=0u,Wa=0u,Wb=0u,Wc=0u,Wd=0u,We=0u,Wf=0x00000300u; \
    TRANSFORM(so); \
  } \
  dg[0]=so[0]; dg[1]=so[1]; dg[2]=so[2]; dg[3]=so[3]; \
  dg[4]=so[4]; dg[5]=so[5]; dg[6]=so[6]; dg[7]=so[7]; \
}

// 命中判定:先比首字(2^-32 过滤),全等再 CAS 记录
#define CHECK_AND_REPORT(idx) \
  if (dg[0]==expectW[0]) { \
    if (dg[1]==expectW[1] && dg[2]==expectW[2] && dg[3]==expectW[3] && \
        dg[4]==expectW[4] && dg[5]==expectW[5] && dg[6]==expectW[6] && dg[7]==expectW[7]) { \
      if (atomic_cmpxchg(foundOut, 0u, 1u) == 0) { \
        foundOut[1] = (uint)((idx) & 0xffffffffu); \
        foundOut[2] = (uint)((idx) >> 32); \
      } \
    } \
  }

// ===== 掩码模式 =====
// 每 work-item 处理 loopN 个连续候选:反解一次,内层递增+进位,只重建受影响的密钥字。
__kernel void jwt_crack_mask(
    __constant uint *msgW, int nBlocks,     // 签名输入填充块(BE 字,nBlocks*16)
    __constant uint *expectW,               // 期望签名(8 个 BE 字)
    __constant uchar *csets, __constant uint *csoff, __constant uint *cslen,
    uint maskLen, uint loopN,
    __global uint *foundOut,                // [0]=found, [1]=idx 低32, [2]=idx 高32
    ulong base)                             // 分块调度:候选序号 = base + gid*loopN + j
{
  const ulong gid0 = base + (ulong)get_global_id(0) * (ulong)loopN;

  // 一次性混合进制反解(hashcat 语义:最右位变化最快)
  uchar digits[64];
  ulong x = gid0;
  for (int i = (int)maskLen - 1; i >= 0; i--) {
    digits[i] = (uchar)(x % (ulong)cslen[i]);
    x /= (ulong)cslen[i];
  }

  // 密钥不再以字节数组保存,直接维护 ipad 字(寄存器;opad = ipad ^ 0x6a6a6a6a 现算):
  // 字 w 覆盖字节 4w..4w+3(BE),字节 p 的 pad 值为 (p<maskLen ? 字符 : 0) ^ 0x36
  uint ip[16];
  #pragma unroll
  for (int w = 0; w < 16; w++) {
    uint ipv = 0;
    #pragma unroll
    for (int j = 0; j < 4; j++) {
      const int p = w * 4 + j;
      uchar ch = (p < (int)maskLen) ? csets[csoff[p] + (uint)digits[p]] : (uchar)0;
      ipv = (ipv << 8) | (uint)(ch ^ 0x36);
    }
    ip[w] = ipv;
  }

  const int lastW = ((int)maskLen - 1) / 4;
  for (uint jn = 0; jn < loopN; jn++) {
    uint dg[8];
    HMAC256_CORE(dg);
    CHECK_AND_REPORT(gid0 + jn);

    // 递增 digits(最右位最快),wFrom..lastW 为受影响字
    int i = (int)maskLen - 1;
    while (i >= 0) {
      uchar d = (uchar)(digits[i] + 1);
      if (d == (uchar)cslen[i]) { digits[i] = 0; i--; }
      else { digits[i] = d; break; }
    }
    if (i < 0) break;  // 进位溢出:keyspace 用尽
    const int wFrom = i / 4;
    #pragma unroll
    for (int w = 0; w < 16; w++) {
      if (w < wFrom || w > lastW) continue;
      uint ipv = ip[w];
      #pragma unroll
      for (int j = 0; j < 4; j++) {
        const int p = w * 4 + j;
        uchar ch = (p < (int)maskLen) ? csets[csoff[p] + (uint)digits[p]] : (uchar)0;
        uint ib = (uint)(ch ^ 0x36);
        uint msk, ishf;
        if (j == 0)      { msk = 0x00ffffffu; ishf = ib << 24; }
        else if (j == 1) { msk = 0xff00ffffu; ishf = ib << 16; }
        else if (j == 2) { msk = 0xffff00ffu; ishf = ib << 8;  }
        else             { msk = 0xffffff00u; ishf = ib;       }
        ipv = (ipv & msk) | ishf;
      }
      ip[w] = ipv;
    }
  }
}

// ===== 字典模式 =====
// host 侧已将词条打包为定长 16 个 BE u32(零填充,HMAC ≤64B 密钥语义)。
// 每 work-item 处理 loopN 个连续词条。
__kernel void jwt_crack_dict(
    __constant uint *msgW, int nBlocks,
    __constant uint *expectW,
    __global const uint *wordsW, ulong count,
    uint loopN,
    __global uint *foundOut,                // [0]=found, [1]=idx
    ulong base)                             // 词条下标 = base + gid*loopN + j
{
  const ulong gid0 = base + (ulong)get_global_id(0) * (ulong)loopN;
  for (uint jn = 0; jn < loopN; jn++) {
    const ulong idx = gid0 + jn;
    if (idx >= count) return;
    const __global uint *wp = wordsW + idx * 16;
    uint ip[16];
    #pragma unroll
    for (int w = 0; w < 16; w++) {
      ip[w] = wp[w] ^ 0x36363636u;
    }
    uint dg[8];
    HMAC256_CORE(dg);
    CHECK_AND_REPORT(idx);
  }
}

// ===== HS512 =====
__constant ulong K512[80] = {
  0x428a2f98d728ae22UL,0x7137449123ef65cdUL,0xb5c0fbcfec4d3b2fUL,0xe9b5dba58189dbbcUL,
  0x3956c25bf348b538UL,0x59f111f1b605d019UL,0x923f82a4af194f9bUL,0xab1c5ed5da6d8118UL,
  0xd807aa98a3030242UL,0x12835b0145706fbeUL,0x243185be4ee4b28cUL,0x550c7dc3d5ffb4e2UL,
  0x72be5d74f27b896fUL,0x80deb1fe3b1696b1UL,0x9bdc06a725c71235UL,0xc19bf174cf692694UL,
  0xe49b69c19ef14ad2UL,0xefbe4786384f25e3UL,0x0fc19dc68b8cd5b5UL,0x240ca1cc77ac9c65UL,
  0x2de92c6f592b0275UL,0x4a7484aa6ea6e483UL,0x5cb0a9dcbd41fbd4UL,0x76f988da831153b5UL,
  0x983e5152ee66dfabUL,0xa831c66d2db43210UL,0xb00327c898fb213fUL,0xbf597fc7beef0ee4UL,
  0xc6e00bf33da88fc2UL,0xd5a79147930aa725UL,0x06ca6351e003826fUL,0x142929670a0e6e70UL,
  0x27b70a8546d22ffcUL,0x2e1b21385c26c926UL,0x4d2c6dfc5ac42aedUL,0x53380d139d95b3dfUL,
  0x650a73548baf63deUL,0x766a0abb3c77b2a8UL,0x81c2c92e47edaee6UL,0x92722c851482353bUL,
  0xa2bfe8a14cf10364UL,0xa81a664bbc423001UL,0xc24b8b70d0f89791UL,0xc76c51a30654be30UL,
  0xd192e819d6ef5218UL,
  0xd69906245565a910UL,0xf40e35855771202aUL,0x106aa07032bbd1b8UL,0x19a4c116b8d2d0c8UL,
  0x1e376c085141ab53UL,0x2748774cdf8eeb99UL,0x34b0bcb5e19b48a8UL,0x391c0cb3c5c95a63UL,
  0x4ed8aa4ae3418acbUL,0x5b9cca4f7763e373UL,0x682e6ff3d6b2b8a3UL,0x748f82ee5defb2fcUL,
  0x78a5636f43172f60UL,0x84c87814a1f0ab72UL,0x8cc702081a6439ecUL,0x90befffa23631e28UL,
  0xa4506cebde82bde9UL,0xbef9a3f7b2c67915UL,0xc67178f2e372532bUL,0xca273eceea26619cUL,
  0xd186b8c721c0c207UL,0xeada7dd6cde0eb1eUL,0xf57d4f7fee6ed178UL,0x06f067aa72176fbaUL,
  0x0a637dc5a2c898a6UL,0x113f9804bef90daeUL,0x1b710b35131c471bUL,0x28db77f523047d84UL,
  0x32caab7b40c72493UL,0x3c9ebe0a15c9bebcUL,0x431d67c49c100d4cUL,0x4cc5d4becb3e42b6UL,
  0x597f299cfc657e2aUL,0x5fcb6fab3ad6faecUL,0x6c44198c4a475817UL};

#define ROR64(x,n) (((x) >> (n)) | ((x) << (64 - (n))))
#define BS0(x) (ROR64(x,28) ^ ROR64(x,34) ^ ROR64(x,39))
#define BS1(x) (ROR64(x,14) ^ ROR64(x,18) ^ ROR64(x,41))
#define SS0(x) (ROR64(x,1) ^ ROR64(x,8) ^ ((x)>>7))
#define SS1(x) (ROR64(x,19) ^ ROR64(x,61) ^ ((x)>>6))
#define CH64(x,y,z) bitselect((z),(y),(x))
#define MAJ64(x,y,z) bitselect((x),(y),((x)^(z)))

inline void TRANSFORM512(__private ulong st[8], __private ulong W[16]) {
  ulong a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7];
  for (int i=0; i<80; i++) {
    ulong wi = W[i & 15];
    if (i >= 16) {
      wi += SS1(W[(i-2)&15]) + W[(i-7)&15] + SS0(W[(i-15)&15]);
      W[i & 15] = wi;
    }
    ulong t1 = h + BS1(e) + CH64(e,f,g) + K512[i] + wi;
    ulong t2 = BS0(a) + MAJ64(a,b,c);
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d;
  st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

#define HMAC512_CORE(dg) \
{ \
  ulong st[8] = {0x6a09e667f3bcc908UL,0xbb67ae8584caa73bUL,0x3c6ef372fe94f82bUL,0xa54ff53a5f1d36f1UL, \
                 0x510e527fade682d1UL,0x9b05688c2b3e6c1fUL,0x1f83d9abfb41bd6bUL,0x5be0cd19137e2179UL}; \
  ulong W[16]; \
  for (int wi=0;wi<16;wi++) W[wi]=ip[wi]; \
  TRANSFORM512(st,W); \
  for (int bi=0;bi<nBlocks;bi++) { \
    __constant ulong *mp=msgW+(uint)bi*16; \
    for (int wi=0;wi<16;wi++) W[wi]=mp[wi]; \
    TRANSFORM512(st,W); \
  } \
  ulong so[8] = {0x6a09e667f3bcc908UL,0xbb67ae8584caa73bUL,0x3c6ef372fe94f82bUL,0xa54ff53a5f1d36f1UL, \
                 0x510e527fade682d1UL,0x9b05688c2b3e6c1fUL,0x1f83d9abfb41bd6bUL,0x5be0cd19137e2179UL}; \
  for (int wi=0;wi<16;wi++) W[wi]=ip[wi]^0x6a6a6a6a6a6a6a6aUL; \
  TRANSFORM512(so,W); \
  W[0]=st[0];W[1]=st[1];W[2]=st[2];W[3]=st[3];W[4]=st[4];W[5]=st[5];W[6]=st[6];W[7]=st[7]; \
  W[8]=0x8000000000000000UL;W[9]=0;W[10]=0;W[11]=0;W[12]=0;W[13]=0;W[14]=0;W[15]=0x0000000000000600UL; \
  TRANSFORM512(so,W); \
  for (int wi=0;wi<8;wi++) dg[wi]=so[wi]; \
}

#define CHECK512(idx) \
  if (dg[0]==expectW[0] && dg[1]==expectW[1] && dg[2]==expectW[2] && dg[3]==expectW[3] && \
      dg[4]==expectW[4] && dg[5]==expectW[5] && dg[6]==expectW[6] && dg[7]==expectW[7]) { \
    if (atomic_cmpxchg(foundOut,0u,1u)==0) { foundOut[1]=(uint)((idx)&0xffffffffUL); foundOut[2]=(uint)((idx)>>32); } \
  }

__kernel void jwt_crack_mask512(
    __constant ulong *msgW, int nBlocks, __constant ulong *expectW,
    __constant uchar *csets, __constant uint *csoff, __constant uint *cslen,
    uint maskLen, uint loopN, __global uint *foundOut, ulong base) {
  const ulong gid0=base+(ulong)get_global_id(0)*(ulong)loopN;
  uchar digits[64]; ulong x=gid0;
  for (int i=(int)maskLen-1;i>=0;i--) { digits[i]=(uchar)(x%(ulong)cslen[i]); x/=(ulong)cslen[i]; }
  ulong ip[16];
  for (int w=0;w<16;w++) { ulong v=0; for (int j=0;j<8;j++) { int p=w*8+j; uchar ch=(p<(int)maskLen)?csets[csoff[p]+(uint)digits[p]]:(uchar)0; v=(v<<8)|(ulong)(ch^0x36); } ip[w]=v; }
  for (uint jn=0;jn<loopN;jn++) {
    ulong dg[8]; HMAC512_CORE(dg); CHECK512(gid0+jn);
    int i=(int)maskLen-1;
    while (i>=0) { uchar d=(uchar)(digits[i]+1); if (d==(uchar)cslen[i]) { digits[i]=0;i--; } else { digits[i]=d;break; } }
    if (i<0) break;
    for (int w=0;w<16;w++) { ulong v=0; for (int j=0;j<8;j++) { int p=w*8+j; uchar ch=(p<(int)maskLen)?csets[csoff[p]+(uint)digits[p]]:(uchar)0; v=(v<<8)|(ulong)(ch^0x36); } ip[w]=v; }
  }
}

__kernel void jwt_crack_dict512(
    __constant ulong *msgW, int nBlocks, __constant ulong *expectW,
    __global const ulong *wordsW, ulong count, uint loopN,
    __global uint *foundOut, ulong base) {
  const ulong gid0=base+(ulong)get_global_id(0)*(ulong)loopN;
  for (uint jn=0;jn<loopN;jn++) {
    const ulong idx=gid0+jn; if (idx>=count) return;
    const __global ulong *wp=wordsW+idx*8; ulong ip[16];
    for (int w=0;w<8;w++) ip[w]=wp[w]^0x3636363636363636UL;
    for (int w=8;w<16;w++) ip[w]=0x3636363636363636UL;
    ulong dg[8]; HMAC512_CORE(dg); CHECK512(idx);
  }
}
)CLC";

}  // namespace jose::gpu
