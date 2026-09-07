/** jose.cpp — JOSE 核心实现:自动识别 + decode/verify/sign/crack 编排。 */
#include "jose.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>

#include "b64.h"
#include "crack_cpu.h"
#include "gpu/ocl.h"
#include "ossl.h"
#include "rsa.h"
#include "sha2.h"

namespace jose {

/* ==================== 算法探测 ==================== */

AlgInfo detectAlg(const std::string& name) {
  AlgInfo a;
  a.name = name;
  if (name == "HS256") { a.algo = Algo::HS256; a.hashBits = 256; a.symmetric = true; a.supported = true; }
  else if (name == "HS384") { a.algo = Algo::HS384; a.hashBits = 384; a.symmetric = true; a.supported = true; }
  else if (name == "HS512") { a.algo = Algo::HS512; a.hashBits = 512; a.symmetric = true; a.supported = true; }
  else if (name == "RS256") { a.algo = Algo::RS256; a.hashBits = 256; a.supported = true; }
  else if (name == "RS384") { a.algo = Algo::RS384; a.hashBits = 384; a.supported = true; }
  else if (name == "RS512") { a.algo = Algo::RS512; a.hashBits = 512; a.supported = true; }
  else if (name == "PS256") { a.algo = Algo::PS256; a.hashBits = 256; a.supported = false; }
  else if (name == "PS384") { a.algo = Algo::PS384; a.hashBits = 384; a.supported = false; }
  else if (name == "PS512") { a.algo = Algo::PS512; a.hashBits = 512; a.supported = false; }
  else if (name == "ES256") { a.algo = Algo::ES256; a.hashBits = 256; a.supported = true; }
  else if (name == "ES384") { a.algo = Algo::ES384; a.hashBits = 384; a.supported = true; }
  else if (name == "ES512") { a.algo = Algo::ES512; a.hashBits = 512; a.supported = true; }
  else if (name == "EdDSA") { a.algo = Algo::ED25519; a.hashBits = 0; a.supported = true; }
  else if (name == "none") { a.algo = Algo::NONE; a.supported = true; }
  return a;
}

std::optional<std::string> headerStr(const Json& h, const char* name) {
  if (h.type != Json::OBJ) return std::nullopt;
  for (auto& [k, v] : h.obj)
    if (k == name && v.type == Json::STR) return v.str;
  return std::nullopt;
}

/* ==================== 自动识别 ==================== */

Token parseToken(std::string_view raw) {
  Token t;
  t.raw = std::string(raw);
  // 去首尾空白
  const std::size_t first = t.raw.find_first_not_of(" \t\n\r");
  if (first == std::string::npos) {
    t.raw.clear();
    return t;
  }
  if (first != 0) t.raw.erase(0, first);
  while (!t.raw.empty() && (t.raw.back() == ' ' || t.raw.back() == '\n' || t.raw.back() == '\r'))
    t.raw.pop_back();
  if (t.raw.empty()) return t;

  // JSON 序列化?
  if (t.raw.front() == '{') {
    t.kind = Token::Kind::JSON;
    Json j;
    JsonParser p(t.raw);
    if (p.parse(j) && j.type == Json::OBJ) {
      for (auto& [k, v] : j.obj) {
        if (k == "payload" && v.type == Json::STR) t.jsonPayloadB64 = v.str;
        if (k == "protected" && v.type == Json::STR) t.jsonProtected.push_back(v.str);
        if (k == "signature" && v.type == Json::STR) t.sigB64 = v.str;
        if (k == "signatures" && v.type == Json::ARR) {
          for (auto& s : v.arr) {
            if (s.type == Json::OBJ)
              for (auto& [k2, v2] : s.obj)
                if (k2 == "protected" && v2.type == Json::STR) t.jsonProtected.push_back(v2.str);
          }
        }
      }
      // 用第一个 protected header 探测 alg
      if (!t.jsonProtected.empty()) {
        auto hb = b64::decode(t.jsonProtected[0]);
        if (hb) {
          Json h;
          std::string headerText((const char*)hb->data(), hb->size());
          JsonParser hp(headerText);
          if (hp.parse(h)) {
            t.header = h;
            if (auto a = headerStr(h, "alg")) t.alg = *a;
            if (auto e = headerStr(h, "enc")) t.enc = *e;
            t.algInfo = detectAlg(t.alg);
          }
        }
      }
    }
    return t;
  }

  // compact 分段
  std::vector<std::string> parts;
  std::string cur;
  for (char c : t.raw) {
    if (c == '.') { parts.push_back(cur); cur.clear(); }
    else cur.push_back(c);
  }
  parts.push_back(cur);

  if (parts.size() == 2) {
    // 2 段 = 无签名(alg=none);header/payload 照常解码展示
    t.kind = Token::Kind::Unsecured;
    t.headerB64 = parts[0];
    t.payloadB64 = parts[1];
    t.alg = "none";
    t.algInfo = detectAlg("none");
    if (auto hb2 = b64::decode(t.headerB64)) {
      t.headerBytes = *hb2;
      Json h2;
      std::string headerText((const char*)hb2->data(), hb2->size());
      JsonParser hp2(headerText);
      if (hp2.parse(h2) && h2.type == Json::OBJ) t.header = h2;
    }
    if (!t.payloadB64.empty())
      t.payload = b64::decode(t.payloadB64).value_or(std::vector<std::uint8_t>{});
    return t;
  } else if (parts.size() == 3) {
    t.kind = Token::Kind::JWS;
    t.headerB64 = parts[0];
    t.payloadB64 = parts[1];
    t.sigB64 = parts[2];
  } else if (parts.size() == 5) {
    t.kind = Token::Kind::JWE;
    t.headerB64 = parts[0];
    t.ekB64 = parts[1];
    t.ivB64 = parts[2];
    t.ctB64 = parts[3];
    t.tagB64 = parts[4];
  } else {
    return t;
  }

  // 解码 header
  auto hb = b64::decode(t.headerB64);
  if (!hb) { t.kind = Token::Kind::INVALID; return t; }
  t.headerBytes = *hb;
  Json h;
  std::string headerText((const char*)hb->data(), hb->size());
  JsonParser hp(headerText);
  if (!hp.parse(h) || !hp.atEnd() || h.type != Json::OBJ) { t.kind = Token::Kind::INVALID; return t; }
  t.header = h;
  if (auto a = headerStr(h, "alg")) t.alg = *a;
  if (auto e = headerStr(h, "enc")) t.enc = *e;
  t.algInfo = detectAlg(t.alg);

  if (t.kind == Token::Kind::JWS) {
    if (!t.payloadB64.empty()) t.payload = b64::decode(t.payloadB64).value_or(std::vector<std::uint8_t>{});
    if (!t.sigB64.empty()) t.sig = b64::decode(t.sigB64).value_or(std::vector<std::uint8_t>{});
  } else if (t.kind == Token::Kind::JWE) {
    if (!t.ekB64.empty()) t.ek = b64::decode(t.ekB64).value_or(std::vector<std::uint8_t>{});
    if (!t.ivB64.empty()) t.iv = b64::decode(t.ivB64).value_or(std::vector<std::uint8_t>{});
    if (!t.ctB64.empty()) t.ct = b64::decode(t.ctB64).value_or(std::vector<std::uint8_t>{});
    if (!t.tagB64.empty()) t.tag = b64::decode(t.tagB64).value_or(std::vector<std::uint8_t>{});
  }
  return t;
}

/* ==================== JSON 打印 ==================== */

void printJson(const Json& j, std::string& out, int indent) {
  auto pad = [&](int n) { out.append(n * 2, ' '); };
  switch (j.type) {
    case Json::STR: {
      out.push_back('"');
      for (char c : j.str) {
        if (c == '"' || c == '\\') { out.push_back('\\'); out.push_back(c); }
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if ((unsigned char)c < 0x20) {
          char buf[8]; std::snprintf(buf, sizeof buf, "\\u%04x", c);
          out += buf;
        } else out.push_back(c);
      }
      out.push_back('"');
      break;
    }
    case Json::NUM: out += j.num; break;
    case Json::BOOL: out += j.b ? "true" : "false"; break;
    case Json::NIL: out += "null"; break;
    case Json::ARR: {
      if (j.arr.empty()) { out += "[]"; break; }
      out += "[\n";
      for (std::size_t i = 0; i < j.arr.size(); i++) {
        pad(indent + 1);
        printJson(j.arr[i], out, indent + 1);
        if (i + 1 < j.arr.size()) out.push_back(',');
        out.push_back('\n');
      }
      pad(indent);
      out.push_back(']');
      break;
    }
    case Json::OBJ: {
      if (j.obj.empty()) { out += "{}"; break; }
      out += "{\n";
      std::size_t i = 0;
      for (auto& [k, v] : j.obj) {
        pad(indent + 1);
        out.push_back('"');
        out += k;
        out += "\": ";
        printJson(v, out, indent + 1);
        if (++i < j.obj.size()) out.push_back(',');
        out.push_back('\n');
      }
      pad(indent);
      out.push_back('}');
      break;
    }
  }
}

/* ==================== decode ==================== */

std::string decodeToString(const Token& t, const std::string& keyHint) {
  std::string out;
  auto appendSafe = [&](std::string_view s) {
    for (unsigned char c : s) {
      if (c < 0x20 || c == 0x7f) {
        char buf[5];
        std::snprintf(buf, sizeof buf, "\\x%02x", c);
        out += buf;
      } else {
        out.push_back((char)c);
      }
    }
  };
  auto sep = [&](const char* name, const std::string& val) {
    out += name;
    out += val;
    out += "\n";
  };
  switch (t.kind) {
    case Token::Kind::INVALID:
      out += "[!] 无法解析:不是合法的 JOSE token(段数不对或 header 不是 JSON)\n";
      return out;
    case Token::Kind::Unsecured:
      out += "格式:无签名 JWS(alg=none)\n";
      sep("alg      : ", "none");
      break;
    case Token::Kind::JWS:
      out += "格式:JWS compact(JWT)\n";
      sep("alg      : ", t.alg);
      break;
    case Token::Kind::JWE:
      out += "格式:JWE compact\n";
      sep("alg      : ", t.alg);
      sep("enc      : ", t.enc);
      break;
    case Token::Kind::JSON:
      out += "格式:JSON 序列化(JWS/JWE JSON)\n";
      break;
  }

  if (t.kind == Token::Kind::JSON) {
    Json j;
    JsonParser p(t.raw);
    if (p.parse(j)) printJson(j, out, 0);
    out += "\n";
    return out;
  }

  // header
  out += "\n[header]\n";
  if (t.header.type == Json::OBJ) printJson(t.header, out, 0);
  out += "\n";
  // 提示潜在风险字段
  for (auto& risk : {"kid", "jku", "x5u", "crit"}) {
    if (headerStr(t.header, risk)) {
      out += "[!] 注意:header 含 ";
      out += risk;
      out += " 字段,可能存在注入面(kid 路径穿越/SQLi、jku/x5u JWKS 拉取、crit 强制算法切换)\n";
    }
  }

  if (t.kind == Token::Kind::JWS || t.kind == Token::Kind::Unsecured) {
    out += "\n[payload]\n";
    if (!t.payload.empty()) {
      std::string ps((const char*)t.payload.data(), t.payload.size());
      Json j;
      JsonParser p(ps);
      if (p.parse(j) && p.atEnd()) printJson(j, out, 0);
      else {
        if (ps.size() > 512) {
          appendSafe(std::string_view(ps).substr(0, 512));
          out += "\n... (截断,共 " + std::to_string(ps.size()) + " 字节)";
        } else appendSafe(ps);
      }
    } else out += "(空 payload)\n";
    if (t.kind == Token::Kind::Unsecured) return out;
    out += "\n[signature]\n";
    out += "base64url: " + t.sigB64 + "\n";
    if (!t.sig.empty()) {
      out += "hex      : ";
      for (auto b : t.sig) { char buf[4]; std::snprintf(buf, sizeof buf, "%02x", b); out += buf; }
      out += "\n";
    }
  } else if (t.kind == Token::Kind::JWE) {
    out += "\n[JWE 加密结构]\n";
    sep("encrypted_key : ", t.ekB64);
    sep("iv            : ", t.ivB64);
    sep("ciphertext    : ", t.ctB64);
    sep("tag           : ", t.tagB64);
    if (t.alg == "dir" && !t.ek.empty())
      out += "[!] 注意:alg=dir 要求 encrypted_key 为空,当前非空,token 不合规\n";
    if (!keyHint.empty() && t.alg == "dir" && t.enc.size() == 7 && t.enc.rfind("A", 0) == 0) {
      // dir 模式尝试解密
      int keyBits = 0;
      if (t.enc == "A128GCM") keyBits = 128;
      else if (t.enc == "A192GCM") keyBits = 192;
      else if (t.enc == "A256GCM") keyBits = 256;
      if (keyBits) {
        // --key 支持 32 字节原始密钥或等长 hex 串
        std::vector<std::uint8_t> keyBytes;
        std::size_t want = (std::size_t)keyBits / 8;
        bool allHex = keyHint.size() == want * 2;
        for (char c : keyHint)
          if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) allHex = false;
        if (allHex) {
          for (std::size_t i = 0; i < keyHint.size(); i += 2) {
            auto hv = [](char c) -> int {
              if (c >= '0' && c <= '9') return c - '0';
              if (c >= 'a' && c <= 'f') return c - 'a' + 10;
              return c - 'A' + 10;
            };
            keyBytes.push_back((std::uint8_t)((hv(keyHint[i]) << 4) | hv(keyHint[i + 1])));
          }
        } else {
          keyBytes.assign(keyHint.begin(), keyHint.end());
        }
        // JWE 规范:AAD = ASCII(BASE64URL(protected header)),即 headerB64 原文
        auto plain = ossl::jweDirDecrypt(keyBits, keyBytes.data(), keyBytes.size(),
                                         t.iv.data(), t.iv.size(),
                                         (const std::uint8_t*)t.headerB64.data(), t.headerB64.size(),
                                         t.ct.data(), t.ct.size(), t.tag.data(), t.tag.size());
        if (plain) {
          out += "\n[解密明文]\n";
          out += std::string((const char*)plain->data(), plain->size());
          out += "\n";
        } else {
          out += "\n[!] dir 解密失败(密钥错误或 tag 校验失败)\n";
        }
      }
    }
  }
  return out;
}

/* ==================== verify ==================== */

namespace {
/** 尝试加载密钥:PEM 文本 → 公钥/私钥;失败再试 JWK */
bool loadKeyPemOrJwk(const std::string& pem, const std::string& jwk, bool wantPrivate,
                     void*& key) {
  key = nullptr;
  if (!pem.empty()) key = ossl::loadPemKey(pem, wantPrivate);
  if (!key && !jwk.empty()) {
    key = ossl::loadEcJwk(jwk, wantPrivate);
    if (!key) key = ossl::loadOkpJwk(jwk, wantPrivate);
  }
  return key != nullptr;
}
}  // namespace

int verifyToken(const Token& t, const std::string& secret, const std::string& keyPem,
                const std::string& keyJwk, std::string& err) {
  if (t.kind != Token::Kind::JWS) {
    err = "verify 仅支持 JWS compact 格式(当前: " + std::to_string((int)t.kind) + ")";
    return -1;
  }
  const auto& a = t.algInfo;
  std::string signingInput = t.headerB64 + "." + t.payloadB64;

  switch (a.algo) {
    case Algo::NONE:
      // compact JWS 的 none 算法必须使用真正的空签名段。
      return t.sigB64.empty() && t.sig.empty() ? 0 : 1;
    case Algo::HS256:
    case Algo::HS384:
    case Algo::HS512: {
      if (secret.empty()) { err = "HS* 需要 --secret"; return -1; }
      std::uint8_t mac[64];
      sha2::hmacSha(secret, std::span<const std::uint8_t>((const std::uint8_t*)signingInput.data(),
                                                           signingInput.size()),
                    a.hashBits, mac);
      std::size_t dlen = a.hashBits / 8;
      if (t.sig.size() != dlen) { err = "签名长度不符"; return -1; }
      // 常数时间比较
      unsigned char diff = 0;
      for (std::size_t i = 0; i < dlen; i++) diff |= mac[i] ^ t.sig[i];
      return diff == 0 ? 0 : 1;
    }
    case Algo::RS256:
    case Algo::RS384:
    case Algo::RS512: {
      std::optional<rsa::RsaKey> k;
      if (!keyPem.empty()) k = rsa::parsePem(keyPem);
      if (!k && !keyJwk.empty()) k = rsa::parseJwk(keyJwk);
      if (!k) { err = "RS* 需要公钥(PEM 或 JWK)"; return -1; }
      auto digest = sha2::sha256(std::span<const std::uint8_t>((const std::uint8_t*)signingInput.data(), signingInput.size()));
      if (a.hashBits == 384) {
        std::uint8_t d[48];
        sha2::Sha512 h(true);
        h.update(signingInput);
        h.final(d);
        digest.assign(d, d + 48);
      } else if (a.hashBits == 512) {
        std::uint8_t d[64];
        sha2::Sha512 h(false);
        h.update(signingInput);
        h.final(d);
        digest.assign(d, d + 64);
      }
      return rsa::verify(*k, digest, a.hashBits, t.sig) ? 0 : 1;
    }
    case Algo::ES256:
    case Algo::ES384:
    case Algo::ES512: {
      void* key = nullptr;
      if (!loadKeyPemOrJwk(keyPem, keyJwk, false, key)) { err = "ES* 需要公钥(PEM 或 JWK)"; return -1; }
      int rc = ossl::verifyEs(key, a.hashBits, (const std::uint8_t*)signingInput.data(),
                              signingInput.size(), t.sig.data(), t.sig.size());
      ossl::freeKey(key);
      return rc;
    }
    case Algo::ED25519:
    case Algo::ED448: {
      void* key = nullptr;
      if (!loadKeyPemOrJwk(keyPem, keyJwk, false, key)) { err = "EdDSA 需要公钥(PEM 或 JWK)"; return -1; }
      int rc = ossl::verifyEddsa(key, (const std::uint8_t*)signingInput.data(),
                                 signingInput.size(), t.sig.data(), t.sig.size());
      ossl::freeKey(key);
      return rc;
    }
    default:
      err = "算法 " + t.alg + " 不支持(PS* 暂未实现)";
      return -1;
  }
}

/* ==================== sign ==================== */

std::optional<std::string> signToken(const std::string& alg, const std::string& secret,
                                     const std::string& keyPem, const std::string& keyJwk,
                                     const std::string& headerJson, const std::string& payloadJson,
                                     std::string& err) {
  AlgInfo a = detectAlg(alg);
  if (a.algo == Algo::UNKNOWN) { err = "未知算法: " + alg; return std::nullopt; }

  // header
  Json h;
  if (!headerJson.empty()) {
    JsonParser p(headerJson);
    if (!p.parse(h) || !p.atEnd() || h.type != Json::OBJ) { err = "header 必须是 JSON 对象"; return std::nullopt; }
  }
  // 确保 alg 存在(用户 header 可覆盖,但默认用 --alg;两者不一致会签出自相矛盾的 token,直接拒绝)
  auto userAlg = headerStr(h, "alg");
  std::string headerText;
  if (userAlg) {
    if (*userAlg != alg) {
      err = "--alg(=" + alg + ")与 --header 中的 alg(=" + *userAlg + ")不一致";
      return std::nullopt;
    }
    headerText = headerJson;  // 保留用户原始 header 文本
  } else {
    // 构造 {alg: ..., ...}
    Json out;
    out.type = Json::OBJ;
    Json av; av.type = Json::STR; av.str = alg;
    out.obj.push_back({"alg", av});
    for (auto& [k, v] : h.obj) out.obj.push_back({k, v});
    jsonCanonical(out, headerText);
  }
  std::string headerB64 = b64::encode(headerText);
  std::string payloadB64 = b64::encode(payloadJson);
  std::string signingInput = headerB64 + "." + payloadB64;

  switch (a.algo) {
    case Algo::NONE: {
      return headerB64 + "." + payloadB64 + ".";
    }
    case Algo::HS256:
    case Algo::HS384:
    case Algo::HS512: {
      if (secret.empty()) { err = "HS* 需要 --secret"; return std::nullopt; }
      std::uint8_t mac[64];
      sha2::hmacSha(secret, std::span<const std::uint8_t>((const std::uint8_t*)signingInput.data(),
                                                           signingInput.size()),
                    a.hashBits, mac);
      std::string sig = b64::encode(std::span<const std::uint8_t>(mac, a.hashBits / 8));
      return signingInput + "." + sig;
    }
    case Algo::RS256:
    case Algo::RS384:
    case Algo::RS512: {
      std::optional<rsa::RsaKey> k;
      if (!keyPem.empty()) k = rsa::parsePem(keyPem);
      if (!k && !keyJwk.empty()) k = rsa::parseJwk(keyJwk);
      if (!k || !k->hasPrivate()) { err = "RS* 签名需要私钥(PEM 或 JWK)"; return std::nullopt; }
      std::vector<std::uint8_t> digest;
      if (a.hashBits == 256) {
        digest = sha2::sha256(std::span<const std::uint8_t>((const std::uint8_t*)signingInput.data(), signingInput.size()));
      } else {
        std::uint8_t d[64];
        sha2::Sha512 h(a.hashBits == 384);
        h.update(signingInput);
        h.final(d);
        digest.assign(d, d + a.hashBits / 8);
      }
      auto sig = rsa::sign(*k, digest, a.hashBits);
      if (sig.empty()) { err = "RSA 密钥过短,无法编码(需 ≥ DigestInfo+11 字节)"; return std::nullopt; }
      return signingInput + "." + b64::encode(sig);
    }
    case Algo::ES256:
    case Algo::ES384:
    case Algo::ES512: {
      void* key = nullptr;
      if (!loadKeyPemOrJwk(keyPem, keyJwk, true, key)) { err = "ES* 签名需要私钥"; return std::nullopt; }
      if (!ossl::ecKeyMatchesAlg(key, a.hashBits)) {
        ossl::freeKey(key);
        err = "ES* 私钥曲线与 alg 不匹配";
        return std::nullopt;
      }
      std::vector<std::uint8_t> sig;
      int rc = ossl::signEs(key, a.hashBits, (const std::uint8_t*)signingInput.data(),
                            signingInput.size(), sig);
      ossl::freeKey(key);
      if (rc != 0) { err = "ES* 签名失败"; return std::nullopt; }
      return signingInput + "." + b64::encode(sig);
    }
    case Algo::ED25519:
    case Algo::ED448: {
      void* key = nullptr;
      if (!loadKeyPemOrJwk(keyPem, keyJwk, true, key)) { err = "EdDSA 签名需要私钥"; return std::nullopt; }
      std::vector<std::uint8_t> sig;
      int rc = ossl::signEddsa(key, (const std::uint8_t*)signingInput.data(), signingInput.size(), sig);
      ossl::freeKey(key);
      if (rc != 0) { err = "EdDSA 签名失败"; return std::nullopt; }
      return signingInput + "." + b64::encode(sig);
    }
    default:
      err = "算法 " + alg + " 不支持";
      return std::nullopt;
  }
}

/* ==================== crack ==================== */

CrackResult crackHmac(const Token& t, const CrackOptions& opt) {
  CrackResult res;
  if (t.kind != Token::Kind::JWS) {
    res.error = "crack 仅支持 JWS compact 格式";
    return res;
  }
  const auto& a = t.algInfo;
  if (a.algo != Algo::HS256 && a.algo != Algo::HS384 && a.algo != Algo::HS512) {
    res.error = "crack 仅支持对称 HS* 算法(当前 alg=" + t.alg + ",非对称密钥无法爆破)";
    return res;
  }
  if (t.sig.empty()) {
    res.error = "token 签名段为空";
    return res;
  }

  CrackShared cs;
  cs.hashBits = a.hashBits;
  cs.expect = t.sig;
  std::string signingInput = t.headerB64 + "." + t.payloadB64;
  cs.signingInput.assign(signingInput.begin(), signingInput.end());
  if (a.hashBits == 256)
    cs.fm = std::make_unique<sha2::HmacSha256FixedMsg>(cs.signingInput);
  else
    cs.fm512 = std::make_unique<sha2::HmacSha512FixedMsg>(cs.signingInput, a.hashBits == 384);

  std::vector<std::string> words;
  std::vector<std::string> pos;
  bool useMask = !opt.mask.empty();
  if (useMask) {
    if (!parseMask(opt.mask, pos)) {
      res.error = "掩码格式错误";
      return res;
    }
    if (pos.size() > CrackShared::MAX_MASK_LEN) {
      res.error = "掩码超过 " + std::to_string(CrackShared::MAX_MASK_LEN) + " 位上限";
      return res;
    }
    // keyspace 溢出防护:2^64-1 不可能是 ≤95 因子的合法乘积,此时必为溢出
    if (maskTotal(pos) == UINT64_MAX) {
      res.error = "掩码 keyspace 超出 uint64 上限(乘积溢出)";
      return res;
    }
    cs.pos = &pos;
  } else {
    if (opt.wordlist.empty()) {
      res.error = "需要 --wordlist 或 --mask";
      return res;
    }
    std::ifstream f(opt.wordlist);
    if (!f) {
      res.error = "无法打开字典: " + opt.wordlist;
      return res;
    }
    std::string line;
    while (std::getline(f, line)) {
      if (!line.empty() && line.back() == '\r') line.pop_back();
      if (!line.empty()) words.push_back(line);
    }
    if (words.empty()) {
      res.error = "字典为空";
      return res;
    }
    cs.words = &words;
  }

  int threads = opt.threads;
  if (threads <= 0) threads = (int)std::thread::hardware_concurrency();
  if (threads <= 0) threads = 4;

  auto t0 = std::chrono::steady_clock::now();

  // GPU 路径(HS256/HS512;auto 时 GPU 从头、CPU 从尾协同,异常再回退 CPU)
  const std::uint64_t maskSpace = useMask ? maskTotal(pos) : 0;
  // 冷启动 OpenCL 有固定开销;auto 对小任务直接走 CPU,显式 gpu 仍强制启用。
  constexpr std::uint64_t GPU_AUTO_THRESHOLD = 1ULL << 23;  // 8M 候选
  const bool autoLarge = opt.engine == "auto" &&
                         ((useMask && maskSpace >= GPU_AUTO_THRESHOLD) ||
                          (!useMask && words.size() >= GPU_AUTO_THRESHOLD));
  // HS512 kernel 更重,掩码需更大空间摊平开销;大字典则沿用通用阈值。
  const bool hs512Auto = a.hashBits == 512 && opt.engine == "auto" &&
                         ((useMask && maskSpace >= (1ULL << 28)) ||
                          (!useMask && words.size() >= GPU_AUTO_THRESHOLD));
  bool tryGpu = opt.engine == "gpu" ||
                (a.hashBits == 256 && autoLarge) ||
                (a.hashBits == 512 && hs512Auto);
  const std::size_t gpuMsgBlocks = a.hashBits == 256 ? cs.fm->msgBlocks.size() : cs.fm512->msgBlocks.size();
  if (tryGpu && gpuMsgBlocks > 16) {
    // GPU kernel 上限 16 个消息块,超出回退 CPU
    if (opt.engine == "gpu") {
      res.error = "签名输入过长,GPU 不支持;请用 --engine cpu";
      return res;
    }
    tryGpu = false;
  }
  if (tryGpu && !useMask) {
    const bool hasLongWord = std::any_of(words.begin(), words.end(),
                                         [](const std::string& w) { return w.size() > 63; });
    if (hasLongWord) {
      if (opt.engine == "gpu") {
        res.error = "GPU 字典模式不支持超过 63 字节的候选,请用 --engine cpu";
        return res;
      }
      // GPU 使用定长 64 字节缓冲,长词必须完整回退 CPU,避免截断造成假命中。
      tryGpu = false;
    }
  }
  if (tryGpu) {
    gpu::GpuProbe pr = gpu::gpuProbe();
    if (!pr.ok && opt.engine == "gpu") {
      res.error = "GPU 不可用: " + pr.error;
      return res;
    }
    if (pr.ok) {
      std::vector<std::uint8_t> msgBlocks;
      if (a.hashBits == 256) {
        for (auto& b : cs.fm->msgBlocks) msgBlocks.insert(msgBlocks.end(), b.begin(), b.end());
      } else {
        for (auto& b : cs.fm512->msgBlocks) msgBlocks.insert(msgBlocks.end(), b.begin(), b.end());
      }
      gpu::GpuCrackParams gp{&msgBlocks, (int)gpuMsgBlocks, &cs.expect, a.hashBits};
      std::string gerr;
      std::uint64_t foundIdx = 0;
      std::uint64_t tried = 0;
      int rc = -1;
      if (useMask) {
        std::uint64_t total = maskTotal(pos);
        if (opt.engine == "auto") {
          HybridCtl ctl;
          ctl.tail.store(total, std::memory_order_relaxed);
          gp.hybridHead = &ctl.head;
          gp.hybridTail = &ctl.tail;
          gp.hybridStop = &ctl.stop;
          std::thread cpuT([&] { crackMaskHybrid(cs, threads, ctl); });
          rc = gpu::gpuCrackMask(gp, pos, total, foundIdx, tried, gerr);
          // GPU 返回 1 可能只是 head 已追上 tail; CPU 仍需完成已领取的尾段。
          if (rc == -1) ctl.stop.store(true, std::memory_order_relaxed);
          cpuT.join();
          if (cs.found.load(std::memory_order_relaxed)) {
            res.found = true;
            res.secret = cs.foundSecret;
            rc = 0;
          }
        } else {
          rc = gpu::gpuCrackMask(gp, pos, total, foundIdx, tried, gerr);
        }
        if (rc == 0) {
          if (!res.found) {
            res.found = true;
            char buf[CrackShared::MAX_MASK_LEN];
            maskUnrank(pos, foundIdx, buf);
            res.secret.assign(buf, pos.size());
          }
        }
      } else {
        // 字典:打包定长,超长词截断到 63 字节(防越界)
        std::size_t stride = 64;
        std::vector<std::uint8_t> packed(words.size() * stride, 0);
        for (std::size_t i = 0; i < words.size(); i++)
          std::memcpy(packed.data() + i * stride, words[i].data(),
                      std::min(words[i].size(), (std::size_t)63));
        if (opt.engine == "auto") {
          HybridCtl ctl;
          ctl.tail.store(words.size(), std::memory_order_relaxed);
          gp.hybridHead = &ctl.head;
          gp.hybridTail = &ctl.tail;
          gp.hybridStop = &ctl.stop;
          std::thread cpuT([&] { crackDictHybrid(cs, threads, ctl); });
          rc = gpu::gpuCrackDict(gp, packed.data(), stride, words.size(), foundIdx, tried, gerr);
          // GPU 返回 1 可能只是 head 已追上 tail; CPU 仍需完成已领取的尾段。
          if (rc == -1) ctl.stop.store(true, std::memory_order_relaxed);
          cpuT.join();
          if (cs.found.load(std::memory_order_relaxed)) {
            res.found = true;
            res.secret = cs.foundSecret;
            rc = 0;
          }
        } else {
          rc = gpu::gpuCrackDict(gp, packed.data(), stride, words.size(), foundIdx, tried, gerr);
        }
        if (rc == 0) {
          if (!res.found) {
            res.found = true;
            res.secret = words[foundIdx];
          }
        }
      }
      if (rc == 0 || rc == 1) {
        auto t1 = std::chrono::steady_clock::now();
        res.elapsedSec = std::chrono::duration<double>(t1 - t0).count();
        res.attempts = tried + cs.attempts.load(std::memory_order_relaxed);
        if (res.elapsedSec > 0) res.ratePerSec = (double)res.attempts / res.elapsedSec;
        return res;
      }
      // GPU 出错 → 回退 CPU
      if (opt.engine == "gpu") {
        res.error = "GPU 爆破失败: " + gerr;
        return res;
      }
    }
  }
  std::vector<std::thread> pool;
  if (useMask) {
    std::uint64_t total = maskTotal(pos);
    std::uint64_t chunk = total / threads + 1;
    for (int i = 0; i < threads; i++) {
      std::uint64_t b = (std::uint64_t)i * chunk, e = std::min(total, b + chunk);
      if (b >= e) break;
      pool.emplace_back([&, b, e] { crackMaskRange(cs, b, e); });
    }
  } else {
    std::size_t chunk = words.size() / threads + 1;
    for (int i = 0; i < threads; i++) {
      std::size_t b = (std::size_t)i * chunk, e = std::min(words.size(), b + chunk);
      if (b >= e) break;
      pool.emplace_back([&, b, e] { crackDictRange(cs, b, e); });
    }
  }
  for (auto& th : pool) th.join();
  auto t1 = std::chrono::steady_clock::now();

  res.attempts = cs.attempts.load();
  res.elapsedSec = std::chrono::duration<double>(t1 - t0).count();
  if (res.elapsedSec > 0) res.ratePerSec = (double)res.attempts / res.elapsedSec;
  if (cs.found.load()) {
    res.found = true;
    res.secret = cs.foundSecret;
  }
  return res;
}

/* ==================== 工具 ==================== */

std::string sha256Hex(const std::string& s) {
  auto d = sha2::sha256(std::span<const std::uint8_t>((const std::uint8_t*)s.data(), s.size()));
  std::string out;
  for (auto b : d) { char buf[4]; std::snprintf(buf, sizeof buf, "%02x", b); out += buf; }
  return out;
}

}  // namespace jose
