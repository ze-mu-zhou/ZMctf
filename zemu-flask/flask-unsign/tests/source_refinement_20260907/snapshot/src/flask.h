/**
 * flask.h:Flask session cookie 命令(decode / verify / sign / crack)。
 * 格式与 itsdangerous 2.x(URLSafeTimedSerializer)+ Flask 3.x 逐字节对齐:
 *   cookie  = b64url(json) "." b64url(ts) "." b64url(hmac)
 *   ts      = int(unix_time) → 8 字节大端去前导零(legacy: time - 1293840000,itsdangerous <1.0 的 EPOCH)
 *   derived = HMAC-SHA1(key=secret, msg=salt)      // key_derivation='hmac'
 *   hmac    = HMAC-SHA1(key=derived, msg=b64url(json)"."b64url(ts))
 *   salt    = 'cookie-session'(Flask 固定)
 * 压缩格式的 payload 为 '.' + b64url(zlib(json)),前导点也参与签名。
 * decode / verify / crack 支持压缩格式;sign 当前输出未压缩格式。
 */
#pragma once

#include <string>
#include <cstdint>

int flaskDecode(const std::string& cookie);
// maxAge < 0:仅验签;否则检查时间戳和最大年龄(秒)。legacy 使用旧版 epoch。
int flaskVerify(const std::string& cookie, const std::string& secret, const std::string& salt,
                int64_t maxAge = -1, bool legacy = false);
int flaskSign(const std::string& secret, const std::string& jsonText, const std::string& salt,
              bool legacy);

/**
 * crack:wordlist 与 mask 二选一(mask 优先)。
 * engine: "auto"(GPU 优先回退 CPU)/ "gpu" / "cpu"。
 */
int flaskCrack(const std::string& cookie, const std::string& wordlist, const std::string& mask,
               const std::string& salt, int threads, const std::string& engine);

/** 常驻模式(serve/interactive)由 main 置位:开启字典缓存(含打包产物复用)。
 *  CLI 单发进程默认不写缓存——回填拷贝没有复用机会(实测拖慢约 4~9%)。 */
void flaskSetResident(bool resident);
