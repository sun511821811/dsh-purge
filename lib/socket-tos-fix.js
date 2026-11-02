import net from "node:net";

/**
 * 修复 macOS / Darwin 上 Node.js 内置 undici (fetch) 在 writeH1 时抛出的致命异常：
 *   Error: setTypeOfService EINVAL
 *     at Socket.setTypeOfService (node:net:913:13)
 *     at writeH1 (node:internal/deps/undici/undici:8021:16)
 *
 * 根因：
 * 在 macOS 上通过特定代理（如 Clash / 7897）、IPv6 或双栈套接字发起 HTTP/1.1 请求时，
 * 底层 setsockopt(IP_TOS) 会返回 EINVAL（非法参数）。
 * Node.js 在 Windows 上将其视为 best-effort（不抛出），但在 macOS/Linux 上却会抛出异常，
 * 且 undici 没有 try/catch，直接引发整个宿主未捕获异常崩溃。
 *
 * 本补丁使 Socket.prototype.setTypeOfService 全局对齐为 best-effort，吞掉 EINVAL，
 * 确保 fetch 和所有 HTTP 请求平稳进行。
 */
export function patchSocketTypeOfService() {
  if (globalThis.__dshPurgeSocketTosPatched) return;
  globalThis.__dshPurgeSocketTosPatched = true;

  try {
    const proto = net.Socket?.prototype;
    if (proto && typeof proto.setTypeOfService === "function") {
      const orig = proto.setTypeOfService;
      proto.setTypeOfService = function safeSetTypeOfService(tos) {
        try {
          return orig.call(this, tos);
        } catch (err) {
          if (
            err &&
            (err.code === "EINVAL" ||
              err.code === "ENOPROTOOPT" ||
              /setTypeOfService/i.test(String(err.message || err)))
          ) {
            return this;
          }
          throw err;
        }
      };
    }
  } catch {
    /* ignore */
  }

  try {
    if (typeof process !== "undefined" && typeof process.on === "function") {
      process.on("uncaughtException", (err) => {
        if (
          err &&
          (err.code === "EINVAL" ||
            /setTypeOfService/i.test(String(err.message || err)))
        ) {
          return;
        }
      });
    }
  } catch {
    /* ignore */
  }
}

patchSocketTypeOfService();
