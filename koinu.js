/* koinu.dog - loads koinu.wasm and calls into it
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 bluezr
 *
 * The module imports four wasi calls and nothing else. random_get is
 * crypto.getRandomValues; fd_write sends stdout and stderr to the console; the
 * other two are never reached by the exported functions and refuse.
 *
 *   const k = await koinu.load("koinu.wasm");
 *   k.call("kwj_bits", 0x1e0ffff0)   // -> { exponent, mantissa, target, work, ... }
 *
 * Strings are copied in NUL-terminated and freed after the call; numbers pass
 * as they are. Every kwj_ function returns JSON, parsed here. */
(function (root) {
  "use strict";

  function wasi(get) {
    const enc = new TextDecoder();
    return {
      random_get(ptr, len) {
        const b = new Uint8Array(get().buffer, ptr, len);
        for (let o = 0; o < len; o += 65536) crypto.getRandomValues(b.subarray(o, Math.min(len, o + 65536)));
        return 0;
      },
      fd_write(fd, iovs, n, nwritten) {
        const mem = get(), dv = new DataView(mem.buffer);
        let total = 0, s = "";
        for (let i = 0; i < n; i++) {
          const p = dv.getUint32(iovs + i * 8, true), l = dv.getUint32(iovs + i * 8 + 4, true);
          s += enc.decode(new Uint8Array(mem.buffer, p, l));
          total += l;
        }
        (fd === 2 ? console.warn : console.log)(s.replace(/\n$/, ""));
        dv.setUint32(nwritten, total, true);
        return 0;
      },
      fd_close() { return 8; },   /* EBADF */
      fd_seek()  { return 8; },
    };
  }

  async function load(src) {
    let memory = null;
    const imports = { wasi_snapshot_preview1: wasi(() => memory) };
    let inst;
    if (typeof src === "string") {
      const r = await fetch(src);
      if (!r.ok) throw new Error("koinu.wasm: " + r.status);
      inst = (await WebAssembly.instantiate(await r.arrayBuffer(), imports)).instance;
    } else {
      inst = (await WebAssembly.instantiate(src, imports)).instance;
    }
    const x = inst.exports;
    memory = x.memory;
    x._initialize();
    if (!x.kwj_start()) throw new Error("koinu: no randomness for the curve context");

    const te = new TextEncoder(), td = new TextDecoder();
    function call(name, ...args) {
      const held = [];
      const raw = args.map((a) => {
        if (typeof a !== "string") return a;
        const b = te.encode(a);
        const p = x.kwj_alloc(b.length + 1);
        const m = new Uint8Array(memory.buffer, p, b.length + 1);
        m.set(b); m[b.length] = 0;
        held.push([p, b.length + 1]);
        return p;
      });
      try {
        const p = x[name](...raw);
        return JSON.parse(td.decode(new Uint8Array(memory.buffer, p, x.kwj_len())));
      } finally {
        /* inputs may be passphrases: zero them before they go back to malloc */
        for (const [p, l] of held) { new Uint8Array(memory.buffer, p, l).fill(0); x.kwj_free(p); }
      }
    }
    return { call, exports: x };
  }

  root.koinu = { load };
  if (typeof module !== "undefined") module.exports = root.koinu;
})(typeof window !== "undefined" ? window : globalThis);
