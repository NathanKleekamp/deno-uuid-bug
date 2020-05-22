// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.

// This is a specialised implementation of a System module loader.

// @ts-nocheck
/* eslint-disable */
let System, __instantiateAsync, __instantiate;

(() => {
  const r = new Map();

  System = {
    register(id, d, f) {
      r.set(id, { d, f, exp: {} });
    },
  };

  async function dI(mid, src) {
    let id = mid.replace(/\.\w+$/i, "");
    if (id.includes("./")) {
      const [o, ...ia] = id.split("/").reverse(),
        [, ...sa] = src.split("/").reverse(),
        oa = [o];
      let s = 0,
        i;
      while ((i = ia.shift())) {
        if (i === "..") s++;
        else if (i === ".") break;
        else oa.push(i);
      }
      if (s < sa.length) oa.push(...sa.slice(s));
      id = oa.reverse().join("/");
    }
    return r.has(id) ? gExpA(id) : import(mid);
  }

  function gC(id, main) {
    return {
      id,
      import: (m) => dI(m, id),
      meta: { url: id, main },
    };
  }

  function gE(exp) {
    return (id, v) => {
      v = typeof id === "string" ? { [id]: v } : id;
      for (const [id, value] of Object.entries(v)) {
        Object.defineProperty(exp, id, {
          value,
          writable: true,
          enumerable: true,
        });
      }
    };
  }

  function rF(main) {
    for (const [id, m] of r.entries()) {
      const { f, exp } = m;
      const { execute: e, setters: s } = f(gE(exp), gC(id, id === main));
      delete m.f;
      m.e = e;
      m.s = s;
    }
  }

  async function gExpA(id) {
    if (!r.has(id)) return;
    const m = r.get(id);
    if (m.s) {
      const { d, e, s } = m;
      delete m.s;
      delete m.e;
      for (let i = 0; i < s.length; i++) s[i](await gExpA(d[i]));
      const r = e();
      if (r) await r;
    }
    return m.exp;
  }

  function gExp(id) {
    if (!r.has(id)) return;
    const m = r.get(id);
    if (m.s) {
      const { d, e, s } = m;
      delete m.s;
      delete m.e;
      for (let i = 0; i < s.length; i++) s[i](gExp(d[i]));
      e();
    }
    return m.exp;
  }

  __instantiateAsync = async (m) => {
    System = __instantiateAsync = __instantiate = undefined;
    rF(m);
    return gExpA(m);
  };

  __instantiate = (m) => {
    System = __instantiateAsync = __instantiate = undefined;
    rF(m);
    return gExp(m);
  };
})();

System.register(
  "https://deno.land/std@0.51.0/uuid/_common",
  [],
  function (exports_1, context_1) {
    "use strict";
    var __moduleName = context_1 && context_1.id;
    // Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
    function bytesToUuid(bytes) {
      const bits = [...bytes].map((bit) => {
        const s = bit.toString(16);
        return bit < 0x10 ? "0" + s : s;
      });
      return [
        ...bits.slice(0, 4),
        "-",
        ...bits.slice(4, 6),
        "-",
        ...bits.slice(6, 8),
        "-",
        ...bits.slice(8, 10),
        "-",
        ...bits.slice(10, 16),
      ].join("");
    }
    exports_1("bytesToUuid", bytesToUuid);
    function uuidToBytes(uuid) {
      const bytes = [];
      uuid.replace(/[a-fA-F0-9]{2}/g, (hex) => {
        bytes.push(parseInt(hex, 16));
        return "";
      });
      return bytes;
    }
    exports_1("uuidToBytes", uuidToBytes);
    function stringToBytes(str) {
      str = unescape(encodeURIComponent(str));
      const bytes = new Array(str.length);
      for (let i = 0; i < str.length; i++) {
        bytes[i] = str.charCodeAt(i);
      }
      return bytes;
    }
    exports_1("stringToBytes", stringToBytes);
    function createBuffer(content) {
      const arrayBuffer = new ArrayBuffer(content.length);
      const uint8Array = new Uint8Array(arrayBuffer);
      for (let i = 0; i < content.length; i++) {
        uint8Array[i] = content[i];
      }
      return arrayBuffer;
    }
    exports_1("createBuffer", createBuffer);
    return {
      setters: [],
      execute: function () {
      },
    };
  },
);
// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/std@0.51.0/uuid/v1",
  ["https://deno.land/std@0.51.0/uuid/_common"],
  function (exports_2, context_2) {
    "use strict";
    var _common_ts_1, UUID_RE, _nodeId, _clockseq, _lastMSecs, _lastNSecs;
    var __moduleName = context_2 && context_2.id;
    function validate(id) {
      return UUID_RE.test(id);
    }
    exports_2("validate", validate);
    function generate(options, buf, offset) {
      let i = (buf && offset) || 0;
      const b = buf || [];
      options = options || {};
      let node = options.node || _nodeId;
      let clockseq = options.clockseq !== undefined
        ? options.clockseq
        : _clockseq;
      if (node == null || clockseq == null) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const seedBytes = options.random ||
          options.rng ||
          crypto.getRandomValues(new Uint8Array(16));
        if (node == null) {
          node = _nodeId = [
            seedBytes[0] | 0x01,
            seedBytes[1],
            seedBytes[2],
            seedBytes[3],
            seedBytes[4],
            seedBytes[5],
          ];
        }
        if (clockseq == null) {
          clockseq = _clockseq = ((seedBytes[6] << 8) | seedBytes[7]) & 0x3fff;
        }
      }
      let msecs = options.msecs !== undefined
        ? options.msecs
        : new Date().getTime();
      let nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1;
      const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 10000;
      if (dt < 0 && options.clockseq === undefined) {
        clockseq = (clockseq + 1) & 0x3fff;
      }
      if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
        nsecs = 0;
      }
      if (nsecs >= 10000) {
        throw new Error("Can't create more than 10M uuids/sec");
      }
      _lastMSecs = msecs;
      _lastNSecs = nsecs;
      _clockseq = clockseq;
      msecs += 12219292800000;
      const tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
      b[i++] = (tl >>> 24) & 0xff;
      b[i++] = (tl >>> 16) & 0xff;
      b[i++] = (tl >>> 8) & 0xff;
      b[i++] = tl & 0xff;
      const tmh = ((msecs / 0x100000000) * 10000) & 0xfffffff;
      b[i++] = (tmh >>> 8) & 0xff;
      b[i++] = tmh & 0xff;
      b[i++] = ((tmh >>> 24) & 0xf) | 0x10;
      b[i++] = (tmh >>> 16) & 0xff;
      b[i++] = (clockseq >>> 8) | 0x80;
      b[i++] = clockseq & 0xff;
      for (let n = 0; n < 6; ++n) {
        b[i + n] = node[n];
      }
      return buf ? buf : _common_ts_1.bytesToUuid(b);
    }
    exports_2("generate", generate);
    return {
      setters: [
        function (_common_ts_1_1) {
          _common_ts_1 = _common_ts_1_1;
        },
      ],
      execute: function () {
        UUID_RE = new RegExp(
          "^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
          "i",
        );
        _lastMSecs = 0;
        _lastNSecs = 0;
      },
    };
  },
);
// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/std@0.51.0/uuid/v4",
  ["https://deno.land/std@0.51.0/uuid/_common"],
  function (exports_3, context_3) {
    "use strict";
    var _common_ts_2, UUID_RE;
    var __moduleName = context_3 && context_3.id;
    function validate(id) {
      return UUID_RE.test(id);
    }
    exports_3("validate", validate);
    function generate() {
      const rnds = crypto.getRandomValues(new Uint8Array(16));
      rnds[6] = (rnds[6] & 0x0f) | 0x40; // Version 4
      rnds[8] = (rnds[8] & 0x3f) | 0x80; // Variant 10
      return _common_ts_2.bytesToUuid(rnds);
    }
    exports_3("generate", generate);
    return {
      setters: [
        function (_common_ts_2_1) {
          _common_ts_2 = _common_ts_2_1;
        },
      ],
      execute: function () {
        UUID_RE = new RegExp(
          "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
          "i",
        );
      },
    };
  },
);
/*
 * [js-sha1]{@link https://github.com/emn178/js-sha1}
 *
 * @version 0.6.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2014-2017
 * @license MIT
 */
System.register(
  "https://deno.land/std@0.51.0/hash/sha1",
  [],
  function (exports_4, context_4) {
    "use strict";
    var HEX_CHARS, EXTRA, SHIFT, blocks, Sha1;
    var __moduleName = context_4 && context_4.id;
    return {
      setters: [],
      execute: function () {
        HEX_CHARS = "0123456789abcdef".split("");
        EXTRA = Uint32Array.of(-2147483648, 8388608, 32768, 128);
        SHIFT = Uint32Array.of(24, 16, 8, 0);
        blocks = new Uint32Array(80);
        Sha1 = class Sha1 {
          constructor(sharedMemory = false) {
            this.#h0 = 0x67452301;
            this.#h1 = 0xefcdab89;
            this.#h2 = 0x98badcfe;
            this.#h3 = 0x10325476;
            this.#h4 = 0xc3d2e1f0;
            this.#lastByteIndex = 0;
            if (sharedMemory) {
              this.#blocks = blocks.fill(0, 0, 17);
            } else {
              this.#blocks = new Uint32Array(80);
            }
            this.#h0 = 0x67452301;
            this.#h1 = 0xefcdab89;
            this.#h2 = 0x98badcfe;
            this.#h3 = 0x10325476;
            this.#h4 = 0xc3d2e1f0;
            this.#block = this.#start = this.#bytes = this.#hBytes = 0;
            this.#finalized = this.#hashed = false;
          }
          #blocks;
          #block;
          #start;
          #bytes;
          #hBytes;
          #finalized;
          #hashed;
          #h0;
          #h1;
          #h2;
          #h3;
          #h4;
          #lastByteIndex;
          update(data) {
            if (this.#finalized) {
              return this;
            }
            let notString = true;
            let message;
            if (data instanceof ArrayBuffer) {
              message = new Uint8Array(data);
            } else if (ArrayBuffer.isView(data)) {
              message = new Uint8Array(data.buffer);
            } else {
              notString = false;
              message = String(data);
            }
            let code;
            let index = 0;
            let i;
            const start = this.#start;
            const length = message.length || 0;
            const blocks = this.#blocks;
            while (index < length) {
              if (this.#hashed) {
                this.#hashed = false;
                blocks[0] = this.#block;
                blocks.fill(0, 1, 17);
              }
              if (notString) {
                for (i = start; index < length && i < 64; ++index) {
                  blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
                }
              } else {
                for (i = start; index < length && i < 64; ++index) {
                  code = message.charCodeAt(index);
                  if (code < 0x80) {
                    blocks[i >> 2] |= code << SHIFT[i++ & 3];
                  } else if (code < 0x800) {
                    blocks[i >> 2] |= (0xc0 | (code >> 6)) << SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                  } else if (code < 0xd800 || code >= 0xe000) {
                    blocks[i >> 2] |= (0xe0 | (code >> 12)) << SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) <<
                      SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                  } else {
                    code = 0x10000 +
                      (((code & 0x3ff) << 10) |
                        (message.charCodeAt(++index) & 0x3ff));
                    blocks[i >> 2] |= (0xf0 | (code >> 18)) << SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) <<
                      SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) <<
                      SHIFT[i++ & 3];
                    blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                  }
                }
              }
              this.#lastByteIndex = i;
              this.#bytes += i - start;
              if (i >= 64) {
                this.#block = blocks[16];
                this.#start = i - 64;
                this.hash();
                this.#hashed = true;
              } else {
                this.#start = i;
              }
            }
            if (this.#bytes > 4294967295) {
              this.#hBytes += (this.#bytes / 4294967296) >>> 0;
              this.#bytes = this.#bytes >>> 0;
            }
            return this;
          }
          finalize() {
            if (this.#finalized) {
              return;
            }
            this.#finalized = true;
            const blocks = this.#blocks;
            const i = this.#lastByteIndex;
            blocks[16] = this.#block;
            blocks[i >> 2] |= EXTRA[i & 3];
            this.#block = blocks[16];
            if (i >= 56) {
              if (!this.#hashed) {
                this.hash();
              }
              blocks[0] = this.#block;
              blocks.fill(0, 1, 17);
            }
            blocks[14] = (this.#hBytes << 3) | (this.#bytes >>> 29);
            blocks[15] = this.#bytes << 3;
            this.hash();
          }
          hash() {
            let a = this.#h0;
            let b = this.#h1;
            let c = this.#h2;
            let d = this.#h3;
            let e = this.#h4;
            let f, j, t;
            const blocks = this.#blocks;
            for (j = 16; j < 80; ++j) {
              t = blocks[j - 3] ^ blocks[j - 8] ^ blocks[j - 14] ^
                blocks[j - 16];
              blocks[j] = (t << 1) | (t >>> 31);
            }
            for (j = 0; j < 20; j += 5) {
              f = (b & c) | (~b & d);
              t = (a << 5) | (a >>> 27);
              e = (t + f + e + 1518500249 + blocks[j]) >>> 0;
              b = (b << 30) | (b >>> 2);
              f = (a & b) | (~a & c);
              t = (e << 5) | (e >>> 27);
              d = (t + f + d + 1518500249 + blocks[j + 1]) >>> 0;
              a = (a << 30) | (a >>> 2);
              f = (e & a) | (~e & b);
              t = (d << 5) | (d >>> 27);
              c = (t + f + c + 1518500249 + blocks[j + 2]) >>> 0;
              e = (e << 30) | (e >>> 2);
              f = (d & e) | (~d & a);
              t = (c << 5) | (c >>> 27);
              b = (t + f + b + 1518500249 + blocks[j + 3]) >>> 0;
              d = (d << 30) | (d >>> 2);
              f = (c & d) | (~c & e);
              t = (b << 5) | (b >>> 27);
              a = (t + f + a + 1518500249 + blocks[j + 4]) >>> 0;
              c = (c << 30) | (c >>> 2);
            }
            for (; j < 40; j += 5) {
              f = b ^ c ^ d;
              t = (a << 5) | (a >>> 27);
              e = (t + f + e + 1859775393 + blocks[j]) >>> 0;
              b = (b << 30) | (b >>> 2);
              f = a ^ b ^ c;
              t = (e << 5) | (e >>> 27);
              d = (t + f + d + 1859775393 + blocks[j + 1]) >>> 0;
              a = (a << 30) | (a >>> 2);
              f = e ^ a ^ b;
              t = (d << 5) | (d >>> 27);
              c = (t + f + c + 1859775393 + blocks[j + 2]) >>> 0;
              e = (e << 30) | (e >>> 2);
              f = d ^ e ^ a;
              t = (c << 5) | (c >>> 27);
              b = (t + f + b + 1859775393 + blocks[j + 3]) >>> 0;
              d = (d << 30) | (d >>> 2);
              f = c ^ d ^ e;
              t = (b << 5) | (b >>> 27);
              a = (t + f + a + 1859775393 + blocks[j + 4]) >>> 0;
              c = (c << 30) | (c >>> 2);
            }
            for (; j < 60; j += 5) {
              f = (b & c) | (b & d) | (c & d);
              t = (a << 5) | (a >>> 27);
              e = (t + f + e - 1894007588 + blocks[j]) >>> 0;
              b = (b << 30) | (b >>> 2);
              f = (a & b) | (a & c) | (b & c);
              t = (e << 5) | (e >>> 27);
              d = (t + f + d - 1894007588 + blocks[j + 1]) >>> 0;
              a = (a << 30) | (a >>> 2);
              f = (e & a) | (e & b) | (a & b);
              t = (d << 5) | (d >>> 27);
              c = (t + f + c - 1894007588 + blocks[j + 2]) >>> 0;
              e = (e << 30) | (e >>> 2);
              f = (d & e) | (d & a) | (e & a);
              t = (c << 5) | (c >>> 27);
              b = (t + f + b - 1894007588 + blocks[j + 3]) >>> 0;
              d = (d << 30) | (d >>> 2);
              f = (c & d) | (c & e) | (d & e);
              t = (b << 5) | (b >>> 27);
              a = (t + f + a - 1894007588 + blocks[j + 4]) >>> 0;
              c = (c << 30) | (c >>> 2);
            }
            for (; j < 80; j += 5) {
              f = b ^ c ^ d;
              t = (a << 5) | (a >>> 27);
              e = (t + f + e - 899497514 + blocks[j]) >>> 0;
              b = (b << 30) | (b >>> 2);
              f = a ^ b ^ c;
              t = (e << 5) | (e >>> 27);
              d = (t + f + d - 899497514 + blocks[j + 1]) >>> 0;
              a = (a << 30) | (a >>> 2);
              f = e ^ a ^ b;
              t = (d << 5) | (d >>> 27);
              c = (t + f + c - 899497514 + blocks[j + 2]) >>> 0;
              e = (e << 30) | (e >>> 2);
              f = d ^ e ^ a;
              t = (c << 5) | (c >>> 27);
              b = (t + f + b - 899497514 + blocks[j + 3]) >>> 0;
              d = (d << 30) | (d >>> 2);
              f = c ^ d ^ e;
              t = (b << 5) | (b >>> 27);
              a = (t + f + a - 899497514 + blocks[j + 4]) >>> 0;
              c = (c << 30) | (c >>> 2);
            }
            this.#h0 = (this.#h0 + a) >>> 0;
            this.#h1 = (this.#h1 + b) >>> 0;
            this.#h2 = (this.#h2 + c) >>> 0;
            this.#h3 = (this.#h3 + d) >>> 0;
            this.#h4 = (this.#h4 + e) >>> 0;
          }
          hex() {
            this.finalize();
            const h0 = this.#h0;
            const h1 = this.#h1;
            const h2 = this.#h2;
            const h3 = this.#h3;
            const h4 = this.#h4;
            return (HEX_CHARS[(h0 >> 28) & 0x0f] +
              HEX_CHARS[(h0 >> 24) & 0x0f] +
              HEX_CHARS[(h0 >> 20) & 0x0f] +
              HEX_CHARS[(h0 >> 16) & 0x0f] +
              HEX_CHARS[(h0 >> 12) & 0x0f] +
              HEX_CHARS[(h0 >> 8) & 0x0f] +
              HEX_CHARS[(h0 >> 4) & 0x0f] +
              HEX_CHARS[h0 & 0x0f] +
              HEX_CHARS[(h1 >> 28) & 0x0f] +
              HEX_CHARS[(h1 >> 24) & 0x0f] +
              HEX_CHARS[(h1 >> 20) & 0x0f] +
              HEX_CHARS[(h1 >> 16) & 0x0f] +
              HEX_CHARS[(h1 >> 12) & 0x0f] +
              HEX_CHARS[(h1 >> 8) & 0x0f] +
              HEX_CHARS[(h1 >> 4) & 0x0f] +
              HEX_CHARS[h1 & 0x0f] +
              HEX_CHARS[(h2 >> 28) & 0x0f] +
              HEX_CHARS[(h2 >> 24) & 0x0f] +
              HEX_CHARS[(h2 >> 20) & 0x0f] +
              HEX_CHARS[(h2 >> 16) & 0x0f] +
              HEX_CHARS[(h2 >> 12) & 0x0f] +
              HEX_CHARS[(h2 >> 8) & 0x0f] +
              HEX_CHARS[(h2 >> 4) & 0x0f] +
              HEX_CHARS[h2 & 0x0f] +
              HEX_CHARS[(h3 >> 28) & 0x0f] +
              HEX_CHARS[(h3 >> 24) & 0x0f] +
              HEX_CHARS[(h3 >> 20) & 0x0f] +
              HEX_CHARS[(h3 >> 16) & 0x0f] +
              HEX_CHARS[(h3 >> 12) & 0x0f] +
              HEX_CHARS[(h3 >> 8) & 0x0f] +
              HEX_CHARS[(h3 >> 4) & 0x0f] +
              HEX_CHARS[h3 & 0x0f] +
              HEX_CHARS[(h4 >> 28) & 0x0f] +
              HEX_CHARS[(h4 >> 24) & 0x0f] +
              HEX_CHARS[(h4 >> 20) & 0x0f] +
              HEX_CHARS[(h4 >> 16) & 0x0f] +
              HEX_CHARS[(h4 >> 12) & 0x0f] +
              HEX_CHARS[(h4 >> 8) & 0x0f] +
              HEX_CHARS[(h4 >> 4) & 0x0f] +
              HEX_CHARS[h4 & 0x0f]);
          }
          toString() {
            return this.hex();
          }
          digest() {
            this.finalize();
            const h0 = this.#h0;
            const h1 = this.#h1;
            const h2 = this.#h2;
            const h3 = this.#h3;
            const h4 = this.#h4;
            return [
              (h0 >> 24) & 0xff,
              (h0 >> 16) & 0xff,
              (h0 >> 8) & 0xff,
              h0 & 0xff,
              (h1 >> 24) & 0xff,
              (h1 >> 16) & 0xff,
              (h1 >> 8) & 0xff,
              h1 & 0xff,
              (h2 >> 24) & 0xff,
              (h2 >> 16) & 0xff,
              (h2 >> 8) & 0xff,
              h2 & 0xff,
              (h3 >> 24) & 0xff,
              (h3 >> 16) & 0xff,
              (h3 >> 8) & 0xff,
              h3 & 0xff,
              (h4 >> 24) & 0xff,
              (h4 >> 16) & 0xff,
              (h4 >> 8) & 0xff,
              h4 & 0xff,
            ];
          }
          array() {
            return this.digest();
          }
          arrayBuffer() {
            this.finalize();
            return Uint32Array.of(
              this.#h0,
              this.#h1,
              this.#h2,
              this.#h3,
              this.#h4,
            )
              .buffer;
          }
        };
        exports_4("Sha1", Sha1);
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.51.0/node/util",
  [],
  function (exports_5, context_5) {
    "use strict";
    var __moduleName = context_5 && context_5.id;
    function isArray(value) {
      return Array.isArray(value);
    }
    exports_5("isArray", isArray);
    function isBoolean(value) {
      return typeof value === "boolean" || value instanceof Boolean;
    }
    exports_5("isBoolean", isBoolean);
    function isNull(value) {
      return value === null;
    }
    exports_5("isNull", isNull);
    function isNullOrUndefined(value) {
      return value === null || value === undefined;
    }
    exports_5("isNullOrUndefined", isNullOrUndefined);
    function isNumber(value) {
      return typeof value === "number" || value instanceof Number;
    }
    exports_5("isNumber", isNumber);
    function isString(value) {
      return typeof value === "string" || value instanceof String;
    }
    exports_5("isString", isString);
    function isSymbol(value) {
      return typeof value === "symbol";
    }
    exports_5("isSymbol", isSymbol);
    function isUndefined(value) {
      return value === undefined;
    }
    exports_5("isUndefined", isUndefined);
    function isObject(value) {
      return value !== null && typeof value === "object";
    }
    exports_5("isObject", isObject);
    function isError(e) {
      return e instanceof Error;
    }
    exports_5("isError", isError);
    function isFunction(value) {
      return typeof value === "function";
    }
    exports_5("isFunction", isFunction);
    function isRegExp(value) {
      return value instanceof RegExp;
    }
    exports_5("isRegExp", isRegExp);
    function isPrimitive(value) {
      return (value === null ||
        (typeof value !== "object" && typeof value !== "function"));
    }
    exports_5("isPrimitive", isPrimitive);
    function validateIntegerRange(
      value,
      name,
      min = -2147483648,
      max = 2147483647,
    ) {
      // The defaults for min and max correspond to the limits of 32-bit integers.
      if (!Number.isInteger(value)) {
        throw new Error(`${name} must be 'an integer' but was ${value}`);
      }
      if (value < min || value > max) {
        throw new Error(
          `${name} must be >= ${min} && <= ${max}.  Value was ${value}`,
        );
      }
    }
    exports_5("validateIntegerRange", validateIntegerRange);
    return {
      setters: [],
      execute: function () {
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.51.0/fmt/colors",
  [],
  function (exports_6, context_6) {
    "use strict";
    var noColor, enabled;
    var __moduleName = context_6 && context_6.id;
    function setColorEnabled(value) {
      if (noColor) {
        return;
      }
      enabled = value;
    }
    exports_6("setColorEnabled", setColorEnabled);
    function getColorEnabled() {
      return enabled;
    }
    exports_6("getColorEnabled", getColorEnabled);
    function code(open, close) {
      return {
        open: `\x1b[${open.join(";")}m`,
        close: `\x1b[${close}m`,
        regexp: new RegExp(`\\x1b\\[${close}m`, "g"),
      };
    }
    function run(str, code) {
      return enabled
        ? `${code.open}${str.replace(code.regexp, code.open)}${code.close}`
        : str;
    }
    function reset(str) {
      return run(str, code([0], 0));
    }
    exports_6("reset", reset);
    function bold(str) {
      return run(str, code([1], 22));
    }
    exports_6("bold", bold);
    function dim(str) {
      return run(str, code([2], 22));
    }
    exports_6("dim", dim);
    function italic(str) {
      return run(str, code([3], 23));
    }
    exports_6("italic", italic);
    function underline(str) {
      return run(str, code([4], 24));
    }
    exports_6("underline", underline);
    function inverse(str) {
      return run(str, code([7], 27));
    }
    exports_6("inverse", inverse);
    function hidden(str) {
      return run(str, code([8], 28));
    }
    exports_6("hidden", hidden);
    function strikethrough(str) {
      return run(str, code([9], 29));
    }
    exports_6("strikethrough", strikethrough);
    function black(str) {
      return run(str, code([30], 39));
    }
    exports_6("black", black);
    function red(str) {
      return run(str, code([31], 39));
    }
    exports_6("red", red);
    function green(str) {
      return run(str, code([32], 39));
    }
    exports_6("green", green);
    function yellow(str) {
      return run(str, code([33], 39));
    }
    exports_6("yellow", yellow);
    function blue(str) {
      return run(str, code([34], 39));
    }
    exports_6("blue", blue);
    function magenta(str) {
      return run(str, code([35], 39));
    }
    exports_6("magenta", magenta);
    function cyan(str) {
      return run(str, code([36], 39));
    }
    exports_6("cyan", cyan);
    function white(str) {
      return run(str, code([37], 39));
    }
    exports_6("white", white);
    function gray(str) {
      return run(str, code([90], 39));
    }
    exports_6("gray", gray);
    function bgBlack(str) {
      return run(str, code([40], 49));
    }
    exports_6("bgBlack", bgBlack);
    function bgRed(str) {
      return run(str, code([41], 49));
    }
    exports_6("bgRed", bgRed);
    function bgGreen(str) {
      return run(str, code([42], 49));
    }
    exports_6("bgGreen", bgGreen);
    function bgYellow(str) {
      return run(str, code([43], 49));
    }
    exports_6("bgYellow", bgYellow);
    function bgBlue(str) {
      return run(str, code([44], 49));
    }
    exports_6("bgBlue", bgBlue);
    function bgMagenta(str) {
      return run(str, code([45], 49));
    }
    exports_6("bgMagenta", bgMagenta);
    function bgCyan(str) {
      return run(str, code([46], 49));
    }
    exports_6("bgCyan", bgCyan);
    function bgWhite(str) {
      return run(str, code([47], 49));
    }
    exports_6("bgWhite", bgWhite);
    /* Special Color Sequences */
    function clampAndTruncate(n, max = 255, min = 0) {
      return Math.trunc(Math.max(Math.min(n, max), min));
    }
    /** Set text color using paletted 8bit colors.
     * https://en.wikipedia.org/wiki/ANSI_escape_code#8-bit */
    function rgb8(str, color) {
      return run(str, code([38, 5, clampAndTruncate(color)], 39));
    }
    exports_6("rgb8", rgb8);
    /** Set background color using paletted 8bit colors.
     * https://en.wikipedia.org/wiki/ANSI_escape_code#8-bit */
    function bgRgb8(str, color) {
      return run(str, code([48, 5, clampAndTruncate(color)], 49));
    }
    exports_6("bgRgb8", bgRgb8);
    /** Set text color using 24bit rgb. */
    function rgb24(str, color) {
      return run(
        str,
        code([
          38,
          2,
          clampAndTruncate(color.r),
          clampAndTruncate(color.g),
          clampAndTruncate(color.b),
        ], 39),
      );
    }
    exports_6("rgb24", rgb24);
    /** Set background color using 24bit rgb. */
    function bgRgb24(str, color) {
      return run(
        str,
        code([
          48,
          2,
          clampAndTruncate(color.r),
          clampAndTruncate(color.g),
          clampAndTruncate(color.b),
        ], 49),
      );
    }
    exports_6("bgRgb24", bgRgb24);
    return {
      setters: [],
      execute: function () {
        // Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
        /**
             * A module to print ANSI terminal colors. Inspired by chalk, kleur, and colors
             * on npm.
             *
             * ```
             * import { bgBlue, red, bold } from "https://deno.land/std/fmt/colors.ts";
             * console.log(bgBlue(red(bold("Hello world!"))));
             * ```
             *
             * This module supports `NO_COLOR` environmental variable disabling any coloring
             * if `NO_COLOR` is set.
             */
        noColor = Deno.noColor;
        enabled = !noColor;
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.51.0/testing/diff",
  [],
  function (exports_7, context_7) {
    "use strict";
    var DiffType, REMOVED, COMMON, ADDED;
    var __moduleName = context_7 && context_7.id;
    function createCommon(A, B, reverse) {
      const common = [];
      if (A.length === 0 || B.length === 0) {
        return [];
      }
      for (let i = 0; i < Math.min(A.length, B.length); i += 1) {
        if (
          A[reverse ? A.length - i - 1 : i] ===
            B[reverse ? B.length - i - 1 : i]
        ) {
          common.push(A[reverse ? A.length - i - 1 : i]);
        } else {
          return common;
        }
      }
      return common;
    }
    function diff(A, B) {
      const prefixCommon = createCommon(A, B);
      const suffixCommon = createCommon(
        A.slice(prefixCommon.length),
        B.slice(prefixCommon.length),
        true,
      ).reverse();
      A = suffixCommon.length
        ? A.slice(prefixCommon.length, -suffixCommon.length)
        : A.slice(prefixCommon.length);
      B = suffixCommon.length
        ? B.slice(prefixCommon.length, -suffixCommon.length)
        : B.slice(prefixCommon.length);
      const swapped = B.length > A.length;
      [A, B] = swapped ? [B, A] : [A, B];
      const M = A.length;
      const N = B.length;
      if (!M && !N && !suffixCommon.length && !prefixCommon.length) {
        return [];
      }
      if (!N) {
        return [
          ...prefixCommon.map((c) => ({ type: DiffType.common, value: c })),
          ...A.map((a) => ({
            type: swapped ? DiffType.added : DiffType.removed,
            value: a,
          })),
          ...suffixCommon.map((c) => ({ type: DiffType.common, value: c })),
        ];
      }
      const offset = N;
      const delta = M - N;
      const size = M + N + 1;
      const fp = new Array(size).fill({ y: -1 });
      /**
         * INFO:
         * This buffer is used to save memory and improve performance.
         * The first half is used to save route and last half is used to save diff
         * type.
         * This is because, when I kept new uint8array area to save type,performance
         * worsened.
         */
      const routes = new Uint32Array((M * N + size + 1) * 2);
      const diffTypesPtrOffset = routes.length / 2;
      let ptr = 0;
      let p = -1;
      function backTrace(A, B, current, swapped) {
        const M = A.length;
        const N = B.length;
        const result = [];
        let a = M - 1;
        let b = N - 1;
        let j = routes[current.id];
        let type = routes[current.id + diffTypesPtrOffset];
        while (true) {
          if (!j && !type) {
            break;
          }
          const prev = j;
          if (type === REMOVED) {
            result.unshift({
              type: swapped ? DiffType.removed : DiffType.added,
              value: B[b],
            });
            b -= 1;
          } else if (type === ADDED) {
            result.unshift({
              type: swapped ? DiffType.added : DiffType.removed,
              value: A[a],
            });
            a -= 1;
          } else {
            result.unshift({ type: DiffType.common, value: A[a] });
            a -= 1;
            b -= 1;
          }
          j = routes[prev];
          type = routes[prev + diffTypesPtrOffset];
        }
        return result;
      }
      function createFP(slide, down, k, M) {
        if (slide && slide.y === -1 && down && down.y === -1) {
          return { y: 0, id: 0 };
        }
        if (
          (down && down.y === -1) ||
          k === M ||
          (slide && slide.y) > (down && down.y) + 1
        ) {
          const prev = slide.id;
          ptr++;
          routes[ptr] = prev;
          routes[ptr + diffTypesPtrOffset] = ADDED;
          return { y: slide.y, id: ptr };
        } else {
          const prev = down.id;
          ptr++;
          routes[ptr] = prev;
          routes[ptr + diffTypesPtrOffset] = REMOVED;
          return { y: down.y + 1, id: ptr };
        }
      }
      function snake(k, slide, down, _offset, A, B) {
        const M = A.length;
        const N = B.length;
        if (k < -N || M < k) {
          return { y: -1, id: -1 };
        }
        const fp = createFP(slide, down, k, M);
        while (fp.y + k < M && fp.y < N && A[fp.y + k] === B[fp.y]) {
          const prev = fp.id;
          ptr++;
          fp.id = ptr;
          fp.y += 1;
          routes[ptr] = prev;
          routes[ptr + diffTypesPtrOffset] = COMMON;
        }
        return fp;
      }
      while (fp[delta + offset].y < N) {
        p = p + 1;
        for (let k = -p; k < delta; ++k) {
          fp[k + offset] = snake(
            k,
            fp[k - 1 + offset],
            fp[k + 1 + offset],
            offset,
            A,
            B,
          );
        }
        for (let k = delta + p; k > delta; --k) {
          fp[k + offset] = snake(
            k,
            fp[k - 1 + offset],
            fp[k + 1 + offset],
            offset,
            A,
            B,
          );
        }
        fp[delta + offset] = snake(
          delta,
          fp[delta - 1 + offset],
          fp[delta + 1 + offset],
          offset,
          A,
          B,
        );
      }
      return [
        ...prefixCommon.map((c) => ({ type: DiffType.common, value: c })),
        ...backTrace(A, B, fp[delta + offset], swapped),
        ...suffixCommon.map((c) => ({ type: DiffType.common, value: c })),
      ];
    }
    exports_7("default", diff);
    return {
      setters: [],
      execute: function () {
        (function (DiffType) {
          DiffType["removed"] = "removed";
          DiffType["common"] = "common";
          DiffType["added"] = "added";
        })(DiffType || (DiffType = {}));
        exports_7("DiffType", DiffType);
        REMOVED = 1;
        COMMON = 2;
        ADDED = 3;
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.51.0/testing/asserts",
  [
    "https://deno.land/std@0.51.0/fmt/colors",
    "https://deno.land/std@0.51.0/testing/diff",
  ],
  function (exports_8, context_8) {
    "use strict";
    var colors_ts_1, diff_ts_1, CAN_NOT_DISPLAY, AssertionError;
    var __moduleName = context_8 && context_8.id;
    function format(v) {
      let string = Deno.inspect(v);
      if (typeof v == "string") {
        string = `"${string.replace(/(?=["\\])/g, "\\")}"`;
      }
      return string;
    }
    function createColor(diffType) {
      switch (diffType) {
        case diff_ts_1.DiffType.added:
          return (s) => colors_ts_1.green(colors_ts_1.bold(s));
        case diff_ts_1.DiffType.removed:
          return (s) => colors_ts_1.red(colors_ts_1.bold(s));
        default:
          return colors_ts_1.white;
      }
    }
    function createSign(diffType) {
      switch (diffType) {
        case diff_ts_1.DiffType.added:
          return "+   ";
        case diff_ts_1.DiffType.removed:
          return "-   ";
        default:
          return "    ";
      }
    }
    function buildMessage(diffResult) {
      const messages = [];
      messages.push("");
      messages.push("");
      messages.push(
        `    ${colors_ts_1.gray(colors_ts_1.bold("[Diff]"))} ${
          colors_ts_1.red(colors_ts_1.bold("Actual"))
        } / ${colors_ts_1.green(colors_ts_1.bold("Expected"))}`,
      );
      messages.push("");
      messages.push("");
      diffResult.forEach((result) => {
        const c = createColor(result.type);
        messages.push(c(`${createSign(result.type)}${result.value}`));
      });
      messages.push("");
      return messages;
    }
    function isKeyedCollection(x) {
      return [Symbol.iterator, "size"].every((k) => k in x);
    }
    function equal(c, d) {
      const seen = new Map();
      return (function compare(a, b) {
        // Have to render RegExp & Date for string comparison
        // unless it's mistreated as object
        if (
          a &&
          b &&
          ((a instanceof RegExp && b instanceof RegExp) ||
            (a instanceof Date && b instanceof Date))
        ) {
          return String(a) === String(b);
        }
        if (Object.is(a, b)) {
          return true;
        }
        if (a && typeof a === "object" && b && typeof b === "object") {
          if (seen.get(a) === b) {
            return true;
          }
          if (Object.keys(a || {}).length !== Object.keys(b || {}).length) {
            return false;
          }
          if (isKeyedCollection(a) && isKeyedCollection(b)) {
            if (a.size !== b.size) {
              return false;
            }
            let unmatchedEntries = a.size;
            for (const [aKey, aValue] of a.entries()) {
              for (const [bKey, bValue] of b.entries()) {
                /* Given that Map keys can be references, we need
                             * to ensure that they are also deeply equal */
                if (
                  (aKey === aValue && bKey === bValue && compare(aKey, bKey)) ||
                  (compare(aKey, bKey) && compare(aValue, bValue))
                ) {
                  unmatchedEntries--;
                }
              }
            }
            return unmatchedEntries === 0;
          }
          const merged = { ...a, ...b };
          for (const key in merged) {
            if (!compare(a && a[key], b && b[key])) {
              return false;
            }
          }
          seen.set(a, b);
          return true;
        }
        return false;
      })(c, d);
    }
    exports_8("equal", equal);
    /** Make an assertion, if not `true`, then throw. */
    function assert(expr, msg = "") {
      if (!expr) {
        throw new AssertionError(msg);
      }
    }
    exports_8("assert", assert);
    /**
     * Make an assertion that `actual` and `expected` are equal, deeply. If not
     * deeply equal, then throw.
     */
    function assertEquals(actual, expected, msg) {
      if (equal(actual, expected)) {
        return;
      }
      let message = "";
      const actualString = format(actual);
      const expectedString = format(expected);
      try {
        const diffResult = diff_ts_1.default(
          actualString.split("\n"),
          expectedString.split("\n"),
        );
        message = buildMessage(diffResult).join("\n");
      } catch (e) {
        message = `\n${colors_ts_1.red(CAN_NOT_DISPLAY)} + \n\n`;
      }
      if (msg) {
        message = msg;
      }
      throw new AssertionError(message);
    }
    exports_8("assertEquals", assertEquals);
    /**
     * Make an assertion that `actual` and `expected` are not equal, deeply.
     * If not then throw.
     */
    function assertNotEquals(actual, expected, msg) {
      if (!equal(actual, expected)) {
        return;
      }
      let actualString;
      let expectedString;
      try {
        actualString = String(actual);
      } catch (e) {
        actualString = "[Cannot display]";
      }
      try {
        expectedString = String(expected);
      } catch (e) {
        expectedString = "[Cannot display]";
      }
      if (!msg) {
        msg = `actual: ${actualString} expected: ${expectedString}`;
      }
      throw new AssertionError(msg);
    }
    exports_8("assertNotEquals", assertNotEquals);
    /**
     * Make an assertion that `actual` and `expected` are strictly equal.  If
     * not then throw.
     */
    function assertStrictEq(actual, expected, msg) {
      if (actual !== expected) {
        let actualString;
        let expectedString;
        try {
          actualString = String(actual);
        } catch (e) {
          actualString = "[Cannot display]";
        }
        try {
          expectedString = String(expected);
        } catch (e) {
          expectedString = "[Cannot display]";
        }
        if (!msg) {
          msg = `actual: ${actualString} expected: ${expectedString}`;
        }
        throw new AssertionError(msg);
      }
    }
    exports_8("assertStrictEq", assertStrictEq);
    /**
     * Make an assertion that actual contains expected. If not
     * then thrown.
     */
    function assertStrContains(actual, expected, msg) {
      if (!actual.includes(expected)) {
        if (!msg) {
          msg = `actual: "${actual}" expected to contains: "${expected}"`;
        }
        throw new AssertionError(msg);
      }
    }
    exports_8("assertStrContains", assertStrContains);
    /**
     * Make an assertion that `actual` contains the `expected` values
     * If not then thrown.
     */
    function assertArrayContains(actual, expected, msg) {
      const missing = [];
      for (let i = 0; i < expected.length; i++) {
        let found = false;
        for (let j = 0; j < actual.length; j++) {
          if (equal(expected[i], actual[j])) {
            found = true;
            break;
          }
        }
        if (!found) {
          missing.push(expected[i]);
        }
      }
      if (missing.length === 0) {
        return;
      }
      if (!msg) {
        msg = `actual: "${actual}" expected to contains: "${expected}"`;
        msg += "\n";
        msg += `missing: ${missing}`;
      }
      throw new AssertionError(msg);
    }
    exports_8("assertArrayContains", assertArrayContains);
    /**
     * Make an assertion that `actual` match RegExp `expected`. If not
     * then thrown
     */
    function assertMatch(actual, expected, msg) {
      if (!expected.test(actual)) {
        if (!msg) {
          msg = `actual: "${actual}" expected to match: "${expected}"`;
        }
        throw new AssertionError(msg);
      }
    }
    exports_8("assertMatch", assertMatch);
    /**
     * Forcefully throws a failed assertion
     */
    function fail(msg) {
      // eslint-disable-next-line @typescript-eslint/no-use-before-define
      assert(false, `Failed assertion${msg ? `: ${msg}` : "."}`);
    }
    exports_8("fail", fail);
    /** Executes a function, expecting it to throw.  If it does not, then it
     * throws.  An error class and a string that should be included in the
     * error message can also be asserted.
     */
    function assertThrows(fn, ErrorClass, msgIncludes = "", msg) {
      let doesThrow = false;
      let error = null;
      try {
        fn();
      } catch (e) {
        if (
          ErrorClass && !(Object.getPrototypeOf(e) === ErrorClass.prototype)
        ) {
          msg =
            `Expected error to be instance of "${ErrorClass.name}", but was "${e.constructor.name}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        if (msgIncludes && !e.message.includes(msgIncludes)) {
          msg =
            `Expected error message to include "${msgIncludes}", but got "${e.message}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        doesThrow = true;
        error = e;
      }
      if (!doesThrow) {
        msg = `Expected function to throw${msg ? `: ${msg}` : "."}`;
        throw new AssertionError(msg);
      }
      return error;
    }
    exports_8("assertThrows", assertThrows);
    async function assertThrowsAsync(fn, ErrorClass, msgIncludes = "", msg) {
      let doesThrow = false;
      let error = null;
      try {
        await fn();
      } catch (e) {
        if (
          ErrorClass && !(Object.getPrototypeOf(e) === ErrorClass.prototype)
        ) {
          msg =
            `Expected error to be instance of "${ErrorClass.name}", but got "${e.name}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        if (msgIncludes && !e.message.includes(msgIncludes)) {
          msg =
            `Expected error message to include "${msgIncludes}", but got "${e.message}"${
              msg ? `: ${msg}` : "."
            }`;
          throw new AssertionError(msg);
        }
        doesThrow = true;
        error = e;
      }
      if (!doesThrow) {
        msg = `Expected function to throw${msg ? `: ${msg}` : "."}`;
        throw new AssertionError(msg);
      }
      return error;
    }
    exports_8("assertThrowsAsync", assertThrowsAsync);
    /** Use this to stub out methods that will throw when invoked. */
    function unimplemented(msg) {
      throw new AssertionError(msg || "unimplemented");
    }
    exports_8("unimplemented", unimplemented);
    /** Use this to assert unreachable code. */
    function unreachable() {
      throw new AssertionError("unreachable");
    }
    exports_8("unreachable", unreachable);
    return {
      setters: [
        function (colors_ts_1_1) {
          colors_ts_1 = colors_ts_1_1;
        },
        function (diff_ts_1_1) {
          diff_ts_1 = diff_ts_1_1;
        },
      ],
      execute: function () {
        CAN_NOT_DISPLAY = "[Cannot display]";
        AssertionError = class AssertionError extends Error {
          constructor(message) {
            super(message);
            this.name = "AssertionError";
          }
        };
        exports_8("AssertionError", AssertionError);
      },
    };
  },
);
// Copyright 2018-2020 the Deno authors. All rights reserved. MIT license.
System.register(
  "https://deno.land/std@0.51.0/uuid/v5",
  [
    "https://deno.land/std@0.51.0/uuid/_common",
    "https://deno.land/std@0.51.0/hash/sha1",
    "https://deno.land/std@0.51.0/node/util",
    "https://deno.land/std@0.51.0/testing/asserts",
  ],
  function (exports_9, context_9) {
    "use strict";
    var _common_ts_3, sha1_ts_1, util_ts_1, asserts_ts_1, UUID_RE;
    var __moduleName = context_9 && context_9.id;
    function validate(id) {
      return UUID_RE.test(id);
    }
    exports_9("validate", validate);
    function generate(options, buf, offset) {
      const i = (buf && offset) || 0;
      let { value, namespace } = options;
      if (util_ts_1.isString(value)) {
        value = _common_ts_3.stringToBytes(value);
      }
      if (util_ts_1.isString(namespace)) {
        namespace = _common_ts_3.uuidToBytes(namespace);
      }
      asserts_ts_1.assert(
        namespace.length === 16,
        "namespace must be uuid string or an Array of 16 byte values",
      );
      const content = namespace.concat(value);
      const bytes = new sha1_ts_1.Sha1().update(
        _common_ts_3.createBuffer(content),
      ).digest();
      bytes[6] = (bytes[6] & 0x0f) | 0x50;
      bytes[8] = (bytes[8] & 0x3f) | 0x80;
      if (buf) {
        for (let idx = 0; idx < 16; ++idx) {
          buf[i + idx] = bytes[idx];
        }
      }
      return buf || _common_ts_3.bytesToUuid(bytes);
    }
    exports_9("generate", generate);
    return {
      setters: [
        function (_common_ts_3_1) {
          _common_ts_3 = _common_ts_3_1;
        },
        function (sha1_ts_1_1) {
          sha1_ts_1 = sha1_ts_1_1;
        },
        function (util_ts_1_1) {
          util_ts_1 = util_ts_1_1;
        },
        function (asserts_ts_1_1) {
          asserts_ts_1 = asserts_ts_1_1;
        },
      ],
      execute: function () {
        UUID_RE =
          /^[0-9a-f]{8}-[0-9a-f]{4}-[5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      },
    };
  },
);
System.register(
  "https://deno.land/std@0.51.0/uuid/mod",
  [
    "https://deno.land/std@0.51.0/uuid/v1",
    "https://deno.land/std@0.51.0/uuid/v4",
    "https://deno.land/std@0.51.0/uuid/v5",
  ],
  function (exports_10, context_10) {
    "use strict";
    var v1, v4, v5, NIL_UUID, NOT_IMPLEMENTED, v3;
    var __moduleName = context_10 && context_10.id;
    function isNil(val) {
      return val === NIL_UUID;
    }
    exports_10("isNil", isNil);
    return {
      setters: [
        function (v1_1) {
          v1 = v1_1;
        },
        function (v4_1) {
          v4 = v4_1;
        },
        function (v5_1) {
          v5 = v5_1;
        },
      ],
      execute: function () {
        exports_10("v1", v1);
        exports_10("v4", v4);
        exports_10("v5", v5);
        exports_10(
          "NIL_UUID",
          NIL_UUID = "00000000-0000-0000-0000-000000000000",
        );
        NOT_IMPLEMENTED = {
          generate() {
            throw new Error("Not implemented");
          },
          validate() {
            throw new Error("Not implemented");
          },
        };
        // TODO Implement
        exports_10("v3", v3 = NOT_IMPLEMENTED);
      },
    };
  },
);
System.register(
  "file:///Users/nathan/Projects/Deno/uuid-bug/index",
  ["https://deno.land/std@0.51.0/uuid/mod"],
  function (exports_11, context_11) {
    "use strict";
    var mod_ts_1, uuid;
    var __moduleName = context_11 && context_11.id;
    return {
      setters: [
        function (mod_ts_1_1) {
          mod_ts_1 = mod_ts_1_1;
        },
      ],
      execute: function () {
        uuid = mod_ts_1.v4.generate();
        console.log("uuid", uuid);
      },
    };
  },
);

__instantiate("file:///Users/nathan/Projects/Deno/uuid-bug/index");
