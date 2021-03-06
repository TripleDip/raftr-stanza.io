window.XMPP = (function(e) {
    var t = {};
    function n(i) {
        if (t[i]) return t[i].exports;
        var r = (t[i] = { i: i, l: !1, exports: {} });
        return e[i].call(r.exports, r, r.exports, n), (r.l = !0), r.exports;
    }
    return (
        (n.m = e),
        (n.c = t),
        (n.d = function(e, t, i) {
            n.o(e, t) || Object.defineProperty(e, t, { enumerable: !0, get: i });
        }),
        (n.r = function(e) {
            'undefined' != typeof Symbol &&
                Symbol.toStringTag &&
                Object.defineProperty(e, Symbol.toStringTag, { value: 'Module' }),
                Object.defineProperty(e, '__esModule', { value: !0 });
        }),
        (n.t = function(e, t) {
            if ((1 & t && (e = n(e)), 8 & t)) return e;
            if (4 & t && 'object' == typeof e && e && e.__esModule) return e;
            var i = Object.create(null);
            if (
                (n.r(i),
                Object.defineProperty(i, 'default', { enumerable: !0, value: e }),
                2 & t && 'string' != typeof e)
            )
                for (var r in e)
                    n.d(
                        i,
                        r,
                        function(t) {
                            return e[t];
                        }.bind(null, r)
                    );
            return i;
        }),
        (n.n = function(e) {
            var t =
                e && e.__esModule
                    ? function() {
                          return e.default;
                      }
                    : function() {
                          return e;
                      };
            return n.d(t, 'a', t), t;
        }),
        (n.o = function(e, t) {
            return Object.prototype.hasOwnProperty.call(e, t);
        }),
        (n.p = ''),
        n((n.s = 42))
    );
})([
    function(e, t) {
        'function' == typeof Object.create
            ? (e.exports = function(e, t) {
                  (e.super_ = t),
                      (e.prototype = Object.create(t.prototype, {
                          constructor: { value: e, enumerable: !1, writable: !0, configurable: !0 }
                      }));
              })
            : (e.exports = function(e, t) {
                  e.super_ = t;
                  var n = function() {};
                  (n.prototype = t.prototype),
                      (e.prototype = new n()),
                      (e.prototype.constructor = e);
              });
    },
    function(e, t, n) {
        var i = n(2),
            r = i.Buffer;
        function s(e, t) {
            for (var n in e) t[n] = e[n];
        }
        function o(e, t, n) {
            return r(e, t, n);
        }
        r.from && r.alloc && r.allocUnsafe && r.allocUnsafeSlow
            ? (e.exports = i)
            : (s(i, t), (t.Buffer = o)),
            s(r, o),
            (o.from = function(e, t, n) {
                if ('number' == typeof e) throw new TypeError('Argument must not be a number');
                return r(e, t, n);
            }),
            (o.alloc = function(e, t, n) {
                if ('number' != typeof e) throw new TypeError('Argument must be a number');
                var i = r(e);
                return (
                    void 0 !== t ? ('string' == typeof n ? i.fill(t, n) : i.fill(t)) : i.fill(0), i
                );
            }),
            (o.allocUnsafe = function(e) {
                if ('number' != typeof e) throw new TypeError('Argument must be a number');
                return r(e);
            }),
            (o.allocUnsafeSlow = function(e) {
                if ('number' != typeof e) throw new TypeError('Argument must be a number');
                return i.SlowBuffer(e);
            });
    },
    function(e, t, n) {
        'use strict';
        (function(e) {
            /*!
             * The buffer module from node.js, for the browser.
             *
             * @author   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
             * @license  MIT
             */
            var i = n(43),
                r = n(44),
                s = n(20);
            function o() {
                return u.TYPED_ARRAY_SUPPORT ? 2147483647 : 1073741823;
            }
            function a(e, t) {
                if (o() < t) throw new RangeError('Invalid typed array length');
                return (
                    u.TYPED_ARRAY_SUPPORT
                        ? ((e = new Uint8Array(t)).__proto__ = u.prototype)
                        : (null === e && (e = new u(t)), (e.length = t)),
                    e
                );
            }
            function u(e, t, n) {
                if (!(u.TYPED_ARRAY_SUPPORT || this instanceof u)) return new u(e, t, n);
                if ('number' == typeof e) {
                    if ('string' == typeof t)
                        throw new Error(
                            'If encoding is specified then the first argument must be a string'
                        );
                    return f(this, e);
                }
                return c(this, e, t, n);
            }
            function c(e, t, n, i) {
                if ('number' == typeof t)
                    throw new TypeError('"value" argument must not be a number');
                return 'undefined' != typeof ArrayBuffer && t instanceof ArrayBuffer
                    ? (function(e, t, n, i) {
                          if ((t.byteLength, n < 0 || t.byteLength < n))
                              throw new RangeError("'offset' is out of bounds");
                          if (t.byteLength < n + (i || 0))
                              throw new RangeError("'length' is out of bounds");
                          t =
                              void 0 === n && void 0 === i
                                  ? new Uint8Array(t)
                                  : void 0 === i
                                  ? new Uint8Array(t, n)
                                  : new Uint8Array(t, n, i);
                          u.TYPED_ARRAY_SUPPORT ? ((e = t).__proto__ = u.prototype) : (e = d(e, t));
                          return e;
                      })(e, t, n, i)
                    : 'string' == typeof t
                    ? (function(e, t, n) {
                          ('string' == typeof n && '' !== n) || (n = 'utf8');
                          if (!u.isEncoding(n))
                              throw new TypeError('"encoding" must be a valid string encoding');
                          var i = 0 | p(t, n),
                              r = (e = a(e, i)).write(t, n);
                          r !== i && (e = e.slice(0, r));
                          return e;
                      })(e, t, n)
                    : (function(e, t) {
                          if (u.isBuffer(t)) {
                              var n = 0 | h(t.length);
                              return 0 === (e = a(e, n)).length ? e : (t.copy(e, 0, 0, n), e);
                          }
                          if (t) {
                              if (
                                  ('undefined' != typeof ArrayBuffer &&
                                      t.buffer instanceof ArrayBuffer) ||
                                  'length' in t
                              )
                                  return 'number' != typeof t.length || (i = t.length) != i
                                      ? a(e, 0)
                                      : d(e, t);
                              if ('Buffer' === t.type && s(t.data)) return d(e, t.data);
                          }
                          var i;
                          throw new TypeError(
                              'First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.'
                          );
                      })(e, t);
            }
            function l(e) {
                if ('number' != typeof e) throw new TypeError('"size" argument must be a number');
                if (e < 0) throw new RangeError('"size" argument must not be negative');
            }
            function f(e, t) {
                if ((l(t), (e = a(e, t < 0 ? 0 : 0 | h(t))), !u.TYPED_ARRAY_SUPPORT))
                    for (var n = 0; n < t; ++n) e[n] = 0;
                return e;
            }
            function d(e, t) {
                var n = t.length < 0 ? 0 : 0 | h(t.length);
                e = a(e, n);
                for (var i = 0; i < n; i += 1) e[i] = 255 & t[i];
                return e;
            }
            function h(e) {
                if (e >= o())
                    throw new RangeError(
                        'Attempt to allocate Buffer larger than maximum size: 0x' +
                            o().toString(16) +
                            ' bytes'
                    );
                return 0 | e;
            }
            function p(e, t) {
                if (u.isBuffer(e)) return e.length;
                if (
                    'undefined' != typeof ArrayBuffer &&
                    'function' == typeof ArrayBuffer.isView &&
                    (ArrayBuffer.isView(e) || e instanceof ArrayBuffer)
                )
                    return e.byteLength;
                'string' != typeof e && (e = '' + e);
                var n = e.length;
                if (0 === n) return 0;
                for (var i = !1; ; )
                    switch (t) {
                        case 'ascii':
                        case 'latin1':
                        case 'binary':
                            return n;
                        case 'utf8':
                        case 'utf-8':
                        case void 0:
                            return F(e).length;
                        case 'ucs2':
                        case 'ucs-2':
                        case 'utf16le':
                        case 'utf-16le':
                            return 2 * n;
                        case 'hex':
                            return n >>> 1;
                        case 'base64':
                            return U(e).length;
                        default:
                            if (i) return F(e).length;
                            (t = ('' + t).toLowerCase()), (i = !0);
                    }
            }
            function m(e, t, n) {
                var i = e[t];
                (e[t] = e[n]), (e[n] = i);
            }
            function g(e, t, n, i, r) {
                if (0 === e.length) return -1;
                if (
                    ('string' == typeof n
                        ? ((i = n), (n = 0))
                        : n > 2147483647
                        ? (n = 2147483647)
                        : n < -2147483648 && (n = -2147483648),
                    (n = +n),
                    isNaN(n) && (n = r ? 0 : e.length - 1),
                    n < 0 && (n = e.length + n),
                    n >= e.length)
                ) {
                    if (r) return -1;
                    n = e.length - 1;
                } else if (n < 0) {
                    if (!r) return -1;
                    n = 0;
                }
                if (('string' == typeof t && (t = u.from(t, i)), u.isBuffer(t)))
                    return 0 === t.length ? -1 : b(e, t, n, i, r);
                if ('number' == typeof t)
                    return (
                        (t &= 255),
                        u.TYPED_ARRAY_SUPPORT && 'function' == typeof Uint8Array.prototype.indexOf
                            ? r
                                ? Uint8Array.prototype.indexOf.call(e, t, n)
                                : Uint8Array.prototype.lastIndexOf.call(e, t, n)
                            : b(e, [t], n, i, r)
                    );
                throw new TypeError('val must be string, number or Buffer');
            }
            function b(e, t, n, i, r) {
                var s,
                    o = 1,
                    a = e.length,
                    u = t.length;
                if (
                    void 0 !== i &&
                    ('ucs2' === (i = String(i).toLowerCase()) ||
                        'ucs-2' === i ||
                        'utf16le' === i ||
                        'utf-16le' === i)
                ) {
                    if (e.length < 2 || t.length < 2) return -1;
                    (o = 2), (a /= 2), (u /= 2), (n /= 2);
                }
                function c(e, t) {
                    return 1 === o ? e[t] : e.readUInt16BE(t * o);
                }
                if (r) {
                    var l = -1;
                    for (s = n; s < a; s++)
                        if (c(e, s) === c(t, -1 === l ? 0 : s - l)) {
                            if ((-1 === l && (l = s), s - l + 1 === u)) return l * o;
                        } else -1 !== l && (s -= s - l), (l = -1);
                } else
                    for (n + u > a && (n = a - u), s = n; s >= 0; s--) {
                        for (var f = !0, d = 0; d < u; d++)
                            if (c(e, s + d) !== c(t, d)) {
                                f = !1;
                                break;
                            }
                        if (f) return s;
                    }
                return -1;
            }
            function y(e, t, n, i) {
                n = Number(n) || 0;
                var r = e.length - n;
                i ? (i = Number(i)) > r && (i = r) : (i = r);
                var s = t.length;
                if (s % 2 != 0) throw new TypeError('Invalid hex string');
                i > s / 2 && (i = s / 2);
                for (var o = 0; o < i; ++o) {
                    var a = parseInt(t.substr(2 * o, 2), 16);
                    if (isNaN(a)) return o;
                    e[n + o] = a;
                }
                return o;
            }
            function v(e, t, n, i) {
                return z(F(t, e.length - n), e, n, i);
            }
            function x(e, t, n, i) {
                return z(
                    (function(e) {
                        for (var t = [], n = 0; n < e.length; ++n) t.push(255 & e.charCodeAt(n));
                        return t;
                    })(t),
                    e,
                    n,
                    i
                );
            }
            function w(e, t, n, i) {
                return x(e, t, n, i);
            }
            function _(e, t, n, i) {
                return z(U(t), e, n, i);
            }
            function S(e, t, n, i) {
                return z(
                    (function(e, t) {
                        for (var n, i, r, s = [], o = 0; o < e.length && !((t -= 2) < 0); ++o)
                            (n = e.charCodeAt(o)),
                                (i = n >> 8),
                                (r = n % 256),
                                s.push(r),
                                s.push(i);
                        return s;
                    })(t, e.length - n),
                    e,
                    n,
                    i
                );
            }
            function A(e, t, n) {
                return 0 === t && n === e.length
                    ? i.fromByteArray(e)
                    : i.fromByteArray(e.slice(t, n));
            }
            function E(e, t, n) {
                n = Math.min(e.length, n);
                for (var i = [], r = t; r < n; ) {
                    var s,
                        o,
                        a,
                        u,
                        c = e[r],
                        l = null,
                        f = c > 239 ? 4 : c > 223 ? 3 : c > 191 ? 2 : 1;
                    if (r + f <= n)
                        switch (f) {
                            case 1:
                                c < 128 && (l = c);
                                break;
                            case 2:
                                128 == (192 & (s = e[r + 1])) &&
                                    (u = ((31 & c) << 6) | (63 & s)) > 127 &&
                                    (l = u);
                                break;
                            case 3:
                                (s = e[r + 1]),
                                    (o = e[r + 2]),
                                    128 == (192 & s) &&
                                        128 == (192 & o) &&
                                        (u = ((15 & c) << 12) | ((63 & s) << 6) | (63 & o)) >
                                            2047 &&
                                        (u < 55296 || u > 57343) &&
                                        (l = u);
                                break;
                            case 4:
                                (s = e[r + 1]),
                                    (o = e[r + 2]),
                                    (a = e[r + 3]),
                                    128 == (192 & s) &&
                                        128 == (192 & o) &&
                                        128 == (192 & a) &&
                                        (u =
                                            ((15 & c) << 18) |
                                            ((63 & s) << 12) |
                                            ((63 & o) << 6) |
                                            (63 & a)) > 65535 &&
                                        u < 1114112 &&
                                        (l = u);
                        }
                    null === l
                        ? ((l = 65533), (f = 1))
                        : l > 65535 &&
                          ((l -= 65536),
                          i.push(((l >>> 10) & 1023) | 55296),
                          (l = 56320 | (1023 & l))),
                        i.push(l),
                        (r += f);
                }
                return (function(e) {
                    var t = e.length;
                    if (t <= I) return String.fromCharCode.apply(String, e);
                    var n = '',
                        i = 0;
                    for (; i < t; ) n += String.fromCharCode.apply(String, e.slice(i, (i += I)));
                    return n;
                })(i);
            }
            (t.Buffer = u),
                (t.SlowBuffer = function(e) {
                    +e != e && (e = 0);
                    return u.alloc(+e);
                }),
                (t.INSPECT_MAX_BYTES = 50),
                (u.TYPED_ARRAY_SUPPORT =
                    void 0 !== e.TYPED_ARRAY_SUPPORT
                        ? e.TYPED_ARRAY_SUPPORT
                        : (function() {
                              try {
                                  var e = new Uint8Array(1);
                                  return (
                                      (e.__proto__ = {
                                          __proto__: Uint8Array.prototype,
                                          foo: function() {
                                              return 42;
                                          }
                                      }),
                                      42 === e.foo() &&
                                          'function' == typeof e.subarray &&
                                          0 === e.subarray(1, 1).byteLength
                                  );
                              } catch (e) {
                                  return !1;
                              }
                          })()),
                (t.kMaxLength = o()),
                (u.poolSize = 8192),
                (u._augment = function(e) {
                    return (e.__proto__ = u.prototype), e;
                }),
                (u.from = function(e, t, n) {
                    return c(null, e, t, n);
                }),
                u.TYPED_ARRAY_SUPPORT &&
                    ((u.prototype.__proto__ = Uint8Array.prototype),
                    (u.__proto__ = Uint8Array),
                    'undefined' != typeof Symbol &&
                        Symbol.species &&
                        u[Symbol.species] === u &&
                        Object.defineProperty(u, Symbol.species, {
                            value: null,
                            configurable: !0
                        })),
                (u.alloc = function(e, t, n) {
                    return (function(e, t, n, i) {
                        return (
                            l(t),
                            t <= 0
                                ? a(e, t)
                                : void 0 !== n
                                ? 'string' == typeof i
                                    ? a(e, t).fill(n, i)
                                    : a(e, t).fill(n)
                                : a(e, t)
                        );
                    })(null, e, t, n);
                }),
                (u.allocUnsafe = function(e) {
                    return f(null, e);
                }),
                (u.allocUnsafeSlow = function(e) {
                    return f(null, e);
                }),
                (u.isBuffer = function(e) {
                    return !(null == e || !e._isBuffer);
                }),
                (u.compare = function(e, t) {
                    if (!u.isBuffer(e) || !u.isBuffer(t))
                        throw new TypeError('Arguments must be Buffers');
                    if (e === t) return 0;
                    for (var n = e.length, i = t.length, r = 0, s = Math.min(n, i); r < s; ++r)
                        if (e[r] !== t[r]) {
                            (n = e[r]), (i = t[r]);
                            break;
                        }
                    return n < i ? -1 : i < n ? 1 : 0;
                }),
                (u.isEncoding = function(e) {
                    switch (String(e).toLowerCase()) {
                        case 'hex':
                        case 'utf8':
                        case 'utf-8':
                        case 'ascii':
                        case 'latin1':
                        case 'binary':
                        case 'base64':
                        case 'ucs2':
                        case 'ucs-2':
                        case 'utf16le':
                        case 'utf-16le':
                            return !0;
                        default:
                            return !1;
                    }
                }),
                (u.concat = function(e, t) {
                    if (!s(e)) throw new TypeError('"list" argument must be an Array of Buffers');
                    if (0 === e.length) return u.alloc(0);
                    var n;
                    if (void 0 === t) for (t = 0, n = 0; n < e.length; ++n) t += e[n].length;
                    var i = u.allocUnsafe(t),
                        r = 0;
                    for (n = 0; n < e.length; ++n) {
                        var o = e[n];
                        if (!u.isBuffer(o))
                            throw new TypeError('"list" argument must be an Array of Buffers');
                        o.copy(i, r), (r += o.length);
                    }
                    return i;
                }),
                (u.byteLength = p),
                (u.prototype._isBuffer = !0),
                (u.prototype.swap16 = function() {
                    var e = this.length;
                    if (e % 2 != 0)
                        throw new RangeError('Buffer size must be a multiple of 16-bits');
                    for (var t = 0; t < e; t += 2) m(this, t, t + 1);
                    return this;
                }),
                (u.prototype.swap32 = function() {
                    var e = this.length;
                    if (e % 4 != 0)
                        throw new RangeError('Buffer size must be a multiple of 32-bits');
                    for (var t = 0; t < e; t += 4) m(this, t, t + 3), m(this, t + 1, t + 2);
                    return this;
                }),
                (u.prototype.swap64 = function() {
                    var e = this.length;
                    if (e % 8 != 0)
                        throw new RangeError('Buffer size must be a multiple of 64-bits');
                    for (var t = 0; t < e; t += 8)
                        m(this, t, t + 7),
                            m(this, t + 1, t + 6),
                            m(this, t + 2, t + 5),
                            m(this, t + 3, t + 4);
                    return this;
                }),
                (u.prototype.toString = function() {
                    var e = 0 | this.length;
                    return 0 === e
                        ? ''
                        : 0 === arguments.length
                        ? E(this, 0, e)
                        : function(e, t, n) {
                              var i = !1;
                              if (((void 0 === t || t < 0) && (t = 0), t > this.length)) return '';
                              if (((void 0 === n || n > this.length) && (n = this.length), n <= 0))
                                  return '';
                              if ((n >>>= 0) <= (t >>>= 0)) return '';
                              for (e || (e = 'utf8'); ; )
                                  switch (e) {
                                      case 'hex':
                                          return T(this, t, n);
                                      case 'utf8':
                                      case 'utf-8':
                                          return E(this, t, n);
                                      case 'ascii':
                                          return j(this, t, n);
                                      case 'latin1':
                                      case 'binary':
                                          return k(this, t, n);
                                      case 'base64':
                                          return A(this, t, n);
                                      case 'ucs2':
                                      case 'ucs-2':
                                      case 'utf16le':
                                      case 'utf-16le':
                                          return C(this, t, n);
                                      default:
                                          if (i) throw new TypeError('Unknown encoding: ' + e);
                                          (e = (e + '').toLowerCase()), (i = !0);
                                  }
                          }.apply(this, arguments);
                }),
                (u.prototype.equals = function(e) {
                    if (!u.isBuffer(e)) throw new TypeError('Argument must be a Buffer');
                    return this === e || 0 === u.compare(this, e);
                }),
                (u.prototype.inspect = function() {
                    var e = '',
                        n = t.INSPECT_MAX_BYTES;
                    return (
                        this.length > 0 &&
                            ((e = this.toString('hex', 0, n)
                                .match(/.{2}/g)
                                .join(' ')),
                            this.length > n && (e += ' ... ')),
                        '<Buffer ' + e + '>'
                    );
                }),
                (u.prototype.compare = function(e, t, n, i, r) {
                    if (!u.isBuffer(e)) throw new TypeError('Argument must be a Buffer');
                    if (
                        (void 0 === t && (t = 0),
                        void 0 === n && (n = e ? e.length : 0),
                        void 0 === i && (i = 0),
                        void 0 === r && (r = this.length),
                        t < 0 || n > e.length || i < 0 || r > this.length)
                    )
                        throw new RangeError('out of range index');
                    if (i >= r && t >= n) return 0;
                    if (i >= r) return -1;
                    if (t >= n) return 1;
                    if (this === e) return 0;
                    for (
                        var s = (r >>>= 0) - (i >>>= 0),
                            o = (n >>>= 0) - (t >>>= 0),
                            a = Math.min(s, o),
                            c = this.slice(i, r),
                            l = e.slice(t, n),
                            f = 0;
                        f < a;
                        ++f
                    )
                        if (c[f] !== l[f]) {
                            (s = c[f]), (o = l[f]);
                            break;
                        }
                    return s < o ? -1 : o < s ? 1 : 0;
                }),
                (u.prototype.includes = function(e, t, n) {
                    return -1 !== this.indexOf(e, t, n);
                }),
                (u.prototype.indexOf = function(e, t, n) {
                    return g(this, e, t, n, !0);
                }),
                (u.prototype.lastIndexOf = function(e, t, n) {
                    return g(this, e, t, n, !1);
                }),
                (u.prototype.write = function(e, t, n, i) {
                    if (void 0 === t) (i = 'utf8'), (n = this.length), (t = 0);
                    else if (void 0 === n && 'string' == typeof t)
                        (i = t), (n = this.length), (t = 0);
                    else {
                        if (!isFinite(t))
                            throw new Error(
                                'Buffer.write(string, encoding, offset[, length]) is no longer supported'
                            );
                        (t |= 0),
                            isFinite(n)
                                ? ((n |= 0), void 0 === i && (i = 'utf8'))
                                : ((i = n), (n = void 0));
                    }
                    var r = this.length - t;
                    if (
                        ((void 0 === n || n > r) && (n = r),
                        (e.length > 0 && (n < 0 || t < 0)) || t > this.length)
                    )
                        throw new RangeError('Attempt to write outside buffer bounds');
                    i || (i = 'utf8');
                    for (var s = !1; ; )
                        switch (i) {
                            case 'hex':
                                return y(this, e, t, n);
                            case 'utf8':
                            case 'utf-8':
                                return v(this, e, t, n);
                            case 'ascii':
                                return x(this, e, t, n);
                            case 'latin1':
                            case 'binary':
                                return w(this, e, t, n);
                            case 'base64':
                                return _(this, e, t, n);
                            case 'ucs2':
                            case 'ucs-2':
                            case 'utf16le':
                            case 'utf-16le':
                                return S(this, e, t, n);
                            default:
                                if (s) throw new TypeError('Unknown encoding: ' + i);
                                (i = ('' + i).toLowerCase()), (s = !0);
                        }
                }),
                (u.prototype.toJSON = function() {
                    return {
                        type: 'Buffer',
                        data: Array.prototype.slice.call(this._arr || this, 0)
                    };
                });
            var I = 4096;
            function j(e, t, n) {
                var i = '';
                n = Math.min(e.length, n);
                for (var r = t; r < n; ++r) i += String.fromCharCode(127 & e[r]);
                return i;
            }
            function k(e, t, n) {
                var i = '';
                n = Math.min(e.length, n);
                for (var r = t; r < n; ++r) i += String.fromCharCode(e[r]);
                return i;
            }
            function T(e, t, n) {
                var i = e.length;
                (!t || t < 0) && (t = 0), (!n || n < 0 || n > i) && (n = i);
                for (var r = '', s = t; s < n; ++s) r += q(e[s]);
                return r;
            }
            function C(e, t, n) {
                for (var i = e.slice(t, n), r = '', s = 0; s < i.length; s += 2)
                    r += String.fromCharCode(i[s] + 256 * i[s + 1]);
                return r;
            }
            function R(e, t, n) {
                if (e % 1 != 0 || e < 0) throw new RangeError('offset is not uint');
                if (e + t > n) throw new RangeError('Trying to access beyond buffer length');
            }
            function P(e, t, n, i, r, s) {
                if (!u.isBuffer(e))
                    throw new TypeError('"buffer" argument must be a Buffer instance');
                if (t > r || t < s) throw new RangeError('"value" argument is out of bounds');
                if (n + i > e.length) throw new RangeError('Index out of range');
            }
            function O(e, t, n, i) {
                t < 0 && (t = 65535 + t + 1);
                for (var r = 0, s = Math.min(e.length - n, 2); r < s; ++r)
                    e[n + r] = (t & (255 << (8 * (i ? r : 1 - r)))) >>> (8 * (i ? r : 1 - r));
            }
            function L(e, t, n, i) {
                t < 0 && (t = 4294967295 + t + 1);
                for (var r = 0, s = Math.min(e.length - n, 4); r < s; ++r)
                    e[n + r] = (t >>> (8 * (i ? r : 3 - r))) & 255;
            }
            function M(e, t, n, i, r, s) {
                if (n + i > e.length) throw new RangeError('Index out of range');
                if (n < 0) throw new RangeError('Index out of range');
            }
            function B(e, t, n, i, s) {
                return s || M(e, 0, n, 4), r.write(e, t, n, i, 23, 4), n + 4;
            }
            function D(e, t, n, i, s) {
                return s || M(e, 0, n, 8), r.write(e, t, n, i, 52, 8), n + 8;
            }
            (u.prototype.slice = function(e, t) {
                var n,
                    i = this.length;
                if (
                    ((e = ~~e) < 0 ? (e += i) < 0 && (e = 0) : e > i && (e = i),
                    (t = void 0 === t ? i : ~~t) < 0 ? (t += i) < 0 && (t = 0) : t > i && (t = i),
                    t < e && (t = e),
                    u.TYPED_ARRAY_SUPPORT)
                )
                    (n = this.subarray(e, t)).__proto__ = u.prototype;
                else {
                    var r = t - e;
                    n = new u(r, void 0);
                    for (var s = 0; s < r; ++s) n[s] = this[s + e];
                }
                return n;
            }),
                (u.prototype.readUIntLE = function(e, t, n) {
                    (e |= 0), (t |= 0), n || R(e, t, this.length);
                    for (var i = this[e], r = 1, s = 0; ++s < t && (r *= 256); )
                        i += this[e + s] * r;
                    return i;
                }),
                (u.prototype.readUIntBE = function(e, t, n) {
                    (e |= 0), (t |= 0), n || R(e, t, this.length);
                    for (var i = this[e + --t], r = 1; t > 0 && (r *= 256); )
                        i += this[e + --t] * r;
                    return i;
                }),
                (u.prototype.readUInt8 = function(e, t) {
                    return t || R(e, 1, this.length), this[e];
                }),
                (u.prototype.readUInt16LE = function(e, t) {
                    return t || R(e, 2, this.length), this[e] | (this[e + 1] << 8);
                }),
                (u.prototype.readUInt16BE = function(e, t) {
                    return t || R(e, 2, this.length), (this[e] << 8) | this[e + 1];
                }),
                (u.prototype.readUInt32LE = function(e, t) {
                    return (
                        t || R(e, 4, this.length),
                        (this[e] | (this[e + 1] << 8) | (this[e + 2] << 16)) +
                            16777216 * this[e + 3]
                    );
                }),
                (u.prototype.readUInt32BE = function(e, t) {
                    return (
                        t || R(e, 4, this.length),
                        16777216 * this[e] +
                            ((this[e + 1] << 16) | (this[e + 2] << 8) | this[e + 3])
                    );
                }),
                (u.prototype.readIntLE = function(e, t, n) {
                    (e |= 0), (t |= 0), n || R(e, t, this.length);
                    for (var i = this[e], r = 1, s = 0; ++s < t && (r *= 256); )
                        i += this[e + s] * r;
                    return i >= (r *= 128) && (i -= Math.pow(2, 8 * t)), i;
                }),
                (u.prototype.readIntBE = function(e, t, n) {
                    (e |= 0), (t |= 0), n || R(e, t, this.length);
                    for (var i = t, r = 1, s = this[e + --i]; i > 0 && (r *= 256); )
                        s += this[e + --i] * r;
                    return s >= (r *= 128) && (s -= Math.pow(2, 8 * t)), s;
                }),
                (u.prototype.readInt8 = function(e, t) {
                    return (
                        t || R(e, 1, this.length),
                        128 & this[e] ? -1 * (255 - this[e] + 1) : this[e]
                    );
                }),
                (u.prototype.readInt16LE = function(e, t) {
                    t || R(e, 2, this.length);
                    var n = this[e] | (this[e + 1] << 8);
                    return 32768 & n ? 4294901760 | n : n;
                }),
                (u.prototype.readInt16BE = function(e, t) {
                    t || R(e, 2, this.length);
                    var n = this[e + 1] | (this[e] << 8);
                    return 32768 & n ? 4294901760 | n : n;
                }),
                (u.prototype.readInt32LE = function(e, t) {
                    return (
                        t || R(e, 4, this.length),
                        this[e] | (this[e + 1] << 8) | (this[e + 2] << 16) | (this[e + 3] << 24)
                    );
                }),
                (u.prototype.readInt32BE = function(e, t) {
                    return (
                        t || R(e, 4, this.length),
                        (this[e] << 24) | (this[e + 1] << 16) | (this[e + 2] << 8) | this[e + 3]
                    );
                }),
                (u.prototype.readFloatLE = function(e, t) {
                    return t || R(e, 4, this.length), r.read(this, e, !0, 23, 4);
                }),
                (u.prototype.readFloatBE = function(e, t) {
                    return t || R(e, 4, this.length), r.read(this, e, !1, 23, 4);
                }),
                (u.prototype.readDoubleLE = function(e, t) {
                    return t || R(e, 8, this.length), r.read(this, e, !0, 52, 8);
                }),
                (u.prototype.readDoubleBE = function(e, t) {
                    return t || R(e, 8, this.length), r.read(this, e, !1, 52, 8);
                }),
                (u.prototype.writeUIntLE = function(e, t, n, i) {
                    ((e = +e), (t |= 0), (n |= 0), i) ||
                        P(this, e, t, n, Math.pow(2, 8 * n) - 1, 0);
                    var r = 1,
                        s = 0;
                    for (this[t] = 255 & e; ++s < n && (r *= 256); ) this[t + s] = (e / r) & 255;
                    return t + n;
                }),
                (u.prototype.writeUIntBE = function(e, t, n, i) {
                    ((e = +e), (t |= 0), (n |= 0), i) ||
                        P(this, e, t, n, Math.pow(2, 8 * n) - 1, 0);
                    var r = n - 1,
                        s = 1;
                    for (this[t + r] = 255 & e; --r >= 0 && (s *= 256); )
                        this[t + r] = (e / s) & 255;
                    return t + n;
                }),
                (u.prototype.writeUInt8 = function(e, t, n) {
                    return (
                        (e = +e),
                        (t |= 0),
                        n || P(this, e, t, 1, 255, 0),
                        u.TYPED_ARRAY_SUPPORT || (e = Math.floor(e)),
                        (this[t] = 255 & e),
                        t + 1
                    );
                }),
                (u.prototype.writeUInt16LE = function(e, t, n) {
                    return (
                        (e = +e),
                        (t |= 0),
                        n || P(this, e, t, 2, 65535, 0),
                        u.TYPED_ARRAY_SUPPORT
                            ? ((this[t] = 255 & e), (this[t + 1] = e >>> 8))
                            : O(this, e, t, !0),
                        t + 2
                    );
                }),
                (u.prototype.writeUInt16BE = function(e, t, n) {
                    return (
                        (e = +e),
                        (t |= 0),
                        n || P(this, e, t, 2, 65535, 0),
                        u.TYPED_ARRAY_SUPPORT
                            ? ((this[t] = e >>> 8), (this[t + 1] = 255 & e))
                            : O(this, e, t, !1),
                        t + 2
                    );
                }),
                (u.prototype.writeUInt32LE = function(e, t, n) {
                    return (
                        (e = +e),
                        (t |= 0),
                        n || P(this, e, t, 4, 4294967295, 0),
                        u.TYPED_ARRAY_SUPPORT
                            ? ((this[t + 3] = e >>> 24),
                              (this[t + 2] = e >>> 16),
                              (this[t + 1] = e >>> 8),
                              (this[t] = 255 & e))
                            : L(this, e, t, !0),
                        t + 4
                    );
                }),
                (u.prototype.writeUInt32BE = function(e, t, n) {
                    return (
                        (e = +e),
                        (t |= 0),
                        n || P(this, e, t, 4, 4294967295, 0),
                        u.TYPED_ARRAY_SUPPORT
                            ? ((this[t] = e >>> 24),
                              (this[t + 1] = e >>> 16),
                              (this[t + 2] = e >>> 8),
                              (this[t + 3] = 255 & e))
                            : L(this, e, t, !1),
                        t + 4
                    );
                }),
                (u.prototype.writeIntLE = function(e, t, n, i) {
                    if (((e = +e), (t |= 0), !i)) {
                        var r = Math.pow(2, 8 * n - 1);
                        P(this, e, t, n, r - 1, -r);
                    }
                    var s = 0,
                        o = 1,
                        a = 0;
                    for (this[t] = 255 & e; ++s < n && (o *= 256); )
                        e < 0 && 0 === a && 0 !== this[t + s - 1] && (a = 1),
                            (this[t + s] = (((e / o) >> 0) - a) & 255);
                    return t + n;
                }),
                (u.prototype.writeIntBE = function(e, t, n, i) {
                    if (((e = +e), (t |= 0), !i)) {
                        var r = Math.pow(2, 8 * n - 1);
                        P(this, e, t, n, r - 1, -r);
                    }
                    var s = n - 1,
                        o = 1,
                        a = 0;
                    for (this[t + s] = 255 & e; --s >= 0 && (o *= 256); )
                        e < 0 && 0 === a && 0 !== this[t + s + 1] && (a = 1),
                            (this[t + s] = (((e / o) >> 0) - a) & 255);
                    return t + n;
                }),
                (u.prototype.writeInt8 = function(e, t, n) {
                    return (
                        (e = +e),
                        (t |= 0),
                        n || P(this, e, t, 1, 127, -128),
                        u.TYPED_ARRAY_SUPPORT || (e = Math.floor(e)),
                        e < 0 && (e = 255 + e + 1),
                        (this[t] = 255 & e),
                        t + 1
                    );
                }),
                (u.prototype.writeInt16LE = function(e, t, n) {
                    return (
                        (e = +e),
                        (t |= 0),
                        n || P(this, e, t, 2, 32767, -32768),
                        u.TYPED_ARRAY_SUPPORT
                            ? ((this[t] = 255 & e), (this[t + 1] = e >>> 8))
                            : O(this, e, t, !0),
                        t + 2
                    );
                }),
                (u.prototype.writeInt16BE = function(e, t, n) {
                    return (
                        (e = +e),
                        (t |= 0),
                        n || P(this, e, t, 2, 32767, -32768),
                        u.TYPED_ARRAY_SUPPORT
                            ? ((this[t] = e >>> 8), (this[t + 1] = 255 & e))
                            : O(this, e, t, !1),
                        t + 2
                    );
                }),
                (u.prototype.writeInt32LE = function(e, t, n) {
                    return (
                        (e = +e),
                        (t |= 0),
                        n || P(this, e, t, 4, 2147483647, -2147483648),
                        u.TYPED_ARRAY_SUPPORT
                            ? ((this[t] = 255 & e),
                              (this[t + 1] = e >>> 8),
                              (this[t + 2] = e >>> 16),
                              (this[t + 3] = e >>> 24))
                            : L(this, e, t, !0),
                        t + 4
                    );
                }),
                (u.prototype.writeInt32BE = function(e, t, n) {
                    return (
                        (e = +e),
                        (t |= 0),
                        n || P(this, e, t, 4, 2147483647, -2147483648),
                        e < 0 && (e = 4294967295 + e + 1),
                        u.TYPED_ARRAY_SUPPORT
                            ? ((this[t] = e >>> 24),
                              (this[t + 1] = e >>> 16),
                              (this[t + 2] = e >>> 8),
                              (this[t + 3] = 255 & e))
                            : L(this, e, t, !1),
                        t + 4
                    );
                }),
                (u.prototype.writeFloatLE = function(e, t, n) {
                    return B(this, e, t, !0, n);
                }),
                (u.prototype.writeFloatBE = function(e, t, n) {
                    return B(this, e, t, !1, n);
                }),
                (u.prototype.writeDoubleLE = function(e, t, n) {
                    return D(this, e, t, !0, n);
                }),
                (u.prototype.writeDoubleBE = function(e, t, n) {
                    return D(this, e, t, !1, n);
                }),
                (u.prototype.copy = function(e, t, n, i) {
                    if (
                        (n || (n = 0),
                        i || 0 === i || (i = this.length),
                        t >= e.length && (t = e.length),
                        t || (t = 0),
                        i > 0 && i < n && (i = n),
                        i === n)
                    )
                        return 0;
                    if (0 === e.length || 0 === this.length) return 0;
                    if (t < 0) throw new RangeError('targetStart out of bounds');
                    if (n < 0 || n >= this.length)
                        throw new RangeError('sourceStart out of bounds');
                    if (i < 0) throw new RangeError('sourceEnd out of bounds');
                    i > this.length && (i = this.length),
                        e.length - t < i - n && (i = e.length - t + n);
                    var r,
                        s = i - n;
                    if (this === e && n < t && t < i)
                        for (r = s - 1; r >= 0; --r) e[r + t] = this[r + n];
                    else if (s < 1e3 || !u.TYPED_ARRAY_SUPPORT)
                        for (r = 0; r < s; ++r) e[r + t] = this[r + n];
                    else Uint8Array.prototype.set.call(e, this.subarray(n, n + s), t);
                    return s;
                }),
                (u.prototype.fill = function(e, t, n, i) {
                    if ('string' == typeof e) {
                        if (
                            ('string' == typeof t
                                ? ((i = t), (t = 0), (n = this.length))
                                : 'string' == typeof n && ((i = n), (n = this.length)),
                            1 === e.length)
                        ) {
                            var r = e.charCodeAt(0);
                            r < 256 && (e = r);
                        }
                        if (void 0 !== i && 'string' != typeof i)
                            throw new TypeError('encoding must be a string');
                        if ('string' == typeof i && !u.isEncoding(i))
                            throw new TypeError('Unknown encoding: ' + i);
                    } else 'number' == typeof e && (e &= 255);
                    if (t < 0 || this.length < t || this.length < n)
                        throw new RangeError('Out of range index');
                    if (n <= t) return this;
                    var s;
                    if (
                        ((t >>>= 0),
                        (n = void 0 === n ? this.length : n >>> 0),
                        e || (e = 0),
                        'number' == typeof e)
                    )
                        for (s = t; s < n; ++s) this[s] = e;
                    else {
                        var o = u.isBuffer(e) ? e : F(new u(e, i).toString()),
                            a = o.length;
                        for (s = 0; s < n - t; ++s) this[s + t] = o[s % a];
                    }
                    return this;
                });
            var N = /[^+\/0-9A-Za-z-_]/g;
            function q(e) {
                return e < 16 ? '0' + e.toString(16) : e.toString(16);
            }
            function F(e, t) {
                var n;
                t = t || 1 / 0;
                for (var i = e.length, r = null, s = [], o = 0; o < i; ++o) {
                    if ((n = e.charCodeAt(o)) > 55295 && n < 57344) {
                        if (!r) {
                            if (n > 56319) {
                                (t -= 3) > -1 && s.push(239, 191, 189);
                                continue;
                            }
                            if (o + 1 === i) {
                                (t -= 3) > -1 && s.push(239, 191, 189);
                                continue;
                            }
                            r = n;
                            continue;
                        }
                        if (n < 56320) {
                            (t -= 3) > -1 && s.push(239, 191, 189), (r = n);
                            continue;
                        }
                        n = 65536 + (((r - 55296) << 10) | (n - 56320));
                    } else r && (t -= 3) > -1 && s.push(239, 191, 189);
                    if (((r = null), n < 128)) {
                        if ((t -= 1) < 0) break;
                        s.push(n);
                    } else if (n < 2048) {
                        if ((t -= 2) < 0) break;
                        s.push((n >> 6) | 192, (63 & n) | 128);
                    } else if (n < 65536) {
                        if ((t -= 3) < 0) break;
                        s.push((n >> 12) | 224, ((n >> 6) & 63) | 128, (63 & n) | 128);
                    } else {
                        if (!(n < 1114112)) throw new Error('Invalid code point');
                        if ((t -= 4) < 0) break;
                        s.push(
                            (n >> 18) | 240,
                            ((n >> 12) & 63) | 128,
                            ((n >> 6) & 63) | 128,
                            (63 & n) | 128
                        );
                    }
                }
                return s;
            }
            function U(e) {
                return i.toByteArray(
                    (function(e) {
                        if (
                            (e = (function(e) {
                                return e.trim ? e.trim() : e.replace(/^\s+|\s+$/g, '');
                            })(e).replace(N, '')).length < 2
                        )
                            return '';
                        for (; e.length % 4 != 0; ) e += '=';
                        return e;
                    })(e)
                );
            }
            function z(e, t, n, i) {
                for (var r = 0; r < i && !(r + n >= t.length || r >= e.length); ++r)
                    t[r + n] = e[r];
                return r;
            }
        }.call(this, n(3)));
    },
    function(e, t) {
        var n;
        n = (function() {
            return this;
        })();
        try {
            n = n || new Function('return this')();
        } catch (e) {
            'object' == typeof window && (n = window);
        }
        e.exports = n;
    },
    function(e, t) {
        var n,
            i,
            r = (e.exports = {});
        function s() {
            throw new Error('setTimeout has not been defined');
        }
        function o() {
            throw new Error('clearTimeout has not been defined');
        }
        function a(e) {
            if (n === setTimeout) return setTimeout(e, 0);
            if ((n === s || !n) && setTimeout) return (n = setTimeout), setTimeout(e, 0);
            try {
                return n(e, 0);
            } catch (t) {
                try {
                    return n.call(null, e, 0);
                } catch (t) {
                    return n.call(this, e, 0);
                }
            }
        }
        !(function() {
            try {
                n = 'function' == typeof setTimeout ? setTimeout : s;
            } catch (e) {
                n = s;
            }
            try {
                i = 'function' == typeof clearTimeout ? clearTimeout : o;
            } catch (e) {
                i = o;
            }
        })();
        var u,
            c = [],
            l = !1,
            f = -1;
        function d() {
            l && u && ((l = !1), u.length ? (c = u.concat(c)) : (f = -1), c.length && h());
        }
        function h() {
            if (!l) {
                var e = a(d);
                l = !0;
                for (var t = c.length; t; ) {
                    for (u = c, c = []; ++f < t; ) u && u[f].run();
                    (f = -1), (t = c.length);
                }
                (u = null),
                    (l = !1),
                    (function(e) {
                        if (i === clearTimeout) return clearTimeout(e);
                        if ((i === o || !i) && clearTimeout)
                            return (i = clearTimeout), clearTimeout(e);
                        try {
                            i(e);
                        } catch (t) {
                            try {
                                return i.call(null, e);
                            } catch (t) {
                                return i.call(this, e);
                            }
                        }
                    })(e);
            }
        }
        function p(e, t) {
            (this.fun = e), (this.array = t);
        }
        function m() {}
        (r.nextTick = function(e) {
            var t = new Array(arguments.length - 1);
            if (arguments.length > 1)
                for (var n = 1; n < arguments.length; n++) t[n - 1] = arguments[n];
            c.push(new p(e, t)), 1 !== c.length || l || a(h);
        }),
            (p.prototype.run = function() {
                this.fun.apply(null, this.array);
            }),
            (r.title = 'browser'),
            (r.browser = !0),
            (r.env = {}),
            (r.argv = []),
            (r.version = ''),
            (r.versions = {}),
            (r.on = m),
            (r.addListener = m),
            (r.once = m),
            (r.off = m),
            (r.removeListener = m),
            (r.removeAllListeners = m),
            (r.emit = m),
            (r.prependListener = m),
            (r.prependOnceListener = m),
            (r.listeners = function(e) {
                return [];
            }),
            (r.binding = function(e) {
                throw new Error('process.binding is not supported');
            }),
            (r.cwd = function() {
                return '/';
            }),
            (r.chdir = function(e) {
                throw new Error('process.chdir is not supported');
            }),
            (r.umask = function() {
                return 0;
            });
    },
    function(e, t, n) {
        'use strict';
        var i =
            Object.keys ||
            function(e) {
                var t = [];
                for (var n in e) t.push(n);
                return t;
            };
        e.exports = f;
        var r = n(15),
            s = n(10);
        s.inherits = n(0);
        var o = n(32),
            a = n(17);
        s.inherits(f, o);
        for (var u = i(a.prototype), c = 0; c < u.length; c++) {
            var l = u[c];
            f.prototype[l] || (f.prototype[l] = a.prototype[l]);
        }
        function f(e) {
            if (!(this instanceof f)) return new f(e);
            o.call(this, e),
                a.call(this, e),
                e && !1 === e.readable && (this.readable = !1),
                e && !1 === e.writable && (this.writable = !1),
                (this.allowHalfOpen = !0),
                e && !1 === e.allowHalfOpen && (this.allowHalfOpen = !1),
                this.once('end', d);
        }
        function d() {
            this.allowHalfOpen || this._writableState.ended || r(h, this);
        }
        function h(e) {
            e.end();
        }
    },
    function(e, t, n) {
        'use strict';
        var i,
            r = 'object' == typeof Reflect ? Reflect : null,
            s =
                r && 'function' == typeof r.apply
                    ? r.apply
                    : function(e, t, n) {
                          return Function.prototype.apply.call(e, t, n);
                      };
        i =
            r && 'function' == typeof r.ownKeys
                ? r.ownKeys
                : Object.getOwnPropertySymbols
                ? function(e) {
                      return Object.getOwnPropertyNames(e).concat(Object.getOwnPropertySymbols(e));
                  }
                : function(e) {
                      return Object.getOwnPropertyNames(e);
                  };
        var o =
            Number.isNaN ||
            function(e) {
                return e != e;
            };
        function a() {
            a.init.call(this);
        }
        (e.exports = a),
            (a.EventEmitter = a),
            (a.prototype._events = void 0),
            (a.prototype._eventsCount = 0),
            (a.prototype._maxListeners = void 0);
        var u = 10;
        function c(e) {
            return void 0 === e._maxListeners ? a.defaultMaxListeners : e._maxListeners;
        }
        function l(e, t, n, i) {
            var r, s, o, a;
            if ('function' != typeof n)
                throw new TypeError(
                    'The "listener" argument must be of type Function. Received type ' + typeof n
                );
            if (
                (void 0 === (s = e._events)
                    ? ((s = e._events = Object.create(null)), (e._eventsCount = 0))
                    : (void 0 !== s.newListener &&
                          (e.emit('newListener', t, n.listener ? n.listener : n), (s = e._events)),
                      (o = s[t])),
                void 0 === o)
            )
                (o = s[t] = n), ++e._eventsCount;
            else if (
                ('function' == typeof o
                    ? (o = s[t] = i ? [n, o] : [o, n])
                    : i
                    ? o.unshift(n)
                    : o.push(n),
                (r = c(e)) > 0 && o.length > r && !o.warned)
            ) {
                o.warned = !0;
                var u = new Error(
                    'Possible EventEmitter memory leak detected. ' +
                        o.length +
                        ' ' +
                        String(t) +
                        ' listeners added. Use emitter.setMaxListeners() to increase limit'
                );
                (u.name = 'MaxListenersExceededWarning'),
                    (u.emitter = e),
                    (u.type = t),
                    (u.count = o.length),
                    (a = u),
                    console && console.warn && console.warn(a);
            }
            return e;
        }
        function f(e, t, n) {
            var i = { fired: !1, wrapFn: void 0, target: e, type: t, listener: n },
                r = function() {
                    for (var e = [], t = 0; t < arguments.length; t++) e.push(arguments[t]);
                    this.fired ||
                        (this.target.removeListener(this.type, this.wrapFn),
                        (this.fired = !0),
                        s(this.listener, this.target, e));
                }.bind(i);
            return (r.listener = n), (i.wrapFn = r), r;
        }
        function d(e, t, n) {
            var i = e._events;
            if (void 0 === i) return [];
            var r = i[t];
            return void 0 === r
                ? []
                : 'function' == typeof r
                ? n
                    ? [r.listener || r]
                    : [r]
                : n
                ? (function(e) {
                      for (var t = new Array(e.length), n = 0; n < t.length; ++n)
                          t[n] = e[n].listener || e[n];
                      return t;
                  })(r)
                : p(r, r.length);
        }
        function h(e) {
            var t = this._events;
            if (void 0 !== t) {
                var n = t[e];
                if ('function' == typeof n) return 1;
                if (void 0 !== n) return n.length;
            }
            return 0;
        }
        function p(e, t) {
            for (var n = new Array(t), i = 0; i < t; ++i) n[i] = e[i];
            return n;
        }
        Object.defineProperty(a, 'defaultMaxListeners', {
            enumerable: !0,
            get: function() {
                return u;
            },
            set: function(e) {
                if ('number' != typeof e || e < 0 || o(e))
                    throw new RangeError(
                        'The value of "defaultMaxListeners" is out of range. It must be a non-negative number. Received ' +
                            e +
                            '.'
                    );
                u = e;
            }
        }),
            (a.init = function() {
                (void 0 !== this._events && this._events !== Object.getPrototypeOf(this)._events) ||
                    ((this._events = Object.create(null)), (this._eventsCount = 0)),
                    (this._maxListeners = this._maxListeners || void 0);
            }),
            (a.prototype.setMaxListeners = function(e) {
                if ('number' != typeof e || e < 0 || o(e))
                    throw new RangeError(
                        'The value of "n" is out of range. It must be a non-negative number. Received ' +
                            e +
                            '.'
                    );
                return (this._maxListeners = e), this;
            }),
            (a.prototype.getMaxListeners = function() {
                return c(this);
            }),
            (a.prototype.emit = function(e) {
                for (var t = [], n = 1; n < arguments.length; n++) t.push(arguments[n]);
                var i = 'error' === e,
                    r = this._events;
                if (void 0 !== r) i = i && void 0 === r.error;
                else if (!i) return !1;
                if (i) {
                    var o;
                    if ((t.length > 0 && (o = t[0]), o instanceof Error)) throw o;
                    var a = new Error('Unhandled error.' + (o ? ' (' + o.message + ')' : ''));
                    throw ((a.context = o), a);
                }
                var u = r[e];
                if (void 0 === u) return !1;
                if ('function' == typeof u) s(u, this, t);
                else {
                    var c = u.length,
                        l = p(u, c);
                    for (n = 0; n < c; ++n) s(l[n], this, t);
                }
                return !0;
            }),
            (a.prototype.addListener = function(e, t) {
                return l(this, e, t, !1);
            }),
            (a.prototype.on = a.prototype.addListener),
            (a.prototype.prependListener = function(e, t) {
                return l(this, e, t, !0);
            }),
            (a.prototype.once = function(e, t) {
                if ('function' != typeof t)
                    throw new TypeError(
                        'The "listener" argument must be of type Function. Received type ' +
                            typeof t
                    );
                return this.on(e, f(this, e, t)), this;
            }),
            (a.prototype.prependOnceListener = function(e, t) {
                if ('function' != typeof t)
                    throw new TypeError(
                        'The "listener" argument must be of type Function. Received type ' +
                            typeof t
                    );
                return this.prependListener(e, f(this, e, t)), this;
            }),
            (a.prototype.removeListener = function(e, t) {
                var n, i, r, s, o;
                if ('function' != typeof t)
                    throw new TypeError(
                        'The "listener" argument must be of type Function. Received type ' +
                            typeof t
                    );
                if (void 0 === (i = this._events)) return this;
                if (void 0 === (n = i[e])) return this;
                if (n === t || n.listener === t)
                    0 == --this._eventsCount
                        ? (this._events = Object.create(null))
                        : (delete i[e],
                          i.removeListener && this.emit('removeListener', e, n.listener || t));
                else if ('function' != typeof n) {
                    for (r = -1, s = n.length - 1; s >= 0; s--)
                        if (n[s] === t || n[s].listener === t) {
                            (o = n[s].listener), (r = s);
                            break;
                        }
                    if (r < 0) return this;
                    0 === r
                        ? n.shift()
                        : (function(e, t) {
                              for (; t + 1 < e.length; t++) e[t] = e[t + 1];
                              e.pop();
                          })(n, r),
                        1 === n.length && (i[e] = n[0]),
                        void 0 !== i.removeListener && this.emit('removeListener', e, o || t);
                }
                return this;
            }),
            (a.prototype.off = a.prototype.removeListener),
            (a.prototype.removeAllListeners = function(e) {
                var t, n, i;
                if (void 0 === (n = this._events)) return this;
                if (void 0 === n.removeListener)
                    return (
                        0 === arguments.length
                            ? ((this._events = Object.create(null)), (this._eventsCount = 0))
                            : void 0 !== n[e] &&
                              (0 == --this._eventsCount
                                  ? (this._events = Object.create(null))
                                  : delete n[e]),
                        this
                    );
                if (0 === arguments.length) {
                    var r,
                        s = Object.keys(n);
                    for (i = 0; i < s.length; ++i)
                        'removeListener' !== (r = s[i]) && this.removeAllListeners(r);
                    return (
                        this.removeAllListeners('removeListener'),
                        (this._events = Object.create(null)),
                        (this._eventsCount = 0),
                        this
                    );
                }
                if ('function' == typeof (t = n[e])) this.removeListener(e, t);
                else if (void 0 !== t)
                    for (i = t.length - 1; i >= 0; i--) this.removeListener(e, t[i]);
                return this;
            }),
            (a.prototype.listeners = function(e) {
                return d(this, e, !0);
            }),
            (a.prototype.rawListeners = function(e) {
                return d(this, e, !1);
            }),
            (a.listenerCount = function(e, t) {
                return 'function' == typeof e.listenerCount ? e.listenerCount(t) : h.call(e, t);
            }),
            (a.prototype.listenerCount = h),
            (a.prototype.eventNames = function() {
                return this._eventsCount > 0 ? i(this._events) : [];
            });
    },
    function(e, t, n) {
        var i = n(1).Buffer;
        function r(e, t) {
            (this._block = i.alloc(e)),
                (this._finalSize = t),
                (this._blockSize = e),
                (this._len = 0);
        }
        (r.prototype.update = function(e, t) {
            'string' == typeof e && ((t = t || 'utf8'), (e = i.from(e, t)));
            for (
                var n = this._block, r = this._blockSize, s = e.length, o = this._len, a = 0;
                a < s;

            ) {
                for (var u = o % r, c = Math.min(s - a, r - u), l = 0; l < c; l++)
                    n[u + l] = e[a + l];
                (a += c), (o += c) % r == 0 && this._update(n);
            }
            return (this._len += s), this;
        }),
            (r.prototype.digest = function(e) {
                var t = this._len % this._blockSize;
                (this._block[t] = 128),
                    this._block.fill(0, t + 1),
                    t >= this._finalSize && (this._update(this._block), this._block.fill(0));
                var n = 8 * this._len;
                if (n <= 4294967295) this._block.writeUInt32BE(n, this._blockSize - 4);
                else {
                    var i = (4294967295 & n) >>> 0,
                        r = (n - i) / 4294967296;
                    this._block.writeUInt32BE(r, this._blockSize - 8),
                        this._block.writeUInt32BE(i, this._blockSize - 4);
                }
                this._update(this._block);
                var s = this._hash();
                return e ? s.toString(e) : s;
            }),
            (r.prototype._update = function() {
                throw new Error('_update must be implemented by subclass');
            }),
            (e.exports = r);
    },
    function(e, t, n) {
        'use strict';
        n.r(t),
            n.d(t, '__extends', function() {
                return r;
            }),
            n.d(t, '__assign', function() {
                return s;
            }),
            n.d(t, '__rest', function() {
                return o;
            }),
            n.d(t, '__decorate', function() {
                return a;
            }),
            n.d(t, '__param', function() {
                return u;
            }),
            n.d(t, '__metadata', function() {
                return c;
            }),
            n.d(t, '__awaiter', function() {
                return l;
            }),
            n.d(t, '__generator', function() {
                return f;
            }),
            n.d(t, '__exportStar', function() {
                return d;
            }),
            n.d(t, '__values', function() {
                return h;
            }),
            n.d(t, '__read', function() {
                return p;
            }),
            n.d(t, '__spread', function() {
                return m;
            }),
            n.d(t, '__await', function() {
                return g;
            }),
            n.d(t, '__asyncGenerator', function() {
                return b;
            }),
            n.d(t, '__asyncDelegator', function() {
                return y;
            }),
            n.d(t, '__asyncValues', function() {
                return v;
            }),
            n.d(t, '__makeTemplateObject', function() {
                return x;
            }),
            n.d(t, '__importStar', function() {
                return w;
            }),
            n.d(t, '__importDefault', function() {
                return _;
            });
        /*! *****************************************************************************
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED
WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache Version 2.0 License for specific language governing permissions
and limitations under the License.
***************************************************************************** */
        var i = function(e, t) {
            return (i =
                Object.setPrototypeOf ||
                ({ __proto__: [] } instanceof Array &&
                    function(e, t) {
                        e.__proto__ = t;
                    }) ||
                function(e, t) {
                    for (var n in t) t.hasOwnProperty(n) && (e[n] = t[n]);
                })(e, t);
        };
        function r(e, t) {
            function n() {
                this.constructor = e;
            }
            i(e, t),
                (e.prototype =
                    null === t ? Object.create(t) : ((n.prototype = t.prototype), new n()));
        }
        var s = function() {
            return (s =
                Object.assign ||
                function(e) {
                    for (var t, n = 1, i = arguments.length; n < i; n++)
                        for (var r in (t = arguments[n]))
                            Object.prototype.hasOwnProperty.call(t, r) && (e[r] = t[r]);
                    return e;
                }).apply(this, arguments);
        };
        function o(e, t) {
            var n = {};
            for (var i in e)
                Object.prototype.hasOwnProperty.call(e, i) && t.indexOf(i) < 0 && (n[i] = e[i]);
            if (null != e && 'function' == typeof Object.getOwnPropertySymbols) {
                var r = 0;
                for (i = Object.getOwnPropertySymbols(e); r < i.length; r++)
                    t.indexOf(i[r]) < 0 && (n[i[r]] = e[i[r]]);
            }
            return n;
        }
        function a(e, t, n, i) {
            var r,
                s = arguments.length,
                o = s < 3 ? t : null === i ? (i = Object.getOwnPropertyDescriptor(t, n)) : i;
            if ('object' == typeof Reflect && 'function' == typeof Reflect.decorate)
                o = Reflect.decorate(e, t, n, i);
            else
                for (var a = e.length - 1; a >= 0; a--)
                    (r = e[a]) && (o = (s < 3 ? r(o) : s > 3 ? r(t, n, o) : r(t, n)) || o);
            return s > 3 && o && Object.defineProperty(t, n, o), o;
        }
        function u(e, t) {
            return function(n, i) {
                t(n, i, e);
            };
        }
        function c(e, t) {
            if ('object' == typeof Reflect && 'function' == typeof Reflect.metadata)
                return Reflect.metadata(e, t);
        }
        function l(e, t, n, i) {
            return new (n || (n = Promise))(function(r, s) {
                function o(e) {
                    try {
                        u(i.next(e));
                    } catch (e) {
                        s(e);
                    }
                }
                function a(e) {
                    try {
                        u(i.throw(e));
                    } catch (e) {
                        s(e);
                    }
                }
                function u(e) {
                    e.done
                        ? r(e.value)
                        : new n(function(t) {
                              t(e.value);
                          }).then(o, a);
                }
                u((i = i.apply(e, t || [])).next());
            });
        }
        function f(e, t) {
            var n,
                i,
                r,
                s,
                o = {
                    label: 0,
                    sent: function() {
                        if (1 & r[0]) throw r[1];
                        return r[1];
                    },
                    trys: [],
                    ops: []
                };
            return (
                (s = { next: a(0), throw: a(1), return: a(2) }),
                'function' == typeof Symbol &&
                    (s[Symbol.iterator] = function() {
                        return this;
                    }),
                s
            );
            function a(s) {
                return function(a) {
                    return (function(s) {
                        if (n) throw new TypeError('Generator is already executing.');
                        for (; o; )
                            try {
                                if (
                                    ((n = 1),
                                    i &&
                                        (r =
                                            2 & s[0]
                                                ? i.return
                                                : s[0]
                                                ? i.throw || ((r = i.return) && r.call(i), 0)
                                                : i.next) &&
                                        !(r = r.call(i, s[1])).done)
                                )
                                    return r;
                                switch (((i = 0), r && (s = [2 & s[0], r.value]), s[0])) {
                                    case 0:
                                    case 1:
                                        r = s;
                                        break;
                                    case 4:
                                        return o.label++, { value: s[1], done: !1 };
                                    case 5:
                                        o.label++, (i = s[1]), (s = [0]);
                                        continue;
                                    case 7:
                                        (s = o.ops.pop()), o.trys.pop();
                                        continue;
                                    default:
                                        if (
                                            !(r = (r = o.trys).length > 0 && r[r.length - 1]) &&
                                            (6 === s[0] || 2 === s[0])
                                        ) {
                                            o = 0;
                                            continue;
                                        }
                                        if (3 === s[0] && (!r || (s[1] > r[0] && s[1] < r[3]))) {
                                            o.label = s[1];
                                            break;
                                        }
                                        if (6 === s[0] && o.label < r[1]) {
                                            (o.label = r[1]), (r = s);
                                            break;
                                        }
                                        if (r && o.label < r[2]) {
                                            (o.label = r[2]), o.ops.push(s);
                                            break;
                                        }
                                        r[2] && o.ops.pop(), o.trys.pop();
                                        continue;
                                }
                                s = t.call(e, o);
                            } catch (e) {
                                (s = [6, e]), (i = 0);
                            } finally {
                                n = r = 0;
                            }
                        if (5 & s[0]) throw s[1];
                        return { value: s[0] ? s[1] : void 0, done: !0 };
                    })([s, a]);
                };
            }
        }
        function d(e, t) {
            for (var n in e) t.hasOwnProperty(n) || (t[n] = e[n]);
        }
        function h(e) {
            var t = 'function' == typeof Symbol && e[Symbol.iterator],
                n = 0;
            return t
                ? t.call(e)
                : {
                      next: function() {
                          return (
                              e && n >= e.length && (e = void 0), { value: e && e[n++], done: !e }
                          );
                      }
                  };
        }
        function p(e, t) {
            var n = 'function' == typeof Symbol && e[Symbol.iterator];
            if (!n) return e;
            var i,
                r,
                s = n.call(e),
                o = [];
            try {
                for (; (void 0 === t || t-- > 0) && !(i = s.next()).done; ) o.push(i.value);
            } catch (e) {
                r = { error: e };
            } finally {
                try {
                    i && !i.done && (n = s.return) && n.call(s);
                } finally {
                    if (r) throw r.error;
                }
            }
            return o;
        }
        function m() {
            for (var e = [], t = 0; t < arguments.length; t++) e = e.concat(p(arguments[t]));
            return e;
        }
        function g(e) {
            return this instanceof g ? ((this.v = e), this) : new g(e);
        }
        function b(e, t, n) {
            if (!Symbol.asyncIterator) throw new TypeError('Symbol.asyncIterator is not defined.');
            var i,
                r = n.apply(e, t || []),
                s = [];
            return (
                (i = {}),
                o('next'),
                o('throw'),
                o('return'),
                (i[Symbol.asyncIterator] = function() {
                    return this;
                }),
                i
            );
            function o(e) {
                r[e] &&
                    (i[e] = function(t) {
                        return new Promise(function(n, i) {
                            s.push([e, t, n, i]) > 1 || a(e, t);
                        });
                    });
            }
            function a(e, t) {
                try {
                    (n = r[e](t)).value instanceof g
                        ? Promise.resolve(n.value.v).then(u, c)
                        : l(s[0][2], n);
                } catch (e) {
                    l(s[0][3], e);
                }
                var n;
            }
            function u(e) {
                a('next', e);
            }
            function c(e) {
                a('throw', e);
            }
            function l(e, t) {
                e(t), s.shift(), s.length && a(s[0][0], s[0][1]);
            }
        }
        function y(e) {
            var t, n;
            return (
                (t = {}),
                i('next'),
                i('throw', function(e) {
                    throw e;
                }),
                i('return'),
                (t[Symbol.iterator] = function() {
                    return this;
                }),
                t
            );
            function i(i, r) {
                t[i] = e[i]
                    ? function(t) {
                          return (n = !n)
                              ? { value: g(e[i](t)), done: 'return' === i }
                              : r
                              ? r(t)
                              : t;
                      }
                    : r;
            }
        }
        function v(e) {
            if (!Symbol.asyncIterator) throw new TypeError('Symbol.asyncIterator is not defined.');
            var t,
                n = e[Symbol.asyncIterator];
            return n
                ? n.call(e)
                : ((e = h(e)),
                  (t = {}),
                  i('next'),
                  i('throw'),
                  i('return'),
                  (t[Symbol.asyncIterator] = function() {
                      return this;
                  }),
                  t);
            function i(n) {
                t[n] =
                    e[n] &&
                    function(t) {
                        return new Promise(function(i, r) {
                            (function(e, t, n, i) {
                                Promise.resolve(i).then(function(t) {
                                    e({ value: t, done: n });
                                }, t);
                            })(i, r, (t = e[n](t)).done, t.value);
                        });
                    };
            }
        }
        function x(e, t) {
            return (
                Object.defineProperty ? Object.defineProperty(e, 'raw', { value: t }) : (e.raw = t),
                e
            );
        }
        function w(e) {
            if (e && e.__esModule) return e;
            var t = {};
            if (null != e) for (var n in e) Object.hasOwnProperty.call(e, n) && (t[n] = e[n]);
            return (t.default = e), t;
        }
        function _(e) {
            return e && e.__esModule ? e : { default: e };
        }
    },
    function(e, t, n) {
        'use strict';
        var i = n(11),
            r = i.escapeXML,
            s = i.escapeXMLText,
            o = n(26),
            a = o.equal,
            u = o.name,
            c = o.attrs,
            l = o.children,
            f = n(27);
        function d(e, t) {
            (this.name = e),
                (this.parent = null),
                (this.children = []),
                (this.attrs = {}),
                this.setAttrs(t);
        }
        (d.prototype.is = function(e, t) {
            return this.getName() === e && (!t || this.getNS() === t);
        }),
            (d.prototype.getName = function() {
                return this.name.indexOf(':') >= 0
                    ? this.name.substr(this.name.indexOf(':') + 1)
                    : this.name;
            }),
            (d.prototype.getNS = function() {
                if (this.name.indexOf(':') >= 0) {
                    var e = this.name.substr(0, this.name.indexOf(':'));
                    return this.findNS(e);
                }
                return this.findNS();
            }),
            (d.prototype.findNS = function(e) {
                if (e) {
                    var t = 'xmlns:' + e;
                    if (this.attrs[t]) return this.attrs[t];
                    if (this.parent) return this.parent.findNS(e);
                } else {
                    if (this.attrs.xmlns) return this.attrs.xmlns;
                    if (this.parent) return this.parent.findNS();
                }
            }),
            (d.prototype.getXmlns = function() {
                var e = {};
                for (var t in (this.parent && (e = this.parent.getXmlns()), this.attrs)) {
                    var n = t.match('xmlns:?(.*)');
                    this.attrs.hasOwnProperty(t) && n && (e[this.attrs[t]] = n[1]);
                }
                return e;
            }),
            (d.prototype.setAttrs = function(e) {
                'string' == typeof e
                    ? (this.attrs.xmlns = e)
                    : e &&
                      Object.keys(e).forEach(function(t) {
                          this.attrs[t] = e[t];
                      }, this);
            }),
            (d.prototype.getAttr = function(e, t) {
                if (!t) return this.attrs[e];
                var n = this.getXmlns();
                return n[t] ? this.attrs[[n[t], e].join(':')] : null;
            }),
            (d.prototype.getChild = function(e, t) {
                return this.getChildren(e, t)[0];
            }),
            (d.prototype.getChildren = function(e, t) {
                for (var n = [], i = 0; i < this.children.length; i++) {
                    var r = this.children[i];
                    !r.getName || r.getName() !== e || (t && r.getNS() !== t) || n.push(r);
                }
                return n;
            }),
            (d.prototype.getChildByAttr = function(e, t, n, i) {
                return this.getChildrenByAttr(e, t, n, i)[0];
            }),
            (d.prototype.getChildrenByAttr = function(e, t, n, i) {
                for (var r = [], s = 0; s < this.children.length; s++) {
                    var o = this.children[s];
                    !o.attrs || o.attrs[e] !== t || (n && o.getNS() !== n) || r.push(o),
                        i && o.getChildrenByAttr && r.push(o.getChildrenByAttr(e, t, n, !0));
                }
                return i && (r = [].concat.apply([], r)), r;
            }),
            (d.prototype.getChildrenByFilter = function(e, t) {
                for (var n = [], i = 0; i < this.children.length; i++) {
                    var r = this.children[i];
                    e(r) && n.push(r),
                        t && r.getChildrenByFilter && n.push(r.getChildrenByFilter(e, !0));
                }
                return t && (n = [].concat.apply([], n)), n;
            }),
            (d.prototype.getText = function() {
                for (var e = '', t = 0; t < this.children.length; t++) {
                    var n = this.children[t];
                    ('string' != typeof n && 'number' != typeof n) || (e += n);
                }
                return e;
            }),
            (d.prototype.getChildText = function(e, t) {
                var n = this.getChild(e, t);
                return n ? n.getText() : null;
            }),
            (d.prototype.getChildElements = function() {
                return this.getChildrenByFilter(function(e) {
                    return e instanceof d;
                });
            }),
            (d.prototype.root = function() {
                return this.parent ? this.parent.root() : this;
            }),
            (d.prototype.tree = d.prototype.root),
            (d.prototype.up = function() {
                return this.parent ? this.parent : this;
            }),
            (d.prototype.c = function(e, t) {
                return this.cnode(new d(e, t));
            }),
            (d.prototype.cnode = function(e) {
                return this.children.push(e), 'object' == typeof e && (e.parent = this), e;
            }),
            (d.prototype.t = function(e) {
                return this.children.push(e), this;
            }),
            (d.prototype.remove = function(e, t) {
                var n;
                return (
                    (n =
                        'string' == typeof e
                            ? function(n) {
                                  return !(n.is && n.is(e, t));
                              }
                            : function(t) {
                                  return t !== e;
                              }),
                    (this.children = this.children.filter(n)),
                    this
                );
            }),
            (d.prototype.clone = function() {
                return f(this);
            }),
            (d.prototype.text = function(e) {
                return e && 1 === this.children.length
                    ? ((this.children[0] = e), this)
                    : this.getText();
            }),
            (d.prototype.attr = function(e, t) {
                return void 0 !== t || null === t
                    ? (this.attrs || (this.attrs = {}), (this.attrs[e] = t), this)
                    : this.attrs[e];
            }),
            (d.prototype.toString = function() {
                var e = '';
                return (
                    this.write(function(t) {
                        e += t;
                    }),
                    e
                );
            }),
            (d.prototype.toJSON = function() {
                return {
                    name: this.name,
                    attrs: this.attrs,
                    children: this.children.map(function(e) {
                        return e && e.toJSON ? e.toJSON() : e;
                    })
                };
            }),
            (d.prototype._addChildren = function(e) {
                e('>');
                for (var t = 0; t < this.children.length; t++) {
                    var n = this.children[t];
                    (n || 0 === n) &&
                        (n.write
                            ? n.write(e)
                            : 'string' == typeof n
                            ? e(s(n))
                            : n.toString && e(s(n.toString(10))));
                }
                e('</'), e(this.name), e('>');
            }),
            (d.prototype.write = function(e) {
                for (var t in (e('<'), e(this.name), this.attrs)) {
                    var n = this.attrs[t];
                    null != n &&
                        (e(' '),
                        e(t),
                        e('="'),
                        'string' != typeof n && (n = n.toString()),
                        e(r(n)),
                        e('"'));
                }
                0 === this.children.length ? e('/>') : this._addChildren(e);
            }),
            (d.prototype.nameEquals = function(e) {
                return u(this, e);
            }),
            (d.prototype.attrsEquals = function(e) {
                return c(this, e);
            }),
            (d.prototype.childrenEquals = function(e) {
                return l(this, e);
            }),
            (d.prototype.equals = function(e) {
                return a(this, e);
            }),
            (e.exports = d);
    },
    function(e, t, n) {
        (function(e) {
            function n(e) {
                return Object.prototype.toString.call(e);
            }
            (t.isArray = function(e) {
                return Array.isArray ? Array.isArray(e) : '[object Array]' === n(e);
            }),
                (t.isBoolean = function(e) {
                    return 'boolean' == typeof e;
                }),
                (t.isNull = function(e) {
                    return null === e;
                }),
                (t.isNullOrUndefined = function(e) {
                    return null == e;
                }),
                (t.isNumber = function(e) {
                    return 'number' == typeof e;
                }),
                (t.isString = function(e) {
                    return 'string' == typeof e;
                }),
                (t.isSymbol = function(e) {
                    return 'symbol' == typeof e;
                }),
                (t.isUndefined = function(e) {
                    return void 0 === e;
                }),
                (t.isRegExp = function(e) {
                    return '[object RegExp]' === n(e);
                }),
                (t.isObject = function(e) {
                    return 'object' == typeof e && null !== e;
                }),
                (t.isDate = function(e) {
                    return '[object Date]' === n(e);
                }),
                (t.isError = function(e) {
                    return '[object Error]' === n(e) || e instanceof Error;
                }),
                (t.isFunction = function(e) {
                    return 'function' == typeof e;
                }),
                (t.isPrimitive = function(e) {
                    return (
                        null === e ||
                        'boolean' == typeof e ||
                        'number' == typeof e ||
                        'string' == typeof e ||
                        'symbol' == typeof e ||
                        void 0 === e
                    );
                }),
                (t.isBuffer = e.isBuffer);
        }.call(this, n(2).Buffer));
    },
    function(e, t, n) {
        'use strict';
        var i = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' };
        function r(e) {
            return i[e];
        }
        var s = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&apos;': "'" };
        function o(e) {
            if ('#' === e[1]) {
                var t;
                if (
                    9 ===
                        (t = 'x' === e[2] ? parseInt(e.slice(3), 16) : parseInt(e.slice(2), 10)) ||
                    10 === t ||
                    13 === t ||
                    (t >= 32 && t <= 55295) ||
                    (t >= 57344 && t <= 65533) ||
                    (t >= 65536 && t <= 1114111)
                )
                    return String.fromCodePoint(t);
                throw new Error('Illegal XML character 0x' + t.toString(16));
            }
            if (s[e]) return s[e] || e;
            throw new Error('Illegal XML entity ' + e);
        }
        (t.escapeXML = function(e) {
            return e.replace(/&|<|>|"|'/g, r);
        }),
            (t.unescapeXML = function(e) {
                for (
                    var t = '', n = -1, i = -1, r = 0;
                    -1 !== (n = e.indexOf('&', r)) && -1 !== (i = e.indexOf(';', n + 1));

                )
                    (t = t + e.substring(r, n) + o(e.substring(n, i + 1))), (r = i + 1);
                return 0 === r ? e : (t += e.substring(r));
            }),
            (t.escapeXMLText = function(e) {
                return e.replace(/&|<|>/g, r);
            }),
            (t.unescapeXMLText = function(e) {
                return e.replace(/&(amp|#38|lt|#60|gt|#62);/g, o);
            });
    },
    function(e, t, n) {
        'use strict';
        Object.defineProperty(t, '__esModule', { value: !0 });
        const i = n(49),
            r = n(55);
        function s(e, t, n) {
            const i = new r(t);
            return (n && n === e) || u(i, 'xmlns', e), i;
        }
        function o(e, t, n) {
            const i = [],
                r = e.getElementsByTagName(n);
            for (let n = 0, s = r.length; n < s; n++) {
                const s = r[n];
                s.namespaceURI === t && s.parentNode === e && i.push(s);
            }
            return i;
        }
        function a(e, t, n) {
            return e.getAttribute(t) || n || '';
        }
        function u(e, t, n, i) {
            n || i ? e.setAttribute(t, n) : e.removeAttribute(t);
        }
        function c(e, t, n, i, r) {
            const a = o(e, t, n);
            if (a.length)
                for (let e = 0; e < a.length; e++) {
                    if (r) return void a[e].setAttribute(i, r);
                    a[e].removeAttribute(i);
                }
            else r && ((n = s(t, n, e.namespaceURI)).setAttribute(i, r), e.appendChild(n));
        }
        function l(e, t, n, i) {
            const r = o(e, t, n);
            return (i = i || ''), (r.length && r[0].textContent) || i;
        }
        function f(e, t, n, i) {
            const r = o(e, t, n);
            if (r.length) for (let t = 0; t < r.length; t++) e.removeChild(r[t]);
            if (i) {
                const r = s(t, n, e.namespaceURI);
                !0 !== i && (r.textContent = i), e.appendChild(r);
            }
        }
        function d(e, t, n, i) {
            const r = o(e, t, n),
                s = [];
            i =
                i ||
                function(e) {
                    return e.textContent || '';
                };
            for (let e = 0; e < r.length; e++) s.push(i(r[e]));
            return s;
        }
        function h(e, t, n, i, r) {
            const a = o(e, t, n);
            let u,
                c,
                l = [];
            for (
                r =
                    r ||
                    function(i) {
                        if (i) {
                            const r = s(t, n, e.namespaceURI);
                            (r.textContent = i), e.appendChild(r);
                        }
                    },
                    l = 'string' == typeof i ? (i || '').split('\n') : i,
                    u = 0,
                    c = a.length;
                u < c;
                u++
            )
                e.removeChild(a[u]);
            for (u = 0, c = l.length; u < c; u++) r(l[u]);
        }
        (t.XML_NS = 'http://www.w3.org/XML/1998/namespace'),
            (t.parse = function(e) {
                const t = i.parse(e, { Element: r });
                if (1 === t.nodeType) return t;
            }),
            (t.createElement = s),
            (t.find = o),
            (t.findOrCreate = function(e, t, n) {
                const i = o(e, t, n);
                if (i.length) return i[0];
                {
                    const i = s(t, n, e.namespaceURI);
                    return e.appendChild(i), i;
                }
            }),
            (t.getAttribute = a),
            (t.getAttributeNS = function(e, t, n, i) {
                return e.getAttributeNS(t, n) || i || '';
            }),
            (t.setAttribute = u),
            (t.setAttributeNS = function(e, t, n, i, r) {
                i || r ? e.setAttributeNS(t, n, i) : e.removeAttributeNS(t, n);
            }),
            (t.getBoolAttribute = function(e, t, n) {
                const i = e.getAttribute(t) || n || '';
                return 'true' === i || '1' === i;
            }),
            (t.setBoolAttribute = function(e, t, n) {
                n ? e.setAttribute(t, '1') : e.removeAttribute(t);
            }),
            (t.getSubAttribute = function(e, t, n, i, r) {
                const s = o(e, t, n);
                if (!s) return '';
                for (let e = 0; e < s.length; e++) return s[e].getAttribute(i) || r || '';
                return '';
            }),
            (t.setSubAttribute = c),
            (t.getBoolSubAttribute = function(e, t, n, i, r) {
                const s = e.getSubAttribute(t, n, i) || r || '';
                return 'true' === s || '1' === s;
            }),
            (t.setBoolSubAttribute = function(e, t, n, i, r) {
                c(e, t, n, i, (r = r ? '1' : ''));
            }),
            (t.getText = function(e) {
                return e.textContent;
            }),
            (t.setText = function(e, t) {
                e.textContent = t;
            }),
            (t.getSubText = l),
            (t.getTextSub = l),
            (t.setSubText = f),
            (t.setTextSub = f),
            (t.getMultiSubText = d),
            (t.setMultiSubText = h),
            (t.getMultiSubAttribute = function(e, t, n, i) {
                return d(e, t, n, function(e) {
                    return a(e, i);
                });
            }),
            (t.setMultiSubAttribute = function(e, t, n, i, r) {
                h(e, t, n, r, function(r) {
                    const o = s(t, n, e.namespaceURI);
                    u(o, i, r), e.appendChild(o);
                });
            }),
            (t.getSubLangText = function(e, n, i, r) {
                const s = o(e, n, i);
                if (!s.length) return {};
                let a, u;
                const c = {},
                    l = [];
                for (let e = 0; e < s.length; e++)
                    (a = (u = s[e]).getAttributeNS(t.XML_NS, 'lang') || r),
                        l.push(a),
                        (c[a] = u.textContent || '');
                return c;
            }),
            (t.setSubLangText = function(e, n, i, r, a) {
                let u, c;
                const l = o(e, n, i);
                if (l.length) for (let t = 0; t < l.length; t++) e.removeChild(l[t]);
                if ('string' == typeof r)
                    ((u = s(n, i, e.namespaceURI)).textContent = r), e.appendChild(u);
                else if ('object' == typeof r)
                    for (c in r)
                        r.hasOwnProperty(c) &&
                            ((u = s(n, i, e.namespaceURI)),
                            c !== a && u.setAttributeNS(t.XML_NS, 'lang', c),
                            (u.textContent = r[c]),
                            e.appendChild(u));
            }),
            (t.getBoolSub = function(e, t, n) {
                return !!o(e, t, n).length;
            }),
            (t.setBoolSub = function(e, t, n, i) {
                const r = o(e, t, n);
                if (r.length)
                    for (let t = 0; t < r.length; t++) {
                        if (i) return;
                        e.removeChild(r[t]);
                    }
                else if (i) {
                    const i = s(t, n, e.namespaceURI);
                    e.appendChild(i);
                }
            });
    },
    function(e, t) {
        function n() {}
        (e.exports = n),
            (n.mixin = function(e) {
                var t = e.prototype || e;
                (t.isWildEmitter = !0),
                    (t.on = function(e, t, n) {
                        this.callbacks = this.callbacks || {};
                        var i = 3 === arguments.length,
                            r = i ? arguments[1] : void 0,
                            s = i ? arguments[2] : arguments[1];
                        return (
                            (s._groupName = r),
                            (this.callbacks[e] = this.callbacks[e] || []).push(s),
                            this
                        );
                    }),
                    (t.once = function(e, t, n) {
                        var i = this,
                            r = 3 === arguments.length,
                            s = r ? arguments[1] : void 0,
                            o = r ? arguments[2] : arguments[1];
                        return (
                            this.on(e, s, function t() {
                                i.off(e, t), o.apply(this, arguments);
                            }),
                            this
                        );
                    }),
                    (t.releaseGroup = function(e) {
                        var t, n, i, r;
                        for (t in ((this.callbacks = this.callbacks || {}), this.callbacks))
                            for (n = 0, i = (r = this.callbacks[t]).length; n < i; n++)
                                r[n]._groupName === e && (r.splice(n, 1), n--, i--);
                        return this;
                    }),
                    (t.off = function(e, t) {
                        this.callbacks = this.callbacks || {};
                        var n,
                            i = this.callbacks[e];
                        return i
                            ? 1 === arguments.length
                                ? (delete this.callbacks[e], this)
                                : ((n = i.indexOf(t)),
                                  i.splice(n, 1),
                                  0 === i.length && delete this.callbacks[e],
                                  this)
                            : this;
                    }),
                    (t.emit = function(e) {
                        this.callbacks = this.callbacks || {};
                        var t,
                            n,
                            i,
                            r = [].slice.call(arguments, 1),
                            s = this.callbacks[e],
                            o = this.getWildcardCallbacks(e);
                        if (s)
                            for (t = 0, n = (i = s.slice()).length; t < n && i[t]; ++t)
                                i[t].apply(this, r);
                        if (o)
                            for (
                                n = o.length, t = 0, n = (i = o.slice()).length;
                                t < n && i[t];
                                ++t
                            )
                                i[t].apply(this, [e].concat(r));
                        return this;
                    }),
                    (t.getWildcardCallbacks = function(e) {
                        this.callbacks = this.callbacks || {};
                        var t,
                            n,
                            i = [];
                        for (t in this.callbacks)
                            (n = t.split('*')),
                                ('*' === t ||
                                    (2 === n.length && e.slice(0, n[0].length) === n[0])) &&
                                    (i = i.concat(this.callbacks[t]));
                        return i;
                    });
            }),
            n.mixin(n);
    },
    function(e, t, n) {
        ((t = e.exports = n(32)).Stream = t),
            (t.Readable = t),
            (t.Writable = n(17)),
            (t.Duplex = n(5)),
            (t.Transform = n(35)),
            (t.PassThrough = n(63));
    },
    function(e, t, n) {
        'use strict';
        (function(t) {
            !t.version ||
            0 === t.version.indexOf('v0.') ||
            (0 === t.version.indexOf('v1.') && 0 !== t.version.indexOf('v1.8.'))
                ? (e.exports = function(e, n, i, r) {
                      if ('function' != typeof e)
                          throw new TypeError('"callback" argument must be a function');
                      var s,
                          o,
                          a = arguments.length;
                      switch (a) {
                          case 0:
                          case 1:
                              return t.nextTick(e);
                          case 2:
                              return t.nextTick(function() {
                                  e.call(null, n);
                              });
                          case 3:
                              return t.nextTick(function() {
                                  e.call(null, n, i);
                              });
                          case 4:
                              return t.nextTick(function() {
                                  e.call(null, n, i, r);
                              });
                          default:
                              for (s = new Array(a - 1), o = 0; o < s.length; )
                                  s[o++] = arguments[o];
                              return t.nextTick(function() {
                                  e.apply(null, s);
                              });
                      }
                  })
                : (e.exports = t.nextTick);
        }.call(this, n(4)));
    },
    function(e, t, n) {
        'use strict';
        (function(e) {
            var i = n(2),
                r = i.Buffer,
                s = i.SlowBuffer,
                o = i.kMaxLength || 2147483647;
            (t.alloc = function(e, t, n) {
                if ('function' == typeof r.alloc) return r.alloc(e, t, n);
                if ('number' == typeof n) throw new TypeError('encoding must not be number');
                if ('number' != typeof e) throw new TypeError('size must be a number');
                if (e > o) throw new RangeError('size is too large');
                var i = n,
                    s = t;
                void 0 === s && ((i = void 0), (s = 0));
                var a = new r(e);
                if ('string' == typeof s)
                    for (var u = new r(s, i), c = u.length, l = -1; ++l < e; ) a[l] = u[l % c];
                else a.fill(s);
                return a;
            }),
                (t.allocUnsafe = function(e) {
                    if ('function' == typeof r.allocUnsafe) return r.allocUnsafe(e);
                    if ('number' != typeof e) throw new TypeError('size must be a number');
                    if (e > o) throw new RangeError('size is too large');
                    return new r(e);
                }),
                (t.from = function(t, n, i) {
                    if (
                        'function' == typeof r.from &&
                        (!e.Uint8Array || Uint8Array.from !== r.from)
                    )
                        return r.from(t, n, i);
                    if ('number' == typeof t)
                        throw new TypeError('"value" argument must not be a number');
                    if ('string' == typeof t) return new r(t, n);
                    if ('undefined' != typeof ArrayBuffer && t instanceof ArrayBuffer) {
                        var s = n;
                        if (1 === arguments.length) return new r(t);
                        void 0 === s && (s = 0);
                        var o = i;
                        if ((void 0 === o && (o = t.byteLength - s), s >= t.byteLength))
                            throw new RangeError("'offset' is out of bounds");
                        if (o > t.byteLength - s) throw new RangeError("'length' is out of bounds");
                        return new r(t.slice(s, s + o));
                    }
                    if (r.isBuffer(t)) {
                        var a = new r(t.length);
                        return t.copy(a, 0, 0, t.length), a;
                    }
                    if (t) {
                        if (
                            Array.isArray(t) ||
                            ('undefined' != typeof ArrayBuffer &&
                                t.buffer instanceof ArrayBuffer) ||
                            'length' in t
                        )
                            return new r(t);
                        if ('Buffer' === t.type && Array.isArray(t.data)) return new r(t.data);
                    }
                    throw new TypeError(
                        'First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.'
                    );
                }),
                (t.allocUnsafeSlow = function(e) {
                    if ('function' == typeof r.allocUnsafeSlow) return r.allocUnsafeSlow(e);
                    if ('number' != typeof e) throw new TypeError('size must be a number');
                    if (e >= o) throw new RangeError('size is too large');
                    return new s(e);
                });
        }.call(this, n(3)));
    },
    function(e, t, n) {
        'use strict';
        (function(t, i) {
            e.exports = g;
            var r,
                s = n(15),
                o = !t.browser && ['v0.10', 'v0.9.'].indexOf(t.version.slice(0, 5)) > -1 ? i : s;
            g.WritableState = m;
            var a = n(10);
            a.inherits = n(0);
            var u,
                c = { deprecate: n(62) },
                l = n(33),
                f = n(2).Buffer,
                d = n(16);
            function h() {}
            function p(e, t, n) {
                (this.chunk = e), (this.encoding = t), (this.callback = n), (this.next = null);
            }
            function m(e, t) {
                (r = r || n(5)),
                    (e = e || {}),
                    (this.objectMode = !!e.objectMode),
                    t instanceof r && (this.objectMode = this.objectMode || !!e.writableObjectMode);
                var i = e.highWaterMark,
                    a = this.objectMode ? 16 : 16384;
                (this.highWaterMark = i || 0 === i ? i : a),
                    (this.highWaterMark = ~~this.highWaterMark),
                    (this.needDrain = !1),
                    (this.ending = !1),
                    (this.ended = !1),
                    (this.finished = !1);
                var u = !1 === e.decodeStrings;
                (this.decodeStrings = !u),
                    (this.defaultEncoding = e.defaultEncoding || 'utf8'),
                    (this.length = 0),
                    (this.writing = !1),
                    (this.corked = 0),
                    (this.sync = !0),
                    (this.bufferProcessing = !1),
                    (this.onwrite = function(e) {
                        !(function(e, t) {
                            var n = e._writableState,
                                i = n.sync,
                                r = n.writecb;
                            if (
                                ((function(e) {
                                    (e.writing = !1),
                                        (e.writecb = null),
                                        (e.length -= e.writelen),
                                        (e.writelen = 0);
                                })(n),
                                t)
                            )
                                !(function(e, t, n, i, r) {
                                    --t.pendingcb, n ? s(r, i) : r(i);
                                    (e._writableState.errorEmitted = !0), e.emit('error', i);
                                })(e, n, i, t, r);
                            else {
                                var a = x(n);
                                a ||
                                    n.corked ||
                                    n.bufferProcessing ||
                                    !n.bufferedRequest ||
                                    v(e, n),
                                    i ? o(y, e, n, a, r) : y(e, n, a, r);
                            }
                        })(t, e);
                    }),
                    (this.writecb = null),
                    (this.writelen = 0),
                    (this.bufferedRequest = null),
                    (this.lastBufferedRequest = null),
                    (this.pendingcb = 0),
                    (this.prefinished = !1),
                    (this.errorEmitted = !1),
                    (this.bufferedRequestCount = 0),
                    (this.corkedRequestsFree = new S(this));
            }
            function g(e) {
                if (((r = r || n(5)), !(u.call(g, this) || this instanceof r))) return new g(e);
                (this._writableState = new m(e, this)),
                    (this.writable = !0),
                    e &&
                        ('function' == typeof e.write && (this._write = e.write),
                        'function' == typeof e.writev && (this._writev = e.writev)),
                    l.call(this);
            }
            function b(e, t, n, i, r, s, o) {
                (t.writelen = i),
                    (t.writecb = o),
                    (t.writing = !0),
                    (t.sync = !0),
                    n ? e._writev(r, t.onwrite) : e._write(r, s, t.onwrite),
                    (t.sync = !1);
            }
            function y(e, t, n, i) {
                n ||
                    (function(e, t) {
                        0 === t.length && t.needDrain && ((t.needDrain = !1), e.emit('drain'));
                    })(e, t),
                    t.pendingcb--,
                    i(),
                    _(e, t);
            }
            function v(e, t) {
                t.bufferProcessing = !0;
                var n = t.bufferedRequest;
                if (e._writev && n && n.next) {
                    var i = t.bufferedRequestCount,
                        r = new Array(i),
                        s = t.corkedRequestsFree;
                    s.entry = n;
                    for (var o = 0; n; ) (r[o] = n), (n = n.next), (o += 1);
                    b(e, t, !0, t.length, r, '', s.finish),
                        t.pendingcb++,
                        (t.lastBufferedRequest = null),
                        s.next
                            ? ((t.corkedRequestsFree = s.next), (s.next = null))
                            : (t.corkedRequestsFree = new S(t));
                } else {
                    for (; n; ) {
                        var a = n.chunk,
                            u = n.encoding,
                            c = n.callback;
                        if (
                            (b(e, t, !1, t.objectMode ? 1 : a.length, a, u, c),
                            (n = n.next),
                            t.writing)
                        )
                            break;
                    }
                    null === n && (t.lastBufferedRequest = null);
                }
                (t.bufferedRequestCount = 0), (t.bufferedRequest = n), (t.bufferProcessing = !1);
            }
            function x(e) {
                return (
                    e.ending &&
                    0 === e.length &&
                    null === e.bufferedRequest &&
                    !e.finished &&
                    !e.writing
                );
            }
            function w(e, t) {
                t.prefinished || ((t.prefinished = !0), e.emit('prefinish'));
            }
            function _(e, t) {
                var n = x(t);
                return (
                    n &&
                        (0 === t.pendingcb
                            ? (w(e, t), (t.finished = !0), e.emit('finish'))
                            : w(e, t)),
                    n
                );
            }
            function S(e) {
                var t = this;
                (this.next = null),
                    (this.entry = null),
                    (this.finish = function(n) {
                        var i = t.entry;
                        for (t.entry = null; i; ) {
                            var r = i.callback;
                            e.pendingcb--, r(n), (i = i.next);
                        }
                        e.corkedRequestsFree
                            ? (e.corkedRequestsFree.next = t)
                            : (e.corkedRequestsFree = t);
                    });
            }
            a.inherits(g, l),
                (m.prototype.getBuffer = function() {
                    for (var e = this.bufferedRequest, t = []; e; ) t.push(e), (e = e.next);
                    return t;
                }),
                (function() {
                    try {
                        Object.defineProperty(m.prototype, 'buffer', {
                            get: c.deprecate(function() {
                                return this.getBuffer();
                            }, '_writableState.buffer is deprecated. Use _writableState.getBuffer instead.')
                        });
                    } catch (e) {}
                })(),
                'function' == typeof Symbol &&
                Symbol.hasInstance &&
                'function' == typeof Function.prototype[Symbol.hasInstance]
                    ? ((u = Function.prototype[Symbol.hasInstance]),
                      Object.defineProperty(g, Symbol.hasInstance, {
                          value: function(e) {
                              return !!u.call(this, e) || (e && e._writableState instanceof m);
                          }
                      }))
                    : (u = function(e) {
                          return e instanceof this;
                      }),
                (g.prototype.pipe = function() {
                    this.emit('error', new Error('Cannot pipe, not readable'));
                }),
                (g.prototype.write = function(e, t, n) {
                    var i = this._writableState,
                        r = !1,
                        o = f.isBuffer(e);
                    return (
                        'function' == typeof t && ((n = t), (t = null)),
                        o ? (t = 'buffer') : t || (t = i.defaultEncoding),
                        'function' != typeof n && (n = h),
                        i.ended
                            ? (function(e, t) {
                                  var n = new Error('write after end');
                                  e.emit('error', n), s(t, n);
                              })(this, n)
                            : (o ||
                                  (function(e, t, n, i) {
                                      var r = !0,
                                          o = !1;
                                      return (
                                          null === n
                                              ? (o = new TypeError(
                                                    'May not write null values to stream'
                                                ))
                                              : 'string' == typeof n ||
                                                void 0 === n ||
                                                t.objectMode ||
                                                (o = new TypeError(
                                                    'Invalid non-string/buffer chunk'
                                                )),
                                          o && (e.emit('error', o), s(i, o), (r = !1)),
                                          r
                                      );
                                  })(this, i, e, n)) &&
                              (i.pendingcb++,
                              (r = (function(e, t, n, i, r, s) {
                                  n ||
                                      ((i = (function(e, t, n) {
                                          e.objectMode ||
                                              !1 === e.decodeStrings ||
                                              'string' != typeof t ||
                                              (t = d.from(t, n));
                                          return t;
                                      })(t, i, r)),
                                      f.isBuffer(i) && (r = 'buffer'));
                                  var o = t.objectMode ? 1 : i.length;
                                  t.length += o;
                                  var a = t.length < t.highWaterMark;
                                  a || (t.needDrain = !0);
                                  if (t.writing || t.corked) {
                                      var u = t.lastBufferedRequest;
                                      (t.lastBufferedRequest = new p(i, r, s)),
                                          u
                                              ? (u.next = t.lastBufferedRequest)
                                              : (t.bufferedRequest = t.lastBufferedRequest),
                                          (t.bufferedRequestCount += 1);
                                  } else b(e, t, !1, o, i, r, s);
                                  return a;
                              })(this, i, o, e, t, n))),
                        r
                    );
                }),
                (g.prototype.cork = function() {
                    this._writableState.corked++;
                }),
                (g.prototype.uncork = function() {
                    var e = this._writableState;
                    e.corked &&
                        (e.corked--,
                        e.writing ||
                            e.corked ||
                            e.finished ||
                            e.bufferProcessing ||
                            !e.bufferedRequest ||
                            v(this, e));
                }),
                (g.prototype.setDefaultEncoding = function(e) {
                    if (
                        ('string' == typeof e && (e = e.toLowerCase()),
                        !(
                            [
                                'hex',
                                'utf8',
                                'utf-8',
                                'ascii',
                                'binary',
                                'base64',
                                'ucs2',
                                'ucs-2',
                                'utf16le',
                                'utf-16le',
                                'raw'
                            ].indexOf((e + '').toLowerCase()) > -1
                        ))
                    )
                        throw new TypeError('Unknown encoding: ' + e);
                    return (this._writableState.defaultEncoding = e), this;
                }),
                (g.prototype._write = function(e, t, n) {
                    n(new Error('_write() is not implemented'));
                }),
                (g.prototype._writev = null),
                (g.prototype.end = function(e, t, n) {
                    var i = this._writableState;
                    'function' == typeof e
                        ? ((n = e), (e = null), (t = null))
                        : 'function' == typeof t && ((n = t), (t = null)),
                        null != e && this.write(e, t),
                        i.corked && ((i.corked = 1), this.uncork()),
                        i.ending ||
                            i.finished ||
                            (function(e, t, n) {
                                (t.ending = !0),
                                    _(e, t),
                                    n && (t.finished ? s(n) : e.once('finish', n));
                                (t.ended = !0), (e.writable = !1);
                            })(this, i, n);
                });
        }.call(this, n(4), n(34).setImmediate));
    },
    function(e, t, n) {
        'use strict';
        var i = n(1).Buffer,
            r =
                i.isEncoding ||
                function(e) {
                    switch ((e = '' + e) && e.toLowerCase()) {
                        case 'hex':
                        case 'utf8':
                        case 'utf-8':
                        case 'ascii':
                        case 'binary':
                        case 'base64':
                        case 'ucs2':
                        case 'ucs-2':
                        case 'utf16le':
                        case 'utf-16le':
                        case 'raw':
                            return !0;
                        default:
                            return !1;
                    }
                };
        function s(e) {
            var t;
            switch (
                ((this.encoding = (function(e) {
                    var t = (function(e) {
                        if (!e) return 'utf8';
                        for (var t; ; )
                            switch (e) {
                                case 'utf8':
                                case 'utf-8':
                                    return 'utf8';
                                case 'ucs2':
                                case 'ucs-2':
                                case 'utf16le':
                                case 'utf-16le':
                                    return 'utf16le';
                                case 'latin1':
                                case 'binary':
                                    return 'latin1';
                                case 'base64':
                                case 'ascii':
                                case 'hex':
                                    return e;
                                default:
                                    if (t) return;
                                    (e = ('' + e).toLowerCase()), (t = !0);
                            }
                    })(e);
                    if ('string' != typeof t && (i.isEncoding === r || !r(e)))
                        throw new Error('Unknown encoding: ' + e);
                    return t || e;
                })(e)),
                this.encoding)
            ) {
                case 'utf16le':
                    (this.text = u), (this.end = c), (t = 4);
                    break;
                case 'utf8':
                    (this.fillLast = a), (t = 4);
                    break;
                case 'base64':
                    (this.text = l), (this.end = f), (t = 3);
                    break;
                default:
                    return (this.write = d), void (this.end = h);
            }
            (this.lastNeed = 0), (this.lastTotal = 0), (this.lastChar = i.allocUnsafe(t));
        }
        function o(e) {
            return e <= 127 ? 0 : e >> 5 == 6 ? 2 : e >> 4 == 14 ? 3 : e >> 3 == 30 ? 4 : -1;
        }
        function a(e) {
            var t = this.lastTotal - this.lastNeed,
                n = (function(e, t, n) {
                    if (128 != (192 & t[0])) return (e.lastNeed = 0), '�'.repeat(n);
                    if (e.lastNeed > 1 && t.length > 1) {
                        if (128 != (192 & t[1])) return (e.lastNeed = 1), '�'.repeat(n + 1);
                        if (e.lastNeed > 2 && t.length > 2 && 128 != (192 & t[2]))
                            return (e.lastNeed = 2), '�'.repeat(n + 2);
                    }
                })(this, e, t);
            return void 0 !== n
                ? n
                : this.lastNeed <= e.length
                ? (e.copy(this.lastChar, t, 0, this.lastNeed),
                  this.lastChar.toString(this.encoding, 0, this.lastTotal))
                : (e.copy(this.lastChar, t, 0, e.length), void (this.lastNeed -= e.length));
        }
        function u(e, t) {
            if ((e.length - t) % 2 == 0) {
                var n = e.toString('utf16le', t);
                if (n) {
                    var i = n.charCodeAt(n.length - 1);
                    if (i >= 55296 && i <= 56319)
                        return (
                            (this.lastNeed = 2),
                            (this.lastTotal = 4),
                            (this.lastChar[0] = e[e.length - 2]),
                            (this.lastChar[1] = e[e.length - 1]),
                            n.slice(0, -1)
                        );
                }
                return n;
            }
            return (
                (this.lastNeed = 1),
                (this.lastTotal = 2),
                (this.lastChar[0] = e[e.length - 1]),
                e.toString('utf16le', t, e.length - 1)
            );
        }
        function c(e) {
            var t = e && e.length ? this.write(e) : '';
            if (this.lastNeed) {
                var n = this.lastTotal - this.lastNeed;
                return t + this.lastChar.toString('utf16le', 0, n);
            }
            return t;
        }
        function l(e, t) {
            var n = (e.length - t) % 3;
            return 0 === n
                ? e.toString('base64', t)
                : ((this.lastNeed = 3 - n),
                  (this.lastTotal = 3),
                  1 === n
                      ? (this.lastChar[0] = e[e.length - 1])
                      : ((this.lastChar[0] = e[e.length - 2]),
                        (this.lastChar[1] = e[e.length - 1])),
                  e.toString('base64', t, e.length - n));
        }
        function f(e) {
            var t = e && e.length ? this.write(e) : '';
            return this.lastNeed ? t + this.lastChar.toString('base64', 0, 3 - this.lastNeed) : t;
        }
        function d(e) {
            return e.toString(this.encoding);
        }
        function h(e) {
            return e && e.length ? this.write(e) : '';
        }
        (t.StringDecoder = s),
            (s.prototype.write = function(e) {
                if (0 === e.length) return '';
                var t, n;
                if (this.lastNeed) {
                    if (void 0 === (t = this.fillLast(e))) return '';
                    (n = this.lastNeed), (this.lastNeed = 0);
                } else n = 0;
                return n < e.length ? (t ? t + this.text(e, n) : this.text(e, n)) : t || '';
            }),
            (s.prototype.end = function(e) {
                var t = e && e.length ? this.write(e) : '';
                return this.lastNeed ? t + '�'.repeat(this.lastTotal - this.lastNeed) : t;
            }),
            (s.prototype.text = function(e, t) {
                var n = (function(e, t, n) {
                    var i = t.length - 1;
                    if (i < n) return 0;
                    var r = o(t[i]);
                    if (r >= 0) return r > 0 && (e.lastNeed = r - 1), r;
                    if (--i < n) return 0;
                    if ((r = o(t[i])) >= 0) return r > 0 && (e.lastNeed = r - 2), r;
                    if (--i < n) return 0;
                    if ((r = o(t[i])) >= 0)
                        return r > 0 && (2 === r ? (r = 0) : (e.lastNeed = r - 3)), r;
                    return 0;
                })(this, e, t);
                if (!this.lastNeed) return e.toString('utf8', t);
                this.lastTotal = n;
                var i = e.length - (n - this.lastNeed);
                return e.copy(this.lastChar, 0, i), e.toString('utf8', t, i);
            }),
            (s.prototype.fillLast = function(e) {
                if (this.lastNeed <= e.length)
                    return (
                        e.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, this.lastNeed),
                        this.lastChar.toString(this.encoding, 0, this.lastTotal)
                    );
                e.copy(this.lastChar, this.lastTotal - this.lastNeed, 0, e.length),
                    (this.lastNeed -= e.length);
            });
    },
    function(e, t, n) {
        var i = n(1).Buffer,
            r = n(31).Transform,
            s = n(18).StringDecoder;
        function o(e) {
            r.call(this),
                (this.hashMode = 'string' == typeof e),
                this.hashMode
                    ? (this[e] = this._finalOrDigest)
                    : (this.final = this._finalOrDigest),
                this._final && ((this.__final = this._final), (this._final = null)),
                (this._decoder = null),
                (this._encoding = null);
        }
        n(0)(o, r),
            (o.prototype.update = function(e, t, n) {
                'string' == typeof e && (e = i.from(e, t));
                var r = this._update(e);
                return this.hashMode ? this : (n && (r = this._toString(r, n)), r);
            }),
            (o.prototype.setAutoPadding = function() {}),
            (o.prototype.getAuthTag = function() {
                throw new Error('trying to get auth tag in unsupported state');
            }),
            (o.prototype.setAuthTag = function() {
                throw new Error('trying to set auth tag in unsupported state');
            }),
            (o.prototype.setAAD = function() {
                throw new Error('trying to set aad in unsupported state');
            }),
            (o.prototype._transform = function(e, t, n) {
                var i;
                try {
                    this.hashMode ? this._update(e) : this.push(this._update(e));
                } catch (e) {
                    i = e;
                } finally {
                    n(i);
                }
            }),
            (o.prototype._flush = function(e) {
                var t;
                try {
                    this.push(this.__final());
                } catch (e) {
                    t = e;
                }
                e(t);
            }),
            (o.prototype._finalOrDigest = function(e) {
                var t = this.__final() || i.alloc(0);
                return e && (t = this._toString(t, e, !0)), t;
            }),
            (o.prototype._toString = function(e, t, n) {
                if (
                    (this._decoder || ((this._decoder = new s(t)), (this._encoding = t)),
                    this._encoding !== t)
                )
                    throw new Error("can't switch encodings");
                var i = this._decoder.write(e);
                return n && (i += this._decoder.end()), i;
            }),
            (e.exports = o);
    },
    function(e, t) {
        var n = {}.toString;
        e.exports =
            Array.isArray ||
            function(e) {
                return '[object Array]' == n.call(e);
            };
    },
    function(e, t, n) {
        var i = n(45),
            r = n(46),
            s = r;
        (s.v1 = i), (s.v4 = r), (e.exports = s);
    },
    function(e, t) {
        var n =
            ('undefined' != typeof crypto &&
                crypto.getRandomValues &&
                crypto.getRandomValues.bind(crypto)) ||
            ('undefined' != typeof msCrypto &&
                'function' == typeof window.msCrypto.getRandomValues &&
                msCrypto.getRandomValues.bind(msCrypto));
        if (n) {
            var i = new Uint8Array(16);
            e.exports = function() {
                return n(i), i;
            };
        } else {
            var r = new Array(16);
            e.exports = function() {
                for (var e, t = 0; t < 16; t++)
                    0 == (3 & t) && (e = 4294967296 * Math.random()),
                        (r[t] = (e >>> ((3 & t) << 3)) & 255);
                return r;
            };
        }
    },
    function(e, t) {
        for (var n = [], i = 0; i < 256; ++i) n[i] = (i + 256).toString(16).substr(1);
        e.exports = function(e, t) {
            var i = t || 0,
                r = n;
            return [
                r[e[i++]],
                r[e[i++]],
                r[e[i++]],
                r[e[i++]],
                '-',
                r[e[i++]],
                r[e[i++]],
                '-',
                r[e[i++]],
                r[e[i++]],
                '-',
                r[e[i++]],
                r[e[i++]],
                '-',
                r[e[i++]],
                r[e[i++]],
                r[e[i++]],
                r[e[i++]],
                r[e[i++]],
                r[e[i++]]
            ].join('');
        };
    },
    function(e, t, n) {
        'use strict';
        var i = n(25);
        e.exports = function(e, t) {
            var n;
            n = 'function' == typeof t ? new t() : new i(t);
            var r = null,
                s = null;
            if (
                (n.on('tree', function(e) {
                    r = e;
                }),
                n.on('error', function(e) {
                    s = e;
                }),
                n.write(e),
                n.end(),
                s)
            )
                throw s;
            return r;
        };
    },
    function(e, t, n) {
        'use strict';
        var i = n(6).EventEmitter,
            r = n(0),
            s = n(9),
            o = n(50),
            a = function(e) {
                i.call(this);
                var t,
                    n = (this.Parser = (e && e.Parser) || this.DefaultParser),
                    r = (this.Element = (e && e.Element) || this.DefaultElement);
                this.parser = new n();
                var s = this;
                this.parser.on('startElement', function(e, n) {
                    var i = new r(e, n);
                    t = t ? t.cnode(i) : i;
                }),
                    this.parser.on('endElement', function(e) {
                        t &&
                            e === t.name &&
                            (t.parent ? (t = t.parent) : s.tree || ((s.tree = t), (t = void 0)));
                    }),
                    this.parser.on('text', function(e) {
                        t && t.t(e);
                    }),
                    this.parser.on('error', function(e) {
                        (s.error = e), s.emit('error', e);
                    });
            };
        r(a, i),
            (a.prototype.DefaultParser = o),
            (a.prototype.DefaultElement = s),
            (a.prototype.write = function(e) {
                this.parser.write(e);
            }),
            (a.prototype.end = function(e) {
                this.parser.end(e),
                    this.error ||
                        (this.tree
                            ? this.emit('tree', this.tree)
                            : this.emit('error', new Error('Incomplete document')));
            }),
            (e.exports = a);
    },
    function(e, t, n) {
        'use strict';
        function i(e, t) {
            return e.name === t.name;
        }
        function r(e, t) {
            var n = e.attrs,
                i = Object.keys(n),
                r = i.length;
            if (r !== Object.keys(t.attrs).length) return !1;
            for (var s = 0, o = r; s < o; s++) {
                var a = i[s],
                    u = n[a];
                if (null == u || null == t.attrs[a]) {
                    if (u !== t.attrs[a]) return !1;
                } else if (u.toString() !== t.attrs[a].toString()) return !1;
            }
            return !0;
        }
        function s(e, t) {
            var n = e.children,
                i = n.length;
            if (i !== t.children.length) return !1;
            for (var r = 0, s = i; r < s; r++) {
                var o = n[r];
                if ('string' == typeof o) {
                    if (o !== t.children[r]) return !1;
                } else if (!o.equals(t.children[r])) return !1;
            }
            return !0;
        }
        (e.exports.name = i),
            (e.exports.attrs = r),
            (e.exports.children = s),
            (e.exports.equal = function(e, t) {
                return !!i(e, t) && !!r(e, t) && !!s(e, t);
            });
    },
    function(e, t, n) {
        'use strict';
        e.exports = function(e) {
            for (var t = new e.constructor(e.name, e.attrs), n = 0; n < e.children.length; n++) {
                var i = e.children[n];
                t.cnode(i.clone ? i.clone() : i);
            }
            return t;
        };
    },
    function(e, t, n) {
        'use strict';
        var i = n(11).escapeXML;
        e.exports = function() {
            for (var e = arguments[0], t = '', n = 1; n < arguments.length; n++)
                (t += e[n - 1]), (t += i(arguments[n]));
            return (t += e[e.length - 1]);
        };
    },
    function(e, t, n) {
        'use strict';
        var i = n(0),
            r = n(30),
            s = n(1).Buffer,
            o = new Array(16);
        function a() {
            r.call(this, 64),
                (this._a = 1732584193),
                (this._b = 4023233417),
                (this._c = 2562383102),
                (this._d = 271733878);
        }
        function u(e, t) {
            return (e << t) | (e >>> (32 - t));
        }
        function c(e, t, n, i, r, s, o) {
            return (u((e + ((t & n) | (~t & i)) + r + s) | 0, o) + t) | 0;
        }
        function l(e, t, n, i, r, s, o) {
            return (u((e + ((t & i) | (n & ~i)) + r + s) | 0, o) + t) | 0;
        }
        function f(e, t, n, i, r, s, o) {
            return (u((e + (t ^ n ^ i) + r + s) | 0, o) + t) | 0;
        }
        function d(e, t, n, i, r, s, o) {
            return (u((e + (n ^ (t | ~i)) + r + s) | 0, o) + t) | 0;
        }
        i(a, r),
            (a.prototype._update = function() {
                for (var e = o, t = 0; t < 16; ++t) e[t] = this._block.readInt32LE(4 * t);
                var n = this._a,
                    i = this._b,
                    r = this._c,
                    s = this._d;
                (n = c(n, i, r, s, e[0], 3614090360, 7)),
                    (s = c(s, n, i, r, e[1], 3905402710, 12)),
                    (r = c(r, s, n, i, e[2], 606105819, 17)),
                    (i = c(i, r, s, n, e[3], 3250441966, 22)),
                    (n = c(n, i, r, s, e[4], 4118548399, 7)),
                    (s = c(s, n, i, r, e[5], 1200080426, 12)),
                    (r = c(r, s, n, i, e[6], 2821735955, 17)),
                    (i = c(i, r, s, n, e[7], 4249261313, 22)),
                    (n = c(n, i, r, s, e[8], 1770035416, 7)),
                    (s = c(s, n, i, r, e[9], 2336552879, 12)),
                    (r = c(r, s, n, i, e[10], 4294925233, 17)),
                    (i = c(i, r, s, n, e[11], 2304563134, 22)),
                    (n = c(n, i, r, s, e[12], 1804603682, 7)),
                    (s = c(s, n, i, r, e[13], 4254626195, 12)),
                    (r = c(r, s, n, i, e[14], 2792965006, 17)),
                    (n = l(
                        n,
                        (i = c(i, r, s, n, e[15], 1236535329, 22)),
                        r,
                        s,
                        e[1],
                        4129170786,
                        5
                    )),
                    (s = l(s, n, i, r, e[6], 3225465664, 9)),
                    (r = l(r, s, n, i, e[11], 643717713, 14)),
                    (i = l(i, r, s, n, e[0], 3921069994, 20)),
                    (n = l(n, i, r, s, e[5], 3593408605, 5)),
                    (s = l(s, n, i, r, e[10], 38016083, 9)),
                    (r = l(r, s, n, i, e[15], 3634488961, 14)),
                    (i = l(i, r, s, n, e[4], 3889429448, 20)),
                    (n = l(n, i, r, s, e[9], 568446438, 5)),
                    (s = l(s, n, i, r, e[14], 3275163606, 9)),
                    (r = l(r, s, n, i, e[3], 4107603335, 14)),
                    (i = l(i, r, s, n, e[8], 1163531501, 20)),
                    (n = l(n, i, r, s, e[13], 2850285829, 5)),
                    (s = l(s, n, i, r, e[2], 4243563512, 9)),
                    (r = l(r, s, n, i, e[7], 1735328473, 14)),
                    (n = f(
                        n,
                        (i = l(i, r, s, n, e[12], 2368359562, 20)),
                        r,
                        s,
                        e[5],
                        4294588738,
                        4
                    )),
                    (s = f(s, n, i, r, e[8], 2272392833, 11)),
                    (r = f(r, s, n, i, e[11], 1839030562, 16)),
                    (i = f(i, r, s, n, e[14], 4259657740, 23)),
                    (n = f(n, i, r, s, e[1], 2763975236, 4)),
                    (s = f(s, n, i, r, e[4], 1272893353, 11)),
                    (r = f(r, s, n, i, e[7], 4139469664, 16)),
                    (i = f(i, r, s, n, e[10], 3200236656, 23)),
                    (n = f(n, i, r, s, e[13], 681279174, 4)),
                    (s = f(s, n, i, r, e[0], 3936430074, 11)),
                    (r = f(r, s, n, i, e[3], 3572445317, 16)),
                    (i = f(i, r, s, n, e[6], 76029189, 23)),
                    (n = f(n, i, r, s, e[9], 3654602809, 4)),
                    (s = f(s, n, i, r, e[12], 3873151461, 11)),
                    (r = f(r, s, n, i, e[15], 530742520, 16)),
                    (n = d(
                        n,
                        (i = f(i, r, s, n, e[2], 3299628645, 23)),
                        r,
                        s,
                        e[0],
                        4096336452,
                        6
                    )),
                    (s = d(s, n, i, r, e[7], 1126891415, 10)),
                    (r = d(r, s, n, i, e[14], 2878612391, 15)),
                    (i = d(i, r, s, n, e[5], 4237533241, 21)),
                    (n = d(n, i, r, s, e[12], 1700485571, 6)),
                    (s = d(s, n, i, r, e[3], 2399980690, 10)),
                    (r = d(r, s, n, i, e[10], 4293915773, 15)),
                    (i = d(i, r, s, n, e[1], 2240044497, 21)),
                    (n = d(n, i, r, s, e[8], 1873313359, 6)),
                    (s = d(s, n, i, r, e[15], 4264355552, 10)),
                    (r = d(r, s, n, i, e[6], 2734768916, 15)),
                    (i = d(i, r, s, n, e[13], 1309151649, 21)),
                    (n = d(n, i, r, s, e[4], 4149444226, 6)),
                    (s = d(s, n, i, r, e[11], 3174756917, 10)),
                    (r = d(r, s, n, i, e[2], 718787259, 15)),
                    (i = d(i, r, s, n, e[9], 3951481745, 21)),
                    (this._a = (this._a + n) | 0),
                    (this._b = (this._b + i) | 0),
                    (this._c = (this._c + r) | 0),
                    (this._d = (this._d + s) | 0);
            }),
            (a.prototype._digest = function() {
                (this._block[this._blockOffset++] = 128),
                    this._blockOffset > 56 &&
                        (this._block.fill(0, this._blockOffset, 64),
                        this._update(),
                        (this._blockOffset = 0)),
                    this._block.fill(0, this._blockOffset, 56),
                    this._block.writeUInt32LE(this._length[0], 56),
                    this._block.writeUInt32LE(this._length[1], 60),
                    this._update();
                var e = s.allocUnsafe(16);
                return (
                    e.writeInt32LE(this._a, 0),
                    e.writeInt32LE(this._b, 4),
                    e.writeInt32LE(this._c, 8),
                    e.writeInt32LE(this._d, 12),
                    e
                );
            }),
            (e.exports = a);
    },
    function(e, t, n) {
        'use strict';
        var i = n(1).Buffer,
            r = n(31).Transform;
        function s(e) {
            r.call(this),
                (this._block = i.allocUnsafe(e)),
                (this._blockSize = e),
                (this._blockOffset = 0),
                (this._length = [0, 0, 0, 0]),
                (this._finalized = !1);
        }
        n(0)(s, r),
            (s.prototype._transform = function(e, t, n) {
                var i = null;
                try {
                    this.update(e, t);
                } catch (e) {
                    i = e;
                }
                n(i);
            }),
            (s.prototype._flush = function(e) {
                var t = null;
                try {
                    this.push(this.digest());
                } catch (e) {
                    t = e;
                }
                e(t);
            }),
            (s.prototype.update = function(e, t) {
                if (
                    ((function(e, t) {
                        if (!i.isBuffer(e) && 'string' != typeof e)
                            throw new TypeError(t + ' must be a string or a buffer');
                    })(e, 'Data'),
                    this._finalized)
                )
                    throw new Error('Digest already called');
                i.isBuffer(e) || (e = i.from(e, t));
                for (
                    var n = this._block, r = 0;
                    this._blockOffset + e.length - r >= this._blockSize;

                ) {
                    for (var s = this._blockOffset; s < this._blockSize; ) n[s++] = e[r++];
                    this._update(), (this._blockOffset = 0);
                }
                for (; r < e.length; ) n[this._blockOffset++] = e[r++];
                for (var o = 0, a = 8 * e.length; a > 0; ++o)
                    (this._length[o] += a),
                        (a = (this._length[o] / 4294967296) | 0) > 0 &&
                            (this._length[o] -= 4294967296 * a);
                return this;
            }),
            (s.prototype._update = function() {
                throw new Error('_update is not implemented');
            }),
            (s.prototype.digest = function(e) {
                if (this._finalized) throw new Error('Digest already called');
                this._finalized = !0;
                var t = this._digest();
                void 0 !== e && (t = t.toString(e)), this._block.fill(0), (this._blockOffset = 0);
                for (var n = 0; n < 4; ++n) this._length[n] = 0;
                return t;
            }),
            (s.prototype._digest = function() {
                throw new Error('_digest is not implemented');
            }),
            (e.exports = s);
    },
    function(e, t, n) {
        e.exports = r;
        var i = n(6).EventEmitter;
        function r() {
            i.call(this);
        }
        n(0)(r, i),
            (r.Readable = n(14)),
            (r.Writable = n(64)),
            (r.Duplex = n(65)),
            (r.Transform = n(66)),
            (r.PassThrough = n(67)),
            (r.Stream = r),
            (r.prototype.pipe = function(e, t) {
                var n = this;
                function r(t) {
                    e.writable && !1 === e.write(t) && n.pause && n.pause();
                }
                function s() {
                    n.readable && n.resume && n.resume();
                }
                n.on('data', r),
                    e.on('drain', s),
                    e._isStdio || (t && !1 === t.end) || (n.on('end', a), n.on('close', u));
                var o = !1;
                function a() {
                    o || ((o = !0), e.end());
                }
                function u() {
                    o || ((o = !0), 'function' == typeof e.destroy && e.destroy());
                }
                function c(e) {
                    if ((l(), 0 === i.listenerCount(this, 'error'))) throw e;
                }
                function l() {
                    n.removeListener('data', r),
                        e.removeListener('drain', s),
                        n.removeListener('end', a),
                        n.removeListener('close', u),
                        n.removeListener('error', c),
                        e.removeListener('error', c),
                        n.removeListener('end', l),
                        n.removeListener('close', l),
                        e.removeListener('close', l);
                }
                return (
                    n.on('error', c),
                    e.on('error', c),
                    n.on('end', l),
                    n.on('close', l),
                    e.on('close', l),
                    e.emit('pipe', n),
                    e
                );
            });
    },
    function(e, t, n) {
        'use strict';
        (function(t) {
            e.exports = b;
            var i,
                r = n(15),
                s = n(20);
            b.ReadableState = g;
            n(6).EventEmitter;
            var o = function(e, t) {
                    return e.listeners(t).length;
                },
                a = n(33),
                u = n(2).Buffer,
                c = n(16),
                l = n(10);
            l.inherits = n(0);
            var f = n(59),
                d = void 0;
            d = f && f.debuglog ? f.debuglog('stream') : function() {};
            var h,
                p = n(60);
            l.inherits(b, a);
            var m = ['error', 'close', 'destroy', 'pause', 'resume'];
            function g(e, t) {
                (i = i || n(5)),
                    (e = e || {}),
                    (this.objectMode = !!e.objectMode),
                    t instanceof i && (this.objectMode = this.objectMode || !!e.readableObjectMode);
                var r = e.highWaterMark,
                    s = this.objectMode ? 16 : 16384;
                (this.highWaterMark = r || 0 === r ? r : s),
                    (this.highWaterMark = ~~this.highWaterMark),
                    (this.buffer = new p()),
                    (this.length = 0),
                    (this.pipes = null),
                    (this.pipesCount = 0),
                    (this.flowing = null),
                    (this.ended = !1),
                    (this.endEmitted = !1),
                    (this.reading = !1),
                    (this.sync = !0),
                    (this.needReadable = !1),
                    (this.emittedReadable = !1),
                    (this.readableListening = !1),
                    (this.resumeScheduled = !1),
                    (this.defaultEncoding = e.defaultEncoding || 'utf8'),
                    (this.ranOut = !1),
                    (this.awaitDrain = 0),
                    (this.readingMore = !1),
                    (this.decoder = null),
                    (this.encoding = null),
                    e.encoding &&
                        (h || (h = n(18).StringDecoder),
                        (this.decoder = new h(e.encoding)),
                        (this.encoding = e.encoding));
            }
            function b(e) {
                if (((i = i || n(5)), !(this instanceof b))) return new b(e);
                (this._readableState = new g(e, this)),
                    (this.readable = !0),
                    e && 'function' == typeof e.read && (this._read = e.read),
                    a.call(this);
            }
            function y(e, t, n, i, s) {
                var o = (function(e, t) {
                    var n = null;
                    u.isBuffer(t) ||
                        'string' == typeof t ||
                        null == t ||
                        e.objectMode ||
                        (n = new TypeError('Invalid non-string/buffer chunk'));
                    return n;
                })(t, n);
                if (o) e.emit('error', o);
                else if (null === n)
                    (t.reading = !1),
                        (function(e, t) {
                            if (t.ended) return;
                            if (t.decoder) {
                                var n = t.decoder.end();
                                n &&
                                    n.length &&
                                    (t.buffer.push(n), (t.length += t.objectMode ? 1 : n.length));
                            }
                            (t.ended = !0), w(e);
                        })(e, t);
                else if (t.objectMode || (n && n.length > 0))
                    if (t.ended && !s) {
                        var a = new Error('stream.push() after EOF');
                        e.emit('error', a);
                    } else if (t.endEmitted && s) {
                        var c = new Error('stream.unshift() after end event');
                        e.emit('error', c);
                    } else {
                        var l;
                        !t.decoder ||
                            s ||
                            i ||
                            ((n = t.decoder.write(n)), (l = !t.objectMode && 0 === n.length)),
                            s || (t.reading = !1),
                            l ||
                                (t.flowing && 0 === t.length && !t.sync
                                    ? (e.emit('data', n), e.read(0))
                                    : ((t.length += t.objectMode ? 1 : n.length),
                                      s ? t.buffer.unshift(n) : t.buffer.push(n),
                                      t.needReadable && w(e))),
                            (function(e, t) {
                                t.readingMore || ((t.readingMore = !0), r(S, e, t));
                            })(e, t);
                    }
                else s || (t.reading = !1);
                return (function(e) {
                    return (
                        !e.ended && (e.needReadable || e.length < e.highWaterMark || 0 === e.length)
                    );
                })(t);
            }
            (b.prototype.push = function(e, t) {
                var n = this._readableState;
                return (
                    n.objectMode ||
                        'string' != typeof e ||
                        ((t = t || n.defaultEncoding) !== n.encoding &&
                            ((e = c.from(e, t)), (t = ''))),
                    y(this, n, e, t, !1)
                );
            }),
                (b.prototype.unshift = function(e) {
                    return y(this, this._readableState, e, '', !0);
                }),
                (b.prototype.isPaused = function() {
                    return !1 === this._readableState.flowing;
                }),
                (b.prototype.setEncoding = function(e) {
                    return (
                        h || (h = n(18).StringDecoder),
                        (this._readableState.decoder = new h(e)),
                        (this._readableState.encoding = e),
                        this
                    );
                });
            var v = 8388608;
            function x(e, t) {
                return e <= 0 || (0 === t.length && t.ended)
                    ? 0
                    : t.objectMode
                    ? 1
                    : e != e
                    ? t.flowing && t.length
                        ? t.buffer.head.data.length
                        : t.length
                    : (e > t.highWaterMark &&
                          (t.highWaterMark = (function(e) {
                              return (
                                  e >= v
                                      ? (e = v)
                                      : (e--,
                                        (e |= e >>> 1),
                                        (e |= e >>> 2),
                                        (e |= e >>> 4),
                                        (e |= e >>> 8),
                                        (e |= e >>> 16),
                                        e++),
                                  e
                              );
                          })(e)),
                      e <= t.length ? e : t.ended ? t.length : ((t.needReadable = !0), 0));
            }
            function w(e) {
                var t = e._readableState;
                (t.needReadable = !1),
                    t.emittedReadable ||
                        (d('emitReadable', t.flowing),
                        (t.emittedReadable = !0),
                        t.sync ? r(_, e) : _(e));
            }
            function _(e) {
                d('emit readable'), e.emit('readable'), I(e);
            }
            function S(e, t) {
                for (
                    var n = t.length;
                    !t.reading &&
                    !t.flowing &&
                    !t.ended &&
                    t.length < t.highWaterMark &&
                    (d('maybeReadMore read 0'), e.read(0), n !== t.length);

                )
                    n = t.length;
                t.readingMore = !1;
            }
            function A(e) {
                d('readable nexttick read 0'), e.read(0);
            }
            function E(e, t) {
                t.reading || (d('resume read 0'), e.read(0)),
                    (t.resumeScheduled = !1),
                    (t.awaitDrain = 0),
                    e.emit('resume'),
                    I(e),
                    t.flowing && !t.reading && e.read(0);
            }
            function I(e) {
                var t = e._readableState;
                for (d('flow', t.flowing); t.flowing && null !== e.read(); );
            }
            function j(e, t) {
                return 0 === t.length
                    ? null
                    : (t.objectMode
                          ? (n = t.buffer.shift())
                          : !e || e >= t.length
                          ? ((n = t.decoder
                                ? t.buffer.join('')
                                : 1 === t.buffer.length
                                ? t.buffer.head.data
                                : t.buffer.concat(t.length)),
                            t.buffer.clear())
                          : (n = (function(e, t, n) {
                                var i;
                                e < t.head.data.length
                                    ? ((i = t.head.data.slice(0, e)),
                                      (t.head.data = t.head.data.slice(e)))
                                    : (i =
                                          e === t.head.data.length
                                              ? t.shift()
                                              : n
                                              ? (function(e, t) {
                                                    var n = t.head,
                                                        i = 1,
                                                        r = n.data;
                                                    e -= r.length;
                                                    for (; (n = n.next); ) {
                                                        var s = n.data,
                                                            o = e > s.length ? s.length : e;
                                                        if (
                                                            (o === s.length
                                                                ? (r += s)
                                                                : (r += s.slice(0, e)),
                                                            0 === (e -= o))
                                                        ) {
                                                            o === s.length
                                                                ? (++i,
                                                                  n.next
                                                                      ? (t.head = n.next)
                                                                      : (t.head = t.tail = null))
                                                                : ((t.head = n),
                                                                  (n.data = s.slice(o)));
                                                            break;
                                                        }
                                                        ++i;
                                                    }
                                                    return (t.length -= i), r;
                                                })(e, t)
                                              : (function(e, t) {
                                                    var n = c.allocUnsafe(e),
                                                        i = t.head,
                                                        r = 1;
                                                    i.data.copy(n), (e -= i.data.length);
                                                    for (; (i = i.next); ) {
                                                        var s = i.data,
                                                            o = e > s.length ? s.length : e;
                                                        if (
                                                            (s.copy(n, n.length - e, 0, o),
                                                            0 === (e -= o))
                                                        ) {
                                                            o === s.length
                                                                ? (++r,
                                                                  i.next
                                                                      ? (t.head = i.next)
                                                                      : (t.head = t.tail = null))
                                                                : ((t.head = i),
                                                                  (i.data = s.slice(o)));
                                                            break;
                                                        }
                                                        ++r;
                                                    }
                                                    return (t.length -= r), n;
                                                })(e, t));
                                return i;
                            })(e, t.buffer, t.decoder)),
                      n);
                var n;
            }
            function k(e) {
                var t = e._readableState;
                if (t.length > 0) throw new Error('"endReadable()" called on non-empty stream');
                t.endEmitted || ((t.ended = !0), r(T, t, e));
            }
            function T(e, t) {
                e.endEmitted ||
                    0 !== e.length ||
                    ((e.endEmitted = !0), (t.readable = !1), t.emit('end'));
            }
            function C(e, t) {
                for (var n = 0, i = e.length; n < i; n++) if (e[n] === t) return n;
                return -1;
            }
            (b.prototype.read = function(e) {
                d('read', e), (e = parseInt(e, 10));
                var t = this._readableState,
                    n = e;
                if (
                    (0 !== e && (t.emittedReadable = !1),
                    0 === e && t.needReadable && (t.length >= t.highWaterMark || t.ended))
                )
                    return (
                        d('read: emitReadable', t.length, t.ended),
                        0 === t.length && t.ended ? k(this) : w(this),
                        null
                    );
                if (0 === (e = x(e, t)) && t.ended) return 0 === t.length && k(this), null;
                var i,
                    r = t.needReadable;
                return (
                    d('need readable', r),
                    (0 === t.length || t.length - e < t.highWaterMark) &&
                        d('length less than watermark', (r = !0)),
                    t.ended || t.reading
                        ? d('reading or ended', (r = !1))
                        : r &&
                          (d('do read'),
                          (t.reading = !0),
                          (t.sync = !0),
                          0 === t.length && (t.needReadable = !0),
                          this._read(t.highWaterMark),
                          (t.sync = !1),
                          t.reading || (e = x(n, t))),
                    null === (i = e > 0 ? j(e, t) : null)
                        ? ((t.needReadable = !0), (e = 0))
                        : (t.length -= e),
                    0 === t.length &&
                        (t.ended || (t.needReadable = !0), n !== e && t.ended && k(this)),
                    null !== i && this.emit('data', i),
                    i
                );
            }),
                (b.prototype._read = function(e) {
                    this.emit('error', new Error('_read() is not implemented'));
                }),
                (b.prototype.pipe = function(e, n) {
                    var i = this,
                        a = this._readableState;
                    switch (a.pipesCount) {
                        case 0:
                            a.pipes = e;
                            break;
                        case 1:
                            a.pipes = [a.pipes, e];
                            break;
                        default:
                            a.pipes.push(e);
                    }
                    (a.pipesCount += 1), d('pipe count=%d opts=%j', a.pipesCount, n);
                    var u = (!n || !1 !== n.end) && e !== t.stdout && e !== t.stderr ? l : p;
                    function c(e) {
                        d('onunpipe'), e === i && p();
                    }
                    function l() {
                        d('onend'), e.end();
                    }
                    a.endEmitted ? r(u) : i.once('end', u), e.on('unpipe', c);
                    var f = (function(e) {
                        return function() {
                            var t = e._readableState;
                            d('pipeOnDrain', t.awaitDrain),
                                t.awaitDrain && t.awaitDrain--,
                                0 === t.awaitDrain && o(e, 'data') && ((t.flowing = !0), I(e));
                        };
                    })(i);
                    e.on('drain', f);
                    var h = !1;
                    function p() {
                        d('cleanup'),
                            e.removeListener('close', y),
                            e.removeListener('finish', v),
                            e.removeListener('drain', f),
                            e.removeListener('error', b),
                            e.removeListener('unpipe', c),
                            i.removeListener('end', l),
                            i.removeListener('end', p),
                            i.removeListener('data', g),
                            (h = !0),
                            !a.awaitDrain ||
                                (e._writableState && !e._writableState.needDrain) ||
                                f();
                    }
                    var m = !1;
                    function g(t) {
                        d('ondata'),
                            (m = !1),
                            !1 !== e.write(t) ||
                                m ||
                                (((1 === a.pipesCount && a.pipes === e) ||
                                    (a.pipesCount > 1 && -1 !== C(a.pipes, e))) &&
                                    !h &&
                                    (d('false write response, pause', i._readableState.awaitDrain),
                                    i._readableState.awaitDrain++,
                                    (m = !0)),
                                i.pause());
                    }
                    function b(t) {
                        d('onerror', t),
                            x(),
                            e.removeListener('error', b),
                            0 === o(e, 'error') && e.emit('error', t);
                    }
                    function y() {
                        e.removeListener('finish', v), x();
                    }
                    function v() {
                        d('onfinish'), e.removeListener('close', y), x();
                    }
                    function x() {
                        d('unpipe'), i.unpipe(e);
                    }
                    return (
                        i.on('data', g),
                        (function(e, t, n) {
                            if ('function' == typeof e.prependListener)
                                return e.prependListener(t, n);
                            e._events && e._events[t]
                                ? s(e._events[t])
                                    ? e._events[t].unshift(n)
                                    : (e._events[t] = [n, e._events[t]])
                                : e.on(t, n);
                        })(e, 'error', b),
                        e.once('close', y),
                        e.once('finish', v),
                        e.emit('pipe', i),
                        a.flowing || (d('pipe resume'), i.resume()),
                        e
                    );
                }),
                (b.prototype.unpipe = function(e) {
                    var t = this._readableState;
                    if (0 === t.pipesCount) return this;
                    if (1 === t.pipesCount)
                        return e && e !== t.pipes
                            ? this
                            : (e || (e = t.pipes),
                              (t.pipes = null),
                              (t.pipesCount = 0),
                              (t.flowing = !1),
                              e && e.emit('unpipe', this),
                              this);
                    if (!e) {
                        var n = t.pipes,
                            i = t.pipesCount;
                        (t.pipes = null), (t.pipesCount = 0), (t.flowing = !1);
                        for (var r = 0; r < i; r++) n[r].emit('unpipe', this);
                        return this;
                    }
                    var s = C(t.pipes, e);
                    return -1 === s
                        ? this
                        : (t.pipes.splice(s, 1),
                          (t.pipesCount -= 1),
                          1 === t.pipesCount && (t.pipes = t.pipes[0]),
                          e.emit('unpipe', this),
                          this);
                }),
                (b.prototype.on = function(e, t) {
                    var n = a.prototype.on.call(this, e, t);
                    if ('data' === e) !1 !== this._readableState.flowing && this.resume();
                    else if ('readable' === e) {
                        var i = this._readableState;
                        i.endEmitted ||
                            i.readableListening ||
                            ((i.readableListening = i.needReadable = !0),
                            (i.emittedReadable = !1),
                            i.reading ? i.length && w(this) : r(A, this));
                    }
                    return n;
                }),
                (b.prototype.addListener = b.prototype.on),
                (b.prototype.resume = function() {
                    var e = this._readableState;
                    return (
                        e.flowing ||
                            (d('resume'),
                            (e.flowing = !0),
                            (function(e, t) {
                                t.resumeScheduled || ((t.resumeScheduled = !0), r(E, e, t));
                            })(this, e)),
                        this
                    );
                }),
                (b.prototype.pause = function() {
                    return (
                        d('call pause flowing=%j', this._readableState.flowing),
                        !1 !== this._readableState.flowing &&
                            (d('pause'), (this._readableState.flowing = !1), this.emit('pause')),
                        this
                    );
                }),
                (b.prototype.wrap = function(e) {
                    var t = this._readableState,
                        n = !1,
                        i = this;
                    for (var r in (e.on('end', function() {
                        if ((d('wrapped end'), t.decoder && !t.ended)) {
                            var e = t.decoder.end();
                            e && e.length && i.push(e);
                        }
                        i.push(null);
                    }),
                    e.on('data', function(r) {
                        (d('wrapped data'),
                        t.decoder && (r = t.decoder.write(r)),
                        t.objectMode && null == r) ||
                            ((t.objectMode || (r && r.length)) &&
                                (i.push(r) || ((n = !0), e.pause())));
                    }),
                    e))
                        void 0 === this[r] &&
                            'function' == typeof e[r] &&
                            (this[r] = (function(t) {
                                return function() {
                                    return e[t].apply(e, arguments);
                                };
                            })(r));
                    for (var s = 0; s < m.length; s++) e.on(m[s], i.emit.bind(i, m[s]));
                    return (
                        (i._read = function(t) {
                            d('wrapped _read', t), n && ((n = !1), e.resume());
                        }),
                        i
                    );
                }),
                (b._fromList = j);
        }.call(this, n(4)));
    },
    function(e, t, n) {
        e.exports = n(6).EventEmitter;
    },
    function(e, t, n) {
        (function(e) {
            var i = (void 0 !== e && e) || ('undefined' != typeof self && self) || window,
                r = Function.prototype.apply;
            function s(e, t) {
                (this._id = e), (this._clearFn = t);
            }
            (t.setTimeout = function() {
                return new s(r.call(setTimeout, i, arguments), clearTimeout);
            }),
                (t.setInterval = function() {
                    return new s(r.call(setInterval, i, arguments), clearInterval);
                }),
                (t.clearTimeout = t.clearInterval = function(e) {
                    e && e.close();
                }),
                (s.prototype.unref = s.prototype.ref = function() {}),
                (s.prototype.close = function() {
                    this._clearFn.call(i, this._id);
                }),
                (t.enroll = function(e, t) {
                    clearTimeout(e._idleTimeoutId), (e._idleTimeout = t);
                }),
                (t.unenroll = function(e) {
                    clearTimeout(e._idleTimeoutId), (e._idleTimeout = -1);
                }),
                (t._unrefActive = t.active = function(e) {
                    clearTimeout(e._idleTimeoutId);
                    var t = e._idleTimeout;
                    t >= 0 &&
                        (e._idleTimeoutId = setTimeout(function() {
                            e._onTimeout && e._onTimeout();
                        }, t));
                }),
                n(61),
                (t.setImmediate =
                    ('undefined' != typeof self && self.setImmediate) ||
                    (void 0 !== e && e.setImmediate) ||
                    (this && this.setImmediate)),
                (t.clearImmediate =
                    ('undefined' != typeof self && self.clearImmediate) ||
                    (void 0 !== e && e.clearImmediate) ||
                    (this && this.clearImmediate));
        }.call(this, n(3)));
    },
    function(e, t, n) {
        'use strict';
        e.exports = o;
        var i = n(5),
            r = n(10);
        function s(e) {
            (this.afterTransform = function(t, n) {
                return (function(e, t, n) {
                    var i = e._transformState;
                    i.transforming = !1;
                    var r = i.writecb;
                    if (!r) return e.emit('error', new Error('no writecb in Transform class'));
                    (i.writechunk = null), (i.writecb = null), null != n && e.push(n);
                    r(t);
                    var s = e._readableState;
                    (s.reading = !1),
                        (s.needReadable || s.length < s.highWaterMark) && e._read(s.highWaterMark);
                })(e, t, n);
            }),
                (this.needTransform = !1),
                (this.transforming = !1),
                (this.writecb = null),
                (this.writechunk = null),
                (this.writeencoding = null);
        }
        function o(e) {
            if (!(this instanceof o)) return new o(e);
            i.call(this, e), (this._transformState = new s(this));
            var t = this;
            (this._readableState.needReadable = !0),
                (this._readableState.sync = !1),
                e &&
                    ('function' == typeof e.transform && (this._transform = e.transform),
                    'function' == typeof e.flush && (this._flush = e.flush)),
                this.once('prefinish', function() {
                    'function' == typeof this._flush
                        ? this._flush(function(e, n) {
                              a(t, e, n);
                          })
                        : a(t);
                });
        }
        function a(e, t, n) {
            if (t) return e.emit('error', t);
            null != n && e.push(n);
            var i = e._writableState,
                r = e._transformState;
            if (i.length) throw new Error('Calling transform done when ws.length != 0');
            if (r.transforming) throw new Error('Calling transform done when still transforming');
            return e.push(null);
        }
        (r.inherits = n(0)),
            r.inherits(o, i),
            (o.prototype.push = function(e, t) {
                return (this._transformState.needTransform = !1), i.prototype.push.call(this, e, t);
            }),
            (o.prototype._transform = function(e, t, n) {
                throw new Error('_transform() is not implemented');
            }),
            (o.prototype._write = function(e, t, n) {
                var i = this._transformState;
                if (((i.writecb = n), (i.writechunk = e), (i.writeencoding = t), !i.transforming)) {
                    var r = this._readableState;
                    (i.needTransform || r.needReadable || r.length < r.highWaterMark) &&
                        this._read(r.highWaterMark);
                }
            }),
            (o.prototype._read = function(e) {
                var t = this._transformState;
                null !== t.writechunk && t.writecb && !t.transforming
                    ? ((t.transforming = !0),
                      this._transform(t.writechunk, t.writeencoding, t.afterTransform))
                    : (t.needTransform = !0);
            });
    },
    function(e, t, n) {
        'use strict';
        var i = n(2).Buffer,
            r = n(0),
            s = n(30),
            o = new Array(16),
            a = [
                0,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                7,
                4,
                13,
                1,
                10,
                6,
                15,
                3,
                12,
                0,
                9,
                5,
                2,
                14,
                11,
                8,
                3,
                10,
                14,
                4,
                9,
                15,
                8,
                1,
                2,
                7,
                0,
                6,
                13,
                11,
                5,
                12,
                1,
                9,
                11,
                10,
                0,
                8,
                12,
                4,
                13,
                3,
                7,
                15,
                14,
                5,
                6,
                2,
                4,
                0,
                5,
                9,
                7,
                12,
                2,
                10,
                14,
                1,
                3,
                8,
                11,
                6,
                15,
                13
            ],
            u = [
                5,
                14,
                7,
                0,
                9,
                2,
                11,
                4,
                13,
                6,
                15,
                8,
                1,
                10,
                3,
                12,
                6,
                11,
                3,
                7,
                0,
                13,
                5,
                10,
                14,
                15,
                8,
                12,
                4,
                9,
                1,
                2,
                15,
                5,
                1,
                3,
                7,
                14,
                6,
                9,
                11,
                8,
                12,
                2,
                10,
                0,
                4,
                13,
                8,
                6,
                4,
                1,
                3,
                11,
                15,
                0,
                5,
                12,
                2,
                13,
                9,
                7,
                10,
                14,
                12,
                15,
                10,
                4,
                1,
                5,
                8,
                7,
                6,
                2,
                13,
                14,
                0,
                3,
                9,
                11
            ],
            c = [
                11,
                14,
                15,
                12,
                5,
                8,
                7,
                9,
                11,
                13,
                14,
                15,
                6,
                7,
                9,
                8,
                7,
                6,
                8,
                13,
                11,
                9,
                7,
                15,
                7,
                12,
                15,
                9,
                11,
                7,
                13,
                12,
                11,
                13,
                6,
                7,
                14,
                9,
                13,
                15,
                14,
                8,
                13,
                6,
                5,
                12,
                7,
                5,
                11,
                12,
                14,
                15,
                14,
                15,
                9,
                8,
                9,
                14,
                5,
                6,
                8,
                6,
                5,
                12,
                9,
                15,
                5,
                11,
                6,
                8,
                13,
                12,
                5,
                12,
                13,
                14,
                11,
                8,
                5,
                6
            ],
            l = [
                8,
                9,
                9,
                11,
                13,
                15,
                15,
                5,
                7,
                7,
                8,
                11,
                14,
                14,
                12,
                6,
                9,
                13,
                15,
                7,
                12,
                8,
                9,
                11,
                7,
                7,
                12,
                7,
                6,
                15,
                13,
                11,
                9,
                7,
                15,
                11,
                8,
                6,
                6,
                14,
                12,
                13,
                5,
                14,
                13,
                13,
                7,
                5,
                15,
                5,
                8,
                11,
                14,
                14,
                6,
                14,
                6,
                9,
                12,
                9,
                12,
                5,
                15,
                8,
                8,
                5,
                12,
                9,
                12,
                5,
                14,
                6,
                8,
                13,
                6,
                5,
                15,
                13,
                11,
                11
            ],
            f = [0, 1518500249, 1859775393, 2400959708, 2840853838],
            d = [1352829926, 1548603684, 1836072691, 2053994217, 0];
        function h() {
            s.call(this, 64),
                (this._a = 1732584193),
                (this._b = 4023233417),
                (this._c = 2562383102),
                (this._d = 271733878),
                (this._e = 3285377520);
        }
        function p(e, t) {
            return (e << t) | (e >>> (32 - t));
        }
        function m(e, t, n, i, r, s, o, a) {
            return (p((e + (t ^ n ^ i) + s + o) | 0, a) + r) | 0;
        }
        function g(e, t, n, i, r, s, o, a) {
            return (p((e + ((t & n) | (~t & i)) + s + o) | 0, a) + r) | 0;
        }
        function b(e, t, n, i, r, s, o, a) {
            return (p((e + ((t | ~n) ^ i) + s + o) | 0, a) + r) | 0;
        }
        function y(e, t, n, i, r, s, o, a) {
            return (p((e + ((t & i) | (n & ~i)) + s + o) | 0, a) + r) | 0;
        }
        function v(e, t, n, i, r, s, o, a) {
            return (p((e + (t ^ (n | ~i)) + s + o) | 0, a) + r) | 0;
        }
        r(h, s),
            (h.prototype._update = function() {
                for (var e = o, t = 0; t < 16; ++t) e[t] = this._block.readInt32LE(4 * t);
                for (
                    var n = 0 | this._a,
                        i = 0 | this._b,
                        r = 0 | this._c,
                        s = 0 | this._d,
                        h = 0 | this._e,
                        x = 0 | this._a,
                        w = 0 | this._b,
                        _ = 0 | this._c,
                        S = 0 | this._d,
                        A = 0 | this._e,
                        E = 0;
                    E < 80;
                    E += 1
                ) {
                    var I, j;
                    E < 16
                        ? ((I = m(n, i, r, s, h, e[a[E]], f[0], c[E])),
                          (j = v(x, w, _, S, A, e[u[E]], d[0], l[E])))
                        : E < 32
                        ? ((I = g(n, i, r, s, h, e[a[E]], f[1], c[E])),
                          (j = y(x, w, _, S, A, e[u[E]], d[1], l[E])))
                        : E < 48
                        ? ((I = b(n, i, r, s, h, e[a[E]], f[2], c[E])),
                          (j = b(x, w, _, S, A, e[u[E]], d[2], l[E])))
                        : E < 64
                        ? ((I = y(n, i, r, s, h, e[a[E]], f[3], c[E])),
                          (j = g(x, w, _, S, A, e[u[E]], d[3], l[E])))
                        : ((I = v(n, i, r, s, h, e[a[E]], f[4], c[E])),
                          (j = m(x, w, _, S, A, e[u[E]], d[4], l[E]))),
                        (n = h),
                        (h = s),
                        (s = p(r, 10)),
                        (r = i),
                        (i = I),
                        (x = A),
                        (A = S),
                        (S = p(_, 10)),
                        (_ = w),
                        (w = j);
                }
                var k = (this._b + r + S) | 0;
                (this._b = (this._c + s + A) | 0),
                    (this._c = (this._d + h + x) | 0),
                    (this._d = (this._e + n + w) | 0),
                    (this._e = (this._a + i + _) | 0),
                    (this._a = k);
            }),
            (h.prototype._digest = function() {
                (this._block[this._blockOffset++] = 128),
                    this._blockOffset > 56 &&
                        (this._block.fill(0, this._blockOffset, 64),
                        this._update(),
                        (this._blockOffset = 0)),
                    this._block.fill(0, this._blockOffset, 56),
                    this._block.writeUInt32LE(this._length[0], 56),
                    this._block.writeUInt32LE(this._length[1], 60),
                    this._update();
                var e = i.alloc ? i.alloc(20) : new i(20);
                return (
                    e.writeInt32LE(this._a, 0),
                    e.writeInt32LE(this._b, 4),
                    e.writeInt32LE(this._c, 8),
                    e.writeInt32LE(this._d, 12),
                    e.writeInt32LE(this._e, 16),
                    e
                );
            }),
            (e.exports = h);
    },
    function(e, t, n) {
        ((t = e.exports = function(e) {
            e = e.toLowerCase();
            var n = t[e];
            if (!n) throw new Error(e + ' is not supported (we accept pull requests)');
            return new n();
        }).sha = n(68)),
            (t.sha1 = n(69)),
            (t.sha224 = n(70)),
            (t.sha256 = n(38)),
            (t.sha384 = n(71)),
            (t.sha512 = n(39));
    },
    function(e, t, n) {
        var i = n(0),
            r = n(7),
            s = n(1).Buffer,
            o = [
                1116352408,
                1899447441,
                3049323471,
                3921009573,
                961987163,
                1508970993,
                2453635748,
                2870763221,
                3624381080,
                310598401,
                607225278,
                1426881987,
                1925078388,
                2162078206,
                2614888103,
                3248222580,
                3835390401,
                4022224774,
                264347078,
                604807628,
                770255983,
                1249150122,
                1555081692,
                1996064986,
                2554220882,
                2821834349,
                2952996808,
                3210313671,
                3336571891,
                3584528711,
                113926993,
                338241895,
                666307205,
                773529912,
                1294757372,
                1396182291,
                1695183700,
                1986661051,
                2177026350,
                2456956037,
                2730485921,
                2820302411,
                3259730800,
                3345764771,
                3516065817,
                3600352804,
                4094571909,
                275423344,
                430227734,
                506948616,
                659060556,
                883997877,
                958139571,
                1322822218,
                1537002063,
                1747873779,
                1955562222,
                2024104815,
                2227730452,
                2361852424,
                2428436474,
                2756734187,
                3204031479,
                3329325298
            ],
            a = new Array(64);
        function u() {
            this.init(), (this._w = a), r.call(this, 64, 56);
        }
        function c(e, t, n) {
            return n ^ (e & (t ^ n));
        }
        function l(e, t, n) {
            return (e & t) | (n & (e | t));
        }
        function f(e) {
            return ((e >>> 2) | (e << 30)) ^ ((e >>> 13) | (e << 19)) ^ ((e >>> 22) | (e << 10));
        }
        function d(e) {
            return ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        }
        function h(e) {
            return ((e >>> 7) | (e << 25)) ^ ((e >>> 18) | (e << 14)) ^ (e >>> 3);
        }
        i(u, r),
            (u.prototype.init = function() {
                return (
                    (this._a = 1779033703),
                    (this._b = 3144134277),
                    (this._c = 1013904242),
                    (this._d = 2773480762),
                    (this._e = 1359893119),
                    (this._f = 2600822924),
                    (this._g = 528734635),
                    (this._h = 1541459225),
                    this
                );
            }),
            (u.prototype._update = function(e) {
                for (
                    var t,
                        n = this._w,
                        i = 0 | this._a,
                        r = 0 | this._b,
                        s = 0 | this._c,
                        a = 0 | this._d,
                        u = 0 | this._e,
                        p = 0 | this._f,
                        m = 0 | this._g,
                        g = 0 | this._h,
                        b = 0;
                    b < 16;
                    ++b
                )
                    n[b] = e.readInt32BE(4 * b);
                for (; b < 64; ++b)
                    n[b] =
                        0 |
                        (((((t = n[b - 2]) >>> 17) | (t << 15)) ^
                            ((t >>> 19) | (t << 13)) ^
                            (t >>> 10)) +
                            n[b - 7] +
                            h(n[b - 15]) +
                            n[b - 16]);
                for (var y = 0; y < 64; ++y) {
                    var v = (g + d(u) + c(u, p, m) + o[y] + n[y]) | 0,
                        x = (f(i) + l(i, r, s)) | 0;
                    (g = m),
                        (m = p),
                        (p = u),
                        (u = (a + v) | 0),
                        (a = s),
                        (s = r),
                        (r = i),
                        (i = (v + x) | 0);
                }
                (this._a = (i + this._a) | 0),
                    (this._b = (r + this._b) | 0),
                    (this._c = (s + this._c) | 0),
                    (this._d = (a + this._d) | 0),
                    (this._e = (u + this._e) | 0),
                    (this._f = (p + this._f) | 0),
                    (this._g = (m + this._g) | 0),
                    (this._h = (g + this._h) | 0);
            }),
            (u.prototype._hash = function() {
                var e = s.allocUnsafe(32);
                return (
                    e.writeInt32BE(this._a, 0),
                    e.writeInt32BE(this._b, 4),
                    e.writeInt32BE(this._c, 8),
                    e.writeInt32BE(this._d, 12),
                    e.writeInt32BE(this._e, 16),
                    e.writeInt32BE(this._f, 20),
                    e.writeInt32BE(this._g, 24),
                    e.writeInt32BE(this._h, 28),
                    e
                );
            }),
            (e.exports = u);
    },
    function(e, t, n) {
        var i = n(0),
            r = n(7),
            s = n(1).Buffer,
            o = [
                1116352408,
                3609767458,
                1899447441,
                602891725,
                3049323471,
                3964484399,
                3921009573,
                2173295548,
                961987163,
                4081628472,
                1508970993,
                3053834265,
                2453635748,
                2937671579,
                2870763221,
                3664609560,
                3624381080,
                2734883394,
                310598401,
                1164996542,
                607225278,
                1323610764,
                1426881987,
                3590304994,
                1925078388,
                4068182383,
                2162078206,
                991336113,
                2614888103,
                633803317,
                3248222580,
                3479774868,
                3835390401,
                2666613458,
                4022224774,
                944711139,
                264347078,
                2341262773,
                604807628,
                2007800933,
                770255983,
                1495990901,
                1249150122,
                1856431235,
                1555081692,
                3175218132,
                1996064986,
                2198950837,
                2554220882,
                3999719339,
                2821834349,
                766784016,
                2952996808,
                2566594879,
                3210313671,
                3203337956,
                3336571891,
                1034457026,
                3584528711,
                2466948901,
                113926993,
                3758326383,
                338241895,
                168717936,
                666307205,
                1188179964,
                773529912,
                1546045734,
                1294757372,
                1522805485,
                1396182291,
                2643833823,
                1695183700,
                2343527390,
                1986661051,
                1014477480,
                2177026350,
                1206759142,
                2456956037,
                344077627,
                2730485921,
                1290863460,
                2820302411,
                3158454273,
                3259730800,
                3505952657,
                3345764771,
                106217008,
                3516065817,
                3606008344,
                3600352804,
                1432725776,
                4094571909,
                1467031594,
                275423344,
                851169720,
                430227734,
                3100823752,
                506948616,
                1363258195,
                659060556,
                3750685593,
                883997877,
                3785050280,
                958139571,
                3318307427,
                1322822218,
                3812723403,
                1537002063,
                2003034995,
                1747873779,
                3602036899,
                1955562222,
                1575990012,
                2024104815,
                1125592928,
                2227730452,
                2716904306,
                2361852424,
                442776044,
                2428436474,
                593698344,
                2756734187,
                3733110249,
                3204031479,
                2999351573,
                3329325298,
                3815920427,
                3391569614,
                3928383900,
                3515267271,
                566280711,
                3940187606,
                3454069534,
                4118630271,
                4000239992,
                116418474,
                1914138554,
                174292421,
                2731055270,
                289380356,
                3203993006,
                460393269,
                320620315,
                685471733,
                587496836,
                852142971,
                1086792851,
                1017036298,
                365543100,
                1126000580,
                2618297676,
                1288033470,
                3409855158,
                1501505948,
                4234509866,
                1607167915,
                987167468,
                1816402316,
                1246189591
            ],
            a = new Array(160);
        function u() {
            this.init(), (this._w = a), r.call(this, 128, 112);
        }
        function c(e, t, n) {
            return n ^ (e & (t ^ n));
        }
        function l(e, t, n) {
            return (e & t) | (n & (e | t));
        }
        function f(e, t) {
            return ((e >>> 28) | (t << 4)) ^ ((t >>> 2) | (e << 30)) ^ ((t >>> 7) | (e << 25));
        }
        function d(e, t) {
            return ((e >>> 14) | (t << 18)) ^ ((e >>> 18) | (t << 14)) ^ ((t >>> 9) | (e << 23));
        }
        function h(e, t) {
            return ((e >>> 1) | (t << 31)) ^ ((e >>> 8) | (t << 24)) ^ (e >>> 7);
        }
        function p(e, t) {
            return ((e >>> 1) | (t << 31)) ^ ((e >>> 8) | (t << 24)) ^ ((e >>> 7) | (t << 25));
        }
        function m(e, t) {
            return ((e >>> 19) | (t << 13)) ^ ((t >>> 29) | (e << 3)) ^ (e >>> 6);
        }
        function g(e, t) {
            return ((e >>> 19) | (t << 13)) ^ ((t >>> 29) | (e << 3)) ^ ((e >>> 6) | (t << 26));
        }
        function b(e, t) {
            return e >>> 0 < t >>> 0 ? 1 : 0;
        }
        i(u, r),
            (u.prototype.init = function() {
                return (
                    (this._ah = 1779033703),
                    (this._bh = 3144134277),
                    (this._ch = 1013904242),
                    (this._dh = 2773480762),
                    (this._eh = 1359893119),
                    (this._fh = 2600822924),
                    (this._gh = 528734635),
                    (this._hh = 1541459225),
                    (this._al = 4089235720),
                    (this._bl = 2227873595),
                    (this._cl = 4271175723),
                    (this._dl = 1595750129),
                    (this._el = 2917565137),
                    (this._fl = 725511199),
                    (this._gl = 4215389547),
                    (this._hl = 327033209),
                    this
                );
            }),
            (u.prototype._update = function(e) {
                for (
                    var t = this._w,
                        n = 0 | this._ah,
                        i = 0 | this._bh,
                        r = 0 | this._ch,
                        s = 0 | this._dh,
                        a = 0 | this._eh,
                        u = 0 | this._fh,
                        y = 0 | this._gh,
                        v = 0 | this._hh,
                        x = 0 | this._al,
                        w = 0 | this._bl,
                        _ = 0 | this._cl,
                        S = 0 | this._dl,
                        A = 0 | this._el,
                        E = 0 | this._fl,
                        I = 0 | this._gl,
                        j = 0 | this._hl,
                        k = 0;
                    k < 32;
                    k += 2
                )
                    (t[k] = e.readInt32BE(4 * k)), (t[k + 1] = e.readInt32BE(4 * k + 4));
                for (; k < 160; k += 2) {
                    var T = t[k - 30],
                        C = t[k - 30 + 1],
                        R = h(T, C),
                        P = p(C, T),
                        O = m((T = t[k - 4]), (C = t[k - 4 + 1])),
                        L = g(C, T),
                        M = t[k - 14],
                        B = t[k - 14 + 1],
                        D = t[k - 32],
                        N = t[k - 32 + 1],
                        q = (P + B) | 0,
                        F = (R + M + b(q, P)) | 0;
                    (F =
                        ((F = (F + O + b((q = (q + L) | 0), L)) | 0) +
                            D +
                            b((q = (q + N) | 0), N)) |
                        0),
                        (t[k] = F),
                        (t[k + 1] = q);
                }
                for (var U = 0; U < 160; U += 2) {
                    (F = t[U]), (q = t[U + 1]);
                    var z = l(n, i, r),
                        X = l(x, w, _),
                        Q = f(n, x),
                        Y = f(x, n),
                        G = d(a, A),
                        $ = d(A, a),
                        H = o[U],
                        K = o[U + 1],
                        W = c(a, u, y),
                        V = c(A, E, I),
                        J = (j + $) | 0,
                        Z = (v + G + b(J, j)) | 0;
                    Z =
                        ((Z =
                            ((Z = (Z + W + b((J = (J + V) | 0), V)) | 0) +
                                H +
                                b((J = (J + K) | 0), K)) |
                            0) +
                            F +
                            b((J = (J + q) | 0), q)) |
                        0;
                    var ee = (Y + X) | 0,
                        te = (Q + z + b(ee, Y)) | 0;
                    (v = y),
                        (j = I),
                        (y = u),
                        (I = E),
                        (u = a),
                        (E = A),
                        (a = (s + Z + b((A = (S + J) | 0), S)) | 0),
                        (s = r),
                        (S = _),
                        (r = i),
                        (_ = w),
                        (i = n),
                        (w = x),
                        (n = (Z + te + b((x = (J + ee) | 0), J)) | 0);
                }
                (this._al = (this._al + x) | 0),
                    (this._bl = (this._bl + w) | 0),
                    (this._cl = (this._cl + _) | 0),
                    (this._dl = (this._dl + S) | 0),
                    (this._el = (this._el + A) | 0),
                    (this._fl = (this._fl + E) | 0),
                    (this._gl = (this._gl + I) | 0),
                    (this._hl = (this._hl + j) | 0),
                    (this._ah = (this._ah + n + b(this._al, x)) | 0),
                    (this._bh = (this._bh + i + b(this._bl, w)) | 0),
                    (this._ch = (this._ch + r + b(this._cl, _)) | 0),
                    (this._dh = (this._dh + s + b(this._dl, S)) | 0),
                    (this._eh = (this._eh + a + b(this._el, A)) | 0),
                    (this._fh = (this._fh + u + b(this._fl, E)) | 0),
                    (this._gh = (this._gh + y + b(this._gl, I)) | 0),
                    (this._hh = (this._hh + v + b(this._hl, j)) | 0);
            }),
            (u.prototype._hash = function() {
                var e = s.allocUnsafe(64);
                function t(t, n, i) {
                    e.writeInt32BE(t, i), e.writeInt32BE(n, i + 4);
                }
                return (
                    t(this._ah, this._al, 0),
                    t(this._bh, this._bl, 8),
                    t(this._ch, this._cl, 16),
                    t(this._dh, this._dl, 24),
                    t(this._eh, this._el, 32),
                    t(this._fh, this._fl, 40),
                    t(this._gh, this._gl, 48),
                    t(this._hh, this._hl, 56),
                    e
                );
            }),
            (e.exports = u);
    },
    function(e, t) {
        e.exports = function(e) {
            return (
                e.webpackPolyfill ||
                    ((e.deprecate = function() {}),
                    (e.paths = []),
                    e.children || (e.children = []),
                    Object.defineProperty(e, 'loaded', {
                        enumerable: !0,
                        get: function() {
                            return e.l;
                        }
                    }),
                    Object.defineProperty(e, 'id', {
                        enumerable: !0,
                        get: function() {
                            return e.i;
                        }
                    }),
                    (e.webpackPolyfill = 1)),
                e
            );
        };
    },
    function(e, t, n) {
        'use strict';
        var i = {
            generateIdentifier: function() {
                return Math.random()
                    .toString(36)
                    .substr(2, 10);
            }
        };
        (i.localCName = i.generateIdentifier()),
            (i.splitLines = function(e) {
                return e
                    .trim()
                    .split('\n')
                    .map(function(e) {
                        return e.trim();
                    });
            }),
            (i.splitSections = function(e) {
                return e.split('\nm=').map(function(e, t) {
                    return (t > 0 ? 'm=' + e : e).trim() + '\r\n';
                });
            }),
            (i.getDescription = function(e) {
                var t = i.splitSections(e);
                return t && t[0];
            }),
            (i.getMediaSections = function(e) {
                var t = i.splitSections(e);
                return t.shift(), t;
            }),
            (i.matchPrefix = function(e, t) {
                return i.splitLines(e).filter(function(e) {
                    return 0 === e.indexOf(t);
                });
            }),
            (i.parseCandidate = function(e) {
                for (
                    var t,
                        n = {
                            foundation: (t =
                                0 === e.indexOf('a=candidate:')
                                    ? e.substring(12).split(' ')
                                    : e.substring(10).split(' '))[0],
                            component: parseInt(t[1], 10),
                            protocol: t[2].toLowerCase(),
                            priority: parseInt(t[3], 10),
                            ip: t[4],
                            address: t[4],
                            port: parseInt(t[5], 10),
                            type: t[7]
                        },
                        i = 8;
                    i < t.length;
                    i += 2
                )
                    switch (t[i]) {
                        case 'raddr':
                            n.relatedAddress = t[i + 1];
                            break;
                        case 'rport':
                            n.relatedPort = parseInt(t[i + 1], 10);
                            break;
                        case 'tcptype':
                            n.tcpType = t[i + 1];
                            break;
                        case 'ufrag':
                            (n.ufrag = t[i + 1]), (n.usernameFragment = t[i + 1]);
                            break;
                        default:
                            n[t[i]] = t[i + 1];
                    }
                return n;
            }),
            (i.writeCandidate = function(e) {
                var t = [];
                t.push(e.foundation),
                    t.push(e.component),
                    t.push(e.protocol.toUpperCase()),
                    t.push(e.priority),
                    t.push(e.address || e.ip),
                    t.push(e.port);
                var n = e.type;
                return (
                    t.push('typ'),
                    t.push(n),
                    'host' !== n &&
                        e.relatedAddress &&
                        e.relatedPort &&
                        (t.push('raddr'),
                        t.push(e.relatedAddress),
                        t.push('rport'),
                        t.push(e.relatedPort)),
                    e.tcpType &&
                        'tcp' === e.protocol.toLowerCase() &&
                        (t.push('tcptype'), t.push(e.tcpType)),
                    (e.usernameFragment || e.ufrag) &&
                        (t.push('ufrag'), t.push(e.usernameFragment || e.ufrag)),
                    'candidate:' + t.join(' ')
                );
            }),
            (i.parseIceOptions = function(e) {
                return e.substr(14).split(' ');
            }),
            (i.parseRtpMap = function(e) {
                var t = e.substr(9).split(' '),
                    n = { payloadType: parseInt(t.shift(), 10) };
                return (
                    (t = t[0].split('/')),
                    (n.name = t[0]),
                    (n.clockRate = parseInt(t[1], 10)),
                    (n.channels = 3 === t.length ? parseInt(t[2], 10) : 1),
                    (n.numChannels = n.channels),
                    n
                );
            }),
            (i.writeRtpMap = function(e) {
                var t = e.payloadType;
                void 0 !== e.preferredPayloadType && (t = e.preferredPayloadType);
                var n = e.channels || e.numChannels || 1;
                return (
                    'a=rtpmap:' +
                    t +
                    ' ' +
                    e.name +
                    '/' +
                    e.clockRate +
                    (1 !== n ? '/' + n : '') +
                    '\r\n'
                );
            }),
            (i.parseExtmap = function(e) {
                var t = e.substr(9).split(' ');
                return {
                    id: parseInt(t[0], 10),
                    direction: t[0].indexOf('/') > 0 ? t[0].split('/')[1] : 'sendrecv',
                    uri: t[1]
                };
            }),
            (i.writeExtmap = function(e) {
                return (
                    'a=extmap:' +
                    (e.id || e.preferredId) +
                    (e.direction && 'sendrecv' !== e.direction ? '/' + e.direction : '') +
                    ' ' +
                    e.uri +
                    '\r\n'
                );
            }),
            (i.parseFmtp = function(e) {
                for (
                    var t, n = {}, i = e.substr(e.indexOf(' ') + 1).split(';'), r = 0;
                    r < i.length;
                    r++
                )
                    n[(t = i[r].trim().split('='))[0].trim()] = t[1];
                return n;
            }),
            (i.writeFmtp = function(e) {
                var t = '',
                    n = e.payloadType;
                if (
                    (void 0 !== e.preferredPayloadType && (n = e.preferredPayloadType),
                    e.parameters && Object.keys(e.parameters).length)
                ) {
                    var i = [];
                    Object.keys(e.parameters).forEach(function(t) {
                        e.parameters[t] ? i.push(t + '=' + e.parameters[t]) : i.push(t);
                    }),
                        (t += 'a=fmtp:' + n + ' ' + i.join(';') + '\r\n');
                }
                return t;
            }),
            (i.parseRtcpFb = function(e) {
                var t = e.substr(e.indexOf(' ') + 1).split(' ');
                return { type: t.shift(), parameter: t.join(' ') };
            }),
            (i.writeRtcpFb = function(e) {
                var t = '',
                    n = e.payloadType;
                return (
                    void 0 !== e.preferredPayloadType && (n = e.preferredPayloadType),
                    e.rtcpFeedback &&
                        e.rtcpFeedback.length &&
                        e.rtcpFeedback.forEach(function(e) {
                            t +=
                                'a=rtcp-fb:' +
                                n +
                                ' ' +
                                e.type +
                                (e.parameter && e.parameter.length ? ' ' + e.parameter : '') +
                                '\r\n';
                        }),
                    t
                );
            }),
            (i.parseSsrcMedia = function(e) {
                var t = e.indexOf(' '),
                    n = { ssrc: parseInt(e.substr(7, t - 7), 10) },
                    i = e.indexOf(':', t);
                return (
                    i > -1
                        ? ((n.attribute = e.substr(t + 1, i - t - 1)), (n.value = e.substr(i + 1)))
                        : (n.attribute = e.substr(t + 1)),
                    n
                );
            }),
            (i.parseSsrcGroup = function(e) {
                var t = e.substr(13).split(' ');
                return {
                    semantics: t.shift(),
                    ssrcs: t.map(function(e) {
                        return parseInt(e, 10);
                    })
                };
            }),
            (i.getMid = function(e) {
                var t = i.matchPrefix(e, 'a=mid:')[0];
                if (t) return t.substr(6);
            }),
            (i.parseFingerprint = function(e) {
                var t = e.substr(14).split(' ');
                return { algorithm: t[0].toLowerCase(), value: t[1] };
            }),
            (i.getDtlsParameters = function(e, t) {
                return {
                    role: 'auto',
                    fingerprints: i.matchPrefix(e + t, 'a=fingerprint:').map(i.parseFingerprint)
                };
            }),
            (i.writeDtlsParameters = function(e, t) {
                var n = 'a=setup:' + t + '\r\n';
                return (
                    e.fingerprints.forEach(function(e) {
                        n += 'a=fingerprint:' + e.algorithm + ' ' + e.value + '\r\n';
                    }),
                    n
                );
            }),
            (i.getIceParameters = function(e, t) {
                var n = i.splitLines(e);
                return {
                    usernameFragment: (n = n.concat(i.splitLines(t)))
                        .filter(function(e) {
                            return 0 === e.indexOf('a=ice-ufrag:');
                        })[0]
                        .substr(12),
                    password: n
                        .filter(function(e) {
                            return 0 === e.indexOf('a=ice-pwd:');
                        })[0]
                        .substr(10)
                };
            }),
            (i.writeIceParameters = function(e) {
                return 'a=ice-ufrag:' + e.usernameFragment + '\r\na=ice-pwd:' + e.password + '\r\n';
            }),
            (i.parseRtpParameters = function(e) {
                for (
                    var t = { codecs: [], headerExtensions: [], fecMechanisms: [], rtcp: [] },
                        n = i.splitLines(e)[0].split(' '),
                        r = 3;
                    r < n.length;
                    r++
                ) {
                    var s = n[r],
                        o = i.matchPrefix(e, 'a=rtpmap:' + s + ' ')[0];
                    if (o) {
                        var a = i.parseRtpMap(o),
                            u = i.matchPrefix(e, 'a=fmtp:' + s + ' ');
                        switch (
                            ((a.parameters = u.length ? i.parseFmtp(u[0]) : {}),
                            (a.rtcpFeedback = i
                                .matchPrefix(e, 'a=rtcp-fb:' + s + ' ')
                                .map(i.parseRtcpFb)),
                            t.codecs.push(a),
                            a.name.toUpperCase())
                        ) {
                            case 'RED':
                            case 'ULPFEC':
                                t.fecMechanisms.push(a.name.toUpperCase());
                        }
                    }
                }
                return (
                    i.matchPrefix(e, 'a=extmap:').forEach(function(e) {
                        t.headerExtensions.push(i.parseExtmap(e));
                    }),
                    t
                );
            }),
            (i.writeRtpDescription = function(e, t) {
                var n = '';
                (n += 'm=' + e + ' '),
                    (n += t.codecs.length > 0 ? '9' : '0'),
                    (n += ' UDP/TLS/RTP/SAVPF '),
                    (n +=
                        t.codecs
                            .map(function(e) {
                                return void 0 !== e.preferredPayloadType
                                    ? e.preferredPayloadType
                                    : e.payloadType;
                            })
                            .join(' ') + '\r\n'),
                    (n += 'c=IN IP4 0.0.0.0\r\n'),
                    (n += 'a=rtcp:9 IN IP4 0.0.0.0\r\n'),
                    t.codecs.forEach(function(e) {
                        (n += i.writeRtpMap(e)), (n += i.writeFmtp(e)), (n += i.writeRtcpFb(e));
                    });
                var r = 0;
                return (
                    t.codecs.forEach(function(e) {
                        e.maxptime > r && (r = e.maxptime);
                    }),
                    r > 0 && (n += 'a=maxptime:' + r + '\r\n'),
                    (n += 'a=rtcp-mux\r\n'),
                    t.headerExtensions &&
                        t.headerExtensions.forEach(function(e) {
                            n += i.writeExtmap(e);
                        }),
                    n
                );
            }),
            (i.parseRtpEncodingParameters = function(e) {
                var t,
                    n = [],
                    r = i.parseRtpParameters(e),
                    s = -1 !== r.fecMechanisms.indexOf('RED'),
                    o = -1 !== r.fecMechanisms.indexOf('ULPFEC'),
                    a = i
                        .matchPrefix(e, 'a=ssrc:')
                        .map(function(e) {
                            return i.parseSsrcMedia(e);
                        })
                        .filter(function(e) {
                            return 'cname' === e.attribute;
                        }),
                    u = a.length > 0 && a[0].ssrc,
                    c = i.matchPrefix(e, 'a=ssrc-group:FID').map(function(e) {
                        return e
                            .substr(17)
                            .split(' ')
                            .map(function(e) {
                                return parseInt(e, 10);
                            });
                    });
                c.length > 0 && c[0].length > 1 && c[0][0] === u && (t = c[0][1]),
                    r.codecs.forEach(function(e) {
                        if ('RTX' === e.name.toUpperCase() && e.parameters.apt) {
                            var i = { ssrc: u, codecPayloadType: parseInt(e.parameters.apt, 10) };
                            u && t && (i.rtx = { ssrc: t }),
                                n.push(i),
                                s &&
                                    (((i = JSON.parse(JSON.stringify(i))).fec = {
                                        ssrc: u,
                                        mechanism: o ? 'red+ulpfec' : 'red'
                                    }),
                                    n.push(i));
                        }
                    }),
                    0 === n.length && u && n.push({ ssrc: u });
                var l = i.matchPrefix(e, 'b=');
                return (
                    l.length &&
                        ((l =
                            0 === l[0].indexOf('b=TIAS:')
                                ? parseInt(l[0].substr(7), 10)
                                : 0 === l[0].indexOf('b=AS:')
                                ? 1e3 * parseInt(l[0].substr(5), 10) * 0.95 - 16e3
                                : void 0),
                        n.forEach(function(e) {
                            e.maxBitrate = l;
                        })),
                    n
                );
            }),
            (i.parseRtcpParameters = function(e) {
                var t = {},
                    n = i
                        .matchPrefix(e, 'a=ssrc:')
                        .map(function(e) {
                            return i.parseSsrcMedia(e);
                        })
                        .filter(function(e) {
                            return 'cname' === e.attribute;
                        })[0];
                n && ((t.cname = n.value), (t.ssrc = n.ssrc));
                var r = i.matchPrefix(e, 'a=rtcp-rsize');
                (t.reducedSize = r.length > 0), (t.compound = 0 === r.length);
                var s = i.matchPrefix(e, 'a=rtcp-mux');
                return (t.mux = s.length > 0), t;
            }),
            (i.parseMsid = function(e) {
                var t,
                    n = i.matchPrefix(e, 'a=msid:');
                if (1 === n.length)
                    return { stream: (t = n[0].substr(7).split(' '))[0], track: t[1] };
                var r = i
                    .matchPrefix(e, 'a=ssrc:')
                    .map(function(e) {
                        return i.parseSsrcMedia(e);
                    })
                    .filter(function(e) {
                        return 'msid' === e.attribute;
                    });
                return r.length > 0
                    ? { stream: (t = r[0].value.split(' '))[0], track: t[1] }
                    : void 0;
            }),
            (i.generateSessionId = function() {
                return Math.random()
                    .toString()
                    .substr(2, 21);
            }),
            (i.writeSessionBoilerplate = function(e, t, n) {
                var r = void 0 !== t ? t : 2;
                return (
                    'v=0\r\no=' +
                    (n || 'thisisadapterortc') +
                    ' ' +
                    (e || i.generateSessionId()) +
                    ' ' +
                    r +
                    ' IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n'
                );
            }),
            (i.writeMediaSection = function(e, t, n, r) {
                var s = i.writeRtpDescription(e.kind, t);
                if (
                    ((s += i.writeIceParameters(e.iceGatherer.getLocalParameters())),
                    (s += i.writeDtlsParameters(
                        e.dtlsTransport.getLocalParameters(),
                        'offer' === n ? 'actpass' : 'active'
                    )),
                    (s += 'a=mid:' + e.mid + '\r\n'),
                    e.direction
                        ? (s += 'a=' + e.direction + '\r\n')
                        : e.rtpSender && e.rtpReceiver
                        ? (s += 'a=sendrecv\r\n')
                        : e.rtpSender
                        ? (s += 'a=sendonly\r\n')
                        : e.rtpReceiver
                        ? (s += 'a=recvonly\r\n')
                        : (s += 'a=inactive\r\n'),
                    e.rtpSender)
                ) {
                    var o = 'msid:' + r.id + ' ' + e.rtpSender.track.id + '\r\n';
                    (s += 'a=' + o),
                        (s += 'a=ssrc:' + e.sendEncodingParameters[0].ssrc + ' ' + o),
                        e.sendEncodingParameters[0].rtx &&
                            ((s += 'a=ssrc:' + e.sendEncodingParameters[0].rtx.ssrc + ' ' + o),
                            (s +=
                                'a=ssrc-group:FID ' +
                                e.sendEncodingParameters[0].ssrc +
                                ' ' +
                                e.sendEncodingParameters[0].rtx.ssrc +
                                '\r\n'));
                }
                return (
                    (s +=
                        'a=ssrc:' +
                        e.sendEncodingParameters[0].ssrc +
                        ' cname:' +
                        i.localCName +
                        '\r\n'),
                    e.rtpSender &&
                        e.sendEncodingParameters[0].rtx &&
                        (s +=
                            'a=ssrc:' +
                            e.sendEncodingParameters[0].rtx.ssrc +
                            ' cname:' +
                            i.localCName +
                            '\r\n'),
                    s
                );
            }),
            (i.getDirection = function(e, t) {
                for (var n = i.splitLines(e), r = 0; r < n.length; r++)
                    switch (n[r]) {
                        case 'a=sendrecv':
                        case 'a=sendonly':
                        case 'a=recvonly':
                        case 'a=inactive':
                            return n[r].substr(2);
                    }
                return t ? i.getDirection(t) : 'sendrecv';
            }),
            (i.getKind = function(e) {
                return i
                    .splitLines(e)[0]
                    .split(' ')[0]
                    .substr(2);
            }),
            (i.isRejected = function(e) {
                return '0' === e.split(' ', 2)[1];
            }),
            (i.parseMLine = function(e) {
                var t = i
                    .splitLines(e)[0]
                    .substr(2)
                    .split(' ');
                return {
                    kind: t[0],
                    port: parseInt(t[1], 10),
                    protocol: t[2],
                    fmt: t.slice(3).join(' ')
                };
            }),
            (i.parseOLine = function(e) {
                var t = i
                    .matchPrefix(e, 'o=')[0]
                    .substr(2)
                    .split(' ');
                return {
                    username: t[0],
                    sessionId: t[1],
                    sessionVersion: parseInt(t[2], 10),
                    netType: t[3],
                    addressType: t[4],
                    address: t[5]
                };
            }),
            (i.isValidSDP = function(e) {
                if ('string' != typeof e || 0 === e.length) return !1;
                for (var t = i.splitLines(e), n = 0; n < t.length; n++)
                    if (t[n].length < 2 || '=' !== t[n].charAt(1)) return !1;
                return !0;
            }),
            (e.exports = i);
    },
    function(e, t, n) {
        'use strict';
        (function(e, i, r) {
            Object.defineProperty(t, '__esModule', { value: !0 });
            const s = n(8),
                o = n(21),
                a = s.__importDefault(n(47)),
                u = s.__importDefault(n(13)),
                c = n(57),
                l = n(8),
                f = s.__importDefault(n(77)),
                d = n(78),
                h = n(6),
                p = n(41),
                m = n(79);
            let g;
            try {
                g = n(80);
            } catch (e) {
                g = !1;
            }
            const b = !!g && !!g.StringPrep,
                y = b && new g.StringPrep('nodeprep').isNative();
            function v(e) {
                return b ? m.toUnicode(g.toUnicode(e)) : m.toUnicode(e);
            }
            function x(e) {
                if (b) {
                    return new g.StringPrep('nameprep').prepare(e);
                }
                return e.toLowerCase();
            }
            function w(e) {
                if (b) {
                    return new g.StringPrep('nodeprep').prepare(e);
                }
                return e.toLowerCase();
            }
            function _(e) {
                if (b) {
                    return new g.StringPrep('resourceprep').prepare(e);
                }
                return e;
            }
            const S = /^[\x00-\x7F]*$/;
            function A(e, t) {
                return e ? e + '@' + t : t;
            }
            function E(e, t, n) {
                return n ? A(e, t) + '/' + n : A(e, t);
            }
            function I(e) {
                let t = e.local,
                    n = e.domain,
                    i = e.resource,
                    r = t;
                return (
                    t && (r = T((t = w(t)))),
                    i && (i = _(i)),
                    '.' === n[n.length - 1] && (n = n.slice(0, n.length - 1)),
                    {
                        bare: A(
                            t,
                            (n = x(
                                n
                                    .split('.')
                                    .map(v)
                                    .join('.')
                            ))
                        ),
                        domain: n,
                        full: E(t, n, i),
                        local: t,
                        prepped: e.prepped || y,
                        resource: i,
                        unescapedBare: A(r, n),
                        unescapedFull: E(r, n, i),
                        unescapedLocal: r
                    }
                );
            }
            function j(e, t) {
                let n = '',
                    i = '',
                    r = '';
                t = t || S.test(e);
                const s = e.indexOf('/');
                s > 0 && ((r = e.slice(s + 1)), (e = e.slice(0, s)));
                const o = e.indexOf('@');
                o > 0 && ((n = e.slice(0, o)), (e = e.slice(o + 1)));
                const a = I({ domain: (i = e), local: n, resource: r });
                return (a.prepped = a.prepped || t), a;
            }
            function k(e) {
                return e
                    .replace(/^\s+|\s+$/g, '')
                    .replace(/\\5c/g, '\\5c5c')
                    .replace(/\\20/g, '\\5c20')
                    .replace(/\\22/g, '\\5c22')
                    .replace(/\\26/g, '\\5c26')
                    .replace(/\\27/g, '\\5c27')
                    .replace(/\\2f/g, '\\5c2f')
                    .replace(/\\3a/g, '\\5c3a')
                    .replace(/\\3c/g, '\\5c3c')
                    .replace(/\\3e/g, '\\5c3e')
                    .replace(/\\40/g, '\\5c40')
                    .replace(/ /g, '\\20')
                    .replace(/\"/g, '\\22')
                    .replace(/\&/g, '\\26')
                    .replace(/\'/g, '\\27')
                    .replace(/\//g, '\\2f')
                    .replace(/:/g, '\\3a')
                    .replace(/</g, '\\3c')
                    .replace(/>/g, '\\3e')
                    .replace(/@/g, '\\40');
            }
            function T(e) {
                return e
                    .replace(/\\20/g, ' ')
                    .replace(/\\22/g, '"')
                    .replace(/\\26/g, '&')
                    .replace(/\\27/g, "'")
                    .replace(/\\2f/g, '/')
                    .replace(/\\3a/g, ':')
                    .replace(/\\3c/g, '<')
                    .replace(/\\3e/g, '>')
                    .replace(/\\40/g, '@')
                    .replace(/\\5c/g, '\\');
            }
            class C {
                constructor(e, t, n) {
                    let i = {};
                    if (!e || t || n)
                        if (t) {
                            let r = S.test(e) && S.test(t);
                            n && (r = r && S.test(n)),
                                (i = I({ domain: t, local: k(e), prepped: r, resource: n }));
                        } else i = {};
                    else if ('string' == typeof e) i = j(e);
                    else {
                        if (!(e._isJID || e instanceof C)) throw new Error('Invalid argument type');
                        i = e;
                    }
                    (this._isJID = !0),
                        (this.local = i.local || ''),
                        (this.domain = i.domain || ''),
                        (this.resource = i.resource || ''),
                        (this.bare = i.bare || ''),
                        (this.full = i.full || ''),
                        (this.unescapedLocal = i.unescapedLocal || ''),
                        (this.unescapedBare = i.unescapedBare || ''),
                        (this.unescapedFull = i.unescapedFull || ''),
                        (this.prepped = i.prepped);
                }
                toString() {
                    return this.full;
                }
                toJSON() {
                    return this.full;
                }
            }
            var R = Object.freeze({
                NATIVE_STRINGPREP: y,
                toUnicode: v,
                nameprep: x,
                nodeprep: w,
                resourceprep: _,
                prep: I,
                parse: j,
                equal: function(e, t, n) {
                    return (
                        (e = new C(e)),
                        (t = new C(t)),
                        2 === arguments.length && (n = !0),
                        e.local === t.local &&
                            e.domain === t.domain &&
                            e.resource === t.resource &&
                            (!n || (e.prepped && t.prepped))
                    );
                },
                equalBare: function(e, t, n) {
                    return (
                        (e = new C(e)),
                        (t = new C(t)),
                        2 === arguments.length && (n = !0),
                        e.local === t.local &&
                            e.domain === t.domain &&
                            (!n || (e.prepped && t.prepped))
                    );
                },
                isBare: function(e) {
                    return !(e = new C(e)).resource;
                },
                isFull: function(e) {
                    return !!(e = new C(e)).resource;
                },
                escape: k,
                unescape: T,
                create: function(e, t, n) {
                    return new C(e, t, n);
                },
                JID: C
            });
            t.jid = R;
            class P {
                response(e) {
                    return e.trace || '';
                }
                challenge() {}
            }
            (P.prototype.name = 'ANONYMOUS'), (P.prototype.clientFirst = !0);
            class O {
                response(e) {
                    return e.authzid || '';
                }
                challenge() {}
            }
            (O.prototype.name = 'EXTERNAL'), (O.prototype.clientFirst = !0);
            class L {
                response(e) {
                    let t = '';
                    return (
                        (t += e.authzid || ''),
                        (t += '\0'),
                        (t += e.username),
                        (t += '\0'),
                        (t += e.password)
                    );
                }
                challenge() {}
            }
            function M() {
                return c.randomBytes(16).toString('hex');
            }
            (L.prototype.name = 'PLAIN'), (L.prototype.clientFirst = !0);
            class B {
                constructor(e) {
                    (e = e || {}), (this._genNonce = e.genNonce || M);
                }
                response(e) {
                    if (this._completed) return;
                    let t = e.serviceType + '/' + e.host;
                    e.serviceName && e.host !== e.serviceName && (t += '/' + e.serviceName);
                    const n = e.realm || this._realm || '',
                        i = this._genNonce(),
                        r = '00000001';
                    let s = '';
                    (s += 'username="' + e.username + '"'),
                        n && (s += ',realm="' + n + '"'),
                        (s += ',nonce="' + this._nonce + '"'),
                        (s += ',cnonce="' + i + '"'),
                        (s += ',nc=' + r),
                        (s += ',qop=auth'),
                        (s += ',digest-uri="' + t + '"');
                    const o = c
                        .createHash('md5')
                        .update(e.username)
                        .update(':')
                        .update(n)
                        .update(':')
                        .update(e.password)
                        .digest();
                    let a = c
                        .createHash('md5')
                        .update(o)
                        .update(':')
                        .update(this._nonce)
                        .update(':')
                        .update(i);
                    e.authzid && a.update(':').update(e.authzid), (a = a.digest('hex'));
                    let u = c
                        .createHash('md5')
                        .update('AUTHENTICATE:')
                        .update(t);
                    return (
                        (u = u.digest('hex')),
                        (s +=
                            ',response=' +
                            c
                                .createHash('md5')
                                .update(a)
                                .update(':')
                                .update(this._nonce)
                                .update(':')
                                .update(r)
                                .update(':')
                                .update(i)
                                .update(':')
                                .update('auth')
                                .update(':')
                                .update(u)
                                .digest('hex')),
                        'utf-8' === this._charset && (s += ',charset=utf-8'),
                        e.authzid && (s += 'authzid="' + e.authzid + '"'),
                        s
                    );
                }
                challenge(e) {
                    const t = (function(e) {
                        const t = {},
                            n = e.split(/,(?=(?:[^"]|"[^"]*")*$)/);
                        for (let e = 0, i = n.length; e < i; e++) {
                            const i = /(\w+)=["]?([^"]+)["]?$/.exec(n[e]);
                            i && (t[i[1]] = i[2]);
                        }
                        return t;
                    })(e);
                    return (
                        (this._completed = !!t.rspauth),
                        (this._realm = t.realm),
                        (this._nonce = t.nonce),
                        (this._qop = (t.qop || 'auth').split(',')),
                        (this._stale = t.stale),
                        (this._maxbuf = parseInt(t.maxbuf, 10) || 65536),
                        (this._charset = t.charset),
                        (this._algo = t.algorithm),
                        (this._cipher = t.cipher),
                        this._cipher && this._cipher.split(','),
                        this
                    );
                }
            }
            (B.prototype.name = 'DIGEST-MD5'), (B.prototype.clientFirst = !1);
            const D = {};
            function N(e) {
                const t = [];
                let n = '';
                for (let i = 0; i < e.length; i++)
                    ',' === (n = e[i]) ? t.push('=2C') : '=' === n ? t.push('=3D') : t.push(n);
                return t.join('');
            }
            function q(e) {
                return c.randomBytes((e || 32) / 2).toString('hex');
            }
            function F(t, n) {
                const i = Math.min(t.length, n.length),
                    r = e.alloc(Math.max(t.length, n.length));
                for (let e = 0; e < i; ++e) r[e] = t[e] ^ n[e];
                return r;
            }
            function U(e, t) {
                return c
                    .createHmac('sha1', e)
                    .update(t)
                    .digest();
            }
            class z {
                constructor(e) {
                    (e = e || {}), (this._genNonce = e.genNonce || q), (this._stage = 'initial');
                }
                response(e) {
                    return D[this._stage](this, e);
                }
                challenge(t) {
                    const n = (function(e) {
                        const t = {},
                            n = e.split(/,(?=(?:[^"]|"[^"]*")*$)/);
                        for (let e = 0, i = n.length; e < i; e++) {
                            const i = /(\w+)=["]?([^"]+)["]?$/.exec(n[e]);
                            i && (t[i[1]] = i[2]);
                        }
                        return t;
                    })(t);
                    return (
                        (this._salt = e.from(n.s || '', 'base64')),
                        (this._iterationCount = parseInt(n.i, 10)),
                        (this._nonce = n.r),
                        (this._verifier = n.v),
                        (this._error = n.e),
                        (this._challenge = t),
                        this
                    );
                }
            }
            (z.prototype.name = 'SCRAM-SHA-1'),
                (z.prototype.clientFirst = !0),
                (D.initial = function(e, t) {
                    e._cnonce = e._genNonce();
                    let n = '';
                    t.authzid && (n = 'a=' + N(t.authzid)), (e._gs2Header = 'n,' + n + ',');
                    const i = 'r=' + e._cnonce,
                        r = 'n=' + N(t.username || '');
                    e._clientFirstMessageBare = r + ',' + i;
                    const s = e._gs2Header + e._clientFirstMessageBare;
                    return (e._stage = 'challenge'), s;
                }),
                (D.challenge = function(t, n) {
                    const i = e.from(t._gs2Header).toString('base64');
                    let r, s, o;
                    (t._clientFinalMessageWithoutProof = 'c=' + i + ',r=' + t._nonce),
                        n.salt && 0 === e.compare(n.salt, t._salt)
                            ? n.clientKey && n.serverKey
                                ? ((s = n.clientKey), (o = n.serverKey))
                                : n.saltedPassword &&
                                  ((s = U((r = n.saltedPassword), 'Client Key')),
                                  (o = U(r, 'Server Key')))
                            : ((r = (function(t, n, i) {
                                  let r = U(t, e.concat([n, e.from([0, 0, 0, 1], 'binary')])),
                                      s = r;
                                  for (let e = 0; e < i - 1; e++) s = F(s, (r = U(t, r)));
                                  return s;
                              })(n.password || '', t._salt, t._iterationCount)),
                              (s = U(r, 'Client Key')),
                              (o = U(r, 'Server Key')));
                    const a = ((u = s),
                    c
                        .createHash('sha1')
                        .update(u)
                        .digest());
                    var u;
                    const l =
                            t._clientFirstMessageBare +
                            ',' +
                            t._challenge +
                            ',' +
                            t._clientFinalMessageWithoutProof,
                        f = F(s, U(a, l)).toString('base64');
                    t._serverSignature = U(o, l);
                    const d = t._clientFinalMessageWithoutProof + ',p=' + f;
                    return (
                        (t._stage = 'final'),
                        (t.cache = {
                            clientKey: s,
                            salt: t._salt,
                            saltedPassword: r,
                            serverKey: o
                        }),
                        d
                    );
                }),
                (D.final = function() {
                    return '';
                });
            class X {
                response(e) {
                    let t = '';
                    return (t += '\0'), (t += e.username), (t += '\0'), (t += e.token);
                }
                challenge() {}
            }
            (X.prototype.name = 'X-OAUTH2'), (X.prototype.clientFirst = !0);
            class Q {
                constructor() {
                    this._mechs = [];
                }
                use(e, t) {
                    return (
                        t || (e = (t = e).prototype.name),
                        this._mechs.push({ name: e, mech: t }),
                        this
                    );
                }
                create(e) {
                    for (let t = 0, n = this._mechs.length; t < n; t++)
                        for (let n = 0, i = e.length; n < i; n++) {
                            const i = this._mechs[t];
                            if (i.name === e[n]) return new i.mech();
                        }
                    return null;
                }
            }
            const Y = 'urn:ietf:params:xml:ns:xmpp-bind',
                G = 'jabber:client',
                $ = 'urn:ietf:params:xml:ns:xmpp-sasl',
                H = 'jabber:server',
                K = 'urn:ietf:params:xml:ns:xmpp-session',
                W = 'urn:ietf:params:xml:ns:xmpp-stanzas',
                V = 'http://etherx.jabber.org/streams',
                J = 'urn:ietf:params:xml:ns:xmpp-streams',
                Z = 'jabber:iq:roster',
                ee = 'urn:xmpp:features:rosterver',
                te = 'urn:xmpp:features:pre-approval',
                ne = 'urn:ietf:params:xml:ns:xmpp-framing',
                ie = 'jabber:x:data',
                re = 'http://jabber.org/protocol/disco#info',
                se = 'http://jabber.org/protocol/disco#items',
                oe = 'http://jabber.org/protocol/address',
                ae = 'http://jabber.org/protocol/muc',
                ue = 'http://jabber.org/protocol/muc#admin',
                ce = 'http://jabber.org/protocol/muc#owner',
                le = 'http://jabber.org/protocol/muc#user',
                fe = 'http://jabber.org/protocol/ibb',
                de = 'storage:bookmarks',
                he = 'jabber:iq:private',
                pe = 'http://jabber.org/protocol/commands',
                me = 'vcard-temp',
                ge = 'http://jabber.org/protocol/rsm',
                be = 'http://jabber.org/protocol/pubsub',
                ye = 'http://jabber.org/protocol/pubsub#errors',
                ve = 'http://jabber.org/protocol/pubsub#event',
                xe = 'http://jabber.org/protocol/pubsub#owner',
                we = 'jabber:iq:oob',
                _e = 'jabber:x:oob',
                Se = 'jabber:iq:register',
                Ae = 'http://jabber.org/protocol/geoloc',
                Ee = 'urn:xmpp:avatar:data',
                Ie = 'urn:xmpp:avatar:metadata',
                je = 'http://jabber.org/protocol/chatstates',
                ke = 'jabber:iq:version',
                Te = 'http://jabber.org/protocol/mood',
                Ce = 'jabber:component:accept',
                Re = 'http://jabber.org/protocol/caps',
                Pe = 'http://jabber.org/protocol/tune',
                Oe = 'http://jabber.org/protocol/xdata-validate',
                Le = 'http://jabber.org/protocol/httpbind',
                Me = 'http://jabber.org/protocol/shim',
                Be = 'http://jabber.org/protocol/xdata-layout',
                De = 'urn:xmpp:reach:0',
                Ne = 'urn:xmpp:alt-connections:websocket',
                qe = 'urn:xmpp:alt-connections:xbosh',
                Fe = e => `${e}+notify`,
                Ue = 'urn:xmpp:jingle:1',
                ze = 'urn:xmpp:jingle:errors:1',
                Xe = 'urn:xmpp:jingle:apps:rtp:1',
                Qe = 'urn:xmpp:jingle:apps:rtp:info:1',
                Ye = 'urn:xmpp:jingle:apps:rtp:audio',
                Ge = 'urn:xmpp:jingle:apps:rtp:video',
                $e = 'http://jabber.org/protocol/nick',
                He = 'urn:xmpp:jingle:transports:ice-udp:1',
                Ke = 'urn:xmpp:receipts',
                We = 'urn:xmpp:invisible:0',
                Ve = 'urn:xmpp:blocking',
                Je = 'urn:xmpp:sm:3',
                Ze = 'urn:xmpp:ping',
                et = 'urn:xmpp:time',
                tt = 'urn:xmpp:delay',
                nt = 'urn:xmpp:xbosh',
                it = 'urn:xmpp:extdisco:1',
                rt = 'urn:xmpp:media-element',
                st = 'urn:xmpp:attention:0',
                ot = 'urn:xmpp:bob',
                at = 'urn:xmpp:jingle:apps:file-transfer:3',
                ut = 'jabber:x:conference',
                ct = 'urn:xmpp:jingle:transports:ibb:1',
                lt = 'urn:xmpp:thumbs:0',
                ft = 'urn:xmpp:carbons:2',
                dt = 'urn:xmpp:jingle:apps:rtp:rtcp-fb:0',
                ht = 'urn:xmpp:jingle:apps:rtp:rtp-hdrext:0',
                pt = 'urn:xmpp:forward:0',
                mt = 'urn:xmpp:hashes:1',
                gt = e => `urn:xmpp:hash-function-text-names:${e}`,
                bt = 'urn:xmpp:rtt:0',
                yt = 'http://jabber.org/protocol/muc#unique',
                vt = 'urn:xmpp:message-correct:0',
                xt = 'urn:xmpp:psa',
                wt = 'urn:xmpp:mam:1',
                _t = 'urn:xmpp:hats:0',
                St = 'urn:xmpp:idle:1',
                At = 'urn:xmpp:jingle:apps:dtls:0',
                Et = 'urn:xmpp:jidprep:0',
                It = 'urn:xmpp:chat-markers:0',
                jt = 'urn:xmpp:hints',
                kt = 'urn:xmpp:json:0',
                Tt = 'urn:xmpp:eventlog',
                Ct = 'urn:xmpp:jingle:apps:grouping:0',
                Rt = 'urn:xmpp:jingle:apps:rtp:ssma:0',
                Pt = 'urn:xmpp:jingle:transports:dtls-sctp:1',
                Ot = 'urn:xmpp:csi:0',
                Lt = 'urn:xmpp:push:0',
                Mt = 'urn:xmpp:reference:0',
                Bt = 'urn:xmpp:eme:0',
                Dt = 'eu.siacs.conversations.axolotl',
                Nt = 'http://docs.oasis-open.org/ns/xri/xrd-1.0';
            function qt(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'address',
                        fields: {
                            delivered: t.boolAttribute('delivered'),
                            description: t.attribute('desc'),
                            jid: t.jidAttribute('jid'),
                            node: t.attribute('node'),
                            type: t.attribute('type'),
                            uri: t.attribute('uri')
                        },
                        name: '_address',
                        namespace: oe
                    }),
                    i = t.subMultiExtension(oe, 'addresses', n);
                e.withMessage(function(t) {
                    e.add(t, 'addresses', i);
                }),
                    e.withPresence(function(t) {
                        e.add(t, 'addresses', i);
                    });
            }
            function Ft(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'info',
                        fields: {
                            bytes: t.attribute('bytes'),
                            height: t.attribute('height'),
                            id: t.attribute('id'),
                            type: t.attribute('type', 'image/png'),
                            url: t.attribute('url'),
                            width: t.attribute('width')
                        },
                        name: 'avatar',
                        namespace: Ie
                    }),
                    i = {
                        get: function() {
                            const e = t.find(this.xml, Ie, 'metadata'),
                                i = [];
                            if (e.length) {
                                const r = t.find(e[0], Ie, 'info');
                                for (const e of r) i.push(new n({}, e));
                            }
                            return i;
                        },
                        set: function(e) {
                            const i = t.findOrCreate(this.xml, Ie, 'metadata');
                            t.setAttribute(i, 'xmlns', Ie);
                            for (const t of e) {
                                const e = new n(t);
                                i.appendChild(e.xml);
                            }
                        }
                    };
                e.withPubsubItem(function(n) {
                    e.add(n, 'avatars', i), e.add(n, 'avatarData', t.textSub(Ee, 'data'));
                });
            }
            function Ut(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'bind',
                        fields: { jid: t.jidSub(Y, 'jid'), resource: t.textSub(Y, 'resource') },
                        name: 'bind',
                        namespace: Y
                    });
                e.extendIQ(n), e.extendStreamFeatures(n);
            }
            function zt(e) {
                const t = e.utils,
                    n = {
                        get: function() {
                            const e = [],
                                n = t.find(this.xml, Ve, 'item');
                            if (!n.length) return e;
                            for (const i of n) e.push(new C(t.getAttribute(i, 'jid', '')));
                            return e;
                        },
                        set: function(e) {
                            const n = this;
                            for (const i of e) {
                                const e = t.createElement(Ve, 'item', Ve);
                                t.setAttribute(e, 'jid', i.toString()), n.xml.appendChild(e);
                            }
                        }
                    },
                    i = e.define({
                        element: 'block',
                        fields: { jids: n },
                        name: 'block',
                        namespace: Ve
                    }),
                    r = e.define({
                        element: 'unblock',
                        fields: { jids: n },
                        name: 'unblock',
                        namespace: Ve
                    }),
                    s = e.define({
                        element: 'blocklist',
                        fields: { jids: n },
                        name: 'blockList',
                        namespace: Ve
                    });
                e.extendIQ(i), e.extendIQ(r), e.extendIQ(s);
            }
            function Xt(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'data',
                        fields: {
                            cid: t.attribute('cid'),
                            data: t.text(),
                            maxAge: t.numberAttribute('max-age'),
                            type: t.attribute('type')
                        },
                        name: 'bob',
                        namespace: ot
                    });
                e.extendIQ(n), e.extendMessage(n), e.extendPresence(n);
            }
            function Qt(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'conference',
                        fields: {
                            autoJoin: t.boolAttribute('autojoin'),
                            jid: t.jidAttribute('jid'),
                            name: t.attribute('name'),
                            nick: t.textSub(de, 'nick')
                        },
                        name: '_conference',
                        namespace: de
                    }),
                    i = e.define({ element: 'storage', name: 'bookmarks', namespace: de });
                e.extend(i, n, 'conferences'),
                    e.withDefinition('query', he, function(t) {
                        e.extend(t, i);
                    });
            }
            function Yt(e) {
                const t = e.utils;
                e.define({
                    element: 'body',
                    fields: {
                        accept: t.attribute('accept'),
                        ack: t.numberAttribute('ack'),
                        authid: t.attribute('authid'),
                        charsets: t.attribute('charsets'),
                        condition: t.attribute('condition'),
                        content: t.attribute('content'),
                        from: t.jidAttribute('from', !0),
                        hold: t.numberAttribute('hold'),
                        inactivity: t.numberAttribute('inactivity'),
                        key: t.attribute('key'),
                        lang: t.langAttribute(),
                        maxpause: t.numberAttribute('maxpause'),
                        newKey: t.attribute('newkey'),
                        pause: t.numberAttribute('pause'),
                        payload: {
                            get: function() {
                                const t = [];
                                for (let n = 0, i = this.xml.childNodes.length; n < i; n++) {
                                    const i = e.build(this.xml.childNodes[n]);
                                    void 0 !== i && t.push(i);
                                }
                                return t;
                            },
                            set: function(e) {
                                for (const t of e) this.xml.appendChild(t.xml);
                            }
                        },
                        polling: t.numberAttribute('polling'),
                        requests: t.numberAttribute('requests'),
                        resport: t.numberAttribute('report'),
                        restart: t.attribute('xmpp:restart'),
                        restartLogic: t.boolAttribute('xmpp:restartLogic'),
                        rid: t.numberAttribute('rid'),
                        sid: t.attribute('sid'),
                        stream: t.attribute('stream'),
                        time: t.attribute('time'),
                        to: t.jidAttribute('to', !0),
                        type: t.attribute('type'),
                        uri: t.textSub(Le, 'uri'),
                        ver: t.attribute('ver'),
                        version: t.attribute('xmpp:version', '1.0'),
                        wait: t.numberAttribute('wait')
                    },
                    name: 'bosh',
                    namespace: Le,
                    prefixes: { xmpp: nt }
                });
            }
            function Gt(e) {
                const t = e.define({
                        element: 'sent',
                        eventName: 'carbon:sent',
                        name: 'carbonSent',
                        namespace: ft
                    }),
                    n = e.define({
                        element: 'received',
                        eventName: 'carbon:received',
                        name: 'carbonReceived',
                        namespace: ft
                    }),
                    i = e.define({
                        element: 'private',
                        eventName: 'carbon:private',
                        name: 'carbonPrivate',
                        namespace: ft
                    }),
                    r = e.define({ element: 'enable', name: 'enableCarbons', namespace: ft }),
                    s = e.define({ element: 'disable', name: 'disableCarbons', namespace: ft });
                e.withDefinition('forwarded', pt, function(i) {
                    e.extend(t, i), e.extend(n, i);
                }),
                    e.extendMessage(t),
                    e.extendMessage(n),
                    e.extendMessage(i),
                    e.extendIQ(r),
                    e.extendIQ(s);
            }
            const $t = ['next', 'prev', 'complete', 'cancel'],
                Ht = [
                    'bad-action',
                    'bad-locale',
                    'bad-payload',
                    'bad-sessionid',
                    'malformed-action',
                    'session-expired'
                ];
            function Kt(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'command',
                        fields: {
                            action: t.attribute('action'),
                            actions: {
                                get: function() {
                                    const e = [],
                                        n = t.find(this.xml, pe, 'actions');
                                    if (!n.length) return [];
                                    for (const i of $t) {
                                        t.find(n[0], pe, i).length && e.push(i);
                                    }
                                    return e;
                                },
                                set: function(e) {
                                    const n = t.findOrCreate(this.xml, pe, 'actions');
                                    for (let e = 0, t = n.childNodes.length; e < t; e++)
                                        n.removeChild(n.childNodes[e]);
                                    for (const i of e)
                                        n.appendChild(t.createElement(pe, i.toLowerCase(), pe));
                                }
                            },
                            execute: t.subAttribute(pe, 'actions', 'execute'),
                            node: t.attribute('node'),
                            sessionid: t.attribute('sessionid'),
                            status: t.attribute('status')
                        },
                        name: 'command',
                        namespace: pe
                    }),
                    i = e.define({
                        element: 'note',
                        fields: { type: t.attribute('type'), value: t.text() },
                        name: '_commandNote',
                        namespace: pe
                    });
                e.extend(n, i, 'notes'),
                    e.extendIQ(n),
                    e.withStanzaError(function(n) {
                        e.add(n, 'adhocCommandCondition', t.enumSub(pe, Ht));
                    }),
                    e.withDataForm(function(t) {
                        e.extend(n, t);
                    });
            }
            function Wt(e) {
                const t = e.define({
                    element: 'csi',
                    name: 'clientStateIndication',
                    namespace: Ot
                });
                e.define({
                    element: 'active',
                    eventName: 'csi:active',
                    name: 'csiActive',
                    namespace: Ot,
                    topLevel: !0
                }),
                    e.define({
                        element: 'inactive',
                        eventName: 'csi:inactive',
                        name: 'csiInactive',
                        namespace: Ot,
                        topLevel: !0
                    }),
                    e.extendStreamFeatures(t);
            }
            const Vt = ['text-single', 'text-private', 'list-single', 'jid-single'];
            function Jt(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'field',
                        fields: {
                            desc: t.textSub(ie, 'desc'),
                            label: t.attribute('label'),
                            name: t.attribute('var'),
                            required: t.boolSub(ie, 'required'),
                            type: {
                                get: function() {
                                    return t.getAttribute(this.xml, 'type', 'text-single');
                                },
                                set: function(e) {
                                    (this._type = e), t.setAttribute(this.xml, 'type', e);
                                }
                            },
                            value: {
                                get: function() {
                                    const e = t.getMultiSubText(this.xml, ie, 'value');
                                    return 'boolean' === this._type
                                        ? '1' === e[0] || 'true' === e[0]
                                        : e.length > 1
                                        ? 'text-multi' === this._type
                                            ? e.join('\n')
                                            : 'jid-multi' === this._type
                                            ? e.map(function(e) {
                                                  return new C(e);
                                              })
                                            : e
                                        : Vt.indexOf(this._type) >= 0
                                        ? 'jid-single' === this._type
                                            ? new C(e[0])
                                            : e[0]
                                        : e;
                                },
                                set: function(e) {
                                    if ('boolean' === this._type || !0 === e || !1 === e) {
                                        const n = !0 === e || 'true' === e || '1' === e,
                                            i = t.createElement(ie, 'value', ie);
                                        (i.textContent = n ? '1' : '0'), this.xml.appendChild(i);
                                    } else
                                        'text-multi' === this._type &&
                                            'string' == typeof e &&
                                            (e = e.split('\n')),
                                            t.setMultiSubText(
                                                this.xml,
                                                ie,
                                                'value',
                                                e,
                                                function(e) {
                                                    const n = t.createElement(ie, 'value', ie);
                                                    (n.textContent = e), this.xml.appendChild(n);
                                                }.bind(this)
                                            );
                                }
                            }
                        },
                        init: function(e) {
                            this._type = (e || {}).type || this.type;
                        },
                        name: '_field',
                        namespace: ie
                    }),
                    i = e.define({
                        element: 'option',
                        fields: { label: t.attribute('label'), value: t.textSub(ie, 'value') },
                        name: '_formoption',
                        namespace: ie
                    }),
                    r = e.define({ element: 'item', name: '_formitem', namespace: ie }),
                    s = e.define({
                        element: 'media',
                        fields: {
                            height: t.numberAttribute('height'),
                            width: t.numberAttribute('width')
                        },
                        name: 'media',
                        namespace: rt
                    }),
                    o = e.define({
                        element: 'uri',
                        fields: { type: t.attribute('type'), uri: t.text() },
                        name: '_mediaURI',
                        namespace: rt
                    }),
                    a = e.define({
                        element: 'validate',
                        fields: {
                            basic: t.boolSub(Oe, 'basic'),
                            dataType: t.attribute('datatype'),
                            open: t.boolSub(Oe, 'open'),
                            regex: t.textSub(Oe, 'regex')
                        },
                        name: 'validation',
                        namespace: Oe
                    }),
                    u = e.define({
                        element: 'range',
                        fields: { max: t.attribute('max'), min: t.attribute('min') },
                        name: 'range',
                        namespace: Oe
                    }),
                    c = e.define({
                        element: 'list-range',
                        fields: { max: t.numberAttribute('max'), min: t.numberAttribute('min') },
                        name: 'select',
                        namespace: Oe
                    }),
                    l = {
                        get: function() {
                            const e = [];
                            for (let t = 0, n = this.xml.childNodes.length; t < n; t++) {
                                const n = this.xml.childNodes[t];
                                if (n.namespaceURI === Be)
                                    switch (n.localName) {
                                        case 'text':
                                            e.push({ text: n.textContent });
                                            break;
                                        case 'fieldref':
                                            e.push({ field: n.getAttribute('var') });
                                            break;
                                        case 'reportedref':
                                            e.push({ reported: !0 });
                                            break;
                                        case 'section':
                                            e.push({ section: new f(null, n, this).toJSON() });
                                    }
                            }
                            return e;
                        },
                        set: function(e) {
                            for (let n = 0, i = e.length; n < i; n++) {
                                const i = e[n];
                                if (i.text) {
                                    const e = t.createElement(Be, 'text', Be);
                                    (e.textContent = i.text), this.xml.appendChild(e);
                                }
                                if (i.field) {
                                    const e = t.createElement(Be, 'fieldref', Be);
                                    e.setAttribute('var', i.field), this.xml.appendChild(e);
                                }
                                if (
                                    (i.reported &&
                                        this.xml.appendChild(
                                            t.createElement(Be, 'reportedref', Be)
                                        ),
                                    i.section)
                                ) {
                                    const e = t.createElement(Be, 'section', Be);
                                    this.xml.appendChild(e);
                                    const n = new f(null, e);
                                    (n.label = i.section.label), (n.contents = i.section.contents);
                                }
                            }
                        }
                    },
                    f = e.define({
                        element: 'section',
                        fields: { contents: l, label: t.attribute('label') },
                        name: '_section',
                        namespace: Be
                    }),
                    d = e.define({
                        element: 'page',
                        fields: { contents: l, label: t.attribute('label') },
                        name: '_page',
                        namespace: Be
                    }),
                    h = e.define({
                        element: 'x',
                        fields: {
                            instructions: t.multiTextSub(ie, 'instructions'),
                            reportedFields: t.subMultiExtension(ie, 'reported', n),
                            title: t.textSub(ie, 'title'),
                            type: t.attribute('type', 'form')
                        },
                        init: function() {
                            if (!this.reportedFields.length) return;
                            const e = {};
                            for (const t of this.reportedFields) e[t.name] = t.type;
                            for (const t of this.items)
                                for (const n of t.fields) n.type = n._type = e[n.name];
                        },
                        name: 'form',
                        namespace: ie
                    });
                e.extend(h, n, 'fields'),
                    e.extend(h, r, 'items'),
                    e.extend(h, d, 'layout'),
                    e.extend(n, s),
                    e.extend(n, a),
                    e.extend(n, i, 'options'),
                    e.extend(r, n, 'fields'),
                    e.extend(s, o, 'uris'),
                    e.extend(a, u),
                    e.extend(a, c),
                    e.extendMessage(h);
            }
            function Zt(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'delay',
                        fields: {
                            from: t.jidAttribute('from'),
                            reason: t.text(),
                            stamp: t.dateAttribute('stamp')
                        },
                        name: 'delay',
                        namespace: tt
                    });
                e.extendMessage(n), e.extendPresence(n);
            }
            function en(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'c',
                        fields: {
                            ext: t.attribute('ext'),
                            hash: t.attribute('hash'),
                            node: t.attribute('node'),
                            ver: t.attribute('ver')
                        },
                        name: 'caps',
                        namespace: Re
                    }),
                    i = e.define({
                        element: 'query',
                        fields: {
                            features: t.multiSubAttribute(re, 'feature', 'var'),
                            node: t.attribute('node')
                        },
                        name: 'discoInfo',
                        namespace: re
                    }),
                    r = e.define({
                        element: 'identity',
                        fields: {
                            category: t.attribute('category'),
                            lang: t.langAttribute(),
                            name: t.attribute('name'),
                            type: t.attribute('type')
                        },
                        name: '_discoIdentity',
                        namespace: re
                    }),
                    s = e.define({
                        element: 'query',
                        fields: { node: t.attribute('node') },
                        name: 'discoItems',
                        namespace: se
                    }),
                    o = e.define({
                        element: 'item',
                        fields: {
                            jid: t.jidAttribute('jid'),
                            name: t.attribute('name'),
                            node: t.attribute('node')
                        },
                        name: '_discoItem',
                        namespace: se
                    });
                e.extend(s, o, 'items'),
                    e.extend(i, r, 'identities'),
                    e.extendIQ(i),
                    e.extendIQ(s),
                    e.extendPresence(n),
                    e.extendStreamFeatures(n),
                    e.withDataForm(function(t) {
                        e.extend(i, t, 'extensions');
                    }),
                    e.withDefinition('set', ge, function(t) {
                        e.extend(s, t);
                    });
            }
            const tn = [
                'bad-request',
                'conflict',
                'feature-not-implemented',
                'forbidden',
                'gone',
                'internal-server-error',
                'item-not-found',
                'jid-malformed',
                'not-acceptable',
                'not-allowed',
                'not-authorized',
                'payment-required',
                'recipient-unavailable',
                'redirect',
                'registration-required',
                'remote-server-not-found',
                'remote-server-timeout',
                'resource-constraint',
                'service-unavailable',
                'subscription-required',
                'undefined-condition',
                'unexpected-request'
            ];
            function nn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'error',
                        fields: {
                            $text: {
                                get: function() {
                                    return t.getSubLangText(this.xml, W, 'text', this.lang);
                                }
                            },
                            by: t.jidAttribute('by'),
                            code: t.attribute('code'),
                            condition: t.enumSub(W, tn),
                            gone: {
                                get: function() {
                                    return t.getSubText(this.xml, W, 'gone');
                                },
                                set: function(e) {
                                    (this.condition = 'gone'), t.setSubText(this.xml, W, 'gone', e);
                                }
                            },
                            lang: {
                                get: function() {
                                    return (this.parent || {}).lang || '';
                                }
                            },
                            redirect: {
                                get: function() {
                                    return t.getSubText(this.xml, W, 'redirect');
                                },
                                set: function(e) {
                                    (this.condition = 'redirect'),
                                        t.setSubText(this.xml, W, 'redirect', e);
                                }
                            },
                            text: {
                                get: function() {
                                    return this.$text[this.lang] || '';
                                },
                                set: function(e) {
                                    t.setSubLangText(this.xml, W, 'text', e, this.lang);
                                }
                            },
                            type: t.attribute('type')
                        },
                        name: 'error',
                        namespace: G
                    });
                e.extendMessage(n), e.extendPresence(n), e.extendIQ(n);
            }
            function rn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'encryption',
                        fields: { name: t.attribute('name'), namespace: t.attribute('namespace') },
                        name: 'encryptionMethod',
                        namespace: Bt
                    });
                e.extendMessage(n);
            }
            function sn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'services',
                        fields: { type: t.attribute('type') },
                        name: 'services',
                        namespace: it
                    }),
                    i = e.define({ element: 'credentials', name: 'credentials', namespace: it }),
                    r = e.define({
                        element: 'service',
                        fields: {
                            host: t.attribute('host'),
                            password: t.attribute('password'),
                            port: t.attribute('port'),
                            transport: t.attribute('transport'),
                            type: t.attribute('type'),
                            username: t.attribute('username')
                        },
                        name: 'service',
                        namespace: it
                    });
                e.extend(n, r, 'services'),
                    e.extend(i, r),
                    e.extendIQ(n),
                    e.extendIQ(i),
                    e.withDataForm(function(t) {
                        e.extend(r, t);
                    });
            }
            const on = 'urn:xmpp:jingle:apps:file-transfer:4';
            function an(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'file',
                        fields: {
                            date: t.dateSub(on, 'date'),
                            description: t.textSub(on, 'desc'),
                            mediaType: t.textSub(on, 'media-type'),
                            name: t.textSub(on, 'name'),
                            size: t.numberSub(on, 'size')
                        },
                        name: 'file',
                        namespace: on
                    }),
                    i = e.define({
                        element: 'range',
                        fields: {
                            length: t.numberAttribute('length'),
                            offset: t.numberAttribute('offset')
                        },
                        name: 'range',
                        namespace: on
                    }),
                    r = e.define({
                        element: 'description',
                        fields: { applicationType: { value: on, writable: !0 } },
                        name: '_' + on,
                        namespace: on,
                        tags: ['jingle-application']
                    }),
                    s = e.define({
                        element: 'received',
                        fields: {
                            creator: t.attribute('creator'),
                            infoType: { value: '{' + on + '}received' },
                            name: t.attribute('name')
                        },
                        name: '_{' + on + '}received',
                        namespace: on,
                        tags: ['jingle-info']
                    }),
                    o = e.define({
                        element: 'checksum',
                        fields: {
                            creator: t.attribute('creator'),
                            infoType: { value: '{' + on + '}checksum' },
                            name: t.attribute('name')
                        },
                        name: '_{' + on + '}checksum',
                        namespace: on,
                        tags: ['jingle-info']
                    });
                e.extend(n, i),
                    e.extend(o, n),
                    e.extend(r, n),
                    e.withDefinition('hash', mt, function(t) {
                        e.extend(n, t, 'hashes'), e.extend(i, t, 'hashes');
                    }),
                    e.withDefinition('content', Ue, function(t) {
                        e.extend(t, r);
                    }),
                    e.withDefinition('jingle', Ue, function(t) {
                        e.extend(t, s), e.extend(t, o);
                    });
            }
            const un = at;
            function cn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'file',
                        fields: {
                            date: t.dateSub(un, 'date'),
                            desc: t.textSub(un, 'desc'),
                            name: t.textSub(un, 'name'),
                            size: t.numberSub(un, 'size')
                        },
                        name: '_file',
                        namespace: un
                    }),
                    i = e.define({
                        element: 'range',
                        fields: { offset: t.numberAttribute('offset') },
                        name: 'range',
                        namespace: un
                    }),
                    r = e.define({
                        element: 'thumbnail',
                        fields: {
                            cid: t.attribute('cid'),
                            height: t.numberAttribute('height'),
                            mimeType: t.attribute('mime-type'),
                            width: t.numberAttribute('width')
                        },
                        name: 'thumbnail',
                        namespace: lt
                    }),
                    s = e.define({
                        element: 'description',
                        fields: {
                            applicationType: { value: 'filetransfer', writable: !0 },
                            offer: t.subExtension('offer', un, 'offer', n),
                            request: t.subExtension('request', un, 'request', n)
                        },
                        name: '_filetransfer',
                        namespace: un,
                        tags: ['jingle-application']
                    });
                e.extend(n, i),
                    e.extend(n, r),
                    e.withDefinition('hash', mt, function(t) {
                        e.extend(n, t, 'hashes');
                    }),
                    e.withDefinition('content', Ue, function(t) {
                        e.extend(t, s);
                    });
            }
            function ln(e) {
                const t = e.define({ element: 'forwarded', name: 'forwarded', namespace: pt });
                e.withMessage(function(n) {
                    e.extend(n, t), e.extend(t, n);
                }),
                    e.withPresence(function(n) {
                        e.extend(n, t), e.extend(t, n);
                    }),
                    e.withIQ(function(n) {
                        e.extend(n, t), e.extend(t, n);
                    }),
                    e.withDefinition('delay', tt, function(n) {
                        e.extend(t, n);
                    });
            }
            function fn(e) {
                const t = e.utils;
                e.define({
                    element: 'open',
                    fields: {
                        from: t.jidAttribute('from', !0),
                        id: t.attribute('id'),
                        lang: t.langAttribute(),
                        to: t.jidAttribute('to', !0),
                        version: t.attribute('version', '1.0')
                    },
                    name: 'openStream',
                    namespace: ne,
                    topLevel: !0
                }),
                    e.define({
                        element: 'close',
                        fields: { seeOtherURI: t.attribute('see-other-uri') },
                        name: 'closeStream',
                        namespace: ne,
                        topLevel: !0
                    });
            }
            function dn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'geoloc',
                        fields: {
                            accuracy: t.numberSub(Ae, 'accuracy', !0),
                            altitude: t.numberSub(Ae, 'alt', !0),
                            area: t.textSub(Ae, 'area'),
                            bearing: t.numberSub(Ae, 'bearing', !0),
                            building: t.textSub(Ae, 'building'),
                            country: t.textSub(Ae, 'country'),
                            countrycode: t.textSub(Ae, 'countrycode'),
                            datum: t.textSub(Ae, 'datum'),
                            description: t.textSub(Ae, 'description'),
                            error: t.numberSub(Ae, 'error', !0),
                            floor: t.textSub(Ae, 'floor'),
                            heading: t.numberSub(Ae, 'bearing', !0),
                            latitude: t.numberSub(Ae, 'lat', !0),
                            locality: t.textSub(Ae, 'locality'),
                            longitude: t.numberSub(Ae, 'lon', !0),
                            postalcode: t.textSub(Ae, 'postalcode'),
                            region: t.textSub(Ae, 'region'),
                            room: t.textSub(Ae, 'room'),
                            speed: t.numberSub(Ae, 'speed', !0),
                            street: t.textSub(Ae, 'street'),
                            text: t.textSub(Ae, 'text'),
                            timestamp: t.dateSub(Ae, 'timestamp'),
                            tzo: t.tzoSub(Ae, 'tzo'),
                            uri: t.textSub(Ae, 'uri')
                        },
                        name: 'geoloc',
                        namespace: Ae
                    });
                e.extendPubsubItem(n);
            }
            function hn(e) {
                e.define({
                    element: 'hash',
                    fields: { algo: e.utils.attribute('algo'), value: e.utils.text() },
                    name: 'hash',
                    namespace: mt
                });
            }
            function pn(e) {
                const t = e.define({
                    element: 'hat',
                    fields: {
                        displayName: e.utils.attribute('displayName'),
                        lang: e.utils.langAttribute(),
                        name: e.utils.attribute('name')
                    },
                    name: '_hat',
                    namespace: _t
                });
                e.withPresence(function(n) {
                    e.add(n, 'hats', e.utils.subMultiExtension(_t, 'hats', t));
                });
            }
            const mn = {
                    noCopy: 'no-copy',
                    noPermanentStore: 'no-permanent-store',
                    noStore: 'no-store',
                    store: 'store'
                },
                gn = {
                    'no-copy': 'noCopy',
                    'no-permanent-store': 'noPermanentStore',
                    'no-store': 'noStore',
                    store: 'store'
                };
            function bn(e) {
                const t = e.utils;
                e.withMessage(function(n) {
                    e.add(n, 'processingHints', {
                        get: function() {
                            const e = {};
                            for (let t = 0, n = this.xml.childNodes.length; t < n; t++) {
                                const n = this.xml.childNodes[t],
                                    i = n.localName;
                                n.namespaceURI === jt && (gn[i] && (e[gn[i]] = !0));
                            }
                            return e;
                        },
                        set: function(e) {
                            for (let e = 0, t = this.xml.childNodes.length; e < t; e++) {
                                this.xml.childNodes[e].namespaceURI !== jt &&
                                    this.xml.removeChild(this.xml.childNodes[e]);
                            }
                            for (const n of Object.keys(e)) {
                                if (!e[n] || !mn[n]) continue;
                                const i = t.createElement(jt, mn[n]);
                                this.xml.appendChild(i);
                            }
                        }
                    });
                });
            }
            function yn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'transport',
                        fields: {
                            gatheringComplete: t.boolSub(He, 'gathering-complete'),
                            pwd: t.attribute('pwd'),
                            transportType: { value: 'iceUdp', writable: !0 },
                            ufrag: t.attribute('ufrag')
                        },
                        name: '_iceUdp',
                        namespace: He,
                        tags: ['jingle-transport']
                    }),
                    i = e.define({
                        element: 'remote-candidate',
                        fields: {
                            component: t.attribute('component'),
                            ip: t.attribute('ip'),
                            port: t.attribute('port')
                        },
                        name: 'remoteCandidate',
                        namespace: He
                    }),
                    r = e.define({
                        element: 'candidate',
                        fields: {
                            component: t.attribute('component'),
                            foundation: t.attribute('foundation'),
                            generation: t.attribute('generation'),
                            id: t.attribute('id'),
                            ip: t.attribute('ip'),
                            network: t.attribute('network'),
                            port: t.attribute('port'),
                            priority: t.attribute('priority'),
                            protocol: t.attribute('protocol'),
                            relAddr: t.attribute('rel-addr'),
                            relPort: t.attribute('rel-port'),
                            tcpType: t.attribute('tcptype'),
                            type: t.attribute('type')
                        },
                        name: '_iceUdpCandidate',
                        namespace: He
                    }),
                    s = e.define({
                        element: 'fingerprint',
                        fields: {
                            hash: t.attribute('hash'),
                            required: t.boolAttribute('required'),
                            setup: t.attribute('setup'),
                            value: t.text()
                        },
                        name: '_iceFingerprint',
                        namespace: At
                    }),
                    o = e.define({
                        element: 'sctpmap',
                        fields: {
                            number: t.attribute('number'),
                            protocol: t.attribute('protocol'),
                            streams: t.attribute('streams')
                        },
                        name: '_sctpMap',
                        namespace: Pt
                    });
                e.extend(n, r, 'candidates'),
                    e.extend(n, i),
                    e.extend(n, s, 'fingerprints'),
                    e.extend(n, o, 'sctp'),
                    e.withDefinition('content', Ue, function(t) {
                        e.extend(t, n);
                    });
            }
            function vn(t) {
                const n = t.utils,
                    i = {
                        get: function() {
                            let t = n.find(this.xml, fe, 'data');
                            if (t.length)
                                return (
                                    (t = t[0]),
                                    {
                                        action: 'data',
                                        data: e.from(n.getText(t), 'base64'),
                                        seq: parseInt(n.getAttribute(t, 'seq') || '0', 10),
                                        sid: n.getAttribute(t, 'sid')
                                    }
                                );
                            let i = n.find(this.xml, fe, 'open');
                            if (i.length) {
                                i = i[0];
                                let e = n.getAttribute(i, 'stanza');
                                return {
                                    ack: (e = 'message' !== e),
                                    action: 'open',
                                    blockSize: n.getAttribute(i, 'block-size'),
                                    sid: n.getAttribute(i, 'sid')
                                };
                            }
                            const r = n.find(this.xml, fe, 'close');
                            return r.length
                                ? { action: 'close', sid: n.getAttribute(r[0], 'sid') }
                                : void 0;
                        },
                        set: function(e) {
                            if ('data' === e.action) {
                                const t = n.createElement(fe, 'data');
                                n.setAttribute(t, 'sid', e.sid),
                                    n.setAttribute(t, 'seq', e.seq.toString()),
                                    n.setText(t, e.data.toString('base64')),
                                    this.xml.appendChild(t);
                            }
                            if ('open' === e.action) {
                                const t = n.createElement(fe, 'open');
                                n.setAttribute(t, 'sid', e.sid),
                                    n.setAttribute(
                                        t,
                                        'block-size',
                                        (e.blockSize || '4096').toString()
                                    ),
                                    !1 === e.ack
                                        ? n.setAttribute(t, 'stanza', 'message')
                                        : n.setAttribute(t, 'stanza', 'iq'),
                                    this.xml.appendChild(t);
                            }
                            if ('close' === e.action) {
                                const t = n.createElement(fe, 'close');
                                n.setAttribute(t, 'sid', e.sid), this.xml.appendChild(t);
                            }
                        }
                    },
                    r = t.define({
                        element: 'transport',
                        fields: {
                            ack: {
                                get: function() {
                                    return 'message' !== n.getAttribute(this.xml, 'stanza');
                                },
                                set: function(e) {
                                    !1 === e.ack
                                        ? n.setAttribute(this.xml, 'stanza', 'message')
                                        : n.setAttribute(this.xml, 'stanza', 'iq');
                                }
                            },
                            blockSize: n.numberAttribute('block-size'),
                            sid: n.attribute('sid'),
                            transportType: { value: ct, writable: !0 }
                        },
                        name: '_' + ct,
                        namespace: ct,
                        tags: ['jingle-transport']
                    });
                t.withDefinition('content', Ue, function(e) {
                    t.extend(e, r);
                }),
                    t.withIQ(function(e) {
                        t.add(e, 'ibb', i);
                    }),
                    t.withMessage(function(e) {
                        t.add(e, 'ibb', i);
                    });
            }
            const xn = {};
            function wn(e) {
                xn.defineIQ(e, 'iq', G),
                    xn.defineIQ(e, 'serverIQ', H),
                    xn.defineIQ(e, 'componentIQ', Ce);
            }
            function _n(e) {
                e.withIQ(function(t) {
                    e.add(t, 'jidPrep', {
                        get: function() {
                            const t = e.utils.getSubText(this.xml, Et, 'jid');
                            if (t) {
                                const e = new C(t);
                                return (e.prepped = !0), e;
                            }
                        },
                        set: function(t) {
                            e.utils.setSubText(this.xml, Et, 'jid', (t || '').toString());
                        }
                    });
                });
            }
            xn.defineIQ = function(e, t, n) {
                const i = e.utils,
                    r = e.define({
                        element: 'iq',
                        fields: {
                            from: i.jidAttribute('from', !0),
                            id: i.attribute('id'),
                            lang: i.langAttribute(),
                            to: i.jidAttribute('to', !0),
                            type: i.attribute('type')
                        },
                        name: t,
                        namespace: n,
                        topLevel: !0
                    }),
                    s = r.prototype.toJSON;
                Object.assign(r.prototype, {
                    toJSON() {
                        const e = s.call(this);
                        return (
                            (e.resultReply = this.resultReply), (e.errorReply = this.errorReply), e
                        );
                    },
                    resultReply(e) {
                        return (
                            ((e = e || {}).to = this.from),
                            (e.id = this.id),
                            (e.type = 'result'),
                            new r(e)
                        );
                    },
                    errorReply(e) {
                        return (
                            ((e = e || {}).to = this.from),
                            (e.id = this.id),
                            (e.type = 'error'),
                            new r(e)
                        );
                    }
                });
            };
            const Sn = ['out-of-order', 'tie-break', 'unknown-session', 'unsupported-info'],
                An = [
                    'alternative-session',
                    'busy',
                    'cancel',
                    'connectivity-error',
                    'decline',
                    'expired',
                    'failed-application',
                    'failed-transport',
                    'general-error',
                    'gone',
                    'incompatible-parameters',
                    'media-error',
                    'security-error',
                    'success',
                    'timeout',
                    'unsupported-applications',
                    'unsupported-transports'
                ];
            function En(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'jingle',
                        fields: {
                            action: t.attribute('action'),
                            info: {
                                get: function() {
                                    const n = e.tagged('jingle-info').map(function(e) {
                                        return e.prototype._name;
                                    });
                                    for (let e = 0, t = n.length; e < t; e++)
                                        if (this._extensions[n[e]]) return this._extensions[n[e]];
                                    if ('session-info' === t.getAttribute(this.xml, 'action'))
                                        return 0 === this.xml.children.length
                                            ? { infoType: 'ping' }
                                            : { infoType: 'unknown' };
                                },
                                set: function(e) {
                                    if ('ping' === e.infoType) return;
                                    this['_' + e.infoType] = e;
                                }
                            },
                            initiator: t.attribute('initiator'),
                            responder: t.attribute('responder'),
                            sid: t.attribute('sid')
                        },
                        name: 'jingle',
                        namespace: Ue
                    }),
                    i = e.define({
                        element: 'content',
                        fields: {
                            application: {
                                get: function() {
                                    const t = e.tagged('jingle-application').map(function(e) {
                                        return e.prototype._name;
                                    });
                                    for (let e = 0, n = t.length; e < n; e++)
                                        if (this._extensions[t[e]]) return this._extensions[t[e]];
                                },
                                set: function(e) {
                                    this['_' + e.applicationType] = e;
                                }
                            },
                            creator: t.attribute('creator'),
                            disposition: t.attribute('disposition', 'session'),
                            name: t.attribute('name'),
                            security: {
                                get: function() {
                                    const t = e.tagged('jingle-security').map(function(e) {
                                        return e.prototype._name;
                                    });
                                    for (let e = 0, n = t.length; e < n; e++)
                                        if (this._extensions[t[e]]) return this._extensions[t[e]];
                                },
                                set: function(e) {
                                    this['_' + e.securityType] = e;
                                }
                            },
                            senders: t.attribute('senders', 'both'),
                            transport: {
                                get: function() {
                                    const t = e.tagged('jingle-transport').map(function(e) {
                                        return e.prototype._name;
                                    });
                                    for (let e = 0, n = t.length; e < n; e++)
                                        if (this._extensions[t[e]]) return this._extensions[t[e]];
                                },
                                set: function(e) {
                                    this['_' + e.transportType] = e;
                                }
                            }
                        },
                        name: '_jingleContent',
                        namespace: Ue
                    }),
                    r = e.define({
                        element: 'reason',
                        fields: {
                            alternativeSession: {
                                get: function() {
                                    return t.getSubText(this.xml, Ue, 'alternative-session');
                                },
                                set: function(e) {
                                    (this.condition = 'alternative-session'),
                                        t.setSubText(this.xml, Ue, 'alternative-session', e);
                                }
                            },
                            condition: t.enumSub(Ue, An),
                            text: t.textSub(Ue, 'text')
                        },
                        name: 'reason',
                        namespace: Ue
                    });
                e.extend(n, i, 'contents'),
                    e.extend(n, r),
                    e.extendIQ(n),
                    e.withStanzaError(function(n) {
                        e.add(n, 'jingleCondition', t.enumSub(ze, Sn));
                    });
            }
            function In(e) {
                const t = {
                    get: function() {
                        const t = e.utils.getSubText(this.xml, kt, 'json');
                        if (t) return JSON.parse(t);
                    },
                    set: function(t) {
                        (t = JSON.stringify(t)) && e.utils.setSubText(this.xml, kt, 'json', t);
                    }
                };
                e.withMessage(function(n) {
                    e.add(n, 'json', t);
                }),
                    e.withPubsubItem(function(n) {
                        e.add(n, 'json', t);
                    });
            }
            function jn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'log',
                        fields: {
                            facility: t.attribute('facility'),
                            id: t.attribute('id'),
                            level: t.attribute('level'),
                            message: t.textSub(Tt, 'message'),
                            module: t.attribute('module'),
                            object: t.attribute('object'),
                            stackTrace: t.textSub(Tt, 'stackTrace'),
                            subject: t.attribute('subject'),
                            timestamp: t.dateAttribute('timestamp'),
                            type: t.attribute('type')
                        },
                        name: 'log',
                        namespace: Tt
                    }),
                    i = e.define({
                        element: 'tag',
                        fields: {
                            name: t.attribute('name'),
                            type: t.attribute('type'),
                            value: t.attribute('value')
                        },
                        name: '_logtag',
                        namespace: Tt
                    });
                e.extend(n, i, 'tags'), e.extendMessage(n), e.extendPubsubItem(n);
            }
            function kn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'query',
                        fields: { node: t.attribute('node'), queryid: t.attribute('queryid') },
                        name: 'mam',
                        namespace: wt
                    }),
                    i = e.define({
                        element: 'result',
                        fields: { id: t.attribute('id'), queryid: t.attribute('queryid') },
                        name: 'mamItem',
                        namespace: wt
                    }),
                    r = e.define({
                        element: 'fin',
                        fields: {
                            complete: t.boolAttribute('complete'),
                            stable: t.boolAttribute('stable')
                        },
                        name: 'mamResult',
                        namespace: wt
                    }),
                    s = e.define({
                        element: 'prefs',
                        fields: {
                            always: {
                                get: function() {
                                    const e = [];
                                    let n = t.find(this.xml, wt, 'always');
                                    if (0 === n.length) return e;
                                    n = n[0];
                                    const i = t.getMultiSubText(n, wt, 'jid');
                                    for (const t of i) e.push(new C(t.textContent));
                                    return e;
                                },
                                set: function(e) {
                                    if (e.length > 0) {
                                        const n = t.findOrCreate(this.xml, wt, 'always');
                                        t.setMultiSubText(n, wt, 'jid', e);
                                    }
                                }
                            },
                            defaultCondition: t.attribute('default'),
                            never: {
                                get: function() {
                                    const e = [];
                                    let n = t.find(this.xml, wt, 'always');
                                    if (0 === n.length) return e;
                                    n = n[0];
                                    const i = t.getMultiSubText(n, wt, 'jid');
                                    for (const t of i) e.push(new C(t.textContent));
                                    return e;
                                },
                                set: function(e) {
                                    if (e.length > 0) {
                                        const n = t.findOrCreate(this.xml, wt, 'never');
                                        t.setMultiSubText(n, wt, 'jid', e);
                                    }
                                }
                            }
                        },
                        name: 'mamPrefs',
                        namespace: wt
                    });
                e.extendMessage(i),
                    e.extendIQ(n),
                    e.extendIQ(s),
                    e.extendIQ(r),
                    e.withDataForm(function(t) {
                        e.extend(n, t);
                    }),
                    e.withDefinition('forwarded', pt, function(t) {
                        e.extend(i, t);
                    }),
                    e.withDefinition('set', ge, function(t) {
                        e.extend(n, t), e.extend(r, t);
                    });
            }
            function Tn(e) {
                e.withMessage(function(t) {
                    e.add(t, 'markable', e.utils.boolSub(It, 'markable')),
                        e.add(t, 'received', e.utils.subAttribute(It, 'received', 'id')),
                        e.add(t, 'displayed', e.utils.subAttribute(It, 'displayed', 'id')),
                        e.add(t, 'acknowledged', e.utils.subAttribute(It, 'acknowledged', 'id'));
                });
            }
            const Cn = {};
            function Rn(e) {
                Cn.defineMessage(e, 'message', G),
                    Cn.defineMessage(e, 'serverMessage', H),
                    Cn.defineMessage(e, 'componentMessage', Ce);
            }
            Cn.defineMessage = function(e, t, n) {
                const i = e.utils;
                e.define({
                    element: 'message',
                    fields: {
                        $body: {
                            get: function() {
                                return i.getSubLangText(this.xml, n, 'body', this.lang);
                            }
                        },
                        archiveId: {
                            get: function() {
                                return i.getSubAttribute(
                                    this.xml,
                                    'urn:xmpp:mam:tmp',
                                    'archived',
                                    'id'
                                );
                            }
                        },
                        attachment: {
                            get: function() {
                                const e = {
                                        dispay_width: i.getSubAttribute(
                                            this.xml,
                                            n,
                                            'attachment',
                                            'dispay_width'
                                        ),
                                        display_height: i.getSubAttribute(
                                            this.xml,
                                            n,
                                            'attachment',
                                            'display_height'
                                        ),
                                        type: i.getSubAttribute(this.xml, n, 'attachment', 'type')
                                    },
                                    t = i.find(this.xml, n, 'attachment');
                                if (t[0]) {
                                    e.url = i.getSubText(t[0], n, 'url');
                                    const r = i.find(t[0], n, 'thumbnail');
                                    r[0] && (e.thumbnailUrl = i.getSubText(r[0], n, 'url'));
                                }
                                return t[0] ? e : null;
                            },
                            set: function(e) {
                                const t = i.createElement('', 'attachment'),
                                    n = i.createElement('', 'thumbnail'),
                                    r = i.createElement('', 'url'),
                                    s = i.createElement('', 'url');
                                t.setAttribute('type', e.type),
                                    t.setAttribute('dispay_width', e.width),
                                    t.setAttribute('display_height', e.height),
                                    (r.textContent = e.url),
                                    (s.textContent = e.thumbnailUrl),
                                    e.url &&
                                        (n.appendChild(s),
                                        t.appendChild(n),
                                        t.appendChild(r),
                                        this.xml.appendChild(t));
                            }
                        },
                        attention: i.boolSub(st, 'attention'),
                        body: {
                            get: function() {
                                return this.$body[this.lang] || '';
                            },
                            set: function(e) {
                                i.setSubLangText(this.xml, n, 'body', e, this.lang);
                            }
                        },
                        chatState: i.enumSub(je, [
                            'active',
                            'composing',
                            'paused',
                            'inactive',
                            'gone'
                        ]),
                        deleted: i.textSub(n, 'deleted'),
                        from: i.jidAttribute('from', !0),
                        id: i.attribute('id'),
                        lang: i.langAttribute(),
                        parentThread: i.subAttribute(n, 'thread', 'parent'),
                        receipt: i.subAttribute(Ke, 'received', 'id'),
                        replace: i.subAttribute(vt, 'replace', 'id'),
                        requestReceipt: i.boolSub(Ke, 'request'),
                        subject: i.textSub(n, 'subject'),
                        thread: i.textSub(n, 'thread'),
                        to: i.jidAttribute('to', !0),
                        type: i.attribute('type', 'normal')
                    },
                    name: t,
                    namespace: n,
                    topLevel: !0
                });
            };
            const Pn = [
                'afraid',
                'amazed',
                'amorous',
                'angry',
                'annoyed',
                'anxious',
                'aroused',
                'ashamed',
                'bored',
                'brave',
                'calm',
                'cautious',
                'cold',
                'confident',
                'confused',
                'contemplative',
                'contented',
                'cranky',
                'crazy',
                'creative',
                'curious',
                'dejected',
                'depressed',
                'disappointed',
                'disgusted',
                'dismayed',
                'distracted',
                'embarrassed',
                'envious',
                'excited',
                'flirtatious',
                'frustrated',
                'grateful',
                'grieving',
                'grumpy',
                'guilty',
                'happy',
                'hopeful',
                'hot',
                'humbled',
                'humiliated',
                'hungry',
                'hurt',
                'impressed',
                'in_awe',
                'in_love',
                'indignant',
                'interested',
                'intoxicated',
                'invincible',
                'jealous',
                'lonely',
                'lucky',
                'mean',
                'moody',
                'nervous',
                'neutral',
                'offended',
                'outraged',
                'playful',
                'proud',
                'relaxed',
                'relieved',
                'remorseful',
                'restless',
                'sad',
                'sarcastic',
                'serious',
                'shocked',
                'shy',
                'sick',
                'sleepy',
                'spontaneous',
                'stressed',
                'strong',
                'surprised',
                'thankful',
                'thirsty',
                'tired',
                'undefined',
                'weak',
                'worried'
            ];
            function On(e) {
                const t = e.define({
                    element: 'mood',
                    fields: { text: e.utils.textSub(Te, 'text'), value: e.utils.enumSub(Te, Pn) },
                    name: 'mood',
                    namespace: Te
                });
                e.extendMessage(t), e.extendPubsubItem(t);
            }
            function Ln(e, t) {
                return {
                    get: function() {
                        if (this._extensions[e]) return this[e][t];
                    },
                    set: function(n) {
                        this[e][t] = n;
                    }
                };
            }
            function Mn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'item',
                        fields: {
                            affiliation: t.attribute('affiliation'),
                            jid: t.jidAttribute('jid'),
                            nick: t.attribute('nick'),
                            reason: t.textSub(le, 'reason'),
                            role: t.attribute('role')
                        },
                        name: '_mucUserItem',
                        namespace: le
                    }),
                    i = e.define({
                        element: 'actor',
                        fields: { jid: t.jidAttribute('jid'), nick: t.attribute('nick') },
                        name: '_mucUserActor',
                        namespace: le
                    }),
                    r = e.define({
                        element: 'destroy',
                        fields: { jid: t.jidAttribute('jid'), reason: t.textSub(le, 'reason') },
                        name: 'destroyed',
                        namespace: le
                    }),
                    s = e.define({
                        element: 'invite',
                        fields: {
                            continue: t.boolSub(le, 'continue'),
                            from: t.jidAttribute('from'),
                            reason: t.textSub(le, 'reason'),
                            thread: t.subAttribute(le, 'continue', 'thread'),
                            to: t.jidAttribute('to')
                        },
                        name: 'invite',
                        namespace: le
                    }),
                    o = e.define({
                        element: 'decline',
                        fields: {
                            from: t.jidAttribute('from'),
                            reason: t.textSub(le, 'reason'),
                            to: t.jidAttribute('to')
                        },
                        name: 'decline',
                        namespace: le
                    }),
                    a = e.define({
                        element: 'item',
                        fields: {
                            affiliation: t.attribute('affiliation'),
                            jid: t.jidAttribute('jid'),
                            nick: t.attribute('nick'),
                            reason: t.textSub(ue, 'reason'),
                            role: t.attribute('role')
                        },
                        name: '_mucAdminItem',
                        namespace: ue
                    }),
                    u = e.define({
                        element: 'actor',
                        fields: { jid: t.jidAttribute('jid'), nick: t.attribute('nick') },
                        name: 'actor',
                        namespace: le
                    }),
                    c = e.define({
                        element: 'destroy',
                        fields: {
                            jid: t.jidAttribute('jid'),
                            password: t.textSub(ce, 'password'),
                            reason: t.textSub(ce, 'reason')
                        },
                        name: 'destroy',
                        namespace: ce
                    }),
                    l = e.define({
                        element: 'x',
                        fields: {
                            actor: Ln('_mucUserItem', '_mucUserActor'),
                            affiliation: Ln('_mucUserItem', 'affiliation'),
                            codes: {
                                get: function() {
                                    return t.getMultiSubText(this.xml, le, 'status', function(e) {
                                        return t.getAttribute(e, 'code');
                                    });
                                },
                                set: function(e) {
                                    const n = this;
                                    t.setMultiSubText(this.xml, le, 'status', e, function(e) {
                                        const i = t.createElement(le, 'status', le);
                                        t.setAttribute(i, 'code', e), n.xml.appendChild(i);
                                    });
                                }
                            },
                            jid: Ln('_mucUserItem', 'jid'),
                            nick: Ln('_mucUserItem', 'nick'),
                            password: t.textSub(le, 'password'),
                            reason: Ln('_mucUserItem', 'reason'),
                            role: Ln('_mucUserItem', 'role')
                        },
                        name: 'muc',
                        namespace: le
                    }),
                    f = e.define({
                        element: 'query',
                        fields: {
                            actor: Ln('_mucAdminItem', '_mucAdminActor'),
                            affiliation: Ln('_mucAdminItem', 'affiliation'),
                            jid: Ln('_mucAdminItem', 'jid'),
                            nick: Ln('_mucAdminItem', 'nick'),
                            reason: Ln('_mucAdminItem', 'reason'),
                            role: Ln('_mucAdminItem', 'role')
                        },
                        name: 'mucAdmin',
                        namespace: ue
                    }),
                    d = e.define({ element: 'query', name: 'mucOwner', namespace: ce }),
                    h = e.define({
                        element: 'x',
                        fields: {
                            history: {
                                get: function() {
                                    let e = t.find(this.xml, ae, 'history');
                                    if (!e.length) return {};
                                    (e = e[0]).getAttribute('maxchars'),
                                        e.getAttribute('maxstanzas'),
                                        e.getAttribute('seconds'),
                                        e.getAttribute('since');
                                },
                                set: function(e) {
                                    const n = t.find(this.xml, ae, 'history');
                                    if (n.length)
                                        for (let e = 0; e < n.length; e++)
                                            this.xml.removeChild(n[e]);
                                    const i = t.createElement(ae, 'history', ae);
                                    this.xml.appendChild(i),
                                        void 0 !== e.maxchars &&
                                            i.setAttribute('maxchars', '' + e.maxchars),
                                        void 0 !== e.maxstanzas &&
                                            i.setAttribute('maxstanzas', '' + e.maxstanzas),
                                        void 0 !== e.seconds &&
                                            i.setAttribute('seconds', '' + e.seconds),
                                        e.since && i.setAttribute('since', e.since.toISOString());
                                }
                            },
                            password: t.textSub(ae, 'password')
                        },
                        name: 'joinMuc',
                        namespace: ae
                    }),
                    p = e.define({
                        element: 'x',
                        fields: {
                            continue: t.boolAttribute('continue'),
                            jid: t.jidAttribute('jid'),
                            password: t.attribute('password'),
                            reason: t.attribute('reason'),
                            thread: t.attribute('thread')
                        },
                        name: 'mucInvite',
                        namespace: ut
                    });
                e.extend(n, i),
                    e.extend(l, n),
                    e.extend(l, s, 'invites'),
                    e.extend(l, o),
                    e.extend(l, r),
                    e.extend(a, u),
                    e.extend(f, a, 'items'),
                    e.extend(d, c),
                    e.extendPresence(l),
                    e.extendPresence(h),
                    e.extendMessage(l),
                    e.extendMessage(p),
                    e.withIQ(function(n) {
                        e.add(n, 'mucUnique', t.textSub(yt, 'unique')),
                            e.extend(n, f),
                            e.extend(n, d);
                    }),
                    e.withDataForm(function(t) {
                        e.extend(d, t);
                    });
            }
            function Bn(e) {
                const t = e.utils.textSub($e, 'nick');
                e.withPubsubItem(function(n) {
                    e.add(n, 'nick', t);
                }),
                    e.withPresence(function(n) {
                        e.add(n, 'nick', t);
                    }),
                    e.withMessage(function(n) {
                        e.add(n, 'nick', t);
                    });
            }
            function Dn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'encrypted',
                        fields: { payload: t.textSub(Dt, 'payload') },
                        name: 'omemo',
                        namespace: Dt
                    }),
                    i = e.define({
                        element: 'header',
                        fields: { iv: t.textSub(Dt, 'iv'), sid: t.attribute('sid') },
                        name: 'header',
                        namespace: Dt
                    }),
                    r = e.define({
                        element: 'key',
                        fields: {
                            preKey: t.boolAttribute('prekey'),
                            rid: t.attribute('rid'),
                            value: t.text()
                        },
                        namespace: Dt
                    }),
                    s = e.define({
                        element: 'list',
                        fields: { devices: t.multiSubAttribute(Dt, 'device', 'id') },
                        name: 'omemoDeviceList',
                        namespace: Dt
                    }),
                    o = e.define({
                        element: 'preKeyPublic',
                        fields: { id: t.attribute('preKeyId'), value: t.text() },
                        name: 'preKeyPublic',
                        namespace: Dt
                    }),
                    a = e.define({
                        element: 'signedPreKeyPublic',
                        fields: { id: t.attribute('signedPreKeyId'), value: t.text() },
                        name: 'signedPreKeyPublic',
                        namespace: Dt
                    }),
                    u = e.define({
                        element: 'bundle',
                        fields: {
                            identityKey: t.textSub(Dt, 'identityKey'),
                            preKeys: t.subMultiExtension(Dt, 'prekeys', o),
                            signedPreKeySignature: t.textSub(Dt, 'signedPreKeySignature')
                        },
                        name: 'omemoDevice',
                        namespace: Dt
                    });
                e.extend(u, a),
                    e.extend(i, r, 'keys', !0),
                    e.extend(n, i),
                    e.withMessage(function(t) {
                        e.extend(t, n);
                    }),
                    e.withPubsubItem(function(t) {
                        e.extend(t, u), e.extend(t, s);
                    });
            }
            function Nn(e) {
                const t = e.define({
                        element: 'x',
                        fields: {
                            desc: e.utils.textSub(_e, 'desc'),
                            url: e.utils.textSub(_e, 'url')
                        },
                        name: 'oob',
                        namespace: _e
                    }),
                    n = e.define({
                        element: 'query',
                        fields: {
                            desc: e.utils.textSub(_e, 'desc'),
                            url: e.utils.textSub(_e, 'url')
                        },
                        name: 'oob',
                        namespace: we
                    });
                e.extendMessage(t, 'oobURIs'), e.extendIQ(n);
            }
            function qn(e) {
                const t = e.define({ element: 'ping', name: 'ping', namespace: Ze });
                e.extendIQ(t);
            }
            const Fn = {};
            function Un(e) {
                Fn.definePresence(e, 'presence', G),
                    Fn.definePresence(e, 'serverPresence', H),
                    Fn.definePresence(e, 'componentPresence', Ce);
            }
            function zn(e) {
                const t = e.define({ element: 'query', name: 'privateStorage', namespace: he });
                e.extendIQ(t);
            }
            Fn.definePresence = function(e, t, n) {
                const i = e.utils;
                e.define({
                    element: 'presence',
                    fields: {
                        $status: {
                            get: function() {
                                return i.getSubLangText(this.xml, n, 'status', this.lang);
                            }
                        },
                        avatarId: {
                            get: function() {
                                const e = i.find(this.xml, 'vcard-temp:x:update', 'x');
                                return e.length
                                    ? i.getSubText(e[0], 'vcard-temp:x:update', 'photo')
                                    : '';
                            },
                            set: function(e) {
                                const t = i.findOrCreate(this.xml, 'vcard-temp:x:update', 'x');
                                if ('' === e) i.setBoolSub(t, 'vcard-temp:x:update', 'photo', !0);
                                else {
                                    if (!0 === e) return;
                                    e
                                        ? i.setSubText(t, 'vcard-temp:x:update', 'photo', e)
                                        : this.xml.removeChild(t);
                                }
                            }
                        },
                        decloak: i.subAttribute('urn:xmpp:decloaking:0', 'decloak', 'reason'),
                        from: i.jidAttribute('from', !0),
                        id: i.attribute('id'),
                        idleSince: i.dateSubAttribute(St, 'idle', 'since'),
                        lang: i.langAttribute(),
                        priority: i.numberSub(n, 'priority', !1, 0),
                        show: i.textSub(n, 'show'),
                        status: {
                            get: function() {
                                return this.$status[this.lang] || '';
                            },
                            set: function(e) {
                                i.setSubLangText(this.xml, n, 'status', e, this.lang);
                            }
                        },
                        to: i.jidAttribute('to', !0),
                        type: {
                            get: function() {
                                return i.getAttribute(this.xml, 'type', 'available');
                            },
                            set: function(e) {
                                'available' === e && (e = !1), i.setAttribute(this.xml, 'type', e);
                            }
                        }
                    },
                    name: t,
                    namespace: n,
                    topLevel: !0
                });
            };
            const Xn = ['server-unavailable', 'connection-paused'];
            function Qn(e) {
                const t = e.define({
                    element: 'state-annotation',
                    fields: {
                        condition: e.utils.enumSub(xt, Xn),
                        description: e.utils.textSub(xt, 'description'),
                        from: e.utils.jidAttribute('from')
                    },
                    name: 'state',
                    namespace: xt
                });
                e.extendPresence(t);
            }
            function Yn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'pubsub',
                        fields: {
                            create: {
                                get: function() {
                                    const e = t.getSubAttribute(this.xml, be, 'create', 'node');
                                    return e || t.getBoolSub(this.xml, be, 'create');
                                },
                                set: function(e) {
                                    !0 !== e && e
                                        ? t.setSubAttribute(this.xml, be, 'create', 'node', e)
                                        : t.setBoolSub(this.xml, be, 'create', e);
                                }
                            },
                            publishOptions: {
                                get: function() {
                                    const n = e.getDefinition('x', ie),
                                        i = t.find(this.xml, be, 'publish-options');
                                    if (i.length && i[0].childNodes.length)
                                        return new n({}, i[0].childNodes[0]);
                                },
                                set: function(n) {
                                    const i = e.getDefinition('x', ie),
                                        r = t.findOrCreate(this.xml, be, 'publish-options');
                                    if (n) {
                                        const e = new i(n);
                                        r.appendChild(e.xml);
                                    }
                                }
                            }
                        },
                        name: 'pubsub',
                        namespace: be
                    }),
                    i = e.define({ element: 'configure', name: 'config', namespace: be }),
                    r = e.define({
                        element: 'subscribe',
                        fields: { jid: t.jidAttribute('jid'), node: t.attribute('node') },
                        name: 'subscribe',
                        namespace: be
                    }),
                    s = e.define({
                        element: 'subscription',
                        fields: {
                            configurable: t.boolSub('subscribe-options'),
                            configurationRequired: {
                                get: function() {
                                    const e = t.find(this.xml, be, 'subscribe-options');
                                    return !!e.length && t.getBoolSub(e[0], be, 'required');
                                }
                            },
                            jid: t.jidAttribute('jid'),
                            node: t.attribute('node'),
                            subid: t.attribute('subid'),
                            type: t.attribute('subscription')
                        },
                        name: 'subscription',
                        namespace: be
                    }),
                    o = e.define({
                        element: 'subscriptions',
                        fields: { jid: t.jidAttribute('jid'), node: t.attribute('node') },
                        name: 'subscriptions',
                        namespace: be
                    }),
                    a = e.define({
                        element: 'affiliation',
                        fields: { node: t.attribute('node'), type: t.attribute('affiliation') },
                        name: 'affiliation',
                        namespace: be
                    }),
                    u = e.define({
                        element: 'affiliations',
                        fields: { node: t.attribute('node') },
                        name: 'affiliations',
                        namespace: be
                    }),
                    c = e.define({
                        element: 'options',
                        fields: {
                            jid: t.jidAttribute('jid'),
                            node: t.attribute('node'),
                            subid: t.attribute('subid')
                        },
                        name: 'subscriptionOptions',
                        namespace: be
                    }),
                    l = e.define({
                        element: 'unsubscribe',
                        fields: {
                            jid: t.jidAttribute('jid'),
                            node: t.attribute('node'),
                            subid: t.attribute('subid')
                        },
                        name: 'unsubscribe',
                        namespace: be
                    }),
                    f = e.define({
                        element: 'publish',
                        fields: { node: t.attribute('node') },
                        name: 'publish',
                        namespace: be
                    }),
                    d = e.define({
                        element: 'retract',
                        fields: {
                            id: t.subAttribute(be, 'item', 'id'),
                            node: t.attribute('node'),
                            notify: t.boolAttribute('notify')
                        },
                        name: 'retract',
                        namespace: be
                    }),
                    h = e.define({
                        element: 'items',
                        fields: { max: t.attribute('max_items'), node: t.attribute('node') },
                        name: 'retrieve',
                        namespace: be
                    }),
                    p = e.define({
                        element: 'item',
                        fields: { id: t.attribute('id'), publisher: t.jidAttribute('publisher') },
                        name: 'item',
                        namespace: be
                    });
                e.extend(n, i),
                    e.extend(n, r),
                    e.extend(n, l),
                    e.extend(n, f),
                    e.extend(n, d),
                    e.extend(n, h),
                    e.extend(n, s),
                    e.extend(n, c),
                    e.extend(n, o),
                    e.extend(n, u),
                    e.extend(f, p, 'items'),
                    e.extend(h, p, 'items'),
                    e.extend(o, s, 'list'),
                    e.extend(u, a, 'list'),
                    e.extendIQ(n),
                    e.withDataForm(function(t) {
                        e.extend(c, t), e.extend(p, t), e.extend(i, t);
                    }),
                    e.withDefinition('set', ge, function(t) {
                        e.extend(n, t);
                    });
            }
            const Gn = [
                'closed-node',
                'configuration-required',
                'invalid-jid',
                'invalid-options',
                'invalid-payload',
                'invalid-subid',
                'item-forbidden',
                'item-required',
                'jid-required',
                'max-items-exceeded',
                'max-nodes-exceeded',
                'nodeid-required',
                'not-in-roster-group',
                'not-subscribed',
                'payload-too-big',
                'payload-required',
                'pending-subscription',
                'presence-subscription-required',
                'subid-required',
                'too-many-subscriptions',
                'unsupported',
                'unsupported-access-model'
            ];
            function $n(e) {
                e.withStanzaError(function(t) {
                    e.add(t, 'pubsubCondition', e.utils.enumSub(ye, Gn)),
                        e.add(t, 'pubsubUnsupportedFeature', {
                            get: function() {
                                return e.utils.getSubAttribute(
                                    this.xml,
                                    ye,
                                    'unsupported',
                                    'feature'
                                );
                            },
                            set: function(t) {
                                t && (this.pubsubCondition = 'unsupported'),
                                    e.utils.setSubAttribute(
                                        this.xml,
                                        ye,
                                        'unsupported',
                                        'feature',
                                        t
                                    );
                            }
                        });
                });
            }
            function Hn(e) {
                const t = e.utils,
                    n = e.define({ element: 'event', name: 'event', namespace: ve }),
                    i = e.define({
                        element: 'purge',
                        fields: { node: t.attribute('node') },
                        name: 'purged',
                        namespace: ve
                    }),
                    r = e.define({
                        element: 'delete',
                        fields: {
                            node: t.attribute('node'),
                            redirect: t.subAttribute(ve, 'redirect', 'uri')
                        },
                        name: 'deleted',
                        namespace: ve
                    }),
                    s = e.define({
                        element: 'subscription',
                        fields: {
                            expiry: {
                                get: function() {
                                    const e = t.getAttribute(this.xml, 'expiry');
                                    return 'presence' === e ? e : e ? new Date(e) : void 0;
                                },
                                set: function(e) {
                                    e &&
                                        ('string' != typeof e && (e = e.toISOString()),
                                        t.setAttribute(this.xml, 'expiry', e));
                                }
                            },
                            jid: t.jidAttribute('jid'),
                            node: t.attribute('node'),
                            subid: t.attribute('subid'),
                            type: t.attribute('subscription')
                        },
                        name: 'subscriptionChanged',
                        namespace: ve
                    }),
                    o = e.define({
                        element: 'configuration',
                        fields: { node: t.attribute('node') },
                        name: 'configurationChanged',
                        namespace: ve
                    }),
                    a = e.define({
                        element: 'items',
                        fields: {
                            node: t.attribute('node'),
                            retracted: {
                                get: function() {
                                    const e = [],
                                        n = t.find(this.xml, ve, 'retract');
                                    for (const t of n) e.push(t.getAttribute('id'));
                                    return e;
                                },
                                set: function(e) {
                                    const n = this;
                                    for (const i of e) {
                                        const e = t.createElement(ve, 'retract', ve);
                                        e.setAttribute('id', i), n.xml.appendChild(e);
                                    }
                                }
                            }
                        },
                        name: 'updated',
                        namespace: ve
                    }),
                    u = e.define({
                        element: 'item',
                        fields: {
                            id: t.attribute('id'),
                            node: t.attribute('node'),
                            publisher: t.jidAttribute('publisher')
                        },
                        name: '_eventItem',
                        namespace: ve
                    });
                e.extend(a, u, 'published'),
                    e.extend(n, a),
                    e.extend(n, s),
                    e.extend(n, o),
                    e.extend(n, r),
                    e.extend(n, i),
                    e.extendMessage(n),
                    e.withDataForm(function(t) {
                        e.extend(o, t);
                    });
            }
            function Kn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'pubsub',
                        fields: {
                            del: t.subAttribute(xe, 'delete', 'node'),
                            purge: t.subAttribute(xe, 'purge', 'node'),
                            redirect: {
                                get: function() {
                                    const e = t.find(this.xml, xe, 'delete');
                                    return e.length
                                        ? t.getSubAttribute(e[0], xe, 'redirect', 'uri')
                                        : '';
                                },
                                set: function(e) {
                                    const n = t.findOrCreate(this.xml, xe, 'delete');
                                    t.setSubAttribute(n, xe, 'redirect', 'uri', e);
                                }
                            }
                        },
                        name: 'pubsubOwner',
                        namespace: xe
                    }),
                    i = e.define({
                        element: 'subscription',
                        fields: {
                            configurable: t.boolSub('subscribe-options'),
                            configurationRequired: {
                                get: function() {
                                    const e = t.find(this.xml, xe, 'subscribe-options');
                                    return !!e.length && t.getBoolSub(e[0], xe, 'required');
                                }
                            },
                            jid: t.jidAttribute('jid'),
                            node: t.attribute('node'),
                            subid: t.attribute('subid'),
                            type: t.attribute('subscription')
                        },
                        name: 'subscription',
                        namespace: xe
                    }),
                    r = e.define({
                        element: 'subscriptions',
                        fields: { node: t.attribute('node') },
                        name: 'subscriptions',
                        namespace: xe
                    }),
                    s = e.define({
                        element: 'affiliation',
                        fields: { jid: t.jidAttribute('jid'), type: t.attribute('affiliation') },
                        name: 'affiliation',
                        namespace: xe
                    }),
                    o = e.define({
                        element: 'affiliations',
                        fields: { node: t.attribute('node') },
                        name: 'affiliations',
                        namespace: xe
                    }),
                    a = e.define({
                        element: 'configure',
                        fields: { node: t.attribute('node') },
                        name: 'config',
                        namespace: xe
                    }),
                    u = e.define({ element: 'default', name: 'default', namespace: xe });
                e.extend(n, a),
                    e.extend(n, r),
                    e.extend(n, o),
                    e.extend(n, u),
                    e.extend(r, i, 'list'),
                    e.extend(o, s, 'list'),
                    e.extendIQ(n),
                    e.withDataForm(function(t) {
                        e.extend(a, t);
                    });
            }
            function Wn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'enable',
                        fields: { jid: t.jidAttribute('jid'), node: t.attribute('node') },
                        name: 'enablePush',
                        namespace: Lt
                    }),
                    i = e.define({
                        element: 'disable',
                        fields: { jid: t.jidAttribute('jid'), node: t.attribute('node') },
                        name: 'disablePush',
                        namespace: Lt
                    }),
                    r = e.define({
                        element: 'notification',
                        name: 'pushNotification',
                        namespace: Lt
                    });
                e.withDataForm(t => {
                    e.extend(r, t), e.extend(n, t);
                }),
                    e.extendIQ(n),
                    e.extendIQ(i);
            }
            function Vn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'addr',
                        fields: {
                            $desc: {
                                get: function() {
                                    return t.getSubLangText(this.xml, De, 'desc', this.lang);
                                }
                            },
                            desc: {
                                get: function() {
                                    return this.$desc[this.lang] || '';
                                },
                                set: function(e) {
                                    t.setSubLangText(this.xml, De, 'desc', e, this.lang);
                                }
                            },
                            uri: t.attribute('uri')
                        },
                        name: '_reachAddr',
                        namespace: De
                    }),
                    i = {
                        get: function() {
                            const e = t.find(this.xml, De, 'reach'),
                                i = [];
                            if (e.length) {
                                const r = t.find(e[0], De, 'addr');
                                for (const e of r) i.push(new n({}, e));
                            }
                            return i;
                        },
                        set: function(e) {
                            const i = t.findOrCreate(this.xml, De, 'reach');
                            t.setAttribute(i, 'xmlns', De);
                            for (const t of e) {
                                const e = new n(t);
                                i.appendChild(e.xml);
                            }
                        }
                    };
                e.withPubsubItem(function(t) {
                    e.add(t, 'reach', i);
                }),
                    e.withPresence(function(t) {
                        e.add(t, 'reach', i);
                    });
            }
            function Jn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'query',
                        fields: {
                            address: t.textSub(Se, 'address'),
                            city: t.textSub(Se, 'city'),
                            date: t.textSub(Se, 'date'),
                            email: t.textSub(Se, 'email'),
                            first: t.textSub(Se, 'first'),
                            instructions: t.textSub(Se, 'instructions'),
                            key: t.textSub(Se, 'key'),
                            last: t.textSub(Se, 'last'),
                            misc: t.textSub(Se, 'misc'),
                            name: t.textSub(Se, 'name'),
                            nick: t.textSub(Se, 'nick'),
                            password: t.textSub(Se, 'password'),
                            phone: t.textSub(Se, 'phone'),
                            registered: t.boolSub(Se, 'registered'),
                            remove: t.boolSub(Se, 'remove'),
                            state: t.textSub(Se, 'state'),
                            text: t.textSub(Se, 'text'),
                            url: t.textSub(Se, 'url'),
                            username: t.textSub(Se, 'username'),
                            zip: t.textSub(Se, 'zip')
                        },
                        name: 'register',
                        namespace: Se
                    });
                e.extendIQ(n),
                    e.withDefinition('x', _e, function(t) {
                        e.extend(n, t);
                    }),
                    e.withDataForm(function(t) {
                        e.extend(n, t);
                    });
            }
            function Zn(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'reference',
                        fields: {
                            anchor: t.attribute('anchor'),
                            begin: t.numberAttribute('begin'),
                            end: t.numberAttribute('end'),
                            type: t.attribute('type'),
                            uri: t.attribute('uri')
                        },
                        name: 'reference',
                        namespace: Mt
                    }),
                    i = t.multiExtension(n);
                e.withMessage(function(t) {
                    e.add(t, 'references', i);
                });
            }
            function ei(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'query',
                        fields: {
                            ver: {
                                get: function() {
                                    return t.getAttribute(this.xml, 'ver');
                                },
                                set: function(e) {
                                    const n = '' === e;
                                    t.setAttribute(this.xml, 'ver', e, n);
                                }
                            }
                        },
                        name: 'roster',
                        namespace: Z
                    }),
                    i = e.define({
                        element: 'item',
                        fields: {
                            groups: t.multiTextSub(Z, 'group'),
                            jid: t.jidAttribute('jid', !0),
                            name: t.attribute('name'),
                            preApproved: t.boolAttribute(Z, 'approved'),
                            subscription: t.attribute('subscription', 'none'),
                            subscriptionRequested: {
                                get: function() {
                                    return 'subscribe' === t.getAttribute(this.xml, 'ask');
                                }
                            }
                        },
                        name: '_rosterItem',
                        namespace: Z
                    });
                e.extend(n, i, 'items'), e.extendIQ(n);
            }
            function ti(e) {
                const t = e.utils;
                e.define({
                    element: 'set',
                    fields: {
                        after: t.textSub(ge, 'after'),
                        before: {
                            get: function() {
                                return t.getSubText(this.xml, ge, 'before');
                            },
                            set: function(e) {
                                !0 === e
                                    ? t.findOrCreate(this.xml, ge, 'before')
                                    : t.setSubText(this.xml, ge, 'before', e);
                            }
                        },
                        count: t.numberSub(ge, 'count', !1, 0),
                        first: t.textSub(ge, 'first'),
                        firstIndex: t.numberSubAttribute(ge, 'first', 'index'),
                        index: t.numberSub(ge, 'index', !1),
                        last: t.textSub(ge, 'last'),
                        max: t.numberSub(ge, 'max', !1)
                    },
                    name: 'rsm',
                    namespace: ge
                });
            }
            function ni(e) {
                const t = e.utils,
                    n = {
                        get: function() {
                            let e = t.find(this.xml, dt, 'rtcp-fb');
                            const n = [];
                            for (const i of e)
                                n.push({
                                    subtype: t.getAttribute(i, 'subtype'),
                                    type: t.getAttribute(i, 'type')
                                });
                            e = t.find(this.xml, dt, 'rtcp-fb-trr-int');
                            for (const i of e)
                                n.push({
                                    type: t.getAttribute(i, 'type'),
                                    value: t.getAttribute(i, 'value')
                                });
                            return n;
                        },
                        set: function(e) {
                            const n = this;
                            let i = t.find(this.xml, dt, 'rtcp-fb');
                            for (const e of i) n.xml.removeChild(e);
                            i = t.find(this.xml, dt, 'rtcp-fb-trr-int');
                            for (const e of i) n.xml.removeChild(e);
                            for (const i of e) {
                                let e;
                                'trr-int' === i.type
                                    ? ((e = t.createElement(dt, 'rtcp-fb-trr-int', Xe)),
                                      t.setAttribute(e, 'type', i.type),
                                      t.setAttribute(e, 'value', i.value))
                                    : ((e = t.createElement(dt, 'rtcp-fb', Xe)),
                                      t.setAttribute(e, 'type', i.type),
                                      t.setAttribute(e, 'subtype', i.subtype)),
                                    n.xml.appendChild(e);
                            }
                        }
                    },
                    i = e.define({
                        element: 'bandwidth',
                        fields: { bandwidth: t.text(), type: t.attribute('type') },
                        name: 'bandwidth',
                        namespace: Xe
                    }),
                    r = e.define({
                        element: 'description',
                        fields: {
                            applicationType: { value: 'rtp', writable: !0 },
                            encryption: {
                                get: function() {
                                    let e = t.find(this.xml, Xe, 'encryption');
                                    if (!e.length) return [];
                                    e = e[0];
                                    const n = this,
                                        i = t.find(e, Xe, 'crypto'),
                                        r = [];
                                    for (const e of i) r.push(new o({}, e, n).toJSON());
                                    return r;
                                },
                                set: function(e) {
                                    let n = t.find(this.xml, Xe, 'encryption');
                                    if ((n.length && this.xml.removeChild(n), !e.length)) return;
                                    t.setBoolSubAttribute(
                                        this.xml,
                                        Xe,
                                        'encryption',
                                        'required',
                                        !0
                                    ),
                                        (n = t.find(this.xml, Xe, 'encryption')[0]);
                                    const i = this;
                                    for (const t of e) {
                                        const e = new o(t, null, i);
                                        n.appendChild(e.xml);
                                    }
                                }
                            },
                            feedback: n,
                            headerExtensions: {
                                get: function() {
                                    const e = t.find(this.xml, ht, 'rtp-hdrext'),
                                        n = [];
                                    for (const i of e)
                                        n.push({
                                            id: t.getAttribute(i, 'id'),
                                            senders: t.getAttribute(i, 'senders'),
                                            uri: t.getAttribute(i, 'uri')
                                        });
                                    return n;
                                },
                                set: function(e) {
                                    const n = this,
                                        i = t.find(this.xml, ht, 'rtp-hdrext');
                                    for (const e of i) n.xml.removeChild(e);
                                    for (const i of e) {
                                        const e = t.createElement(ht, 'rtp-hdrext', Xe);
                                        t.setAttribute(e, 'id', i.id),
                                            t.setAttribute(e, 'uri', i.uri),
                                            t.setAttribute(e, 'senders', i.senders),
                                            n.xml.appendChild(e);
                                    }
                                }
                            },
                            media: t.attribute('media'),
                            mux: t.boolSub(Xe, 'rtcp-mux'),
                            reducedSize: t.boolSub(Xe, 'rtcp-rsize'),
                            ssrc: t.attribute('ssrc')
                        },
                        name: '_rtp',
                        namespace: Xe,
                        tags: ['jingle-application']
                    }),
                    s = e.define({
                        element: 'payload-type',
                        fields: {
                            channels: t.attribute('channels'),
                            clockrate: t.attribute('clockrate'),
                            feedback: n,
                            id: t.attribute('id'),
                            maxptime: t.attribute('maxptime'),
                            name: t.attribute('name'),
                            parameters: {
                                get: function() {
                                    const e = [],
                                        n = t.find(this.xml, Xe, 'parameter');
                                    for (const i of n)
                                        e.push({
                                            key: t.getAttribute(i, 'name'),
                                            value: t.getAttribute(i, 'value')
                                        });
                                    return e;
                                },
                                set: function(e) {
                                    const n = this;
                                    for (const i of e) {
                                        const e = t.createElement(Xe, 'parameter');
                                        t.setAttribute(e, 'name', i.key),
                                            t.setAttribute(e, 'value', i.value),
                                            n.xml.appendChild(e);
                                    }
                                }
                            },
                            ptime: t.attribute('ptime')
                        },
                        name: '_payloadType',
                        namespace: Xe
                    }),
                    o = e.define({
                        element: 'crypto',
                        fields: {
                            cipherSuite: t.attribute('crypto-suite'),
                            keyParams: t.attribute('key-params'),
                            sessionParams: t.attribute('session-params'),
                            tag: t.attribute('tag')
                        },
                        name: 'crypto',
                        namespace: Xe
                    }),
                    a = e.define({
                        element: 'group',
                        fields: {
                            contents: t.multiSubAttribute(Ct, 'content', 'name'),
                            semantics: t.attribute('semantics')
                        },
                        name: '_group',
                        namespace: Ct
                    }),
                    u = e.define({
                        element: 'ssrc-group',
                        fields: {
                            semantics: t.attribute('semantics'),
                            sources: t.multiSubAttribute(Rt, 'source', 'ssrc')
                        },
                        name: '_sourceGroup',
                        namespace: Rt
                    }),
                    c = e.define({
                        element: 'source',
                        fields: {
                            parameters: {
                                get: function() {
                                    const e = [],
                                        n = t.find(this.xml, Rt, 'parameter');
                                    for (const i of n)
                                        e.push({
                                            key: t.getAttribute(i, 'name'),
                                            value: t.getAttribute(i, 'value')
                                        });
                                    return e;
                                },
                                set: function(e) {
                                    const n = this;
                                    for (const i of e) {
                                        const e = t.createElement(Rt, 'parameter');
                                        t.setAttribute(e, 'name', i.key),
                                            t.setAttribute(e, 'value', i.value),
                                            n.xml.appendChild(e);
                                    }
                                }
                            },
                            ssrc: t.attribute('ssrc')
                        },
                        name: '_source',
                        namespace: Rt
                    }),
                    l = e.define({
                        element: 'stream',
                        fields: { id: t.attribute('id'), track: t.attribute('track') },
                        name: '_stream',
                        namespace: 'urn:xmpp:jingle:apps:rtp:msid:0'
                    }),
                    f = e.define({
                        element: 'mute',
                        fields: { creator: t.attribute('creator'), name: t.attribute('name') },
                        name: 'mute',
                        namespace: Qe
                    }),
                    d = e.define({
                        element: 'unmute',
                        fields: { creator: t.attribute('creator'), name: t.attribute('name') },
                        name: 'unmute',
                        namespace: Qe
                    });
                e.extend(r, i),
                    e.extend(r, s, 'payloads'),
                    e.extend(r, c, 'sources'),
                    e.extend(r, u, 'sourceGroups'),
                    e.extend(r, l, 'streams'),
                    e.withDefinition('content', Ue, function(t) {
                        e.extend(t, r);
                    }),
                    e.withDefinition('jingle', Ue, function(n) {
                        e.extend(n, f),
                            e.extend(n, d),
                            e.extend(n, a, 'groups'),
                            e.add(n, 'ringing', t.boolSub(Qe, 'ringing')),
                            e.add(n, 'hold', t.boolSub(Qe, 'hold')),
                            e.add(n, 'active', t.boolSub(Qe, 'active'));
                    });
            }
            const ii = { erase: 'e', insert: 't', wait: 'w' },
                ri = { e: 'erase', t: 'insert', w: 'wait' };
            function si(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'rtt',
                        fields: {
                            actions: {
                                get: function() {
                                    const e = [];
                                    for (let n = 0, i = this.xml.childNodes.length; n < i; n++) {
                                        const i = this.xml.childNodes[n],
                                            r = i.localName,
                                            s = {};
                                        if (i.namespaceURI !== bt) continue;
                                        if (!ri[r]) continue;
                                        s.type = ri[r];
                                        const o = t.getAttribute(i, 'p');
                                        o && (s.pos = parseInt(o, 10));
                                        const a = t.getAttribute(i, 'n');
                                        a && (s.num = parseInt(a, 10));
                                        const u = t.getText(i);
                                        u && 't' === r && (s.text = u), e.push(s);
                                    }
                                    return e;
                                },
                                set: function(e) {
                                    const n = this;
                                    for (let e = 0, t = this.xml.childNodes.length; e < t; e++)
                                        this.xml.removeChild(this.xml.childNodes[e]);
                                    for (const i of e) {
                                        if (!ii[i.type]) return;
                                        const e = t.createElement(bt, ii[i.type], bt);
                                        void 0 !== i.pos &&
                                            t.setAttribute(e, 'p', i.pos.toString()),
                                            i.num && t.setAttribute(e, 'n', i.num.toString()),
                                            i.text && t.setText(e, i.text),
                                            n.xml.appendChild(e);
                                    }
                                }
                            },
                            event: t.attribute('event', 'edit'),
                            id: t.attribute('id'),
                            seq: t.numberAttribute('seq')
                        },
                        name: 'rtt',
                        namespace: bt
                    });
                e.extendMessage(n);
            }
            const oi = [
                'aborted',
                'account-disabled',
                'credentials-expired',
                'encryption-required',
                'incorrect-encoding',
                'invalid-authzid',
                'invalid-mechanism',
                'malformed-request',
                'mechanism-too-weak',
                'not-authorized',
                'temporary-auth-failure',
                'not-supported'
            ];
            function ai(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'mechanisms',
                        fields: { mechanisms: t.multiTextSub($, 'mechanism') },
                        name: 'sasl',
                        namespace: $
                    });
                e.define({
                    element: 'auth',
                    eventName: 'sasl:auth',
                    fields: { mechanism: t.attribute('mechanism'), value: t.text() },
                    name: 'saslAuth',
                    namespace: $,
                    topLevel: !0
                }),
                    e.define({
                        element: 'challenge',
                        eventName: 'sasl:challenge',
                        fields: { value: t.text() },
                        name: 'saslChallenge',
                        namespace: $,
                        topLevel: !0
                    }),
                    e.define({
                        element: 'response',
                        eventName: 'sasl:response',
                        fields: { value: t.text() },
                        name: 'saslResponse',
                        namespace: $,
                        topLevel: !0
                    }),
                    e.define({
                        element: 'abort',
                        eventName: 'sasl:abort',
                        name: 'saslAbort',
                        namespace: $,
                        topLevel: !0
                    }),
                    e.define({
                        element: 'success',
                        eventName: 'sasl:success',
                        fields: { value: t.text() },
                        name: 'saslSuccess',
                        namespace: $,
                        topLevel: !0
                    }),
                    e.define({
                        element: 'failure',
                        eventName: 'sasl:failure',
                        fields: {
                            $text: {
                                get: function() {
                                    return t.getSubLangText(this.xml, $, 'text', this.lang);
                                }
                            },
                            condition: t.enumSub($, oi),
                            lang: {
                                get: function() {
                                    return this._lang || '';
                                },
                                set: function(e) {
                                    this._lang = e;
                                }
                            },
                            text: {
                                get: function() {
                                    return this.$text[this.lang] || '';
                                },
                                set: function(e) {
                                    t.setSubLangText(this.xml, $, 'text', e, this.lang);
                                }
                            }
                        },
                        name: 'saslFailure',
                        namespace: $,
                        topLevel: !0
                    }),
                    e.extendStreamFeatures(n);
            }
            function ui(e) {
                const t = e.define({
                    element: 'session',
                    fields: {
                        optional: e.utils.boolSub(K, 'optional'),
                        required: e.utils.boolSub(K, 'required')
                    },
                    name: 'session',
                    namespace: K
                });
                e.extendIQ(t), e.extendStreamFeatures(t);
            }
            function ci(e) {
                const t = e.utils,
                    n = {
                        get: function() {
                            const e = t.find(this.xml, Me, 'headers');
                            return e.length
                                ? t.getMultiSubText(e[0], Me, 'header', function(e) {
                                      const n = t.getAttribute(e, 'name');
                                      if (n) return { name: n, value: t.getText(e) };
                                  })
                                : [];
                        },
                        set: function(n) {
                            const i = t.findOrCreate(this.xml, Me, 'headers');
                            e.setMultiSubText(i, Me, 'header', n, function(e) {
                                const n = t.createElement(Me, 'header', Me);
                                t.setAttribute(n, 'name', e.name),
                                    t.setText(n, e.value),
                                    i.appendChild(n);
                            });
                        }
                    };
                e.withMessage(function(t) {
                    e.add(t, 'headers', n);
                }),
                    e.withPresence(function(t) {
                        e.add(t, 'headers', n);
                    });
            }
            function li(e) {
                const t = e.utils,
                    n = e.define({ element: 'sm', name: 'streamManagement', namespace: Je });
                e.define({
                    element: 'enable',
                    eventName: 'stream:management:enable',
                    fields: { resume: t.boolAttribute('resume') },
                    name: 'smEnable',
                    namespace: Je,
                    topLevel: !0
                }),
                    e.define({
                        element: 'enabled',
                        eventName: 'stream:management:enabled',
                        fields: { id: t.attribute('id'), resume: t.boolAttribute('resume') },
                        name: 'smEnabled',
                        namespace: Je,
                        topLevel: !0
                    }),
                    e.define({
                        element: 'resume',
                        eventName: 'stream:management:resume',
                        fields: { h: t.numberAttribute('h', !1, 0), previd: t.attribute('previd') },
                        name: 'smResume',
                        namespace: Je,
                        topLevel: !0
                    }),
                    e.define({
                        element: 'resumed',
                        eventName: 'stream:management:resumed',
                        fields: { h: t.numberAttribute('h', !1, 0), previd: t.attribute('previd') },
                        name: 'smResumed',
                        namespace: Je,
                        topLevel: !0
                    }),
                    e.define({
                        element: 'failed',
                        eventName: 'stream:management:failed',
                        name: 'smFailed',
                        namespace: Je,
                        topLevel: !0
                    }),
                    e.define({
                        element: 'a',
                        eventName: 'stream:management:ack',
                        fields: { h: t.numberAttribute('h', !1, 0) },
                        name: 'smAck',
                        namespace: Je,
                        topLevel: !0
                    }),
                    e.define({
                        element: 'r',
                        eventName: 'stream:management:request',
                        name: 'smRequest',
                        namespace: Je,
                        topLevel: !0
                    }),
                    e.extendStreamFeatures(n);
            }
            function fi(e) {
                const t = e.utils;
                e.define({
                    element: 'stream',
                    fields: {
                        from: t.jidAttribute('from', !0),
                        id: t.attribute('id'),
                        lang: t.langAttribute(),
                        to: t.jidAttribute('to', !0),
                        version: t.attribute('version', '1.0')
                    },
                    name: 'stream',
                    namespace: V
                });
            }
            const di = [
                'bad-format',
                'bad-namespace-prefix',
                'conflict',
                'connection-timeout',
                'host-gone',
                'host-unknown',
                'improper-addressing',
                'internal-server-error',
                'invalid-from',
                'invalid-namespace',
                'invalid-xml',
                'not-authorized',
                'not-well-formed',
                'policy-violation',
                'remote-connection-failed',
                'reset',
                'resource-constraint',
                'restricted-xml',
                'see-other-host',
                'system-shutdown',
                'undefined-condition',
                'unsupported-encoding',
                'unsupported-feature',
                'unsupported-stanza-type',
                'unsupported-version'
            ];
            function hi(e) {
                const t = e.utils;
                e.define({
                    element: 'error',
                    fields: {
                        $text: {
                            get: function() {
                                return t.getSubLangText(this.xml, J, 'text', this.lang);
                            }
                        },
                        condition: t.enumSub(J, di),
                        lang: {
                            get: function() {
                                return this._lang || '';
                            },
                            set: function(e) {
                                this._lang = e;
                            }
                        },
                        seeOtherHost: {
                            get: function() {
                                return t.getSubText(this.xml, J, 'see-other-host');
                            },
                            set: function(e) {
                                (this.condition = 'see-other-host'),
                                    t.setSubText(this.xml, J, 'see-other-host', e);
                            }
                        },
                        text: {
                            get: function() {
                                return this.$text[this.lang] || '';
                            },
                            set: function(e) {
                                t.setSubLangText(this.xml, J, 'text', e, this.lang);
                            }
                        }
                    },
                    name: 'streamError',
                    namespace: V,
                    topLevel: !0
                });
            }
            function pi(e) {
                e.define({
                    element: 'features',
                    name: 'streamFeatures',
                    namespace: V,
                    topLevel: !0
                });
                const t = e.define({ element: 'ver', name: 'rosterVersioning', namespace: ee }),
                    n = e.define({
                        element: 'sub',
                        name: 'subscriptionPreApproval',
                        namespace: te
                    });
                e.extendStreamFeatures(t), e.extendStreamFeatures(n);
            }
            function mi(e) {
                const t = e.define({
                    element: 'time',
                    fields: { tzo: e.utils.tzoSub(et, 'tzo', 0), utc: e.utils.dateSub(et, 'utc') },
                    name: 'time',
                    namespace: et
                });
                e.extendIQ(t);
            }
            function gi(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'tune',
                        fields: {
                            artist: t.textSub(Pe, 'artist'),
                            length: t.numberSub(Pe, 'length'),
                            rating: t.numberSub(Pe, 'rating'),
                            source: t.textSub(Pe, 'source'),
                            title: t.textSub(Pe, 'title'),
                            track: t.textSub(Pe, 'track'),
                            uri: t.textSub(Pe, 'uri')
                        },
                        name: 'tune',
                        namespace: Pe
                    });
                e.extendPubsubItem(n), e.extendMessage(n);
            }
            function bi(e) {
                const t = e.utils,
                    n = e.define({
                        element: 'vCard',
                        fields: {
                            birthday: t.dateSub(me, 'BDAY'),
                            description: t.textSub(me, 'DESC'),
                            fullName: t.textSub(me, 'FN'),
                            jids: t.multiTextSub(me, 'JABBERID'),
                            nicknames: t.multiTextSub(me, 'NICKNAME'),
                            role: t.textSub(me, 'ROLE'),
                            title: t.textSub(me, 'TITLE'),
                            website: t.textSub(me, 'URL')
                        },
                        name: 'vCardTemp',
                        namespace: me
                    }),
                    i = e.define({
                        element: 'EMAIL',
                        fields: {
                            email: t.textSub(me, 'USERID'),
                            home: t.boolSub(me, 'HOME'),
                            preferred: t.boolSub(me, 'PREF'),
                            work: t.boolSub(me, 'WORK')
                        },
                        name: '_email',
                        namespace: me
                    }),
                    r = e.define({
                        element: 'TEL',
                        fields: {
                            home: t.boolSub(me, 'HOME'),
                            mobile: t.boolSub(me, 'CELL'),
                            number: t.textSub(me, 'NUMBER'),
                            preferred: t.boolSub(me, 'PREF'),
                            work: t.boolSub(me, 'WORK')
                        },
                        name: '_tel',
                        namespace: me
                    }),
                    s = e.define({
                        element: 'ADR',
                        fields: {
                            city: t.textSub(me, 'LOCALITY'),
                            country: t.textSub(me, 'CTRY'),
                            home: t.boolSub(me, 'HOME'),
                            pobox: t.textSub(me, 'POBOX'),
                            postalCode: t.textSub(me, 'PCODE'),
                            preferred: t.boolSub(me, 'PREF'),
                            region: t.textSub(me, 'REGION'),
                            street: t.textSub(me, 'STREET'),
                            street2: t.textSub(me, 'EXTADD'),
                            work: t.boolSub(me, 'WORK')
                        },
                        name: '_address',
                        namespace: me
                    }),
                    o = e.define({
                        element: 'ORG',
                        fields: { name: t.textSub(me, 'ORGNAME'), unit: t.textSub(me, 'ORGUNIT') },
                        name: 'organization',
                        namespace: me
                    }),
                    a = e.define({
                        element: 'N',
                        fields: {
                            family: t.textSub(me, 'FAMILY'),
                            given: t.textSub(me, 'GIVEN'),
                            middle: t.textSub(me, 'MIDDLE'),
                            prefix: t.textSub(me, 'PREFIX'),
                            suffix: t.textSub(me, 'SUFFIX')
                        },
                        name: 'name',
                        namespace: me
                    }),
                    u = e.define({
                        element: 'PHOTO',
                        fields: {
                            data: t.textSub(me, 'BINVAL'),
                            type: t.textSub(me, 'TYPE'),
                            url: t.textSub(me, 'EXTVAL')
                        },
                        name: 'photo',
                        namespace: me
                    });
                e.extend(n, i, 'emails'),
                    e.extend(n, s, 'addresses'),
                    e.extend(n, r, 'phoneNumbers'),
                    e.extend(n, o),
                    e.extend(n, a),
                    e.extend(n, u),
                    e.extendIQ(n);
            }
            function yi(e) {
                const t = e.define({
                    element: 'query',
                    fields: {
                        name: e.utils.textSub(ke, 'name'),
                        os: e.utils.textSub(ke, 'os'),
                        version: e.utils.textSub(ke, 'version')
                    },
                    name: 'version',
                    namespace: ke
                });
                e.extendIQ(t);
            }
            function vi(e) {
                e.withIQ(function(t) {
                    e.add(t, 'visible', e.utils.boolSub(We, 'visible')),
                        e.add(t, 'invisible', e.utils.boolSub(We, 'invisible'));
                });
            }
            function xi(e) {
                const t = e.utils,
                    n = {
                        get: function() {
                            const e = {},
                                n = t.find(this.xml, Nt, 'Property');
                            for (let i = 0, r = n.length; i < r; i++) {
                                const r = n[i];
                                e[t.getAttribute(r, 'type')] = r.textContent;
                            }
                            return e;
                        }
                    },
                    i = e.define({
                        element: 'XRD',
                        fields: {
                            aliases: t.multiSubText(Nt, 'Alias'),
                            expires: t.dateSub(Nt, 'Expires'),
                            properties: n,
                            subject: t.subText(Nt, 'Subject')
                        },
                        name: 'xrd',
                        namespace: Nt
                    }),
                    r = e.define({
                        element: 'Link',
                        fields: {
                            href: t.attribute('href'),
                            properties: n,
                            rel: t.attribute('rel'),
                            template: t.attribute('template'),
                            titles: t.subLangText(Nt, 'Title', 'default'),
                            type: t.attribute('type')
                        },
                        name: '_xrdlink',
                        namespace: Nt
                    });
                e.extend(i, r, 'links');
            }
            const wi = { client: G, component: Ce, server: H };
            function _i(e) {
                (e.extendMessage = function(e, t) {
                    this.withMessage(n => {
                        this.extend(n, e, t);
                    });
                }),
                    (e.extendPresence = function(e, t) {
                        this.withPresence(n => {
                            this.extend(n, e, t);
                        });
                    }),
                    (e.extendIQ = function(e, t) {
                        this.withIQ(n => {
                            this.extend(n, e, t);
                        });
                    }),
                    (e.extendStreamFeatures = function(e) {
                        this.withStreamFeatures(t => {
                            this.extend(t, e);
                        });
                    }),
                    (e.extendPubsubItem = function(e) {
                        this.withPubsubItem(t => {
                            this.extend(t, e);
                        });
                    }),
                    (e.withIQ = function(e) {
                        this.withDefinition('iq', G, e), this.withDefinition('iq', Ce, e);
                    }),
                    (e.withMessage = function(e) {
                        this.withDefinition('message', G, e), this.withDefinition('message', Ce, e);
                    }),
                    (e.withPresence = function(e) {
                        this.withDefinition('presence', G, e),
                            this.withDefinition('presence', Ce, e);
                    }),
                    (e.withStreamFeatures = function(e) {
                        this.withDefinition('features', V, e);
                    }),
                    (e.withStanzaError = function(e) {
                        this.withDefinition('error', G, e), this.withDefinition('error', Ce, e);
                    }),
                    (e.withDataForm = function(e) {
                        this.withDefinition('x', ie, e);
                    }),
                    (e.withPubsubItem = function(e) {
                        this.withDefinition('item', be, e), this.withDefinition('item', ve, e);
                    }),
                    (e.getMessage = function(e = 'client') {
                        return this.getDefinition('message', wi[e]);
                    }),
                    (e.getPresence = function(e = 'client') {
                        return this.getDefinition('presence', wi[e]);
                    }),
                    (e.getIQ = function(e = 'client') {
                        return this.getDefinition('iq', wi[e]);
                    }),
                    (e.getStreamError = function() {
                        return this.getDefinition('error', V);
                    }),
                    (e.getIq = e.getIQ),
                    (e.withIq = e.withIQ);
            }
            function Si(e) {
                const t = e.utils;
                (t.jidAttribute = function(e, n) {
                    return {
                        get: function() {
                            const i = new C(t.getAttribute(this.xml, e));
                            return n && (i.prepped = !0), i;
                        },
                        set: function(n) {
                            t.setAttribute(this.xml, e, (n || '').toString());
                        }
                    };
                }),
                    (t.jidSub = function(e, n, i) {
                        return {
                            get: function() {
                                const r = new C(t.getSubText(this.xml, e, n));
                                return i && (r.prepped = !0), r;
                            },
                            set: function(i) {
                                t.setSubText(this.xml, e, n, (i || '').toString());
                            }
                        };
                    }),
                    (t.tzoSub = t.field(
                        function(e, n, i, r) {
                            let s = -1,
                                o = t.getSubText(e, n, i);
                            if (!o) return r;
                            '-' === o.charAt(0) && ((s = 1), (o = o.slice(1)));
                            const a = o.split(':');
                            return (60 * parseInt(a[0], 10) + parseInt(a[1], 10)) * s;
                        },
                        function(e, n, i, r) {
                            let s,
                                o,
                                a = '-';
                            'number' == typeof r
                                ? (r < 0 && ((r = -r), (a = '+')),
                                  (a +=
                                      ((s = r / 60) < 10 ? '0' : '') +
                                      s +
                                      ':' +
                                      ((o = r % 60) < 10 ? '0' : '') +
                                      o))
                                : (a = r),
                                t.setSubText(e, n, i, a);
                        }
                    ));
            }
            function Ai(e) {
                e.use(Si),
                    e.use(_i),
                    e.use(qt),
                    e.use(Ft),
                    e.use(Ut),
                    e.use(zt),
                    e.use(Xt),
                    e.use(Qt),
                    e.use(Yt),
                    e.use(Gt),
                    e.use(Kt),
                    e.use(Wt),
                    e.use(Jt),
                    e.use(Zt),
                    e.use(en),
                    e.use(nn),
                    e.use(rn),
                    e.use(sn),
                    e.use(an),
                    e.use(cn),
                    e.use(ln),
                    e.use(fn),
                    e.use(dn),
                    e.use(hn),
                    e.use(pn),
                    e.use(bn),
                    e.use(yn),
                    e.use(vn),
                    e.use(wn),
                    e.use(_n),
                    e.use(En),
                    e.use(In),
                    e.use(jn),
                    e.use(kn),
                    e.use(Tn),
                    e.use(Rn),
                    e.use(On),
                    e.use(Mn),
                    e.use(Bn),
                    e.use(Dn),
                    e.use(Nn),
                    e.use(qn),
                    e.use(Un),
                    e.use(zn),
                    e.use(Qn),
                    e.use(Yn),
                    e.use($n),
                    e.use(Hn),
                    e.use(Kn),
                    e.use(Wn),
                    e.use(Vn),
                    e.use(Jn),
                    e.use(Zn),
                    e.use(ei),
                    e.use(ti),
                    e.use(ni),
                    e.use(si),
                    e.use(ai),
                    e.use(ui),
                    e.use(ci),
                    e.use(li),
                    e.use(fi),
                    e.use(hi),
                    e.use(pi),
                    e.use(mi),
                    e.use(gi),
                    e.use(bi),
                    e.use(yi),
                    e.use(vi),
                    e.use(xi);
            }
            const Ei = Math.pow(2, 32),
                Ii = (e, t) => ((e % t) + t) % t;
            class ji {
                constructor(e) {
                    (this.client = e),
                        (this.id = !1),
                        (this.allowResume = !0),
                        (this.started = !1),
                        (this.inboundStarted = !1),
                        (this.outboundStarted = !1),
                        (this.lastAck = 0),
                        (this.handled = 0),
                        (this.windowSize = 1),
                        (this.unacked = []),
                        (this.pendingAck = !1),
                        (this.stanzas = {
                            Ack: e.stanzas.getDefinition('a', Je),
                            Enable: e.stanzas.getDefinition('enable', Je),
                            Request: e.stanzas.getDefinition('r', Je),
                            Resume: e.stanzas.getDefinition('resume', Je)
                        });
                }
                get started() {
                    return this.outboundStarted && this.inboundStarted;
                }
                set started(e) {
                    e || ((this.outboundStarted = !1), (this.inboundStarted = !1));
                }
                enable() {
                    const e = new this.stanzas.Enable();
                    (e.resume = this.allowResume),
                        this.client.send(e),
                        (this.handled = 0),
                        (this.outboundStarted = !0);
                }
                resume() {
                    const e = new this.stanzas.Resume({ h: this.handled, previd: this.id });
                    this.client.send(e), (this.outboundStarted = !0);
                }
                enabled(e) {
                    (this.id = e.id), (this.handled = 0), (this.inboundStarted = !0);
                }
                resumed(e) {
                    (this.id = e.previd), e.h && this.process(e, !0), (this.inboundStarted = !0);
                }
                failed() {
                    (this.inboundStarted = !1),
                        (this.outboundStarted = !1),
                        (this.id = !1),
                        (this.lastAck = 0),
                        (this.handled = 0),
                        (this.unacked = []);
                }
                ack() {
                    this.client.send(new this.stanzas.Ack({ h: this.handled }));
                }
                request() {
                    (this.pendingAck = !0), this.client.send(new this.stanzas.Request());
                }
                process(e, t) {
                    const n = this,
                        i = Ii(e.h - this.lastAck, Ei);
                    this.pendingAck = !1;
                    for (let e = 0; e < i && this.unacked.length > 0; e++)
                        this.client.emit('stanza:acked', this.unacked.shift());
                    if (((this.lastAck = e.h), t)) {
                        const e = this.unacked;
                        this.unacked = [];
                        for (const t of e) n.client.send(t);
                    }
                    this.needAck() && this.request();
                }
                track(e) {
                    const t = e._name;
                    this.outboundStarted &&
                        { iq: !0, message: !0, presence: !0 }[t] &&
                        (this.unacked.push(e), this.needAck() && this.request());
                }
                handle() {
                    this.inboundStarted && (this.handled = Ii(this.handled + 1, Ei));
                }
                needAck() {
                    return !this.pendingAck && this.unacked.length >= this.windowSize;
                }
            }
            function ki(e, t) {
                return l.__awaiter(this, void 0, void 0, function*() {
                    'string' == typeof t && (t = { host: t });
                    const n = Object.assign({ json: !0, ssl: !0, xrd: !0 }, t),
                        i = n.ssl ? 'https://' : 'http://';
                    return (function(e) {
                        return l.__awaiter(this, void 0, void 0, function*() {
                            try {
                                const t = yield Promise.all(
                                    e.map(e =>
                                        e.then(e => Promise.reject(e), e => Promise.resolve(e))
                                    )
                                );
                                return Promise.reject(t);
                            } catch (e) {
                                return Promise.resolve(e);
                            }
                        });
                    })([
                        f.default(`${i}${n.host}/.well-known/host-meta.json`).then(e =>
                            l.__awaiter(this, void 0, void 0, function*() {
                                if (!e.ok) throw new Error('could-not-fetch-json');
                                return e.json();
                            })
                        ),
                        f.default(`${i}${n.host}/.well-known/host-meta`).then(t =>
                            l.__awaiter(this, void 0, void 0, function*() {
                                if (!t.ok) throw new Error('could-not-fetch-xml');
                                const n = yield t.text();
                                return e.parse(n);
                            })
                        )
                    ]);
                });
            }
            function Ti(e, t) {
                e.discoverBindings = function(e, n) {
                    ki(t, e)
                        .then(e => {
                            const t = { bosh: [], websocket: [] },
                                i = e.links || [];
                            for (const e of i)
                                e.href && e.rel === Ne && t.websocket.push(e.href),
                                    e.href && e.rel === qe && t.bosh.push(e.href);
                            n(null, t);
                        })
                        .catch(e => {
                            n(e, []);
                        });
                };
            }
            function Ci(e) {
                (e.features = { handlers: {}, negotiated: {}, order: [] }),
                    (e.registerFeature = function(t, n, i) {
                        this.features.order.push({ name: t, priority: n }),
                            this.features.order.sort(function(e, t) {
                                return e.priority < t.priority
                                    ? -1
                                    : e.priority > t.priority
                                    ? 1
                                    : 0;
                            }),
                            (this.features.handlers[t] = i.bind(e));
                    }),
                    e.on('streamFeatures', function(t) {
                        const n = [],
                            i = e.features.negotiated,
                            r = e.features.handlers;
                        for (const s of e.features.order) {
                            const e = s.name;
                            t[e] &&
                                r[e] &&
                                !i[e] &&
                                n.push(function(n) {
                                    i[e] ? n() : r[e](t, n);
                                });
                        }
                        d.series(n, function(t, n) {
                            'restart' === t
                                ? e.transport.restart()
                                : 'disconnect' === t &&
                                  (e.emit('stream:error', {
                                      condition: 'policy-violation',
                                      text: 'Failed to negotiate stream features: ' + n
                                  }),
                                  e.disconnect());
                        });
                    });
            }
            const Ri = 'urn:ietf:params:xml:ns:xmpp-sasl';
            function Pi(t, n) {
                const i = n.getDefinition('auth', Ri),
                    r = n.getDefinition('response', Ri),
                    s = n.getDefinition('abort', Ri);
                t.registerFeature('sasl', 100, function(t, n) {
                    const o = this,
                        a = o.SASLFactory.create(t.sasl.mechanisms);
                    if (!a)
                        return (
                            o.releaseGroup('sasl'),
                            o.emit('auth:failed'),
                            n('disconnect', 'authentication failed')
                        );
                    o.on('sasl:success', 'sasl', function() {
                        (o.features.negotiated.sasl = !0),
                            o.releaseGroup('sasl'),
                            o.emit('auth:success', o.config.credentials),
                            n('restart');
                    }),
                        o.on('sasl:challenge', 'sasl', function(t) {
                            return (
                                a.challenge(e.from(t.value, 'base64').toString()),
                                o.getCredentials(function(t, n) {
                                    if (t) return o.send(new s());
                                    const i = a.response(n);
                                    if (
                                        (i || '' === i
                                            ? o.send(new r({ value: e.from(i).toString('base64') }))
                                            : o.send(new r()),
                                        a.cache)
                                    ) {
                                        for (const t of Object.keys(a.cache)) {
                                            if (!a.cache[t]) return;
                                            o.config.credentials[t] = e.from(a.cache[t]);
                                        }
                                        o.emit('credentials:update', o.config.credentials);
                                    }
                                })
                            );
                        }),
                        o.on('sasl:failure', 'sasl', function() {
                            o.releaseGroup('sasl'),
                                o.emit('auth:failed'),
                                n('disconnect', 'authentication failed');
                        }),
                        o.on('sasl:abort', 'sasl', function() {
                            o.releaseGroup('sasl'),
                                o.emit('auth:failed'),
                                n('disconnect', 'authentication failed');
                        });
                    const u = { mechanism: a.name };
                    if (a.clientFirst)
                        return o.getCredentials(function(t, n) {
                            if (t) return o.send(new s());
                            (u.value = e.from(a.response(n)).toString('base64')), o.send(new i(u));
                        });
                    o.send(new i(u));
                }),
                    t.on('disconnected', function() {
                        (t.features.negotiated.sasl = !1), t.releaseGroup('sasl');
                    });
            }
            function Oi(e, t, n) {
                const i = function(e, t) {
                    const i = this;
                    if (!n.useStreamManagement) return t();
                    i.on('stream:management:enabled', 'sm', function(e) {
                        i.sm.enabled(e),
                            (i.features.negotiated.streamManagement = !0),
                            i.releaseGroup('sm'),
                            t();
                    }),
                        i.on('stream:management:resumed', 'sm', function(e) {
                            i.sm.resumed(e),
                                (i.features.negotiated.streamManagement = !0),
                                (i.features.negotiated.bind = !0),
                                (i.sessionStarted = !0),
                                i.releaseGroup('sm'),
                                t('break');
                        }),
                        i.on('stream:management:failed', 'sm', function() {
                            i.sm.failed(),
                                i.emit('session:end'),
                                i.releaseGroup('session'),
                                i.releaseGroup('sm'),
                                t();
                        }),
                        i.sm.id
                            ? i.sm.id && i.sm.allowResume
                                ? i.sm.resume()
                                : (i.releaseGroup('sm'), t())
                            : i.features.negotiated.bind
                            ? i.sm.enable()
                            : (i.releaseGroup('sm'), t());
                };
                e.on('disconnected', function() {
                    e.features.negotiated.streamManagement = !1;
                }),
                    e.registerFeature('streamManagement', 200, i),
                    e.registerFeature('streamManagement', 500, i);
            }
            function Li(e, t, n) {
                e.registerFeature('bind', 300, function(t, i) {
                    e.sendIq({ bind: { resource: n.resource }, type: 'set' }, function(n, r) {
                        if (n)
                            return (
                                e.emit('session:error', n), i('disconnect', 'JID binding failed')
                            );
                        (e.features.negotiated.bind = !0), e.emit('session:prebind', r.bind.jid);
                        const s = !t.session || (t.session && t.session.optional);
                        return !e.sessionStarted && s && e.emit('session:started', e.jid), i();
                    });
                }),
                    e.on('session:started', function() {
                        e.sessionStarted = !0;
                    }),
                    e.on('session:prebind', function(t) {
                        (e.jid = new C(t)), e.emit('session:bound', e.jid);
                    }),
                    e.on('disconnected', function() {
                        (e.sessionStarted = !1), (e.features.negotiated.bind = !1);
                    });
            }
            function Mi(e) {
                e.registerFeature('session', 1e3, function(e, t) {
                    const n = this;
                    if (e.session.optional || n.sessionStarted)
                        return (n.features.negotiated.session = !0), t();
                    n.sendIq({ session: {}, type: 'set' }, function(e) {
                        if (e) return t('disconnect', 'session request failed');
                        (n.features.negotiated.session = !0),
                            n.sessionStarted ||
                                ((n.sessionStarted = !0), n.emit('session:started', n.jid)),
                            t();
                    });
                }),
                    e.on('disconnected', function() {
                        (e.sessionStarted = !1), (e.features.negotiated.session = !1);
                    });
            }
            let Bi = n(81);
            'function' != typeof Bi && (Bi = window.WebSocket);
            const Di = 1;
            class Ni extends u.default {
                constructor(t, n) {
                    super();
                    const i = this;
                    (i.sm = t),
                        (i.closing = !1),
                        (i.stanzas = {
                            Close: n.getDefinition(
                                'close',
                                'urn:ietf:params:xml:ns:xmpp-framing',
                                !0
                            ),
                            Open: n.getDefinition(
                                'open',
                                'urn:ietf:params:xml:ns:xmpp-framing',
                                !0
                            ),
                            StreamError: n.getStreamError()
                        }),
                        (i.sendQueue = d.queue(function(t, n) {
                            i.conn &&
                                ('string' != typeof t && (t = t.toString()),
                                (t = e.from(t, 'utf8').toString()),
                                i.emit('raw:outgoing', t),
                                i.conn.readyState === Di && i.conn.send(t)),
                                n();
                        }, 1)),
                        i.on('connected', function() {
                            i.send(i.startHeader());
                        }),
                        i.on('raw:incoming', function(e) {
                            let t, r;
                            if ('' !== (e = e.trim())) {
                                try {
                                    t = n.parse(e);
                                } catch (e) {
                                    return (
                                        (r = new i.stanzas.StreamError({
                                            condition: 'invalid-xml'
                                        })),
                                        i.emit('stream:error', r, e),
                                        i.send(r),
                                        i.disconnect()
                                    );
                                }
                                if (t) {
                                    if ('openStream' === t._name)
                                        return (
                                            (i.hasStream = !0),
                                            (i.stream = t),
                                            i.emit('stream:start', t.toJSON())
                                        );
                                    if ('closeStream' === t._name)
                                        return i.emit('stream:end'), i.disconnect();
                                    !t.lang && i.stream && (t.lang = i.stream.lang),
                                        i.emit('stream:data', t);
                                }
                            }
                        });
                }
                connect(t) {
                    const n = this;
                    (n.config = t),
                        (n.hasStream = !1),
                        (n.closing = !1),
                        (n.conn = new Bi(t.wsURL, 'xmpp', t.wsOptions)),
                        (n.conn.onerror = function(e) {
                            e.preventDefault && e.preventDefault(), n.emit('disconnected', n);
                        }),
                        (n.conn.onclose = function() {
                            n.emit('disconnected', n);
                        }),
                        (n.conn.onopen = function() {
                            (n.sm.started = !1), n.emit('connected', n);
                        }),
                        (n.conn.onmessage = function(t) {
                            n.emit('raw:incoming', e.from(t.data, 'utf8').toString());
                        });
                }
                startHeader() {
                    return new this.stanzas.Open({
                        lang: this.config.lang || 'en',
                        to: this.config.server,
                        version: this.config.version || '1.0'
                    });
                }
                closeHeader() {
                    return new this.stanzas.Close();
                }
                disconnect() {
                    this.conn && !this.closing && this.hasStream
                        ? ((this.closing = !0), this.send(this.closeHeader()))
                        : ((this.hasStream = !1),
                          (this.stream = void 0),
                          this.conn && this.conn.readyState === Di && this.conn.close(),
                          (this.conn = void 0));
                }
                restart() {
                    (this.hasStream = !1), this.send(this.startHeader());
                }
                send(e) {
                    this.sendQueue.push(e);
                }
            }
            function qi(e, t, n, i) {
                return l.__awaiter(this, void 0, void 0, function*() {
                    try {
                        const o = yield ((r = f.default(e, t)),
                        (s = 1e3 * n),
                        new Promise((e, t) => {
                            const n = setTimeout(t, s, new Error('Request timed out'));
                            r.then(t => {
                                clearTimeout(n), e(t);
                            }, t);
                        }));
                        if (!o.ok) throw new Error('HTTP Status Error: ' + o.status);
                        return o.text();
                    } catch (r) {
                        if (i > 0) return qi(e, t, n, i - 1);
                        throw r;
                    }
                    var r, s;
                });
            }
            class Fi extends u.default {
                constructor(e, t) {
                    super();
                    const n = this;
                    (n.sm = e),
                        (n.stanzas = {
                            BOSH: t.getDefinition('body', Le),
                            StreamError: t.getStreamError()
                        }),
                        (n.sendQueue = []),
                        (n.requests = []),
                        (n.maxRequests = void 0),
                        (n.sid = ''),
                        (n.authenticated = !1),
                        n.on('raw:incoming', function(e) {
                            if ('' === (e = e.trim())) return;
                            let i, r;
                            try {
                                i = t.parse(e, n.stanzas.BOSH);
                            } catch (e) {
                                return (
                                    (r = new n.stanzas.StreamError({ condition: 'invalid-xml' })),
                                    n.emit('stream:error', r, e),
                                    n.send(r),
                                    n.disconnect()
                                );
                            }
                            n.hasStream ||
                                ((n.hasStream = !0),
                                (n.stream = {
                                    from: i.from,
                                    id: i.sid || n.sid,
                                    lang: i.lang || 'en',
                                    to: i.to,
                                    version: i.version || '1.0'
                                }),
                                (n.sid = i.sid || n.sid),
                                (n.maxRequests = i.requests || n.maxRequests));
                            const s = i.payload;
                            for (const e of s)
                                e.lang || (e.lang = n.stream.lang), n.emit('stream:data', e);
                            'terminate' === i.type &&
                                ((n.rid = void 0),
                                (n.sid = void 0),
                                n.emit('bosh:terminate', i),
                                n.emit('stream:end'),
                                n.emit('disconnected', n));
                        });
                }
                connect(e) {
                    const t = this;
                    if (
                        ((t.config = Object.assign(
                            { maxRetries: 5, rid: Math.ceil(9999999999 * Math.random()), wait: 30 },
                            e
                        )),
                        (t.hasStream = !1),
                        (t.sm.started = !1),
                        (t.url = e.boshURL),
                        (t.sid = t.config.sid),
                        (t.rid = t.config.rid),
                        (t.requests = []),
                        t.sid)
                    )
                        return (
                            (t.hasStream = !0),
                            (t.stream = {}),
                            t.emit('connected', t),
                            t.emit('session:prebind', t.config.jid),
                            void t.emit('session:started')
                        );
                    t.rid++,
                        t.request(
                            new t.stanzas.BOSH({
                                hold: 1,
                                lang: t.config.lang || 'en',
                                to: t.config.server,
                                ver: '1.6',
                                version: t.config.version || '1.0',
                                wait: t.config.wait
                            })
                        );
                }
                disconnect() {
                    this.hasStream
                        ? (this.rid++, this.request(new this.stanzas.BOSH({ type: 'terminate' })))
                        : ((this.stream = void 0),
                          (this.sid = void 0),
                          (this.rid = void 0),
                          this.emit('disconnected', this));
                }
                restart() {
                    this.rid++,
                        this.request(
                            new this.stanzas.BOSH({
                                lang: this.config.lang || 'en',
                                restart: 'true',
                                to: this.config.server
                            })
                        );
                }
                send(e) {
                    const t = this;
                    t.hasStream && (t.sendQueue.push(e), i.nextTick(t.longPoll.bind(t)));
                }
                longPoll() {
                    const e = !this.maxRequests || this.requests.length < this.maxRequests,
                        t =
                            !this.maxRequests ||
                            (this.sendQueue.length > 0 && this.requests.length < this.maxRequests);
                    if (!this.sid || (!e && !t)) return;
                    const n = this.sendQueue;
                    (this.sendQueue = []),
                        this.rid++,
                        this.request(new this.stanzas.BOSH({ payload: n }));
                }
                request(t) {
                    const n = this,
                        i = { id: n.rid, request: null };
                    (t.rid = n.rid), (t.sid = n.sid);
                    const r = e.from(t.toString(), 'utf8').toString();
                    n.emit('raw:outgoing', r),
                        n.emit('raw:outgoing:' + i.id, r),
                        n.requests.push(i);
                    const s = qi(
                        n.url,
                        { body: r, headers: { 'Content-Type': 'text/xml' }, method: 'POST' },
                        1.5 * n.config.wait,
                        this.config.maxRetries
                    )
                        .catch(function(e) {
                            console.log(e), (n.hasStream = !1);
                            const t = new n.stanzas.StreamError({
                                condition: 'connection-timeout'
                            });
                            n.emit('stream:error', t, e), n.disconnect();
                        })
                        .then(function(r) {
                            (n.requests = n.requests.filter(e => e.id !== i.id)),
                                r &&
                                    ((r = e.from(r, 'utf8').toString()),
                                    n.emit('raw:incoming', r),
                                    n.emit('raw:incoming:' + i.id, r)),
                                n.hasStream &&
                                    'terminate' !== t.type &&
                                    !n.requests.length &&
                                    n.authenticated &&
                                    setTimeout(() => {
                                        n.longPoll();
                                    }, 30);
                        });
                    return (i.request = s), s;
                }
            }
            const Ui = {
                anonymous: P,
                'digest-md5': B,
                external: O,
                plain: L,
                'scram-sha-1': z,
                'x-oauth2': X
            };
            class zi extends u.default {
                constructor(e) {
                    super(),
                        (e = e || {}),
                        this._initConfig(e),
                        (this.jid = new C()),
                        (this.stanzas = a.default.createRegistry()),
                        this.stanzas.use(Ai),
                        this.use(Ti),
                        this.use(Ci),
                        this.use(Pi),
                        this.use(Oi),
                        this.use(Li),
                        this.use(Mi),
                        (this.sm = new ji(this)),
                        (this.transports = { bosh: Fi, websocket: Ni }),
                        this.on('stream:data', e => {
                            const t = e ? e.toJSON() : null;
                            if (t) {
                                if ('iq' === e._name) {
                                    t._xmlChildCount = 0;
                                    for (const n of e.xml.childNodes || [])
                                        1 === n.nodeType && (t._xmlChildCount += 1);
                                }
                                if (
                                    (this.emit(e._eventname || e._name, t),
                                    'message' === e._name ||
                                        'presence' === e._name ||
                                        'iq' === e._name)
                                )
                                    this.sm.handle(t), this.emit('stanza', t);
                                else {
                                    if ('smAck' === e._name) return this.sm.process(t);
                                    if ('smRequest' === e._name) return this.sm.ack();
                                }
                                t.id &&
                                    (this.emit('id:' + t.id, t),
                                    this.emit(e._name + ':id:' + t.id, t));
                            }
                        }),
                        this.on('disconnected', () => {
                            this.transport && (this.transport.off('*'), delete this.transport),
                                this.releaseGroup('connection');
                        }),
                        this.on('auth:success', () => {
                            this.transport && (this.transport.authenticated = !0);
                        }),
                        this.on('iq', e => {
                            const t = e.type,
                                n = e._xmlChildCount;
                            delete e._xmlChildCount;
                            const i = Object.keys(e).filter(function(e) {
                                return (
                                    'id' !== e &&
                                    'to' !== e &&
                                    'from' !== e &&
                                    'lang' !== e &&
                                    'type' !== e &&
                                    'errorReply' !== e &&
                                    'resultReply' !== e
                                );
                            });
                            if ('get' === e.type || 'set' === e.type) {
                                if (1 !== n)
                                    return this.sendIq(
                                        e.errorReply({
                                            error: { condition: 'bad-request', type: 'modify' }
                                        })
                                    );
                                if (!i.length)
                                    return this.sendIq(
                                        e.errorReply({
                                            error: {
                                                condition: 'service-unavailable',
                                                type: 'cancel'
                                            }
                                        })
                                    );
                                const r = 'iq:' + t + ':' + i[0];
                                this.callbacks[r]
                                    ? this.emit(r, e)
                                    : this.sendIq(
                                          e.errorReply({
                                              error: {
                                                  condition: 'service-unavailable',
                                                  type: 'cancel'
                                              }
                                          })
                                      );
                            }
                        }),
                        this.on('message', e => {
                            !Object.keys(e.$body || {}).length ||
                                e.received ||
                                e.displayed ||
                                ('chat' === e.type || 'normal' === e.type
                                    ? this.emit('chat', e)
                                    : 'groupchat' === e.type && this.emit('groupchat', e)),
                                'error' === e.type && this.emit('message:error', e);
                        }),
                        this.on('presence', e => {
                            let t = e.type || 'available';
                            'error' === t && (t = 'presence:error'), this.emit(t, e);
                        });
                }
                get stream() {
                    return this.transport ? this.transport.stream : void 0;
                }
                _initConfig(e) {
                    const t = this.config || {};
                    (this.config = Object.assign(
                        {
                            sasl: ['external', 'scram-sha-1', 'digest-md5', 'plain', 'anonymous'],
                            transports: ['websocket', 'bosh'],
                            useStreamManagement: !0
                        },
                        t,
                        e
                    )),
                        Array.isArray(this.config.sasl) || (this.config.sasl = [this.config.sasl]),
                        (this.SASLFactory = new Q());
                    for (const e of this.config.sasl)
                        if ('string' == typeof e) {
                            const t = Ui[e.toLowerCase()];
                            t && t.prototype && t.prototype.name && this.SASLFactory.use(t);
                        } else this.SASLFactory.use(e);
                    (this.config.jid = new C(this.config.jid)),
                        this.config.server || (this.config.server = this.config.jid.domain),
                        this.config.password &&
                            ((this.config.credentials = this.config.credentials || {}),
                            (this.config.credentials.password = this.config.password),
                            delete this.config.password),
                        this.config.transport && (this.config.transports = [this.config.transport]),
                        Array.isArray(this.config.transports) ||
                            (this.config.transports = [this.config.transports]);
                }
                use(e) {
                    'function' == typeof e && e(this, this.stanzas, this.config);
                }
                nextId() {
                    return o.v4();
                }
                _getConfiguredCredentials() {
                    const e = this.config.credentials || {},
                        t = new C(this.config.jid),
                        n = e.username || t.local,
                        i = e.server || t.domain;
                    return Object.assign(
                        {
                            host: i,
                            password: this.config.password,
                            realm: i,
                            server: i,
                            serviceName: i,
                            serviceType: 'xmpp',
                            username: n
                        },
                        e
                    );
                }
                getCredentials(e) {
                    return e(null, this._getConfiguredCredentials());
                }
                connect(e, t) {
                    if (
                        (this._initConfig(e),
                        t ||
                            1 !== this.config.transports.length ||
                            ((t = {}).name = this.config.transports[0]),
                        t && t.name)
                    ) {
                        const e = (this.transport = new this.transports[t.name](
                            this.sm,
                            this.stanzas
                        ));
                        return (
                            e.on('*', (e, t) => {
                                this.emit(e, t);
                            }),
                            e.connect(this.config)
                        );
                    }
                    return this.discoverBindings(this.config.server, (e, t) => {
                        if (e)
                            return (
                                console.error(
                                    'Could not find https://' +
                                        this.config.server +
                                        '/.well-known/host-meta file to discover connection endpoints for the requested transports.'
                                ),
                                this.disconnect()
                            );
                        for (let e = 0, n = this.config.transports.length; e < n; e++) {
                            const n = this.config.transports[e];
                            console.log('Checking for %s endpoints', n);
                            for (let e = 0, i = (t[n] || []).length; e < i; e++) {
                                const i = t[n][e];
                                if (0 === i.indexOf('wss://') || 0 === i.indexOf('https://'))
                                    return (
                                        'websocket' === n
                                            ? (this.config.wsURL = i)
                                            : (this.config.boshURL = i),
                                        console.log('Using %s endpoint: %s', n, i),
                                        this.connect(null, { name: n, url: i })
                                    );
                                console.warn(
                                    'Discovered unencrypted %s endpoint (%s). Ignoring',
                                    n,
                                    i
                                );
                            }
                        }
                        return (
                            console.error('No endpoints found for the requested transports.'),
                            this.disconnect()
                        );
                    });
                }
                disconnect() {
                    this.sessionStarted &&
                        (this.releaseGroup('session'), this.sm.started || this.emit('session:end')),
                        (this.sessionStarted = !1),
                        this.releaseGroup('connection'),
                        this.transport ? this.transport.disconnect() : this.emit('disconnected');
                }
                send(e) {
                    this.sm.track(e), this.transport && this.transport.send(e);
                }
                sendMessage(e) {
                    (e = e || {}).id || (e.id = this.nextId());
                    const t = new (this.stanzas.getMessage())(e);
                    return this.emit('message:sent', t.toJSON()), this.send(t), e.id;
                }
                sendPresence(e) {
                    (e = e || {}).id || (e.id = this.nextId());
                    const t = this.stanzas.getPresence();
                    return this.send(new t(e)), e.id;
                }
                sendIq(e, t) {
                    (e = e || {}).id || (e.id = this.nextId());
                    const n = this.stanzas.getIq(),
                        i = e.toJSON ? e : new n(e);
                    if ('error' === e.type || 'result' === e.type) return void this.send(i);
                    const r = new C(e.to),
                        s = { '': !0 };
                    (s[r.full] = !0),
                        (s[r.bare] = !0),
                        (s[r.domain] = !0),
                        (s[this.jid.bare] = !0),
                        (s[this.jid.domain] = !0);
                    const o = 'iq:id:' + e.id,
                        a = new Promise((e, t) => {
                            const n = i => {
                                s[i.from.full] &&
                                    (('result' !== i.type && 'error' !== i.type) ||
                                        (this.off(o, n), i.error ? t(i) : e(i)));
                            };
                            this.on(o, 'session', n);
                        });
                    return (
                        this.send(i),
                        (function(e, t, n) {
                            let i;
                            return Promise.race([
                                e,
                                new Promise(function(e, r) {
                                    i = setTimeout(function() {
                                        r({
                                            error: { condition: 'timeout' },
                                            id: t,
                                            type: 'error'
                                        });
                                    }, n);
                                })
                            ]).then(function(e) {
                                return clearTimeout(i), e;
                            });
                        })(a, e.id, 1e3 * (this.config.timeout || 15)).then(
                            function(e) {
                                return t && t(null, e), e;
                            },
                            function(e) {
                                if (t) return t(e);
                                throw e;
                            }
                        )
                    );
                }
                sendStreamError(e) {
                    e = e || {};
                    const t = new (this.stanzas.getStreamError())(e);
                    this.emit('stream:error', t.toJSON()), this.send(t), this.disconnect();
                }
            }
            function Xi(t, n) {
                let i = '',
                    r = t.features || [],
                    s = [];
                const o = t.extensions || [],
                    a = {},
                    u = [];
                for (const e of t.identities || [])
                    s.push([e.category || '', e.type || '', e.lang || '', e.name || ''].join('/'));
                const l = s.length,
                    f = r.length;
                if (
                    ((s = [...new Set(s)].sort()),
                    f !== (r = [...new Set(r)].sort()).length || l !== s.length)
                )
                    return !1;
                (i += s.join('<') + '<'), (i += r.join('<') + '<');
                let d = !1;
                for (const e of o) {
                    const t = e.fields;
                    for (let n = 0, i = t.length; n < i; n++)
                        if ('FORM_TYPE' === t[n].name && 'hidden' === t[n].type) {
                            const i = t[n].value;
                            return a[i] ? void (d = !0) : ((a[i] = e), void u.push(i));
                        }
                }
                if (d) return !1;
                u.sort();
                for (const e of u) {
                    const t = a[e],
                        n = {},
                        r = [];
                    i += '<' + e;
                    for (const e of t.fields) {
                        const t = e.name;
                        if ('FORM_TYPE' !== t) {
                            let i = e.value || '';
                            'object' != typeof i && (i = i.split('\n')),
                                (n[t] = i.sort()),
                                r.push(t);
                        }
                    }
                    r.sort();
                    for (const e of r) {
                        i += '<' + e;
                        for (const t of n[e]) i += '<' + t;
                    }
                }
                let h = c
                        .createHash(n)
                        .update(e.from(i, 'utf8'))
                        .digest('base64'),
                    p = 4 - (h.length % 4);
                4 === p && (p = 0);
                for (let e = 0; e < p; e++) h += '=';
                return h;
            }
            function Qi(e, t, n) {
                const i = Xi(e, t);
                return i && i === n;
            }
            t.Client = zi;
            class Yi {
                constructor() {
                    (this.features = {}),
                        (this.identities = {}),
                        (this.extensions = {}),
                        (this.items = {}),
                        (this.caps = {});
                }
                addFeature(e, t) {
                    (t = t || ''),
                        this.features[t] || (this.features[t] = []),
                        this.features[t].push(e);
                }
                addIdentity(e, t) {
                    (t = t || ''),
                        this.identities[t] || (this.identities[t] = []),
                        this.identities[t].push(e);
                }
                addItem(e, t) {
                    (t = t || ''), this.items[t] || (this.items[t] = []), this.items[t].push(e);
                }
                addExtension(e, t) {
                    (t = t || ''),
                        this.extensions[t] || (this.extensions[t] = []),
                        this.extensions[t].push(e);
                }
            }
            function Gi(e) {
                (e.disco = new Yi(e)),
                    e.disco.addFeature(re),
                    e.disco.addFeature(se),
                    e.disco.addIdentity({ category: 'client', type: 'web' }),
                    e.registerFeature('caps', 100, function(t, n) {
                        this.emit('disco:caps', {
                            caps: t.caps,
                            from: new C(e.jid.domain || e.config.server)
                        }),
                            (this.features.negotiated.caps = !0),
                            n();
                    }),
                    (e.getDiscoInfo = function(e, t, n) {
                        return this.sendIq({ discoInfo: { node: t }, to: e, type: 'get' }, n);
                    }),
                    (e.getDiscoItems = function(e, t, n) {
                        return this.sendIq({ discoItems: { node: t }, to: e, type: 'get' }, n);
                    }),
                    (e.updateCaps = function() {
                        let t = this.config.capsNode || 'https://stanza.io';
                        const n = JSON.parse(
                                JSON.stringify({
                                    extensions: this.disco.extensions[''],
                                    features: this.disco.features[''],
                                    identities: this.disco.identities['']
                                })
                            ),
                            i = Xi(n, 'sha-1');
                        return (
                            (this.disco.caps = { hash: 'sha-1', node: t, ver: i }),
                            (t = t + '#' + i),
                            (this.disco.features[t] = n.features),
                            (this.disco.identities[t] = n.identities),
                            (this.disco.extensions[t] = n.extensions),
                            e.getCurrentCaps()
                        );
                    }),
                    (e.getCurrentCaps = function() {
                        const t = e.disco.caps;
                        if (!t.ver) return { ver: null, discoInfo: null };
                        const n = t.node + '#' + t.ver;
                        return {
                            discoInfo: {
                                extensions: e.disco.extensions[n],
                                features: e.disco.features[n],
                                identities: e.disco.identities[n]
                            },
                            ver: t.ver
                        };
                    }),
                    e.on('presence', function(t) {
                        t.caps && e.emit('disco:caps', t);
                    }),
                    e.on('iq:get:discoInfo', function(t) {
                        let n = t.discoInfo.node || '',
                            i = t.discoInfo.node || '';
                        n === e.disco.caps.node + '#' + e.disco.caps.ver && ((i = n), (n = '')),
                            e.sendIq(
                                t.resultReply({
                                    discoInfo: {
                                        extensions: e.disco.extensions[n] || [],
                                        features: e.disco.features[n] || [],
                                        identities: e.disco.identities[n] || [],
                                        node: i
                                    }
                                })
                            );
                    }),
                    e.on('iq:get:discoItems', function(t) {
                        const n = t.discoItems.node;
                        e.sendIq(
                            t.resultReply({
                                discoItems: { items: e.disco.items[n] || [], node: n }
                            })
                        );
                    }),
                    (e.verifyVerString = Qi),
                    (e.generateVerString = Xi),
                    e.updateCaps();
            }
            function $i(e) {
                e.disco.addFeature('jid\\20escaping'),
                    e.disco.addFeature(tt),
                    e.disco.addFeature(Bt),
                    e.disco.addFeature(pt),
                    e.disco.addFeature(mt),
                    e.disco.addFeature(St),
                    e.disco.addFeature(kt),
                    e.disco.addFeature(_e),
                    e.disco.addFeature(xt),
                    e.disco.addFeature(Mt),
                    e.disco.addFeature(Me),
                    e.disco.addFeature(`${Me}#SubID`, Me);
                const t = c.getHashes();
                for (const n of t) e.disco.addFeature(gt(n));
            }
            function Hi(e) {
                e.disco.addFeature(st),
                    (e.getAttention = function(t, n) {
                        ((n = n || {}).to = t),
                            (n.type = 'headline'),
                            (n.attention = !0),
                            e.sendMessage(n);
                    }),
                    e.on('message', function(t) {
                        t.attention && e.emit('attention', t);
                    });
            }
            function Ki(e) {
                e.disco.addFeature(Fe(Ie)),
                    e.on('pubsub:event', function(t) {
                        t.event.updated &&
                            t.event.updated.node === Ie &&
                            e.emit('avatar', {
                                avatars: t.event.updated.published[0].avatars,
                                jid: t.from,
                                source: 'pubsub'
                            });
                    }),
                    e.on('presence', function(t) {
                        t.avatarId &&
                            e.emit('avatar', {
                                avatars: [{ id: t.avatarId }],
                                jid: t.from,
                                source: 'vcard'
                            });
                    }),
                    (e.publishAvatar = function(e, t, n) {
                        return this.publish('', Ee, { avatarData: t, id: e }, n);
                    }),
                    (e.useAvatars = function(e, t) {
                        return this.publish('', Ie, { avatars: e, id: 'current' }, t);
                    }),
                    (e.getAvatar = function(e, t, n) {
                        return this.getItem(e, Ee, t, n);
                    });
            }
            function Wi(e) {
                e.disco.addFeature(Ve),
                    (e.block = function(t, n) {
                        return e.sendIq({ block: { jids: [t] }, type: 'set' }, n);
                    }),
                    (e.unblock = function(t, n) {
                        return e.sendIq({ type: 'set', unblock: { jids: [t] } }, n);
                    }),
                    (e.getBlocked = function(t) {
                        return e.sendIq({ blockList: !0, type: 'get' }, t);
                    }),
                    e.on('iq:set:block', function(t) {
                        e.emit('block', { jids: t.block.jids || [] }), e.sendIq(t.resultReply());
                    }),
                    e.on('iq:set:unblock', function(t) {
                        e.emit('unblock', { jids: t.unblock.jids || [] }),
                            e.sendIq(t.resultReply());
                    });
            }
            function Vi(e) {
                e.disco.addFeature(ot),
                    (e.getBits = function(t, n, i) {
                        return e.sendIq({ bob: { cid: n }, to: t, type: 'get' }, i);
                    });
            }
            function Ji(e) {
                (e.getBookmarks = function(e) {
                    return this.getPrivateData({ bookmarks: !0 }, e);
                }),
                    (e.setBookmarks = function(e, t) {
                        return this.setPrivateData({ bookmarks: e }, t);
                    }),
                    (e.addBookmark = function(t, n) {
                        return (
                            (t.jid = new C(t.jid)),
                            this.getBookmarks()
                                .then(function(n) {
                                    const i = n.privateStorage.bookmarks.conferences || [];
                                    let r = !1;
                                    for (let e = 0; e < i.length; e++) {
                                        const n = i[e];
                                        if (n.jid.bare === t.jid.bare) {
                                            (i[e] = Object.assign({}, n, t)), (r = !0);
                                            break;
                                        }
                                    }
                                    return r || i.push(t), e.setBookmarks({ conferences: i });
                                })
                                .then(
                                    function(e) {
                                        return n && n(null, e), e;
                                    },
                                    function(e) {
                                        if (!n) throw e;
                                        n(e);
                                    }
                                )
                        );
                    }),
                    (e.removeBookmark = function(t, n) {
                        return (
                            (t = new C(t)),
                            this.getBookmarks()
                                .then(function(n) {
                                    let i = n.privateStorage.bookmarks.conferences || [];
                                    return (
                                        (i = i.filter(e => t.bare !== e.jid.bare)),
                                        e.setBookmarks({ conferences: i })
                                    );
                                })
                                .then(
                                    function(e) {
                                        n && n(null, e);
                                    },
                                    function(e) {
                                        if (!n) throw e;
                                        n(e);
                                    }
                                )
                        );
                    });
            }
            function Zi(e) {
                e.disco.addFeature(ft),
                    (e.enableCarbons = function(e) {
                        return this.sendIq({ enableCarbons: !0, type: 'set' }, e);
                    }),
                    (e.disableCarbons = function(e) {
                        return this.sendIq({ disableCarbons: !0, type: 'set' }, e);
                    }),
                    e.on('message', function(t) {
                        return t.carbonSent
                            ? e.emit('carbon:sent', t)
                            : t.carbonReceived
                            ? e.emit('carbon:received', t)
                            : void 0;
                    }),
                    e.on('carbon:*', function(t, n) {
                        const i = t.split(':')[1];
                        if (n.from.bare !== e.jid.bare) return;
                        let r, s;
                        'received' === i
                            ? ((r = n.carbonReceived.forwarded.message),
                              (s = n.carbonReceived.forwarded.delay))
                            : ((r = n.carbonSent.forwarded.message),
                              (s = n.carbonSent.forwarded.delay)),
                            r.delay || (r.delay = { stamp: s ? s.stamp : new Date(Date.now()) }),
                            (r.carbon = !0),
                            r.from.bare === e.jid.bare
                                ? e.emit('message:sent', r)
                                : e.emit('message', r);
                    });
            }
            function er(e) {
                e.disco.addFeature(je);
                const t = ['chat', 'groupchat', 'normal'];
                e.on('message', function(n) {
                    t.indexOf(n.type || 'normal') < 0 ||
                        (n.chatState &&
                            (e.emit('chat:state', {
                                chatState: n.chatState,
                                from: n.from,
                                to: n.to
                            }),
                            e.emit('chatState', {
                                chatState: n.chatState,
                                from: n.from,
                                to: n.to
                            })));
                });
            }
            function tr(e) {
                e.disco.addFeature(pe),
                    e.disco.addItem({ name: 'Ad-Hoc Commands', node: pe }),
                    (e.getCommands = function(t, n) {
                        return e.getDiscoItems(t, pe, n);
                    });
            }
            function nr(e) {
                e.disco.addFeature(vt),
                    e.on('message', function(t) {
                        t.replace && (e.emit('replace', t), e.emit('replace:' + t.id, t));
                    });
            }
            function ir(e, t) {
                const n = t.getDefinition('active', Ot),
                    i = t.getDefinition('inactive', Ot);
                e.registerFeature('clientStateIndication', 400, function(e, t) {
                    (this.features.negotiated.clientStateIndication = !0), t();
                }),
                    (e.markActive = function() {
                        this.features.negotiated.clientStateIndication && this.send(new n());
                    }),
                    (e.markInactive = function() {
                        this.features.negotiated.clientStateIndication && this.send(new i());
                    });
            }
            function rr(e) {
                e.disco.addFeature(ie),
                    e.disco.addFeature(rt),
                    e.disco.addFeature(Oe),
                    e.disco.addFeature(Be),
                    e.on('message', function(t) {
                        t.form && e.emit('dataform', t);
                    });
            }
            function sr(e) {
                e.disco.addFeature(it),
                    (e.getServices = function(e, t, n) {
                        return this.sendIq({ services: { type: t }, to: e, type: 'get' }, n);
                    }),
                    (e.getServiceCredentials = function(e, t, n) {
                        return this.sendIq(
                            { credentials: { service: { host: t } }, to: e, type: 'get' },
                            n
                        );
                    });
            }
            function or(e) {
                e.disco.addFeature(Ae),
                    e.disco.addFeature(Fe(Ae)),
                    e.on('pubsub:event', function(t) {
                        t.event.updated &&
                            t.event.updated.node === Ae &&
                            e.emit('geoloc', {
                                geoloc: t.event.updated.published[0].geoloc,
                                jid: t.from
                            });
                    }),
                    (e.publishGeoLoc = function(e, t) {
                        return this.publish('', Ae, { geoloc: e }, t);
                    });
            }
            function ar(e) {
                (e.goInvisible = function(e) {
                    return this.sendIq({ invisible: !0, type: 'set' }, e);
                }),
                    (e.goVisible = function(e) {
                        return this.sendIq({ type: 'set', visible: !0 }, e);
                    });
            }
            function ur(e) {
                e.prepJID = function(t, n) {
                    return e.sendIq({ jidPrep: t, to: e.jid.domain, type: 'get' }, n);
                };
            }
            const cr = { Initiator: 'initiator', Responder: 'responder' },
                lr = {
                    Inactive: 'inactive',
                    Receive: 'recvonly',
                    Send: 'sendonly',
                    SendReceive: 'sendrecv'
                },
                fr = { Both: 'both', Initiator: 'initiator', None: 'none', Responder: 'responder' };
            function dr(e, t = 'both') {
                const n = e === cr.Initiator;
                switch (t) {
                    case fr.Initiator:
                        return n ? lr.Send : lr.Receive;
                    case fr.Responder:
                        return n ? lr.Receive : lr.Send;
                    case fr.Both:
                        return lr.SendReceive;
                }
                return lr.Inactive;
            }
            function hr(e, t = 'sendrecv') {
                const n = e === cr.Initiator;
                switch (t) {
                    case lr.Send:
                        return n ? fr.Initiator : fr.Responder;
                    case lr.Receive:
                        return n ? fr.Responder : fr.Initiator;
                    case lr.SendReceive:
                        return fr.Both;
                }
                return fr.None;
            }
            function pr(e, t) {
                const n = e.rtpParameters,
                    i = e.rtcpParameters || {},
                    r = e.rtpEncodingParameters || [];
                let s = !1;
                r && r.length && (s = !!r[0].ssrc);
                const o = {
                    applicationType: 'rtp',
                    headerExtensions: [],
                    media: e.kind,
                    mux: i.mux,
                    payloads: [],
                    reducedSize: i.reducedSize,
                    sourceGroups: [],
                    sources: [],
                    ssrc: s ? r[0].ssrc.toString() : void 0,
                    streams: []
                };
                for (const e of n.headerExtensions || [])
                    o.headerExtensions.push({
                        id: e.id,
                        senders:
                            e.direction && 'sendrecv' !== e.direction ? hr(t, e.direction) : void 0,
                        uri: e.uri
                    });
                i.ssrc &&
                    i.cname &&
                    (o.sources = [
                        { parameters: [{ key: 'cname', value: i.cname }], ssrc: i.ssrc.toString() }
                    ]),
                    s &&
                        r[0] &&
                        r[0].rtx &&
                        (o.sourceGroups = [
                            {
                                semantics: 'FID',
                                sources: [r[0].ssrc.toString(), r[0].rtx.ssrc.toString()]
                            }
                        ]);
                for (const t of e.streams || []) o.streams.push({ id: t.stream, track: t.track });
                for (const e of n.codecs || []) {
                    const t = {
                        channels: e.channels.toString(),
                        clockrate: e.clockRate.toString(),
                        feedback: [],
                        id: e.payloadType.toString(),
                        maxptime: e.maxptime ? e.maxptime.toString() : void 0,
                        name: e.name,
                        parameters: []
                    };
                    for (const n of Object.keys(e.parameters || {}))
                        'ptime' !== n
                            ? t.parameters.push({ key: n, value: e.parameters[n] })
                            : (t.ptime = e.parameters[n].toString());
                    for (const n of e.rtcpFeedback || [])
                        t.feedback.push({ subtype: n.parameter, type: n.type });
                    o.payloads.push(t);
                }
                return o;
            }
            function mr(e) {
                return {
                    component: e.component.toString(),
                    foundation: e.foundation,
                    generation: void 0,
                    id: void 0,
                    ip: e.ip,
                    network: void 0,
                    port: e.port.toString(),
                    priority: e.priority.toString(),
                    protocol: e.protocol,
                    relAddr: e.relatedAddress,
                    relPort: e.relatedPort ? e.relatedPort.toString() : void 0,
                    tcpType: e.tcpType,
                    type: e.type
                };
            }
            function gr(e) {
                const t = e.iceParameters,
                    n = e.dtlsParameters,
                    i = { candidates: [], transportType: 'iceUdp' };
                t && ((i.ufrag = t.usernameFragment), (i.pwd = t.password)),
                    n &&
                        (i.fingerprints = n.fingerprints.map(t => ({
                            hash: t.algorithm,
                            setup: e.setup,
                            value: t.value
                        }))),
                    e.sctp && (i.sctp = [e.sctp]);
                for (const t of e.candidates || []) i.candidates.push(mr(t));
                return i;
            }
            function br(e, t) {
                return {
                    contents: e.media.map(e => {
                        return {
                            application:
                                'audio' === e.kind || 'video' === e.kind
                                    ? pr(e, t)
                                    : { applicationType: 'datachannel', protocol: e.protocol },
                            creator: cr.Initiator,
                            name: e.mid,
                            senders: hr(t, e.direction),
                            transport: gr(e)
                        };
                    }),
                    groups: e.groups
                        ? e.groups.map(e => ({ contents: e.mids, semantics: e.semantics }))
                        : void 0
                };
            }
            function yr(e, t) {
                const n = e.application || {},
                    i = e.transport,
                    r = n && 'rtp' === n.applicationType,
                    s = {
                        direction: dr(t, e.senders),
                        kind: n.media || 'application',
                        mid: e.name,
                        protocol: r ? 'UDP/TLS/RTP/SAVPF' : 'UDP/DTLS/SCTP'
                    };
                if (r) {
                    if (
                        ((s.rtcpParameters = { mux: n.mux, reducedSize: n.reducedSize }),
                        n.sources && n.sources.length)
                    ) {
                        const e = n.sources[0];
                        if (((s.rtcpParameters.ssrc = parseInt(e.ssrc, 10)), e.parameters)) {
                            const t = e.parameters.find(e => 'cname' === e.key);
                            s.rtcpParameters.cname = t ? t.value : void 0;
                        }
                    }
                    if (
                        ((s.rtpParameters = {
                            codecs: [],
                            fecMechanisms: [],
                            headerExtensions: []
                        }),
                        n.streams)
                    ) {
                        s.streams = [];
                        for (const e of n.streams) s.streams.push({ stream: e.id, track: e.track });
                    }
                    if (
                        n.ssrc &&
                        ((s.rtpEncodingParameters = [{ ssrc: parseInt(n.ssrc, 10) }]),
                        n.sourceGroups && n.sourceGroups.length)
                    ) {
                        const e = n.sourceGroups[0];
                        s.rtpEncodingParameters[0].rtx = { ssrc: parseInt(e.sources[1], 10) };
                    }
                    for (const e of n.payloads || []) {
                        const i = {};
                        for (const t of e.parameters || []) i[t.key] = t.value;
                        const r = [];
                        for (const t of e.feedback || [])
                            r.push({ parameter: t.subtype, type: t.type });
                        s.rtpParameters.codecs.push({
                            channels: parseInt(e.channels, 10),
                            clockRate: parseInt(e.clockrate, 10),
                            name: e.name,
                            numChannels: parseInt(e.channels, 10),
                            parameters: i,
                            payloadType: parseInt(e.id, 10),
                            rtcpFeedback: r
                        });
                        for (const e of n.headerExtensions || [])
                            s.rtpParameters.headerExtensions.push({
                                direction:
                                    e.senders && 'both' !== e.senders ? dr(t, e.senders) : void 0,
                                id: e.id,
                                uri: e.uri
                            });
                    }
                }
                if (
                    i &&
                    (i.ufrag &&
                        i.pwd &&
                        (s.iceParameters = { password: i.pwd, usernameFragment: i.ufrag }),
                    i.fingerprints && i.fingerprints.length)
                ) {
                    s.dtlsParameters = { fingerprints: [], role: 'auto' };
                    for (const e of i.fingerprints)
                        s.dtlsParameters.fingerprints.push({ algorithm: e.hash, value: e.value });
                    i.sctp && (s.sctp = i.sctp[0]), (s.setup = i.fingerprints[0].setup);
                }
                return s;
            }
            function vr(e, t) {
                const n = { groups: [], media: [] };
                for (const t of e.groups || [])
                    n.groups.push({ mids: t.contents, semantics: t.semantics });
                for (const i of e.contents || []) n.media.push(yr(i, t));
                return n;
            }
            function xr(e) {
                if (p.matchPrefix(e, 'a=sctpmap:').length > 0) {
                    const t = p
                        .matchPrefix(e, 'a=sctpmap:')[0]
                        .substr(10)
                        .split(' ');
                    return { number: t[0], protocol: t[1], streams: t[2] };
                }
                return {
                    number: p.matchPrefix(e, 'a=sctp-port:')[0].substr(12),
                    protocol: 'webrtc-datachannel',
                    streams: '1024'
                };
            }
            function wr(e, t) {
                return [
                    `m=${e.kind} 9 ${e.protocol} ${t.protocol}\r\n`,
                    'c=IN IP4 0.0.0.0\r\n',
                    `a=sctp-port:${t.number}\r\n`
                ].join('');
            }
            function _r(e) {
                const t = p.getMediaSections(e),
                    n = p.getDescription(e),
                    i = { groups: [], media: [] };
                for (const e of p.matchPrefix(n, 'a=group:')) {
                    const t = e.split(' '),
                        n = t.shift().substr(8);
                    i.groups.push({ mids: t, semantics: n });
                }
                for (const e of t) {
                    const t = p.getKind(e),
                        r = p.isRejected(e),
                        s = p.parseMLine(e),
                        o = {
                            direction: p.getDirection(e, n),
                            kind: t,
                            mid: p.getMid(e),
                            protocol: s.protocol
                        };
                    if (
                        (r ||
                            ((o.iceParameters = p.getIceParameters(e, n)),
                            (o.dtlsParameters = p.getDtlsParameters(e, n)),
                            (o.setup = p.matchPrefix(e, 'a=setup:')[0].substr(8))),
                        'audio' === t || 'video' === t)
                    ) {
                        (o.rtpParameters = p.parseRtpParameters(e)),
                            (o.rtpEncodingParameters = p.parseRtpEncodingParameters(e)),
                            (o.rtcpParameters = p.parseRtcpParameters(e));
                        const t = p.parseMsid(e);
                        o.streams = t ? [t] : [];
                    } else 'application' === t && (o.sctp = xr(e));
                    (o.candidates = p.matchPrefix(e, 'a=candidate:').map(p.parseCandidate)),
                        i.media.push(o);
                }
                return i;
            }
            function Sr(e) {
                const t = [];
                t.push(
                    p.writeSessionBoilerplate(e.sessionId, e.sessionVersion),
                    'a=msid-semantic:WMS *\r\n'
                ),
                    e.iceLite && t.push('a=ice-lite\r\n');
                for (const n of e.groups || [])
                    t.push(`a=group:${n.semantics} ${n.mids.join(' ')}\r\n`);
                for (const n of e.media || []) {
                    const e = !(n.iceParameters && n.dtlsParameters);
                    if ('application' === n.kind && n.sctp) t.push(wr(n, n.sctp));
                    else if (n.rtpParameters) {
                        let i = p.writeRtpDescription(n.kind, n.rtpParameters);
                        e && (i = i.replace(`m=${n.kind} 9 `, `m=${n.kind} 0 `)),
                            t.push(i),
                            t.push(`a=${n.direction || 'sendrecv'}\r\n`);
                        for (const e of n.streams || [])
                            t.push(`a=msid:${e.stream} ${e.track}\r\n`);
                        if (
                            n.rtcpParameters &&
                            n.rtcpParameters.cname &&
                            (t.push(
                                `a=ssrc:${n.rtcpParameters.ssrc} cname:${
                                    n.rtcpParameters.cname
                                }\r\n`
                            ),
                            n.rtpEncodingParameters && n.rtpEncodingParameters[0].rtx)
                        ) {
                            const e = n.rtpEncodingParameters[0];
                            t.push(`a=ssrc-group:FID ${e.ssrc} ${e.rtx.ssrc}\r\n`),
                                t.push(`a=ssrc:${e.rtx.ssrc} cname:${n.rtcpParameters.cname}\r\n`);
                        }
                    }
                    if (
                        (void 0 !== n.mid && t.push(`a=mid:${n.mid}\r\n`),
                        n.iceParameters && t.push(p.writeIceParameters(n.iceParameters)),
                        n.dtlsParameters &&
                            n.setup &&
                            t.push(p.writeDtlsParameters(n.dtlsParameters, n.setup)),
                        n.candidates && n.candidates.length)
                    )
                        for (const e of n.candidates) t.push(`a=${p.writeCandidate(e)}`);
                }
                return t.join('');
            }
            const Ar = n(13),
                Er = {
                    'content-accept': 'onContentAccept',
                    'content-add': 'onContentAdd',
                    'content-modify': 'onContentModify',
                    'content-reject': 'onContentReject',
                    'content-remove': 'onContentRemove',
                    'description-info': 'onDescriptionInfo',
                    'security-info': 'onSecurityInfo',
                    'session-accept': 'onSessionAccept',
                    'session-info': 'onSessionInfo',
                    'session-initiate': 'onSessionInitiate',
                    'session-terminate': 'onSessionTerminate',
                    'transport-accept': 'onTransportAccept',
                    'transport-info': 'onTransportInfo',
                    'transport-reject': 'onTransportReject',
                    'transport-replace': 'onTransportReplace'
                };
            class Ir extends Ar {
                constructor(e) {
                    super(),
                        (this.sid = e.sid || o.v4()),
                        (this.peerID = e.peerID),
                        (this.role = e.initiator ? 'initiator' : 'responder'),
                        (this.parent = e.parent),
                        (this.state = 'starting'),
                        (this.connectionState = 'starting'),
                        (this.pendingApplicationTypes = e.applicationTypes || []),
                        (this.pendingAction = !1),
                        (this.processingQueue = d.queue((e, t) => {
                            if ('ended' === this.state) return t();
                            const n = e.action,
                                i = e.changes,
                                r = e.cb;
                            if ((this._log('debug', n), !Er[n] || !this[Er[n]]))
                                return (
                                    this._log('error', 'Invalid or unsupported action: ' + n),
                                    r({ condition: 'bad-request' }),
                                    t()
                                );
                            this[Er[n]](i, function(e, n) {
                                return r(e, n), t();
                            });
                        }));
                }
                get isInitiator() {
                    return 'initiator' === this.role;
                }
                get peerRole() {
                    return this.isInitiator ? 'responder' : 'initiator';
                }
                get state() {
                    return this._sessionState;
                }
                set state(e) {
                    if (e !== this._sessionState) {
                        this._sessionState;
                        this._log('info', 'Changing session state to: ' + e),
                            (this._sessionState = e),
                            this.emit('sessionState', this, e);
                    }
                }
                get connectionState() {
                    return this._connectionState;
                }
                set connectionState(e) {
                    if (e !== this._connectionState) {
                        this._connectionState;
                        this._log('info', 'Changing connection state to: ' + e),
                            (this._connectionState = e),
                            this.emit('connectionState', this, e);
                    }
                }
                _log(e, t, ...n) {
                    (t = this.sid + ': ' + t), this.emit('log:' + e, t, ...n);
                }
                send(e, t) {
                    ((t = t || {}).sid = this.sid), (t.action = e);
                    (this.pendingAction =
                        !!{
                            'content-accept': !0,
                            'content-add': !0,
                            'content-modify': !0,
                            'content-reject': !0,
                            'content-remove': !0,
                            'session-accept': !0,
                            'session-inititate': !0,
                            'transport-accept': !0,
                            'transport-reject': !0,
                            'transport-replace': !0
                        }[e] && e),
                        this.emit('send', { id: o.v4(), jingle: t, to: this.peerID, type: 'set' });
                }
                process(e, t, n) {
                    this.processingQueue.push({ action: e, cb: n, changes: t });
                }
                start(e, t) {
                    this._log('error', 'Can not start base sessions'),
                        this.end('unsupported-applications', !0);
                }
                accept(e, t) {
                    this._log('error', 'Can not accept base sessions'),
                        this.end('unsupported-applications');
                }
                cancel() {
                    this.end('cancel');
                }
                decline() {
                    this.end('decline');
                }
                end(e, t) {
                    (this.state = 'ended'),
                        this.processingQueue.kill(),
                        e || (e = 'success'),
                        'string' == typeof e && (e = { condition: e }),
                        t || this.send('session-terminate', { reason: e }),
                        this.emit('terminated', this, e);
                }
                onSessionInitiate(e, t) {
                    t();
                }
                onSessionTerminate(e, t) {
                    this.end(e.reason, !0), t();
                }
                onSessionInfo(e, t) {
                    const n = { action: !0, initiator: !0, responder: !0, sid: !0 };
                    let i = !1;
                    Object.keys(e).forEach(function(e) {
                        n[e] || (i = !0);
                    }),
                        i
                            ? t({
                                  condition: 'feature-not-implemented',
                                  jingleCondition: 'unsupported-info',
                                  type: 'modify'
                              })
                            : t();
                }
                onDescriptionInfo(e, t) {
                    t({
                        condition: 'feature-not-implemented',
                        jingleCondition: 'unsupported-info',
                        type: 'modify'
                    });
                }
                onTransportInfo(e, t) {
                    t({
                        condition: 'feature-not-implemented',
                        jingleCondition: 'unsupported-info',
                        type: 'modify'
                    });
                }
                onContentAdd(e, t) {
                    t(),
                        this.send('content-reject', {
                            reason: {
                                condition: 'failed-application',
                                text: 'content-add is not supported'
                            }
                        });
                }
                onTransportReplace(e, t) {
                    t(),
                        this.send('transport-reject', {
                            reason: {
                                condition: 'failed-application',
                                text: 'transport-replace is not supported'
                            }
                        });
                }
            }
            const jr = n(41);
            class kr extends Ir {
                constructor(e) {
                    super(e),
                        (this.pc = new RTCPeerConnection(e.config, e.constraints)),
                        this.pc.addEventListener('iceconnectionstatechange', () => {
                            this.onIceStateChange(), this.restrictRelayBandwidth();
                        }),
                        this.pc.addEventListener('icecandidate', e => {
                            e.candidate ? this.onIceCandidate(e) : this.onIceEndOfCandidates();
                        }),
                        (this.bitrateLimit = 0),
                        (this.maxRelayBandwidth = e.maxRelayBandwidth);
                }
                end(e, t) {
                    this.pc.close(), super.end(e, t);
                }
                onTransportInfo(e, t) {
                    if (e.contents[0].transport.gatheringComplete)
                        return this.pc
                            .addIceCandidate(null)
                            .then(() => t())
                            .catch(e => {
                                this._log('error', 'Could not add null ICE candidate', e.name), t();
                            });
                    if (this.pc.remoteDescription) {
                        const n = this.pc.remoteDescription,
                            i = _r(n.sdp),
                            r = i.media.find(t => t.mid === e.contents[0].name).iceParameters
                                .usernameFragment,
                            s = e.contents[0].transport.ufrag;
                        if (s && r !== s)
                            return (
                                e.contents.forEach((e, t) => {
                                    (i.media[t].iceParameters = {
                                        password: e.transport.pwd,
                                        usernameFragment: e.transport.ufrag
                                    }),
                                        (i.media[t].candidates = []);
                                }),
                                'offer' === n.type
                                    ? this.pc
                                          .setRemoteDescription(n)
                                          .then(() => this.pc.createAnswer())
                                          .then(e => {
                                              const t = {
                                                  action: 'transport-info',
                                                  contents: _r(e.sdp).media.map(e => ({
                                                      creator: 'initiator',
                                                      name: e.mid,
                                                      transport: gr(e)
                                                  })),
                                                  sessionId: this.sid
                                              };
                                              return (
                                                  this.send('transport-info', t),
                                                  this.pc.setLocalDescription(e)
                                              );
                                          })
                                          .then(() => t())
                                          .catch(e => {
                                              this._log(
                                                  'error',
                                                  'Could not do remote ICE restart',
                                                  e
                                              ),
                                                  this.end('failed-application', !0),
                                                  t(e);
                                          })
                                    : this.pc
                                          .setRemoteDescription(n)
                                          .then(() => t())
                                          .catch(e => {
                                              this._log(
                                                  'error',
                                                  'Could not do local ICE restart',
                                                  e
                                              ),
                                                  this.end('failed-application', !0),
                                                  t(e);
                                          })
                            );
                    }
                    const n = e.contents.map(e => {
                        const t = e.name,
                            n = e.transport.candidates.map(e => {
                                (e.relatedAddress = e.relAddr), (e.relatedPort = e.relPort);
                                const n = jr.writeCandidate(e);
                                let i;
                                const r = this.pc.remoteDescription.sdp,
                                    s = jr.getMediaSections(r);
                                for (let e = 0; e < s.length; e++)
                                    if (jr.getMid(s[e]) === n.sdpMid) {
                                        i = e;
                                        break;
                                    }
                                return this.pc
                                    .addIceCandidate({ sdpMid: t, sdpMLineIndex: i, candidate: n })
                                    .catch(e =>
                                        this._log('error', 'Could not add ICE candidate', e.name)
                                    );
                            });
                        return Promise.all(n);
                    });
                    return Promise.all(n).then(() => t());
                }
                onSessionAccept(e, t) {
                    this.state = 'active';
                    const n = Sr(vr(e, this.peerRole));
                    this.pc.setRemoteDescription({ type: 'answer', sdp: n }).then(
                        () => {
                            this.emit('accepted', this, void 0), t();
                        },
                        e => {
                            this._log('error', `Could not process WebRTC answer: ${e}`),
                                t({ condition: 'general-error' });
                        }
                    );
                }
                onSessionTerminate(e, t) {
                    this._log('info', 'Terminating session'),
                        this.pc.close(),
                        super.end(e.reason, !0),
                        t();
                }
                onIceCandidate(e) {
                    const t = jr.parseCandidate(e.candidate.candidate),
                        n = (function(e, t) {
                            return {
                                contents: [
                                    {
                                        creator: cr.Initiator,
                                        name: e,
                                        transport: {
                                            candidates: [mr(t)],
                                            transportType: 'iceUdp',
                                            ufrag: t.usernameFragment || void 0
                                        }
                                    }
                                ]
                            };
                        })(e.candidate.sdpMid, t);
                    n.contents.forEach((e, t) => {
                        if (!e.transport.ufrag) {
                            const n = _r(this.pc.localDescription.sdp);
                            e.transport.ufrag = n.media[t].iceParameters.usernameFragment;
                        }
                    }),
                        this._log('info', 'Discovered new ICE candidate', n),
                        this.send('transport-info', n);
                }
                onIceEndOfCandidates() {
                    this._log('info', 'ICE end of candidates');
                    const e = _r(this.pc.localDescription.sdp).media[0],
                        t = {
                            contents: [
                                {
                                    name: e.mid,
                                    transport: {
                                        gatheringComplete: !0,
                                        transportType: 'iceUdp',
                                        ufrag: e.iceParameters.usernameFragment
                                    }
                                }
                            ]
                        };
                    this.send('transport-info', t);
                }
                onIceStateChange() {
                    switch (this.pc.iceConnectionState) {
                        case 'checking':
                            this.connectionState = 'connecting';
                            break;
                        case 'completed':
                        case 'connected':
                            this.connectionState = 'connected';
                            break;
                        case 'disconnected':
                            'stable' === this.pc.signalingState
                                ? (this.connectionState = 'interrupted')
                                : (this.connectionState = 'disconnected'),
                                this.maybeRestartIce();
                            break;
                        case 'failed':
                            'failed' === this.connectionState
                                ? ((this.connectionState = 'failed'), this.end('failed-transport'))
                                : this.restartIce();
                            break;
                        case 'closed':
                            this.connectionState = 'disconnected';
                    }
                }
                restrictRelayBandwidth() {
                    window.RTCRtpSender &&
                        'getParameters' in window.RTCRtpSender.prototype &&
                        this.pc.addEventListener('iceconnectionstatechange', () => {
                            switch (this.pc.iceConnectionState) {
                                case 'completed':
                                case 'connected':
                                    this._firstTimeConnected ||
                                        ((this._firstTimeConnected = !0),
                                        this.pc.getStats().then(e => {
                                            let t;
                                            if (
                                                (e.forEach(n => {
                                                    'transport' === n.type &&
                                                        (t = e.get(n.selectedCandidatePairId));
                                                }),
                                                t ||
                                                    e.forEach(e => {
                                                        'candidate-pair' === e.type &&
                                                            e.selected &&
                                                            (t = e);
                                                    }),
                                                t)
                                            ) {
                                                let n = !1;
                                                if (t.remoteCandidateId) {
                                                    const i = e.get(t.remoteCandidateId);
                                                    i && 'relay' === i.candidateType && (n = !0);
                                                }
                                                if (t.localCandidateId) {
                                                    const i = e.get(t.localCandidateId);
                                                    i && 'relay' === i.candidateType && (n = !0);
                                                }
                                                n &&
                                                    ((this.maximumBitrate = this.maxRelayBandwidth),
                                                    this.currentBitrate &&
                                                        this.setMaximumBitrate(
                                                            Math.min(
                                                                this.currentBitrate,
                                                                this.maximumBitrate
                                                            )
                                                        ));
                                            }
                                        }));
                            }
                        });
                }
                maybeRestartIce() {
                    this.isInitiator &&
                        (void 0 !== this._maybeRestartingIce &&
                            clearTimeout(this._maybeRestartingIce),
                        (this._maybeRestartingIce = setTimeout(() => {
                            delete this._maybeRestartingIce,
                                'disconnected' === this.pc.iceConnectionState && this.restartIce();
                        }, 2e3)));
                }
                restartIce() {
                    this.isInitiator &&
                        (void 0 !== this._maybeRestartingIce &&
                            clearTimeout(this._maybeRestartingIce),
                        this.pc.createOffer({ iceRestart: !0 }).then(
                            e => {
                                const t = {
                                    action: 'transport-info',
                                    contents: _r(e.sdp).media.map(e => ({
                                        creator: 'initiator',
                                        name: e.mid,
                                        transport: gr(e)
                                    })),
                                    sessionId: this.sid
                                };
                                return (
                                    this.send('transport-info', t), this.pc.setLocalDescription(e)
                                );
                            },
                            e => {
                                this._log('error', 'Could not create WebRTC offer', e),
                                    this.end('failed-application', !0);
                            }
                        ));
                }
                setMaximumBitrate(e) {
                    if (
                        (this.maximumBitrate && (e = Math.min(e, this.maximumBitrate)),
                        (this.currentBitrate = e),
                        !(window.RTCRtpSender && 'getParameters' in window.RTCRtpSender.prototype))
                    )
                        return;
                    const t = this.pc.getSenders().find(e => e.track && 'video' === e.track.kind);
                    if (!t) return;
                    let n = '';
                    window.navigator && window.navigator.mozGetUserMedia
                        ? (n = 'firefox')
                        : window.navigator && window.navigator.webkitGetUserMedia && (n = 'chrome');
                    const i = t.getParameters();
                    'firefox' !== n || i.encodings || (i.encodings = [{}]),
                        0 === e
                            ? delete i.encodings[0].maximumBitrate
                            : (i.encodings.length || (i.encodings[0] = {}),
                              (i.encodings[0].maxBitrate = e)),
                        'chrome' === n
                            ? t.setParameters(i).catch(e => {
                                  this._log('error', 'setParameters failed', e);
                              })
                            : 'firefox' === n &&
                              ('stable' !== this.pc.signalingState
                                  ? t.setParameters(i).catch(e => {
                                        this._log('error', 'setParameters failed', e);
                                    })
                                  : 'offer' === this.pc.localDescription.type
                                  ? t
                                        .setParameters(i)
                                        .then(() => this.pc.createOffer())
                                        .then(e => this.pc.setLocalDescription(e))
                                        .then(() =>
                                            this.pc.setRemoteDescription(this.pc.remoteDescription)
                                        )
                                        .catch(e => {
                                            this._log('error', 'setParameters failed', e);
                                        })
                                  : 'answer' === this.pc.localDescription.type &&
                                    t
                                        .setParameters(i)
                                        .then(() =>
                                            this.pc.setRemoteDescription(this.pc.remoteDescription)
                                        )
                                        .then(() => this.pc.createAnswer())
                                        .then(e => this.pc.setLocalDescription(e))
                                        .catch(e => {
                                            this._log('error', 'setParameters failed', e);
                                        }));
                }
            }
            class Tr extends h.EventEmitter {
                constructor(e = {}) {
                    super(),
                        (this.config = Object.assign(
                            { chunkSize: 16384, hash: 'sha-1', pacing: 0 },
                            e
                        )),
                        (this.file = null),
                        (this.channel = null),
                        (this.hash = c.createHash(this.config.hash));
                }
                send(e, t) {
                    if (this.file && this.channel) return;
                    (this.file = e), (this.channel = t), (this.channel.binaryType = 'arraybuffer');
                    const n = 'number' != typeof t.bufferedAmountLowThreshold,
                        i = (r = 0) => {
                            const s = new FileReader();
                            s.onload = () => {
                                const o = new Uint8Array(s.result);
                                this.channel.send(o),
                                    this.hash.update(o),
                                    this.emit('progress', r, e.size, o),
                                    e.size > r + this.config.chunkSize
                                        ? n
                                            ? setTimeout(
                                                  i,
                                                  this.config.pacing,
                                                  r + this.config.chunkSize
                                              )
                                            : t.bufferedAmount <= t.bufferedAmountLowThreshold &&
                                              setTimeout(i, 0, r + this.config.chunkSize)
                                        : (this.emit('progress', e.size, e.size, null),
                                          this.emit('sentFile', {
                                              algo: this.config.hash,
                                              hash: this.hash.digest('hex')
                                          }));
                            };
                            const o = e.slice(r, r + this.config.chunkSize);
                            s.readAsArrayBuffer(o);
                        };
                    n ||
                        ((t.bufferedAmountLowThreshold = 8 * this.config.chunkSize),
                        t.addEventListener('bufferedamountlow', i)),
                        setTimeout(i, 0, 0);
                }
            }
            class Cr extends h.EventEmitter {
                constructor(e = {}) {
                    super(),
                        (this.config = Object.assign({ hash: 'sha-1' }, e)),
                        (this.receiveBuffer = []),
                        (this.received = 0),
                        (this.metadata = {}),
                        (this.channel = null),
                        (this.hash = c.createHash(this.config.hash));
                }
                receive(e, t) {
                    e && (this.metadata = e),
                        (this.channel = t),
                        (this.channel.binaryType = 'arraybuffer'),
                        (this.channel.onmessage = e => {
                            const t = e.data.byteLength;
                            (this.received += t),
                                this.receiveBuffer.push(e.data),
                                e.data && this.hash.update(new Uint8Array(e.data)),
                                this.emit('progress', this.received, this.metadata.size, e.data),
                                this.received === this.metadata.size
                                    ? ((this.metadata.actualhash = this.hash.digest('hex')),
                                      this.emit(
                                          'receivedFile',
                                          new Blob(this.receiveBuffer),
                                          this.metadata
                                      ),
                                      (this.receiveBuffer = []))
                                    : this.received > this.metadata.size &&
                                      (console.error('received more than expected, discarding...'),
                                      (this.receiveBuffer = []));
                        });
                }
            }
            class Rr extends kr {
                constructor(e) {
                    super(e), (this.sender = null), (this.receiver = null), (this.file = null);
                }
                start(e, t) {
                    (t = t || (() => void 0)),
                        (this.state = 'pending'),
                        (this.role = 'initiator'),
                        (this.file = e),
                        (this.sender = new Tr()),
                        this.sender.on('progress', (e, t) => {
                            this._log('info', 'Send progress ' + e + '/' + t);
                        }),
                        this.sender.on('sentFile', e => {
                            this._log('info', 'Sent file', e.name),
                                this.send('description-info', {
                                    contents: [
                                        {
                                            application: {
                                                applicationType: 'filetransfer',
                                                offer: { hash: { algo: e.algo, value: e.hash } }
                                            },
                                            creator: 'initiator',
                                            name: this.contentName
                                        }
                                    ]
                                }),
                                this.emit('sentFile', this, e);
                        }),
                        (this.channel = this.pc.createDataChannel('filetransfer', { ordered: !0 })),
                        (this.channel.onopen = () => {
                            this.sender.send(this.file, this.channel);
                        }),
                        this.pc
                            .createOffer({ offerToReceiveAudio: !1, offerToReceiveVideo: !1 })
                            .then(n => {
                                const i = br(_r(n.sdp), this.role);
                                return (
                                    (this.contentName = i.contents[0].name),
                                    (i.sessionId = this.sid),
                                    (i.action = 'session-initate'),
                                    (i.contents[0].application = {
                                        applicationType: 'filetransfer',
                                        offer: {
                                            date: e.lastModifiedDate,
                                            hash: { algo: 'sha-1', value: '' },
                                            name: e.name,
                                            size: e.size
                                        }
                                    }),
                                    this.send('session-initiate', i),
                                    this.pc.setLocalDescription(n).then(() => t())
                                );
                            })
                            .catch(
                                e => (
                                    console.error(e),
                                    this._log('error', 'Could not create WebRTC offer', e),
                                    this.end('failed-application', !0)
                                )
                            );
                }
                accept(e) {
                    this._log('info', 'Accepted incoming session'),
                        (this.role = 'responder'),
                        (this.state = 'active'),
                        (e = e || (() => void 0)),
                        this.pc
                            .createAnswer()
                            .then(t => {
                                const n = br(_r(t.sdp), this.role);
                                return (
                                    (n.sessionId = this.sid),
                                    (n.action = 'session-accept'),
                                    n.contents.forEach(e => {
                                        e.creator = 'initiator';
                                    }),
                                    (this.contentName = n.contents[0].name),
                                    this.send('session-accept', n),
                                    this.pc.setLocalDescription(t).then(() => e())
                                );
                            })
                            .catch(e => {
                                console.error(e),
                                    this._log('error', 'Could not create WebRTC answer', e),
                                    this.end('failed-application');
                            });
                }
                onSessionInitiate(e, t) {
                    this._log('info', 'Initiating incoming session'),
                        (this.role = 'responder'),
                        (this.state = 'pending');
                    const n = Sr(vr(e, this.peerRole)),
                        i = e.contents[0].application;
                    (this.receiver = new Cr({ hash: i.offer.hash.algo })),
                        this.receiver.on('progress', (e, t) => {
                            this._log('info', 'Receive progress ' + e + '/' + t);
                        }),
                        this.receiver.on('receivedFile', e => {
                            (this.receivedFile = e), this._maybeReceivedFile();
                        }),
                        (this.receiver.metadata = i.offer),
                        this.pc.addEventListener('datachannel', e => {
                            (this.channel = e.channel), this.receiver.receive(null, e.channel);
                        }),
                        this.pc
                            .setRemoteDescription({ type: 'offer', sdp: n })
                            .then(() => {
                                if (t) return t();
                            })
                            .catch(e => {
                                if (
                                    (console.error(e),
                                    this._log('error', 'Could not create WebRTC answer', e),
                                    t)
                                )
                                    return t({ condition: 'general-error' });
                            });
                }
                onDescriptionInfo(e, t) {
                    const n = e.contents[0].application.offer.hash;
                    (this.receiver.metadata.hash = n),
                        this.receiver.metadata.actualhash && this._maybeReceivedFile(),
                        t();
                }
                _maybeReceivedFile() {
                    this.receiver.metadata.hash.value &&
                        (this.receiver.metadata.hash.value === this.receiver.metadata.actualhash
                            ? (this._log('info', 'File hash matches'),
                              this.emit(
                                  'receivedFile',
                                  this,
                                  this.receivedFile,
                                  this.receiver.metadata
                              ),
                              this.end('success'))
                            : (this._log('error', 'File hash does not match'),
                              this.end('media-error')));
                }
            }
            class Pr extends kr {
                constructor(e) {
                    if (
                        (super(e),
                        this.pc.addEventListener('track', e => {
                            this.onAddTrack(e.track, e.streams[0]);
                        }),
                        e.stream)
                    )
                        for (const t of e.stream.getTracks()) this.addTrack(t, e.stream);
                    this._ringing = !1;
                }
                start(e, t) {
                    (this.state = 'pending'),
                        (t = t || (() => void 0)),
                        (this.role = 'initiator'),
                        (this.offerOptions = e),
                        this.pc
                            .createOffer(e)
                            .then(e => {
                                const n = br(_r(e.sdp), this.role);
                                return (
                                    (n.sessionId = this.sid),
                                    (n.action = 'session-initate'),
                                    n.contents.forEach(e => {
                                        (e.creator = 'initiator'),
                                            (function(e) {
                                                if (
                                                    e.application.streams &&
                                                    e.application.streams.length &&
                                                    e.application.sources &&
                                                    e.application.sources.length
                                                ) {
                                                    const t = e.application.streams[0];
                                                    e.application.sources[0].parameters.push({
                                                        key: 'msid',
                                                        value: `${t.id} ${t.track}`
                                                    }),
                                                        e.application.sourceGroups &&
                                                            e.application.sourceGroups.length > 0 &&
                                                            e.application.sources.push({
                                                                parameters: [
                                                                    {
                                                                        key: 'cname',
                                                                        value:
                                                                            e.application.sources[0]
                                                                                .parameters[0].value
                                                                    },
                                                                    {
                                                                        key: 'msid',
                                                                        value: `${t.id} ${t.track}`
                                                                    }
                                                                ],
                                                                ssrc:
                                                                    e.application.sourceGroups[0]
                                                                        .sources[1]
                                                            });
                                                }
                                            })(e);
                                    }),
                                    this.send('session-initiate', n),
                                    this.pc.setLocalDescription(e).then(() => t())
                                );
                            })
                            .catch(e => {
                                this._log('error', 'Could not create WebRTC offer', e),
                                    this.end('failed-application', !0);
                            });
                }
                accept(e, t) {
                    1 === arguments.length && 'function' == typeof e && ((t = e), (e = {})),
                        (t = t || (() => void 0)),
                        (e = e || {}),
                        this._log('info', 'Accepted incoming session'),
                        (this.state = 'active'),
                        (this.role = 'responder'),
                        this.pc
                            .createAnswer(e)
                            .then(e => {
                                const n = br(_r(e.sdp), this.role);
                                return (
                                    (n.sessionId = this.sid),
                                    (n.action = 'session-accept'),
                                    n.contents.forEach(e => {
                                        e.creator = 'initiator';
                                    }),
                                    this.send('session-accept', n),
                                    this.pc.setLocalDescription(e).then(() => t())
                                );
                            })
                            .catch(e => {
                                this._log('error', 'Could not create WebRTC answer', e),
                                    this.end('failed-application');
                            });
                }
                end(e, t) {
                    this.pc.getReceivers().forEach(e => {
                        this.onRemoveTrack(e.track);
                    }),
                        super.end(e, t);
                }
                ring() {
                    this._log('info', 'Ringing on incoming session'),
                        (this.ringing = !0),
                        this.send('session-info', { ringing: !0 });
                }
                mute(e, t) {
                    this._log('info', 'Muting', t),
                        this.send('session-info', { mute: { creator: e, name: t } });
                }
                unmute(e, t) {
                    this._log('info', 'Unmuting', t),
                        this.send('session-info', { unmute: { creator: e, name: t } });
                }
                hold() {
                    this._log('info', 'Placing on hold'), this.send('session-info', { hold: !0 });
                }
                resume() {
                    this._log('info', 'Resuming from hold'),
                        this.send('session-info', { active: !0 });
                }
                addTrack(e, t, n) {
                    if ((this.pc.addTrack ? this.pc.addTrack(e, t) : this.pc.addStream(t, n), n))
                        return n();
                }
                removeTrack(e, t) {
                    if ((this.pc.removeTrack(e), t)) return t();
                }
                onAddTrack(e, t) {
                    this._log('info', 'Track added'), this.emit('peerTrackAdded', this, e, t);
                }
                onRemoveTrack(e) {
                    this._log('info', 'Track removed'), this.emit('peerTrackRemoved', this, e);
                }
                onSessionInitiate(e, t) {
                    this._log('info', 'Initiating incoming session'),
                        (this.state = 'pending'),
                        (this.role = 'responder');
                    const n = vr(e, this.peerRole);
                    n.media.forEach(e => {
                        e.streams || (e.streams = [{ stream: 'legacy', track: e.kind }]);
                    });
                    const i = Sr(n);
                    this.pc
                        .setRemoteDescription({ type: 'offer', sdp: i })
                        .then(() => {
                            if (t) return t();
                        })
                        .catch(e => {
                            if ((this._log('error', 'Could not create WebRTC answer', e), t))
                                return t({ condition: 'general-error' });
                        });
                }
                onSessionTerminate(e, t) {
                    for (const e of this.pc.getReceivers()) this.onRemoveTrack(e.track);
                    super.onSessionTerminate(e, t);
                }
                onSessionInfo(e, t) {
                    return e.ringing
                        ? (this._log('info', 'Outgoing session is ringing'),
                          (this.ringing = !0),
                          this.emit('ringing', this),
                          t())
                        : e.hold
                        ? (this._log('info', 'On hold'), this.emit('hold', this), t())
                        : e.active
                        ? (this._log('info', 'Resuming from hold'), this.emit('resumed', this), t())
                        : e.mute
                        ? (this._log('info', 'Muting', e.mute),
                          this.emit('mute', this, e.mute),
                          t())
                        : e.unmute
                        ? (this._log('info', 'Unmuting', e.unmute),
                          this.emit('unmute', this, e.unmute),
                          t())
                        : t();
                }
                get ringing() {
                    return this._ringing;
                }
                set ringing(e) {
                    e !== this._ringing && ((this._ringing = e), this.emit('change:ringing', e));
                }
                get streams() {
                    return 'closed' !== this.pc.signalingState ? this.pc.getRemoteStreams() : [];
                }
            }
            const Or = n(13),
                Lr = 786432;
            class Mr extends Or {
                constructor(e) {
                    super(),
                        (e = e || {}),
                        (this.selfID = e.selfID),
                        (this.sessions = {}),
                        (this.peers = {}),
                        (this.prepareSession =
                            e.prepareSession ||
                            function(e) {
                                return e.applicationTypes.indexOf('rtp') >= 0
                                    ? new Pr(e)
                                    : e.applicationTypes.indexOf('filetransfer') >= 0
                                    ? new Rr(e)
                                    : void 0;
                            }),
                        (this.performTieBreak =
                            e.performTieBreak ||
                            function(e, t) {
                                const n = t.jingle.contents.map(e => {
                                    if (e.application) return e.application.applicationType;
                                });
                                return (
                                    e.pendingApplicationTypes.filter(e => n.includes(e)).length > 0
                                );
                            }),
                        (this.config = Object.assign(
                            {
                                debug: !1,
                                peerConnectionConfig: {
                                    bundlePolicy: e.bundlePolicy || 'balanced',
                                    iceServers: e.iceServers || [
                                        { urls: 'stun:stun.l.google.com:19302' }
                                    ],
                                    iceTransportPolicy: e.iceTransportPolicy || 'all',
                                    rtcpMuxPolicy: e.rtcpMuxPolicy || 'require'
                                },
                                peerConnectionConstraints: {
                                    optional: [
                                        { DtlsSrtpKeyAgreement: !0 },
                                        { RtpDataChannels: !1 }
                                    ]
                                }
                            },
                            e
                        )),
                        (this.iceServers = this.config.peerConnectionConfig.iceServers);
                }
                addICEServer(e) {
                    'string' == typeof e && (e = { urls: e }), this.iceServers.push(e);
                }
                addSession(e) {
                    const t = e.sid,
                        n = e.peerID;
                    return (
                        (this.sessions[t] = e),
                        this.peers[n] || (this.peers[n] = []),
                        this.peers[n].push(e),
                        e.on('terminated', () => {
                            const i = this.peers[n] || [];
                            i.length && i.splice(i.indexOf(e), 1), delete this.sessions[t];
                        }),
                        e.on('*', (t, n, ...i) => {
                            if ('send' === t) {
                                const t = n.jingle && n.jingle.action;
                                e.isInitiator &&
                                    'session-initiate' === t &&
                                    this.emit('outgoing', e);
                            }
                            !this.config.debug ||
                                ('log:debug' !== t && 'log:error' !== t) ||
                                console.log('Jingle:', n, ...i),
                                0 !== t.indexOf('change') && this.emit(t, n, ...i);
                        }),
                        this.emit('createdSession', e),
                        e
                    );
                }
                createMediaSession(e, t, n) {
                    const i = new Pr({
                        config: this.config.peerConnectionConfig,
                        constraints: this.config.peerConnectionConstraints,
                        iceServers: this.iceServers,
                        initiator: !0,
                        maxRelayBandwidth: Lr,
                        parent: this,
                        peerID: e,
                        sid: t,
                        stream: n
                    });
                    return this.addSession(i), i;
                }
                createFileTransferSession(e, t) {
                    const n = new Rr({
                        config: this.config.peerConnectionConfig,
                        constraints: this.config.peerConnectionConstraints,
                        iceServers: this.iceServers,
                        initiator: !0,
                        maxRelayBandwidth: Lr,
                        parent: this,
                        peerID: e,
                        sid: t
                    });
                    return this.addSession(n), n;
                }
                endPeerSessions(e, t, n) {
                    e = e.full || e;
                    const i = this.peers[e] || [];
                    delete this.peers[e],
                        i.forEach(function(e) {
                            e.end(t || 'gone', n);
                        });
                }
                endAllSessions(e, t) {
                    Object.keys(this.peers).forEach(n => {
                        this.endPeerSessions(n, e, t);
                    });
                }
                _createIncomingSession(e, t) {
                    let n;
                    return (
                        this.prepareSession && (n = this.prepareSession(e, t)),
                        n || (n = new Ir(e)),
                        this.addSession(n),
                        n
                    );
                }
                _sendError(e, t, n) {
                    n.type || (n.type = 'cancel'),
                        this.emit('send', { error: n, id: t, to: e, type: 'error' });
                }
                _log(e, t, ...n) {
                    this.emit('log:' + e, t, ...n);
                }
                process(e) {
                    const t = this,
                        n = e.jingle ? e.jingle.sid : null;
                    let i = this.sessions[n] || null;
                    const r = e.id,
                        s = e.from ? e.from.full || e.from : void 0;
                    if ('error' === e.type) {
                        const t = e.error && 'tie-break' === e.error.jingleCondition;
                        return i && 'pending' === i.state && t
                            ? i.end('alternative-session', !0)
                            : (i && (i.pendingAction = !1), this.emit('error', e));
                    }
                    if ('result' === e.type) return void (i && (i.pendingAction = !1));
                    const o = e.jingle.action,
                        a = e.jingle.contents || [],
                        u = a.map(function(e) {
                            if (e.application) return e.application.applicationType;
                        }),
                        c = a.map(function(e) {
                            if (e.transport) return e.transport.transportType;
                        });
                    if ('session-initiate' !== o) {
                        if (!i)
                            return (
                                this._log('error', 'Unknown session', n),
                                this._sendError(s, r, {
                                    condition: 'item-not-found',
                                    jingleCondition: 'unknown-session'
                                })
                            );
                        if (i.peerID !== s || 'ended' === i.state)
                            return (
                                this._log('error', 'Session has ended, or action has wrong sender'),
                                this._sendError(s, r, {
                                    condition: 'item-not-found',
                                    jingleCondition: 'unknown-session'
                                })
                            );
                        if ('session-accept' === o && 'pending' !== i.state)
                            return (
                                this._log('error', 'Tried to accept session twice', n),
                                this._sendError(s, r, {
                                    condition: 'unexpected-request',
                                    jingleCondition: 'out-of-order'
                                })
                            );
                        if (
                            'session-terminate' !== o &&
                            o === i.pendingAction &&
                            (this._log('error', 'Tie break during pending request'), i.isInitiator)
                        )
                            return this._sendError(s, r, {
                                condition: 'conflict',
                                jingleCondition: 'tie-break'
                            });
                    } else if (i) {
                        if (i.peerID !== s)
                            return (
                                this._log('error', 'Duplicate sid from new sender'),
                                this._sendError(s, r, { condition: 'service-unavailable' })
                            );
                        if ('pending' !== i.state)
                            return (
                                this._log('error', 'Someone is doing this wrong'),
                                this._sendError(s, r, {
                                    condition: 'unexpected-request',
                                    jingleCondition: 'out-of-order'
                                })
                            );
                        if (this.selfID > i.peerID && this.performTieBreak(i, e))
                            return (
                                this._log(
                                    'error',
                                    'Tie break new session because of duplicate sids'
                                ),
                                this._sendError(s, r, {
                                    condition: 'conflict',
                                    jingleCondition: 'tie-break'
                                })
                            );
                    } else if (this.peers[s] && this.peers[s].length)
                        for (let t = 0, i = this.peers[s].length; t < i; t++) {
                            const i = this.peers[s][t];
                            if (
                                i &&
                                'pending' === i.state &&
                                i.sid > n &&
                                this.performTieBreak(i, e)
                            )
                                return (
                                    this._log('info', 'Tie break session-initiate'),
                                    this._sendError(s, r, {
                                        condition: 'conflict',
                                        jingleCondition: 'tie-break'
                                    })
                                );
                        }
                    if ('session-initiate' === o) {
                        if (!a.length) return t._sendError(s, r, { condition: 'bad-request' });
                        i = this._createIncomingSession(
                            {
                                applicationTypes: u,
                                config: this.config.peerConnectionConfig,
                                constraints: this.config.peerConnectionConstraints,
                                iceServers: this.iceServers,
                                initiator: !1,
                                parent: this,
                                peerID: s,
                                sid: n,
                                transportTypes: c
                            },
                            e
                        );
                    }
                    i.process(o, e.jingle, t => {
                        t
                            ? (this._log('error', 'Could not process request', e, t),
                              this._sendError(s, r, t))
                            : (this.emit('send', { id: r, to: s, type: 'result' }),
                              'session-initiate' === o && this.emit('incoming', i));
                    });
                }
            }
            let Br;
            try {
                Br = window;
            } catch (e) {
                Br = r;
            }
            function Dr(e) {
                const t = (e.jingle = new Mr());
                if (
                    ((e.supportedICEServiceTypes = { stun: !0, stuns: !0, turn: !0, turns: !0 }),
                    e.disco.addFeature(Ue),
                    Br.RTCPeerConnection)
                ) {
                    const t = [
                        Xe,
                        dt,
                        ht,
                        Rt,
                        At,
                        Ct,
                        at,
                        He,
                        Ye,
                        Ge,
                        'urn:xmpp:jingle:transports:dtls-sctp:1',
                        'urn:ietf:rfc:3264',
                        'urn:ietf:rfc:5576',
                        'urn:ietf:rfc:5888'
                    ];
                    for (const n of t) e.disco.addFeature(n);
                }
                const n = [
                    'outgoing',
                    'incoming',
                    'accepted',
                    'terminated',
                    'ringing',
                    'mute',
                    'unmute',
                    'hold',
                    'resumed'
                ];
                for (const i of n)
                    t.on(i, function(t, n) {
                        e.emit('jingle:' + i, t, n);
                    });
                t.on('createdSession', function(t) {
                    e.emit('jingle:created', t);
                }),
                    t.on('send', function(n) {
                        e.sendIq(n, function(i, r) {
                            i && e.emit('jingle:error', i);
                            const s = i || r;
                            s.jingle || (s.jingle = {}),
                                (s.jingle.sid = n.jingle.sid),
                                t.process(s);
                        });
                    }),
                    e.on('session:bound', 'jingle', function(e) {
                        t.selfID = e.full;
                    }),
                    e.on('iq:set:jingle', 'jingle', function(e) {
                        t.process(e);
                    }),
                    e.on('unavailable', 'jingle', function(e) {
                        const n = e.from.full;
                        t.endPeerSessions(n, !0);
                    }),
                    (e.discoverICEServers = function(t) {
                        return this.getServices(e.config.server)
                            .then(function(t) {
                                const n = t.services.services,
                                    i = [];
                                for (let t = 0; t < n.length; t++) {
                                    const r = n[t],
                                        s = {};
                                    e.supportedICEServiceTypes[r.type] &&
                                        ('stun' === r.type || 'stuns' === r.type
                                            ? ((s.urls = r.type + ':' + r.host),
                                              r.port && (s.urls += ':' + r.port),
                                              i.push(s),
                                              e.jingle.addICEServer(s))
                                            : ('turn' !== r.type && 'turns' !== r.type) ||
                                              ((s.urls = r.type + ':' + r.host),
                                              r.port && (s.urls += ':' + r.port),
                                              r.transport &&
                                                  'udp' !== r.transport &&
                                                  (s.urls += '?transport=' + r.transport),
                                              r.username && (s.username = r.username),
                                              r.password && (s.credential = r.password),
                                              i.push(s),
                                              e.jingle.addICEServer(s)));
                                }
                                return i;
                            })
                            .then(
                                function(e) {
                                    return t && t(null, e), e;
                                },
                                function(e) {
                                    if (!t) throw e;
                                    t(e);
                                }
                            );
                    });
            }
            function Nr(e, t) {
                return (function(e, t) {
                    let n;
                    return Promise.race([
                        e,
                        new Promise(function(e, i) {
                            n = setTimeout(function() {
                                i();
                            }, t);
                        })
                    ]).then(function(e) {
                        return clearTimeout(n), e;
                    });
                })(
                    new Promise(function(t, n) {
                        e.sm.started
                            ? (e.once('stream:management:ack', t), e.sm.request())
                            : e
                                  .ping()
                                  .then(t)
                                  .catch(function(e) {
                                      e.error && 'timeout' !== e.error.condition ? t() : n();
                                  });
                    }),
                    1e3 * t || 15e3
                );
            }
            function qr(e) {
                (e.enableKeepAlive = function(t) {
                    ((t = t || {}).interval = t.interval || 300),
                        (t.timeout = t.timeout || 15),
                        (e._keepAliveInterval = setInterval(function() {
                            e.sessionStarted &&
                                Nr(e, t.timeout).catch(function() {
                                    e.emit('stream:error', {
                                        condition: 'connection-timeout',
                                        text: 'Server did not respond in ' + t.timeout + ' seconds'
                                    }),
                                        e.transport &&
                                            ((e.transport.hasStream = !1),
                                            e.transport.disconnect());
                                });
                        }, 1e3 * t.interval));
                }),
                    (e.disableKeepAlive = function() {
                        e._keepAliveInterval &&
                            (clearInterval(e._keepAliveInterval), delete e._keepAliveInterval);
                    }),
                    e.on('disconnected', function() {
                        e.disableKeepAlive();
                    });
            }
            function Fr(e) {
                e.disco.addFeature('', Tt),
                    (e.sendLog = function(t, n) {
                        e.sendMessage({ log: n, to: t, type: 'normal' });
                    });
            }
            function Ur(e) {
                e.disco.addFeature(wt),
                    (e.getHistorySearchForm = function(t, n) {
                        return e.sendIq({ mam: !0, to: t, type: 'get' }, n);
                    }),
                    (e.searchHistory = function(t, n) {
                        const i = this.nextId();
                        (t = t || {}).queryid = i;
                        const r = t.jid || t.to || '';
                        delete t.jid,
                            delete t.to,
                            t.form || (t.form = {}),
                            (t.form.type = 'submit');
                        const s = (t.form.fields = t.form.fields || []),
                            o = ['FORM_TYPE', 'with', 'start', 'end'];
                        for (const e of o)
                            if (t[e] || 'FORM_TYPE' === e) {
                                let n = t[e];
                                ('start' === e || 'end' === e) &&
                                    'string' != typeof n &&
                                    (n = n.toISOString()),
                                    'FORM_TYPE' === e && (n = wt);
                                for (let e = 0, t = s.length; e < t; e++) s[e].name;
                                s.push({ name: e, value: n }), delete t[e];
                            }
                        const a = new C(r || e.jid.bare),
                            u = { '': !0 };
                        (u[a.full] = !0),
                            (u[a.bare] = !0),
                            (u[a.domain] = !0),
                            (u[e.jid.bare] = !0),
                            (u[e.jid.domain] = !0);
                        const c = [];
                        return (
                            this.on('mam:item:' + i, 'session', function(e) {
                                u[e.from.full] && c.push(e.mamItem);
                            }),
                            (function(e, t, n) {
                                let i;
                                return Promise.race([
                                    e,
                                    new Promise(function(e, r) {
                                        i = setTimeout(function() {
                                            r({
                                                error: { condition: 'timeout' },
                                                id: t,
                                                type: 'error'
                                            });
                                        }, n);
                                    })
                                ]).then(function(e) {
                                    return clearTimeout(i), e;
                                });
                            })(
                                this.sendIq({ id: i, mam: t, to: r, type: 'set' }),
                                i,
                                1e3 * this.config.timeout || 15e3
                            )
                                .then(
                                    e => (
                                        (e.mamResult.items = c),
                                        this.off('mam:item:' + i),
                                        n && n(null, e),
                                        e
                                    )
                                )
                                .catch(e => {
                                    if ((this.off('mam:item:' + i), !n)) throw e;
                                    n(e);
                                })
                        );
                    }),
                    (e.getHistoryPreferences = function(e) {
                        return this.sendIq({ mamPrefs: !0, type: 'get' }, e);
                    }),
                    (e.setHistoryPreferences = function(e, t) {
                        return this.sendIq({ mamPrefs: e, type: 'set' }, t);
                    }),
                    e.on('message', function(t) {
                        t.mamItem &&
                            (e.emit('mam:item', t), e.emit('mam:item:' + t.mamItem.queryid, t));
                    });
            }
            function zr(e) {
                function t(t) {
                    return t.markable && !1 !== e.config.chatMarkers;
                }
                e.disco.addFeature(It),
                    e.on('message', function(n) {
                        if (!t(n))
                            return n.received
                                ? e.emit('marker:received', n)
                                : n.displayed
                                ? e.emit('marker:displayed', n)
                                : n.acknowledged
                                ? e.emit('marker:acknowledged', n)
                                : void 0;
                        e.markReceived(n);
                    }),
                    (e.markReceived = function(n) {
                        if (t(n)) {
                            const t = 'groupchat' === n.type ? new C(n.from.bare) : n.from;
                            e.sendMessage({ body: '', received: n.id, to: t, type: n.type });
                        }
                    }),
                    (e.markDisplayed = function(n) {
                        if (t(n)) {
                            const t = 'groupchat' === n.type ? new C(n.from.bare) : n.from;
                            e.sendMessage({ body: '', displayed: n.id, to: t, type: n.type });
                        }
                    }),
                    (e.markAcknowledged = function(n) {
                        if (t(n)) {
                            const t = 'groupchat' === n.type ? new C(n.from.bare) : n.from;
                            e.sendMessage({ acknowledged: n.id, body: '', to: t, type: n.type });
                        }
                    });
            }
            function Xr(e) {
                function t() {
                    const t = e.joiningRooms;
                    e.joiningRooms = {};
                    for (const n of Object.keys(t)) {
                        const i = t[n];
                        e.joinRoom(n, i);
                    }
                    const n = e.joinedRooms;
                    e.joinedRooms = {};
                    for (const t of Object.keys(n)) {
                        const i = n[t];
                        e.joinRoom(t, i);
                    }
                }
                e.disco.addFeature(ae),
                    e.disco.addFeature(ut),
                    e.disco.addFeature(_t),
                    (e.joinedRooms = {}),
                    (e.joiningRooms = {}),
                    e.on('session:started', t),
                    e.on('stream:management:resumed', t),
                    e.on('message', function(t) {
                        t.muc
                            ? t.muc.invite
                                ? e.emit('muc:invite', {
                                      from: t.muc.invite.from,
                                      password: t.muc.password,
                                      reason: t.muc.invite.reason,
                                      room: t.from,
                                      thread: t.muc.invite.thread,
                                      type: 'mediated'
                                  })
                                : t.muc.decline
                                ? e.emit('muc:declined', {
                                      from: t.muc.decline.from,
                                      reason: t.muc.decline.reason,
                                      room: t.from
                                  })
                                : e.emit('muc:other', { muc: t.muc, room: t.from, to: t.to })
                            : t.mucInvite &&
                              e.emit('muc:invite', {
                                  from: t.from,
                                  password: t.mucInvite.password,
                                  reason: t.mucInvite.reason,
                                  room: t.mucInvite.jid,
                                  thread: t.mucInvite.thread,
                                  type: 'direct'
                              }),
                            'groupchat' === t.type && t.subject && e.emit('muc:subject', t);
                    }),
                    e.on('presence', function(t) {
                        if (e.joiningRooms[t.from.bare] && 'error' === t.type)
                            delete e.joiningRooms[t.from.bare],
                                e.emit('muc:failed', t),
                                e.emit('muc:error', t);
                        else if (t.muc) {
                            const n = t.muc.codes && t.muc.codes.indexOf('110') >= 0;
                            'error' === t.type
                                ? e.emit('muc:error', t)
                                : 'unavailable' === t.type
                                ? (e.emit('muc:unavailable', t),
                                  n && (e.emit('muc:leave', t), delete e.joinedRooms[t.from.bare]),
                                  t.muc.destroyed &&
                                      e.emit('muc:destroyed', {
                                          newRoom: t.muc.destroyed.jid,
                                          password: t.muc.destroyed.password,
                                          reason: t.muc.destroyed.reason,
                                          room: t.from
                                      }))
                                : (e.emit('muc:available', t),
                                  n &&
                                      !e.joinedRooms[t.from.bare] &&
                                      (e.emit('muc:join', t),
                                      delete e.joiningRooms[t.from.bare],
                                      (e.joinedRooms[t.from.bare] = t.from.resource)));
                        }
                    }),
                    (e.joinRoom = function(e, t, n) {
                        ((n = n || {}).to = e + '/' + t),
                            (n.caps = this.disco.caps),
                            (n.joinMuc = n.joinMuc || {}),
                            (this.joiningRooms[e] = t),
                            this.sendPresence(n);
                    }),
                    (e.leaveRoom = function(e, t, n) {
                        ((n = n || {}).to = e + '/' + t),
                            (n.type = 'unavailable'),
                            this.sendPresence(n);
                    }),
                    (e.ban = function(t, n, i, r) {
                        e.setRoomAffiliation(t, n, 'outcast', i, r);
                    }),
                    (e.kick = function(t, n, i, r) {
                        e.setRoomRole(t, n, 'none', i, r);
                    }),
                    (e.invite = function(t, n) {
                        e.sendMessage({ muc: { invites: n }, to: t });
                    }),
                    (e.directInvite = function(t, n) {
                        (n.jid = t), e.sendMessage({ mucInvite: n, to: n.to });
                    }),
                    (e.declineInvite = function(t, n, i) {
                        e.sendMessage({ muc: { decline: { reason: i, to: n } }, to: t });
                    }),
                    (e.changeNick = function(t, n) {
                        e.sendPresence({ to: new C(t).bare + '/' + n });
                    }),
                    (e.setSubject = function(t, n) {
                        e.sendMessage({ subject: n, to: t, type: 'groupchat' });
                    }),
                    (e.discoverReservedNick = function(t, n) {
                        e.getDiscoInfo(t, 'x-roomuser-item', function(e, t) {
                            if (e) return n(e);
                            const i = t.discoInfo.identities[0] || {};
                            n(null, i.name);
                        });
                    }),
                    (e.requestRoomVoice = function(t) {
                        e.sendMessage({
                            form: {
                                fields: [
                                    {
                                        name: 'FORM_TYPE',
                                        value: 'http://jabber.org/protocol/muc#request'
                                    },
                                    { name: 'muc#role', type: 'text-single', value: 'participant' }
                                ]
                            },
                            to: t
                        });
                    }),
                    (e.setRoomAffiliation = function(e, t, n, i, r) {
                        return this.sendIq(
                            { mucAdmin: { affiliation: n, jid: t, reason: i }, to: e, type: 'set' },
                            r
                        );
                    }),
                    (e.setRoomRole = function(e, t, n, i, r) {
                        return this.sendIq(
                            { mucAdmin: { nick: t, reason: i, role: n }, to: e, type: 'set' },
                            r
                        );
                    }),
                    (e.getRoomMembers = function(e, t, n) {
                        return this.sendIq({ mucAdmin: t, to: e, type: 'get' }, n);
                    }),
                    (e.getRoomConfig = function(e, t) {
                        return this.sendIq({ mucOwner: !0, to: e, type: 'get' }, t);
                    }),
                    (e.configureRoom = function(e, t, n) {
                        return (
                            t.type || (t.type = 'submit'),
                            this.sendIq({ mucOwner: { form: t }, to: e, type: 'set' }, n)
                        );
                    }),
                    (e.destroyRoom = function(e, t, n) {
                        return this.sendIq({ mucOwner: { destroy: t }, to: e, type: 'set' }, n);
                    }),
                    (e.getUniqueRoomName = function(e, t) {
                        return this.sendIq({ mucUnique: !0, to: e, type: 'get' }, t);
                    });
            }
            function Qr(e) {
                e.disco.addFeature(Te),
                    e.disco.addFeature(Fe(Te)),
                    e.on('pubsub:event', function(t) {
                        t.event.updated &&
                            t.event.updated.node === Te &&
                            e.emit('mood', {
                                jid: t.from,
                                mood: t.event.updated.published[0].mood
                            });
                    }),
                    (e.publishMood = function(e, t, n) {
                        return this.publish('', Te, { mood: { text: t, value: e } }, n);
                    });
            }
            function Yr(e) {
                e.disco.addFeature($e),
                    e.disco.addFeature(Fe($e)),
                    e.on('pubsub:event', function(t) {
                        t.event.updated &&
                            t.event.updated.node === $e &&
                            e.emit('nick', {
                                jid: t.from,
                                nick: t.event.updated.published[0].nick
                            });
                    }),
                    (e.publishNick = function(e, t) {
                        return this.publish('', $e, { nick: e }, t);
                    });
            }
            function Gr(e) {
                e.disco.addFeature(Ze),
                    e.on('iq:get:ping', function(t) {
                        e.sendIq(t.resultReply());
                    }),
                    (e.ping = function(e, t) {
                        return this.sendIq({ ping: !0, to: e, type: 'get' }, t);
                    });
            }
            function $r(e) {
                (e.getPrivateData = function(e, t) {
                    return this.sendIq({ privateStorage: e, type: 'get' }, t);
                }),
                    (e.setPrivateData = function(e, t) {
                        return this.sendIq({ privateStorage: e, type: 'set' }, t);
                    });
            }
            function Hr(e) {
                e.disco.addFeature(Lt),
                    (e.enableNotifications = function(e, t, n, i) {
                        const r = [
                                {
                                    name: 'FORM_TYPE',
                                    value: 'http://jabber.org/protocol/pubsub#publish-options'
                                }
                            ],
                            s = { enablePush: { jid: e, node: t }, type: 'set' };
                        return (
                            n &&
                                n.length &&
                                (s.enablePush.form = { fields: r.concat(n), type: 'submit' }),
                            this.sendIq(s, i)
                        );
                    }),
                    (e.disableNotifications = function(e, t, n) {
                        const i = { disablePush: { jid: e }, type: 'set' };
                        return t && (i.disablePush.node = t), this.sendIq(i, n);
                    });
            }
            function Kr(e) {
                e.on('message', function(t) {
                    if (t.event) {
                        if (
                            (e.emit('pubsub:event', t), e.emit('pubsubEvent', t), t.event.updated)
                        ) {
                            const n = t.event.updated.published,
                                i = t.event.updated.retracted;
                            n && n.length && e.emit('pubsub:published', t),
                                i && i.length && e.emit('pubsub:retracted', t);
                        }
                        t.event.purged && e.emit('pubsub:purged', t),
                            t.event.deleted && e.emit('pubsub:deleted', t),
                            t.event.subscriptionChanged && e.emit('pubsub:subscription', t),
                            t.event.configurationChanged && e.emit('pubsub:config', t);
                    }
                    t.pubsub && t.pubsub.affiliations && e.emit('pubsub:affiliation', t);
                }),
                    (e.subscribeToNode = function(t, n, i) {
                        return (
                            'string' == typeof n && (n = { node: n }),
                            (n.jid = n.jid || e.jid),
                            this.sendIq({ pubsub: { subscribe: n }, to: t, type: 'set' }, i)
                        );
                    }),
                    (e.unsubscribeFromNode = function(t, n, i) {
                        return (
                            'string' == typeof n && (n = { node: n }),
                            (n.jid = n.jid || e.jid.bare),
                            this.sendIq({ pubsub: { unsubscribe: n }, to: t, type: 'set' }, i)
                        );
                    }),
                    (e.publish = function(e, t, n, i) {
                        return this.sendIq(
                            { pubsub: { publish: { item: n, node: t } }, to: e, type: 'set' },
                            i
                        );
                    }),
                    (e.getItem = function(e, t, n, i) {
                        return this.sendIq(
                            {
                                pubsub: { retrieve: { item: { id: n }, node: t } },
                                to: e,
                                type: 'get'
                            },
                            i
                        );
                    }),
                    (e.getItems = function(e, t, n, i) {
                        return (
                            ((n = n || {}).node = t),
                            this.sendIq(
                                {
                                    pubsub: { retrieve: { max: n.max, node: t }, rsm: n.rsm },
                                    to: e,
                                    type: 'get'
                                },
                                i
                            )
                        );
                    }),
                    (e.retract = function(e, t, n, i, r) {
                        return this.sendIq(
                            {
                                pubsub: { retract: { id: n, node: t, notify: i } },
                                to: e,
                                type: 'set'
                            },
                            r
                        );
                    }),
                    (e.purgeNode = function(e, t, n) {
                        return this.sendIq({ pubsubOwner: { purge: t }, to: e, type: 'set' }, n);
                    }),
                    (e.deleteNode = function(e, t, n) {
                        return this.sendIq({ pubsubOwner: { del: t }, to: e, type: 'set' }, n);
                    }),
                    (e.createNode = function(e, t, n, i) {
                        const r = { pubsub: { create: t }, to: e, type: 'set' };
                        return n && (r.pubsub.config = { form: n }), this.sendIq(r, i);
                    }),
                    (e.getSubscriptions = function(e, t, n) {
                        return (
                            (t = t || {}),
                            this.sendIq({ pubsub: { subscriptions: t }, to: e, type: 'get' }, n)
                        );
                    }),
                    (e.getAffiliations = function(e, t, n) {
                        return (
                            (t = t || {}),
                            this.sendIq({ pubsub: { affiliations: t }, to: e, type: 'get' }, n)
                        );
                    }),
                    (e.getNodeSubscribers = function(e, t, n, i) {
                        return (
                            ((n = n || {}).node = t),
                            this.sendIq(
                                { pubsubOwner: { subscriptions: n }, to: e, type: 'get' },
                                i
                            )
                        );
                    }),
                    (e.updateNodeSubscriptions = function(e, t, n, i) {
                        return this.sendIq(
                            {
                                pubsubOwner: { subscriptions: { list: n, node: t } },
                                to: e,
                                type: 'set'
                            },
                            i
                        );
                    }),
                    (e.getNodeAffiliations = function(e, t, n, i) {
                        return (
                            ((n = n || {}).node = t),
                            this.sendIq({ pubsubOwner: { affiliations: n }, to: e, type: 'get' }, i)
                        );
                    }),
                    (e.updateNodeAffiliations = function(e, t, n, i) {
                        return this.sendIq(
                            {
                                pubsubOwner: { affiliations: { list: n, node: t } },
                                to: e,
                                type: 'set'
                            },
                            i
                        );
                    });
            }
            function Wr(e) {
                e.disco.addFeature(De),
                    e.disco.addFeature(Fe(De)),
                    e.on('pubsub:event', function(t) {
                        t.event.updated &&
                            t.event.updated.node === De &&
                            e.emit('reachability', {
                                addresses: t.event.updated.published[0].reach,
                                jid: t.from
                            });
                    }),
                    e.on('presence', function(t) {
                        t.reach &&
                            t.reach.length &&
                            e.emit('reachability', { addresses: t.reach, jid: t.from });
                    }),
                    (e.publishReachability = function(e, t) {
                        return this.publish('', De, { reach: e }, t);
                    });
            }
            function Vr(e, t, n) {
                const i = !1 !== n.sendReceipts;
                e.disco.addFeature(Ke),
                    e.on('message', function(t) {
                        i &&
                            { chat: !0, headline: !0, normal: !0 }[t.type] &&
                            t.requestReceipt &&
                            !t.receipt &&
                            e.sendMessage({ id: t.id, receipt: t.id, to: t.from, type: t.type }),
                            t.receipt && (e.emit('receipt', t), e.emit('receipt:' + t.receipt));
                    });
            }
            function Jr(e) {
                (e.getAccountInfo = function(e, t) {
                    return this.sendIq({ register: !0, to: e, type: 'get' }, t);
                }),
                    (e.updateAccount = function(e, t, n) {
                        return this.sendIq({ register: t, to: e, type: 'set' }, n);
                    }),
                    (e.deleteAccount = function(e, t) {
                        return this.sendIq({ register: { remove: !0 }, to: e, type: 'set' }, t);
                    });
            }
            function Zr(e) {
                e.on('iq:set:roster', function(t) {
                    const n = { '': !0 };
                    if (((n[e.jid.bare] = !0), (n[e.jid.domain] = !0), !n[t.from.full]))
                        return e.sendIq(
                            t.errorReply({
                                error: { condition: 'service-unavailable', type: 'cancel' }
                            })
                        );
                    e.emit('roster:update', t), e.sendIq({ id: t.id, type: 'result' });
                }),
                    (e.getRoster = function(t) {
                        return e
                            .sendIq({ roster: { ver: this.config.rosterVer }, type: 'get' })
                            .then(e => {
                                if (e.roster) {
                                    const t = e.roster.ver;
                                    t && ((this.config.rosterVer = t), this.emit('roster:ver', t));
                                }
                                return e;
                            })
                            .then(
                                function(e) {
                                    return t && t(null, e), e;
                                },
                                function(e) {
                                    if (!t) throw e;
                                    t(e);
                                }
                            );
                    }),
                    (e.updateRosterItem = function(t, n) {
                        return e.sendIq({ roster: { items: [t] }, type: 'set' }, n);
                    }),
                    (e.removeRosterItem = function(t, n) {
                        return e.updateRosterItem({ jid: t, subscription: 'remove' }, n);
                    }),
                    (e.subscribe = function(t) {
                        e.sendPresence({ type: 'subscribe', to: t });
                    }),
                    (e.unsubscribe = function(t) {
                        e.sendPresence({ type: 'unsubscribe', to: t });
                    }),
                    (e.acceptSubscription = function(t) {
                        e.sendPresence({ type: 'subscribed', to: t });
                    }),
                    (e.denySubscription = function(t) {
                        e.sendPresence({ type: 'unsubscribed', to: t });
                    });
            }
            function es(e) {
                e.disco.addFeature(bt),
                    e.on('message', function(t) {
                        t.rtt && (e.emit('rtt', t), e.emit('rtt:' + t.rtt.event, t));
                    });
            }
            function ts(e) {
                e.disco.addFeature(et),
                    (e.getTime = function(e, t) {
                        return this.sendIq({ time: !0, to: e, type: 'get' }, t);
                    }),
                    e.on('iq:get:time', function(t) {
                        const n = new Date();
                        e.sendIq(t.resultReply({ time: { tzo: n.getTimezoneOffset(), utc: n } }));
                    });
            }
            function ns(e) {
                e.disco.addFeature('vcard-temp'),
                    (e.getVCard = function(e, t) {
                        return this.sendIq({ to: e, type: 'get', vCardTemp: !0 }, t);
                    }),
                    (e.publishVCard = function(e, t) {
                        return this.sendIq({ type: 'set', vCardTemp: e }, t);
                    });
            }
            function is(e) {
                e.disco.addFeature('jabber:iq:version'),
                    e.on('iq:get:version', function(t) {
                        e.sendIq(
                            t.resultReply({
                                version: e.config.softwareVersion || { name: 'stanza.io' }
                            })
                        );
                    }),
                    (e.getSoftwareVersion = function(e, t) {
                        return this.sendIq({ to: e, type: 'get', version: !0 }, t);
                    });
            }
            function rs(e) {
                e.use(Gi),
                    e.use($i),
                    e.use(Hi),
                    e.use(Ki),
                    e.use(Wi),
                    e.use(Vi),
                    e.use(Ji),
                    e.use(Zi),
                    e.use(er),
                    e.use(tr),
                    e.use(nr),
                    e.use(ir),
                    e.use(rr),
                    e.use(sr),
                    e.use(or),
                    e.use(ar),
                    e.use(ur),
                    e.use(Dr),
                    e.use(qr),
                    e.use(Fr),
                    e.use(Ur),
                    e.use(zr),
                    e.use(Xr),
                    e.use(Qr),
                    e.use(Yr),
                    e.use(Gr),
                    e.use($r),
                    e.use(Hr),
                    e.use(Kr),
                    e.use(Wr),
                    e.use(Vr),
                    e.use(Jr),
                    e.use(Zr),
                    e.use(es),
                    e.use(ts),
                    e.use(ns),
                    e.use(is);
            }
            t.VERSION = '__STANZAIO_VERSION__';
            const ss = C;
            (t.JID = ss),
                (t.createClient = function(e) {
                    const t = new zi(e);
                    return t.use(rs), t;
                });
        }.call(this, n(2).Buffer, n(4), n(3)));
    },
    function(e, t, n) {
        'use strict';
        (t.byteLength = function(e) {
            var t = c(e),
                n = t[0],
                i = t[1];
            return (3 * (n + i)) / 4 - i;
        }),
            (t.toByteArray = function(e) {
                for (
                    var t,
                        n = c(e),
                        i = n[0],
                        o = n[1],
                        a = new s(
                            (function(e, t, n) {
                                return (3 * (t + n)) / 4 - n;
                            })(0, i, o)
                        ),
                        u = 0,
                        l = o > 0 ? i - 4 : i,
                        f = 0;
                    f < l;
                    f += 4
                )
                    (t =
                        (r[e.charCodeAt(f)] << 18) |
                        (r[e.charCodeAt(f + 1)] << 12) |
                        (r[e.charCodeAt(f + 2)] << 6) |
                        r[e.charCodeAt(f + 3)]),
                        (a[u++] = (t >> 16) & 255),
                        (a[u++] = (t >> 8) & 255),
                        (a[u++] = 255 & t);
                2 === o &&
                    ((t = (r[e.charCodeAt(f)] << 2) | (r[e.charCodeAt(f + 1)] >> 4)),
                    (a[u++] = 255 & t));
                1 === o &&
                    ((t =
                        (r[e.charCodeAt(f)] << 10) |
                        (r[e.charCodeAt(f + 1)] << 4) |
                        (r[e.charCodeAt(f + 2)] >> 2)),
                    (a[u++] = (t >> 8) & 255),
                    (a[u++] = 255 & t));
                return a;
            }),
            (t.fromByteArray = function(e) {
                for (var t, n = e.length, r = n % 3, s = [], o = 0, a = n - r; o < a; o += 16383)
                    s.push(l(e, o, o + 16383 > a ? a : o + 16383));
                1 === r
                    ? ((t = e[n - 1]), s.push(i[t >> 2] + i[(t << 4) & 63] + '=='))
                    : 2 === r &&
                      ((t = (e[n - 2] << 8) + e[n - 1]),
                      s.push(i[t >> 10] + i[(t >> 4) & 63] + i[(t << 2) & 63] + '='));
                return s.join('');
            });
        for (
            var i = [],
                r = [],
                s = 'undefined' != typeof Uint8Array ? Uint8Array : Array,
                o = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
                a = 0,
                u = o.length;
            a < u;
            ++a
        )
            (i[a] = o[a]), (r[o.charCodeAt(a)] = a);
        function c(e) {
            var t = e.length;
            if (t % 4 > 0) throw new Error('Invalid string. Length must be a multiple of 4');
            var n = e.indexOf('=');
            return -1 === n && (n = t), [n, n === t ? 0 : 4 - (n % 4)];
        }
        function l(e, t, n) {
            for (var r, s, o = [], a = t; a < n; a += 3)
                (r = ((e[a] << 16) & 16711680) + ((e[a + 1] << 8) & 65280) + (255 & e[a + 2])),
                    o.push(
                        i[((s = r) >> 18) & 63] + i[(s >> 12) & 63] + i[(s >> 6) & 63] + i[63 & s]
                    );
            return o.join('');
        }
        (r['-'.charCodeAt(0)] = 62), (r['_'.charCodeAt(0)] = 63);
    },
    function(e, t) {
        (t.read = function(e, t, n, i, r) {
            var s,
                o,
                a = 8 * r - i - 1,
                u = (1 << a) - 1,
                c = u >> 1,
                l = -7,
                f = n ? r - 1 : 0,
                d = n ? -1 : 1,
                h = e[t + f];
            for (
                f += d, s = h & ((1 << -l) - 1), h >>= -l, l += a;
                l > 0;
                s = 256 * s + e[t + f], f += d, l -= 8
            );
            for (
                o = s & ((1 << -l) - 1), s >>= -l, l += i;
                l > 0;
                o = 256 * o + e[t + f], f += d, l -= 8
            );
            if (0 === s) s = 1 - c;
            else {
                if (s === u) return o ? NaN : (1 / 0) * (h ? -1 : 1);
                (o += Math.pow(2, i)), (s -= c);
            }
            return (h ? -1 : 1) * o * Math.pow(2, s - i);
        }),
            (t.write = function(e, t, n, i, r, s) {
                var o,
                    a,
                    u,
                    c = 8 * s - r - 1,
                    l = (1 << c) - 1,
                    f = l >> 1,
                    d = 23 === r ? Math.pow(2, -24) - Math.pow(2, -77) : 0,
                    h = i ? 0 : s - 1,
                    p = i ? 1 : -1,
                    m = t < 0 || (0 === t && 1 / t < 0) ? 1 : 0;
                for (
                    t = Math.abs(t),
                        isNaN(t) || t === 1 / 0
                            ? ((a = isNaN(t) ? 1 : 0), (o = l))
                            : ((o = Math.floor(Math.log(t) / Math.LN2)),
                              t * (u = Math.pow(2, -o)) < 1 && (o--, (u *= 2)),
                              (t += o + f >= 1 ? d / u : d * Math.pow(2, 1 - f)) * u >= 2 &&
                                  (o++, (u /= 2)),
                              o + f >= l
                                  ? ((a = 0), (o = l))
                                  : o + f >= 1
                                  ? ((a = (t * u - 1) * Math.pow(2, r)), (o += f))
                                  : ((a = t * Math.pow(2, f - 1) * Math.pow(2, r)), (o = 0)));
                    r >= 8;
                    e[n + h] = 255 & a, h += p, a /= 256, r -= 8
                );
                for (o = (o << r) | a, c += r; c > 0; e[n + h] = 255 & o, h += p, o /= 256, c -= 8);
                e[n + h - p] |= 128 * m;
            });
    },
    function(e, t, n) {
        var i,
            r,
            s = n(22),
            o = n(23),
            a = 0,
            u = 0;
        e.exports = function(e, t, n) {
            var c = (t && n) || 0,
                l = t || [],
                f = (e = e || {}).node || i,
                d = void 0 !== e.clockseq ? e.clockseq : r;
            if (null == f || null == d) {
                var h = s();
                null == f && (f = i = [1 | h[0], h[1], h[2], h[3], h[4], h[5]]),
                    null == d && (d = r = 16383 & ((h[6] << 8) | h[7]));
            }
            var p = void 0 !== e.msecs ? e.msecs : new Date().getTime(),
                m = void 0 !== e.nsecs ? e.nsecs : u + 1,
                g = p - a + (m - u) / 1e4;
            if (
                (g < 0 && void 0 === e.clockseq && (d = (d + 1) & 16383),
                (g < 0 || p > a) && void 0 === e.nsecs && (m = 0),
                m >= 1e4)
            )
                throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
            (a = p), (u = m), (r = d);
            var b = (1e4 * (268435455 & (p += 122192928e5)) + m) % 4294967296;
            (l[c++] = (b >>> 24) & 255),
                (l[c++] = (b >>> 16) & 255),
                (l[c++] = (b >>> 8) & 255),
                (l[c++] = 255 & b);
            var y = ((p / 4294967296) * 1e4) & 268435455;
            (l[c++] = (y >>> 8) & 255),
                (l[c++] = 255 & y),
                (l[c++] = ((y >>> 24) & 15) | 16),
                (l[c++] = (y >>> 16) & 255),
                (l[c++] = (d >>> 8) | 128),
                (l[c++] = 255 & d);
            for (var v = 0; v < 6; ++v) l[c + v] = f[v];
            return t || o(l);
        };
    },
    function(e, t, n) {
        var i = n(22),
            r = n(23);
        e.exports = function(e, t, n) {
            var s = (t && n) || 0;
            'string' == typeof e && ((t = 'binary' === e ? new Array(16) : null), (e = null));
            var o = (e = e || {}).random || (e.rng || i)();
            if (((o[6] = (15 & o[6]) | 64), (o[8] = (63 & o[8]) | 128), t))
                for (var a = 0; a < 16; ++a) t[s + a] = o[a];
            return t || r(o);
        };
    },
    function(e, t, n) {
        'use strict';
        Object.defineProperty(t, '__esModule', { value: !0 });
        const i = n(8),
            r = i.__importStar(n(21)),
            s = i.__importStar(n(48)),
            o = i.__importStar(n(12)),
            a = i.__importDefault(n(56));
        class u {
            constructor() {
                (this._LOOKUP = {}),
                    (this._LOOKUP_EXT = {}),
                    (this._TAGS = {}),
                    (this._CB_DEFINITION = {}),
                    (this._CB_TAG = {}),
                    (this._ID = r.v4()),
                    (this.utils = Object.assign({}, s, o));
            }
            use(e) {
                return e && 'function' == typeof e
                    ? (e['__JXT_LOADED_' + this._ID] ||
                          (e(this), (e['__JXT_LOADED_' + this._ID] = !0)),
                      this)
                    : this;
            }
            getDefinition(e, t, n) {
                const i = this._LOOKUP[t + '|' + e];
                if (n && !i)
                    throw new Error(
                        'Could not find definition for <' + e + ' xmlns="' + t + '" />'
                    );
                return i;
            }
            getExtensions(e, t) {
                return this._LOOKUP_EXT[t + '|' + e] || {};
            }
            withDefinition(e, t, n) {
                const i = t + '|' + e;
                this._CB_DEFINITION[i] || (this._CB_DEFINITION[i] = []),
                    this._CB_DEFINITION[i].push(n),
                    this._LOOKUP[i] && n(this._LOOKUP[i]);
            }
            withTag(e, t) {
                this._CB_TAG[e] || (this._CB_TAG[e] = []),
                    this._CB_TAG[e].push(t),
                    this.tagged(e).forEach(function(e) {
                        t(e);
                    });
            }
            tagged(e) {
                return this._TAGS[e] || [];
            }
            build(e) {
                const t = this.getDefinition(e.localName, e.namespaceURI);
                if (t) return new t(null, e);
            }
            parse(e) {
                const t = o.parse(e);
                if (t) return this.build(t);
            }
            extend(e, t, n, i) {
                const r = e.prototype._NS + '|' + e.prototype._EL,
                    o = t.prototype._name,
                    a = t.prototype._NS + '|' + t.prototype._EL;
                (this._LOOKUP[a] = t),
                    this._LOOKUP_EXT[a] || (this._LOOKUP_EXT[a] = {}),
                    this._LOOKUP_EXT[r] || (this._LOOKUP_EXT[r] = {}),
                    (this._LOOKUP_EXT[r][o] = t),
                    (!n || (n && !i)) && this.add(e, o, s.extension(t)),
                    n && this.add(e, n, s.multiExtension(t));
            }
            add(e, t, n) {
                (n.enumerable = !0), Object.defineProperty(e.prototype, t, n);
            }
            define(e) {
                const t = this,
                    n = a.default(this, e),
                    i = n.prototype._NS,
                    r = n.prototype._EL,
                    s = n.prototype._TAGS,
                    o = i + '|' + r;
                return (
                    (this._LOOKUP[o] = n),
                    s.forEach(function(e) {
                        t._TAGS[e] || (t._TAGS[e] = []), t._TAGS[e].push(n);
                    }),
                    Object.keys(e.fields || {}).forEach(function(i) {
                        t.add(n, i, e.fields[i]);
                    }),
                    this._CB_DEFINITION[o] &&
                        this._CB_DEFINITION[o].forEach(function(e) {
                            e(n);
                        }),
                    s.forEach(function(e) {
                        t._CB_TAG[e] &&
                            t._CB_TAG[e].forEach(function(e) {
                                e(n);
                            });
                    }),
                    n
                );
            }
            static createRegistry() {
                return new u();
            }
        }
        Object.assign(u, o),
            Object.assign(u, s),
            (t.createRegistry = function() {
                return new u();
            }),
            (t.default = u);
    },
    function(e, t, n) {
        'use strict';
        (function(e) {
            Object.defineProperty(t, '__esModule', { value: !0 });
            const i = n(8).__importStar(n(12)),
                r = i.find,
                s = i.createElement,
                o = (t.field = function(e, t) {
                    return function() {
                        const n = Array.prototype.slice.call(arguments);
                        return {
                            get: function() {
                                return e.apply(null, [this.xml].concat(n));
                            },
                            set: function(e) {
                                t.apply(null, [this.xml].concat(n).concat([e]));
                            }
                        };
                    };
                });
            (t.boolAttribute = o(i.getBoolAttribute, i.setBoolAttribute)),
                (t.subAttribute = o(i.getSubAttribute, i.setSubAttribute)),
                (t.boolSubAttribute = o(i.getSubBoolAttribute, i.setSubBoolAttribute)),
                (t.text = o(i.getText, i.setText)),
                (t.subText = o(i.getSubText, i.setSubText)),
                (t.textSub = t.subText),
                (t.multiTextSub = t.multiSubText = o(i.getMultiSubText, i.setMultiSubText)),
                (t.multiSubAttribute = o(i.getMultiSubAttribute, i.setMultiSubAttribute)),
                (t.subLangText = o(i.getSubLangText, i.setSubLangText)),
                (t.langTextSub = t.subLangText),
                (t.boolSub = o(i.getBoolSub, i.setBoolSub)),
                (t.langAttribute = o(
                    function(e) {
                        return e.getAttributeNS(i.XML_NS, 'lang') || '';
                    },
                    function(e, t) {
                        e.setAttributeNS(i.XML_NS, 'lang', t);
                    }
                )),
                (t.b64Text = o(
                    function(t) {
                        return t.textContent && '=' !== t.textContent
                            ? e.from(t.textContent, 'base64')
                            : '';
                    },
                    function(t, n) {
                        if ('string' == typeof n) {
                            const i = e.from(n).toString('base64');
                            t.textContent = i || '=';
                        } else t.textContent = '';
                    }
                )),
                (t.dateAttribute = function(e, t) {
                    return {
                        get: function() {
                            const n = i.getAttribute(this.xml, e);
                            return n ? new Date(n) : t ? new Date(Date.now()) : void 0;
                        },
                        set: function(t) {
                            t &&
                                ('string' != typeof t && (t = t.toISOString()),
                                i.setAttribute(this.xml, e, t));
                        }
                    };
                }),
                (t.dateSub = function(e, t, n) {
                    return {
                        get: function() {
                            const r = i.getSubText(this.xml, e, t);
                            return r ? new Date(r) : n ? new Date(Date.now()) : void 0;
                        },
                        set: function(n) {
                            n &&
                                ('string' != typeof n && (n = n.toISOString()),
                                i.setSubText(this.xml, e, t, n));
                        }
                    };
                }),
                (t.dateSubAttribute = function(e, t, n, r) {
                    return {
                        get: function() {
                            const s = i.getSubAttribute(this.xml, e, t, n);
                            return s ? new Date(s) : r ? new Date(Date.now()) : void 0;
                        },
                        set: function(r) {
                            r &&
                                ('string' != typeof r && (r = r.toISOString()),
                                i.setSubAttribute(this.xml, e, t, n, r));
                        }
                    };
                }),
                (t.numberAttribute = function(e, t, n) {
                    return {
                        get: function() {
                            const r = t ? parseFloat : parseInt,
                                s = i.getAttribute(this.xml, e, '');
                            if (!s) return n;
                            const o = r(s, 10);
                            return isNaN(o) ? n : o;
                        },
                        set: function(t) {
                            i.setAttribute(this.xml, e, t.toString());
                        }
                    };
                }),
                (t.numberSub = function(e, t, n, r) {
                    return {
                        get: function() {
                            const s = n ? parseFloat : parseInt,
                                o = i.getSubText(this.xml, e, t, '');
                            if (!o) return r;
                            const a = s(o, 10);
                            return isNaN(a) ? r : a;
                        },
                        set: function(n) {
                            i.setSubText(this.xml, e, t, n.toString());
                        }
                    };
                }),
                (t.numberSubAttribute = function(e, t, n, r, s) {
                    return {
                        get: function() {
                            const o = r ? parseFloat : parseInt,
                                a = i.getSubAttribute(this.xml, e, t, n, '');
                            if (!a) return s;
                            const u = o(a, 10);
                            return isNaN(u) ? s : u;
                        },
                        set: function(r) {
                            i.setSubAttribute(this.xml, e, t, n, r.toString());
                        }
                    };
                }),
                (t.attribute = function(e, t) {
                    return {
                        get: function() {
                            return i.getAttribute(this.xml, e, t);
                        },
                        set: function(t) {
                            i.setAttribute(this.xml, e, t);
                        }
                    };
                }),
                (t.attributeNS = function(e, t, n) {
                    return {
                        get: function() {
                            return i.getAttributeNS(this.xml, e, t, n);
                        },
                        set: function(n) {
                            i.setAttributeNS(this.xml, e, t, n);
                        }
                    };
                }),
                (t.extension = function(e) {
                    return {
                        get: function() {
                            const t = this,
                                n = e.prototype._name;
                            if (!this._extensions[n]) {
                                const i = r(this.xml, e.prototype._NS, e.prototype._EL);
                                i.length
                                    ? (this._extensions[n] = new e(null, i[0], t))
                                    : ((this._extensions[n] = new e({}, null, t)),
                                      this.xml.appendChild(this._extensions[n].xml)),
                                    (this._extensions[n].parent = this);
                            }
                            return this._extensions[n];
                        },
                        set: function(t) {
                            if (t) {
                                const n = this[e.prototype._name];
                                !0 === t && (t = {}), Object.assign(n, t);
                            }
                        }
                    };
                }),
                (t.multiExtension = function(e) {
                    return {
                        get: function() {
                            const t = this,
                                n = r(this.xml, e.prototype._NS, e.prototype._EL),
                                i = [];
                            for (let r = 0, s = n.length; r < s; r++) i.push(new e({}, n[r], t));
                            return i;
                        },
                        set: function(t) {
                            t = t || [];
                            const n = this,
                                i = r(this.xml, e.prototype._NS, e.prototype._EL);
                            let s, o;
                            for (s = 0, o = i.length; s < o; s++) n.xml.removeChild(i[s]);
                            for (s = 0, o = t.length; s < o; s++) {
                                const i = new e(t[s], null, n);
                                n.xml.appendChild(i.xml);
                            }
                        }
                    };
                }),
                (t.enumSub = function(e, t) {
                    return {
                        get: function() {
                            const n = this,
                                i = [];
                            return (
                                t.forEach(function(t) {
                                    const s = r(n.xml, e, t);
                                    s.length && i.push(s[0].nodeName);
                                }),
                                i[0] || ''
                            );
                        },
                        set: function(n) {
                            const i = this;
                            let o = !1;
                            if (
                                (t.forEach(function(t) {
                                    const s = r(i.xml, e, t);
                                    s.length && (t === n ? (o = !0) : i.xml.removeChild(s[0]));
                                }),
                                n && !o)
                            ) {
                                const t = s(e, n);
                                this.xml.appendChild(t);
                            }
                        }
                    };
                }),
                (t.subExtension = function(e, t, n, i) {
                    return {
                        get: function() {
                            if (!this._extensions[e]) {
                                let o = r(this.xml, t, n);
                                o.length
                                    ? (o = o[0])
                                    : ((o = s(t, n, this._NS)), this.xml.appendChild(o));
                                const a = r(o, i.prototype._NS, i.prototype._EL);
                                a.length
                                    ? (this._extensions[e] = new i(null, a[0], { xml: o }))
                                    : ((this._extensions[e] = new i({}, null, { xml: o })),
                                      o.appendChild(this._extensions[e].xml)),
                                    (this._extensions[e].parent = this);
                            }
                            return this._extensions[e];
                        },
                        set: function(i) {
                            const s = r(this.xml, t, n);
                            if ((s.length && !i && this.xml.removeChild(s[0]), i)) {
                                const t = this[e];
                                !0 === i && (i = {}), Object.assign(t, i);
                            }
                        }
                    };
                }),
                (t.subMultiExtension = function(e, t, n) {
                    return {
                        get: function() {
                            const i = this,
                                s = [];
                            let o = r(this.xml, e, t);
                            return o.length
                                ? ((o = o[0]),
                                  r(o, n.prototype._NS, n.prototype._EL).forEach(function(e) {
                                      s.push(new n({}, e, i));
                                  }),
                                  s)
                                : s;
                        },
                        set: function(i) {
                            const o = this;
                            let a = r(this.xml, e, t);
                            a.length && o.xml.removeChild(a[0]),
                                i.length &&
                                    ((a = s(e, t, this._NS)),
                                    i.forEach(function(t) {
                                        const i = new n(t, null, { xml: { namespaceURI: e } });
                                        a.appendChild(i.xml);
                                    }),
                                    o.xml.appendChild(a));
                        }
                    };
                });
        }.call(this, n(2).Buffer));
    },
    function(e, t, n) {
        'use strict';
        var i = n(24),
            r = n(25),
            s = n(11),
            o = n(9),
            a = n(26),
            u = n(51),
            c = n(52),
            l = n(28),
            f = n(53),
            d = n(27),
            h = n(54);
        ((t = e.exports = function() {
            return c.apply(null, arguments);
        }).Element = o),
            (t.equal = a.equal),
            (t.nameEqual = a.name),
            (t.attrsEqual = a.attrs),
            (t.childrenEqual = a.children),
            (t.isNode = f.isNode),
            (t.isElement = f.isElement),
            (t.isText = f.isText),
            (t.clone = d),
            (t.createElement = u),
            (t.escapeXML = s.escapeXML),
            (t.unescapeXML = s.unescapeXML),
            (t.escapeXMLText = s.escapeXMLText),
            (t.unescapeXMLText = s.unescapeXMLText),
            (t.Parser = r),
            (t.parse = i),
            (t.tag = c),
            (t.tagString = l),
            (t.stringify = h);
    },
    function(e, t, n) {
        'use strict';
        var i = n(0),
            r = n(6).EventEmitter,
            s = n(11).unescapeXML,
            o = (e.exports = function() {
                r.call(this);
                var e,
                    t,
                    n,
                    i,
                    o,
                    a,
                    u,
                    c,
                    l = 0,
                    f = 0;
                (this._handleTagOpening = function(e, t, n) {
                    e
                        ? this.emit('endElement', t)
                        : (this.emit('startElement', t, n), o && this.emit('endElement', t));
                }),
                    (this.write = function(r) {
                        'string' != typeof r && (r = r.toString());
                        var d = 0;
                        function h() {
                            if ('number' == typeof f) {
                                var e = r.substring(f, d);
                                return (f = void 0), e;
                            }
                        }
                        for (e && ((r = e + r), (d += e.length), (e = null)); d < r.length; d++) {
                            if (0 === l) {
                                var p = r.indexOf('<', d);
                                -1 !== p && d !== p && (d = p);
                            } else if (8 === l) {
                                var m = r.indexOf(u, d);
                                -1 !== m && (d = m);
                            } else if (1 === l) {
                                var g = r.indexOf('--\x3e', d);
                                -1 !== g && (d = g + 2);
                            }
                            var b = r.charCodeAt(d);
                            switch (l) {
                                case 0:
                                    if (60 === b) {
                                        var y = h();
                                        y && this.emit('text', s(y)),
                                            (l = 3),
                                            (f = d + 1),
                                            (n = {});
                                    }
                                    break;
                                case 9:
                                    if (93 === b && ']>' === r.substr(d + 1, 2)) {
                                        var v = h();
                                        v && this.emit('text', v), (l = 1);
                                    }
                                    break;
                                case 3:
                                    47 === b && f === d
                                        ? ((f = d + 1), (i = !0))
                                        : 33 === b
                                        ? '[CDATA[' === r.substr(d + 1, 7)
                                            ? ((f = d + 8), (l = 9))
                                            : ((f = void 0), (l = 1))
                                        : 63 === b
                                        ? ((f = void 0), (l = 2))
                                        : (b <= 32 || 47 === b || 62 === b) &&
                                          ((t = h()), d--, (l = 4));
                                    break;
                                case 1:
                                    if (62 === b) {
                                        var x = r.charCodeAt(d - 1),
                                            w = r.charCodeAt(d - 2);
                                        ((45 === x && 45 === w) || (93 === x && 93 === w)) &&
                                            (l = 0);
                                    }
                                    break;
                                case 2:
                                    if (62 === b) 63 === r.charCodeAt(d - 1) && (l = 0);
                                    break;
                                case 4:
                                    62 === b
                                        ? (this._handleTagOpening(i, t, n),
                                          (t = void 0),
                                          (n = void 0),
                                          (i = void 0),
                                          (o = void 0),
                                          (l = 0),
                                          (f = d + 1))
                                        : 47 === b
                                        ? (o = !0)
                                        : b > 32 && ((f = d), (l = 5));
                                    break;
                                case 5:
                                    (b <= 32 || 61 === b) && ((c = h()), d--, (l = 6));
                                    break;
                                case 6:
                                    61 === b && (l = 7);
                                    break;
                                case 7:
                                    (34 !== b && 39 !== b) ||
                                        ((a = b), (u = 34 === b ? '"' : "'"), (l = 8), (f = d + 1));
                                    break;
                                case 8:
                                    if (b === a) {
                                        var _ = s(h());
                                        (n[c] = _), (c = void 0), (l = 4);
                                    }
                            }
                        }
                        'number' == typeof f && f <= r.length && ((e = r.slice(f)), (f = 0));
                    });
            });
        i(o, r),
            (o.prototype.end = function(e) {
                e && this.write(e), (this.write = function() {});
            });
    },
    function(e, t, n) {
        'use strict';
        var i = n(9);
        e.exports = function(e, t) {
            for (var n = new i(e, t), r = 2; r < arguments.length; r++) {
                var s = arguments[r];
                s && n.cnode(s);
            }
            return n;
        };
    },
    function(e, t, n) {
        'use strict';
        var i = n(28),
            r = n(24);
        e.exports = function() {
            return r(i.apply(null, arguments));
        };
    },
    function(e, t, n) {
        'use strict';
        var i = n(9);
        (e.exports.isNode = function(e) {
            return e instanceof i || 'string' == typeof e;
        }),
            (e.exports.isElement = function(e) {
                return e instanceof i;
            }),
            (e.exports.isText = function(e) {
                return 'string' == typeof e;
            });
    },
    function(e, t, n) {
        'use strict';
        e.exports = function e(t, n, i) {
            'number' == typeof n && (n = ' '.repeat(n)), i || (i = 1);
            var r = '';
            return (
                (r += '<' + t.name),
                Object.keys(t.attrs).forEach(function(e) {
                    r += ' ' + e + '="' + t.attrs[e] + '"';
                }),
                t.children.length
                    ? ((r += '>'),
                      t.children.forEach(function(t, s) {
                          n && (r += '\n' + n.repeat(i)),
                              (r += 'string' == typeof t ? t : e(t, n, i + 1));
                      }),
                      n && (r += '\n' + n.repeat(i - 1)),
                      (r += '</' + t.name + '>'))
                    : (r += '/>'),
                r
            );
        };
    },
    function(e, t, n) {
        'use strict';
        var i = n(0),
            r = n(9);
        function s(e, t) {
            r.call(this, e, t), (this.nodeType = 1), (this.nodeName = this.localName);
        }
        i(s, r),
            (s.prototype._getElement = function(e, t) {
                return new s(e, t);
            }),
            Object.defineProperty(s.prototype, 'localName', {
                get: function() {
                    return this.getName();
                }
            }),
            Object.defineProperty(s.prototype, 'namespaceURI', {
                get: function() {
                    return this.getNS();
                }
            }),
            Object.defineProperty(s.prototype, 'parentNode', {
                get: function() {
                    return this.parent;
                }
            }),
            Object.defineProperty(s.prototype, 'childNodes', {
                get: function() {
                    return this.children;
                }
            }),
            Object.defineProperty(s.prototype, 'textContent', {
                get: function() {
                    return this.getText();
                },
                set: function(e) {
                    this.children.push(e);
                }
            }),
            (s.prototype.getElementsByTagName = function(e) {
                return this.getChildren(e);
            }),
            (s.prototype.getAttribute = function(e) {
                return this.getAttr(e);
            }),
            (s.prototype.setAttribute = function(e, t) {
                this.attr(e, t);
            }),
            (s.prototype.getAttributeNS = function(e, t) {
                return 'http://www.w3.org/XML/1998/namespace' === e
                    ? this.getAttr(['xml', t].join(':'))
                    : this.getAttr(t, e);
            }),
            (s.prototype.setAttributeNS = function(e, t, n) {
                var i;
                'http://www.w3.org/XML/1998/namespace' === e
                    ? (i = 'xml')
                    : (i = this.getXmlns()[e] || '');
                i && this.attr([i, t].join(':'), n);
            }),
            (s.prototype.removeAttribute = function(e) {
                this.attr(e, null);
            }),
            (s.prototype.removeAttributeNS = function(e, t) {
                var n;
                'http://www.w3.org/XML/1998/namespace' === e
                    ? (n = 'xml')
                    : (n = this.getXmlns()[e] || '');
                n && this.attr([n, t].join(':'), null);
            }),
            (s.prototype.appendChild = function(e) {
                this.cnode(e);
            }),
            (s.prototype.removeChild = function(e) {
                this.remove(e);
            }),
            (s.createElement = function(e, t) {
                var n = new s(e, t);
                return (
                    Array.prototype.slice.call(arguments, 2).forEach(function(e) {
                        n.appendChild(e);
                    }),
                    n
                );
            }),
            (e.exports = s);
    },
    function(e, t, n) {
        'use strict';
        Object.defineProperty(t, '__esModule', { value: !0 });
        const i = n(8).__importStar(n(12)),
            r = { constructor: !0, parent: !0, prototype: !0, toJSON: !0, toString: !0, xml: !0 };
        t.default = function(e, t) {
            class n {
                constructor(n, r, s) {
                    const o = this,
                        a = ((r || {}).parentNode || (s || {}).xml || {}).namespaceURI;
                    (o.xml = r || i.createElement(o._NS, o._EL, a)),
                        Object.keys(o._PREFIXES).forEach(function(e) {
                            const t = o._PREFIXES[e];
                            o.xml.setAttribute('xmlns:' + e, t);
                        }),
                        (o._extensions = {});
                    for (let t = 0, n = o.xml.childNodes.length; t < n; t++) {
                        const n = o.xml.childNodes[t],
                            i = e.getDefinition(n.localName, n.namespaceURI);
                        if (void 0 !== i) {
                            const e = i.prototype._name;
                            (o._extensions[e] = new i(null, n)), (o._extensions[e].parent = o);
                        }
                    }
                    const u = Object.getPrototypeOf(o);
                    for (const e of Object.keys(n || {})) {
                        const t = Object.getOwnPropertyDescriptor(u, e);
                        t.set && t.set.call(o, n[e]);
                    }
                    return t.init && t.init.apply(o, [n]), o;
                }
                toString() {
                    return this.xml.toString();
                }
                toJSON() {
                    let t;
                    const n = {};
                    for (t of Object.keys(this._extensions))
                        this._extensions[t].toJSON &&
                            '_' !== t[0] &&
                            (n[t] = this._extensions[t].toJSON());
                    for (t in this) {
                        const i = !r[t] && '_' !== t[0],
                            s = e.getExtensions(this._EL, this._NS)[t];
                        if (i && !s) {
                            const e = this[t];
                            if ('function' == typeof e) continue;
                            const i = Object.prototype.toString.call(e);
                            if (i.indexOf('Object') >= 0)
                                Object.keys(e).length > 0 &&
                                    (e._isJXT ? (n[t] = e.toJSON()) : (n[t] = e));
                            else if (i.indexOf('Array') >= 0) {
                                if (e.length > 0) {
                                    const i = [],
                                        r = e.length;
                                    for (let t = 0; t < r; t++) {
                                        const n = e[t];
                                        void 0 !== n && (n._isJXT ? i.push(n.toJSON()) : i.push(n));
                                    }
                                    n[t] = i;
                                }
                            } else void 0 !== e && !1 !== e && '' !== e && (n[t] = e);
                        }
                    }
                    return n;
                }
            }
            return (
                (n.prototype._isJXT = !0),
                (n.prototype._name = t.name),
                (n.prototype._eventname = t.eventName),
                (n.prototype._NS = t.namespace),
                (n.prototype._EL = t.element || t.name),
                (n.prototype._PREFIXES = t.prefixes || {}),
                (n.prototype._TAGS = t.tags || []),
                n
            );
        };
    },
    function(e, t, n) {
        var i = n(58),
            r = n(72),
            s = n(75),
            o = n(76),
            a = {
                md2: 'md2',
                md5: 'md5',
                'sha-1': 'sha1',
                'sha-224': 'sha224',
                'sha-256': 'sha256',
                'sha-384': 'sha384',
                'sha-512': 'sha512'
            },
            u = Object.keys(a);
        (t.getHashes = function() {
            for (var e = [], t = o(), n = 0, i = u.length; n < i; n++)
                t.indexOf(a[u[n]]) >= 0 && e.push(u[n]);
            return e;
        }),
            (t.createHash = function(e) {
                return (e = e.toLowerCase()), a[e] && (e = a[e]), i(e);
            }),
            (t.createHmac = function(e, t) {
                return (e = e.toLowerCase()), a[e] && (e = a[e]), r(e, t);
            }),
            (t.randomBytes = function(e) {
                return s(e);
            });
    },
    function(e, t, n) {
        'use strict';
        var i = n(0),
            r = n(29),
            s = n(36),
            o = n(37),
            a = n(19);
        function u(e) {
            a.call(this, 'digest'), (this._hash = e);
        }
        i(u, a),
            (u.prototype._update = function(e) {
                this._hash.update(e);
            }),
            (u.prototype._final = function() {
                return this._hash.digest();
            }),
            (e.exports = function(e) {
                return 'md5' === (e = e.toLowerCase())
                    ? new r()
                    : 'rmd160' === e || 'ripemd160' === e
                    ? new s()
                    : new u(o(e));
            });
    },
    function(e, t) {},
    function(e, t, n) {
        'use strict';
        n(2).Buffer;
        var i = n(16);
        function r() {
            (this.head = null), (this.tail = null), (this.length = 0);
        }
        (e.exports = r),
            (r.prototype.push = function(e) {
                var t = { data: e, next: null };
                this.length > 0 ? (this.tail.next = t) : (this.head = t),
                    (this.tail = t),
                    ++this.length;
            }),
            (r.prototype.unshift = function(e) {
                var t = { data: e, next: this.head };
                0 === this.length && (this.tail = t), (this.head = t), ++this.length;
            }),
            (r.prototype.shift = function() {
                if (0 !== this.length) {
                    var e = this.head.data;
                    return (
                        1 === this.length
                            ? (this.head = this.tail = null)
                            : (this.head = this.head.next),
                        --this.length,
                        e
                    );
                }
            }),
            (r.prototype.clear = function() {
                (this.head = this.tail = null), (this.length = 0);
            }),
            (r.prototype.join = function(e) {
                if (0 === this.length) return '';
                for (var t = this.head, n = '' + t.data; (t = t.next); ) n += e + t.data;
                return n;
            }),
            (r.prototype.concat = function(e) {
                if (0 === this.length) return i.alloc(0);
                if (1 === this.length) return this.head.data;
                for (var t = i.allocUnsafe(e >>> 0), n = this.head, r = 0; n; )
                    n.data.copy(t, r), (r += n.data.length), (n = n.next);
                return t;
            });
    },
    function(e, t, n) {
        (function(e, t) {
            !(function(e, n) {
                'use strict';
                if (!e.setImmediate) {
                    var i,
                        r,
                        s,
                        o,
                        a,
                        u = 1,
                        c = {},
                        l = !1,
                        f = e.document,
                        d = Object.getPrototypeOf && Object.getPrototypeOf(e);
                    (d = d && d.setTimeout ? d : e),
                        '[object process]' === {}.toString.call(e.process)
                            ? (i = function(e) {
                                  t.nextTick(function() {
                                      p(e);
                                  });
                              })
                            : !(function() {
                                  if (e.postMessage && !e.importScripts) {
                                      var t = !0,
                                          n = e.onmessage;
                                      return (
                                          (e.onmessage = function() {
                                              t = !1;
                                          }),
                                          e.postMessage('', '*'),
                                          (e.onmessage = n),
                                          t
                                      );
                                  }
                              })()
                            ? e.MessageChannel
                                ? (((s = new MessageChannel()).port1.onmessage = function(e) {
                                      p(e.data);
                                  }),
                                  (i = function(e) {
                                      s.port2.postMessage(e);
                                  }))
                                : f && 'onreadystatechange' in f.createElement('script')
                                ? ((r = f.documentElement),
                                  (i = function(e) {
                                      var t = f.createElement('script');
                                      (t.onreadystatechange = function() {
                                          p(e),
                                              (t.onreadystatechange = null),
                                              r.removeChild(t),
                                              (t = null);
                                      }),
                                          r.appendChild(t);
                                  }))
                                : (i = function(e) {
                                      setTimeout(p, 0, e);
                                  })
                            : ((o = 'setImmediate$' + Math.random() + '$'),
                              (a = function(t) {
                                  t.source === e &&
                                      'string' == typeof t.data &&
                                      0 === t.data.indexOf(o) &&
                                      p(+t.data.slice(o.length));
                              }),
                              e.addEventListener
                                  ? e.addEventListener('message', a, !1)
                                  : e.attachEvent('onmessage', a),
                              (i = function(t) {
                                  e.postMessage(o + t, '*');
                              })),
                        (d.setImmediate = function(e) {
                            'function' != typeof e && (e = new Function('' + e));
                            for (var t = new Array(arguments.length - 1), n = 0; n < t.length; n++)
                                t[n] = arguments[n + 1];
                            var r = { callback: e, args: t };
                            return (c[u] = r), i(u), u++;
                        }),
                        (d.clearImmediate = h);
                }
                function h(e) {
                    delete c[e];
                }
                function p(e) {
                    if (l) setTimeout(p, 0, e);
                    else {
                        var t = c[e];
                        if (t) {
                            l = !0;
                            try {
                                !(function(e) {
                                    var t = e.callback,
                                        i = e.args;
                                    switch (i.length) {
                                        case 0:
                                            t();
                                            break;
                                        case 1:
                                            t(i[0]);
                                            break;
                                        case 2:
                                            t(i[0], i[1]);
                                            break;
                                        case 3:
                                            t(i[0], i[1], i[2]);
                                            break;
                                        default:
                                            t.apply(n, i);
                                    }
                                })(t);
                            } finally {
                                h(e), (l = !1);
                            }
                        }
                    }
                }
            })('undefined' == typeof self ? (void 0 === e ? this : e) : self);
        }.call(this, n(3), n(4)));
    },
    function(e, t, n) {
        (function(t) {
            function n(e) {
                try {
                    if (!t.localStorage) return !1;
                } catch (e) {
                    return !1;
                }
                var n = t.localStorage[e];
                return null != n && 'true' === String(n).toLowerCase();
            }
            e.exports = function(e, t) {
                if (n('noDeprecation')) return e;
                var i = !1;
                return function() {
                    if (!i) {
                        if (n('throwDeprecation')) throw new Error(t);
                        n('traceDeprecation') ? console.trace(t) : console.warn(t), (i = !0);
                    }
                    return e.apply(this, arguments);
                };
            };
        }.call(this, n(3)));
    },
    function(e, t, n) {
        'use strict';
        e.exports = s;
        var i = n(35),
            r = n(10);
        function s(e) {
            if (!(this instanceof s)) return new s(e);
            i.call(this, e);
        }
        (r.inherits = n(0)),
            r.inherits(s, i),
            (s.prototype._transform = function(e, t, n) {
                n(null, e);
            });
    },
    function(e, t, n) {
        e.exports = n(17);
    },
    function(e, t, n) {
        e.exports = n(5);
    },
    function(e, t, n) {
        e.exports = n(14).Transform;
    },
    function(e, t, n) {
        e.exports = n(14).PassThrough;
    },
    function(e, t, n) {
        var i = n(0),
            r = n(7),
            s = n(1).Buffer,
            o = [1518500249, 1859775393, -1894007588, -899497514],
            a = new Array(80);
        function u() {
            this.init(), (this._w = a), r.call(this, 64, 56);
        }
        function c(e) {
            return (e << 30) | (e >>> 2);
        }
        function l(e, t, n, i) {
            return 0 === e ? (t & n) | (~t & i) : 2 === e ? (t & n) | (t & i) | (n & i) : t ^ n ^ i;
        }
        i(u, r),
            (u.prototype.init = function() {
                return (
                    (this._a = 1732584193),
                    (this._b = 4023233417),
                    (this._c = 2562383102),
                    (this._d = 271733878),
                    (this._e = 3285377520),
                    this
                );
            }),
            (u.prototype._update = function(e) {
                for (
                    var t,
                        n = this._w,
                        i = 0 | this._a,
                        r = 0 | this._b,
                        s = 0 | this._c,
                        a = 0 | this._d,
                        u = 0 | this._e,
                        f = 0;
                    f < 16;
                    ++f
                )
                    n[f] = e.readInt32BE(4 * f);
                for (; f < 80; ++f) n[f] = n[f - 3] ^ n[f - 8] ^ n[f - 14] ^ n[f - 16];
                for (var d = 0; d < 80; ++d) {
                    var h = ~~(d / 20),
                        p = 0 | ((((t = i) << 5) | (t >>> 27)) + l(h, r, s, a) + u + n[d] + o[h]);
                    (u = a), (a = s), (s = c(r)), (r = i), (i = p);
                }
                (this._a = (i + this._a) | 0),
                    (this._b = (r + this._b) | 0),
                    (this._c = (s + this._c) | 0),
                    (this._d = (a + this._d) | 0),
                    (this._e = (u + this._e) | 0);
            }),
            (u.prototype._hash = function() {
                var e = s.allocUnsafe(20);
                return (
                    e.writeInt32BE(0 | this._a, 0),
                    e.writeInt32BE(0 | this._b, 4),
                    e.writeInt32BE(0 | this._c, 8),
                    e.writeInt32BE(0 | this._d, 12),
                    e.writeInt32BE(0 | this._e, 16),
                    e
                );
            }),
            (e.exports = u);
    },
    function(e, t, n) {
        var i = n(0),
            r = n(7),
            s = n(1).Buffer,
            o = [1518500249, 1859775393, -1894007588, -899497514],
            a = new Array(80);
        function u() {
            this.init(), (this._w = a), r.call(this, 64, 56);
        }
        function c(e) {
            return (e << 5) | (e >>> 27);
        }
        function l(e) {
            return (e << 30) | (e >>> 2);
        }
        function f(e, t, n, i) {
            return 0 === e ? (t & n) | (~t & i) : 2 === e ? (t & n) | (t & i) | (n & i) : t ^ n ^ i;
        }
        i(u, r),
            (u.prototype.init = function() {
                return (
                    (this._a = 1732584193),
                    (this._b = 4023233417),
                    (this._c = 2562383102),
                    (this._d = 271733878),
                    (this._e = 3285377520),
                    this
                );
            }),
            (u.prototype._update = function(e) {
                for (
                    var t,
                        n = this._w,
                        i = 0 | this._a,
                        r = 0 | this._b,
                        s = 0 | this._c,
                        a = 0 | this._d,
                        u = 0 | this._e,
                        d = 0;
                    d < 16;
                    ++d
                )
                    n[d] = e.readInt32BE(4 * d);
                for (; d < 80; ++d)
                    n[d] = ((t = n[d - 3] ^ n[d - 8] ^ n[d - 14] ^ n[d - 16]) << 1) | (t >>> 31);
                for (var h = 0; h < 80; ++h) {
                    var p = ~~(h / 20),
                        m = (c(i) + f(p, r, s, a) + u + n[h] + o[p]) | 0;
                    (u = a), (a = s), (s = l(r)), (r = i), (i = m);
                }
                (this._a = (i + this._a) | 0),
                    (this._b = (r + this._b) | 0),
                    (this._c = (s + this._c) | 0),
                    (this._d = (a + this._d) | 0),
                    (this._e = (u + this._e) | 0);
            }),
            (u.prototype._hash = function() {
                var e = s.allocUnsafe(20);
                return (
                    e.writeInt32BE(0 | this._a, 0),
                    e.writeInt32BE(0 | this._b, 4),
                    e.writeInt32BE(0 | this._c, 8),
                    e.writeInt32BE(0 | this._d, 12),
                    e.writeInt32BE(0 | this._e, 16),
                    e
                );
            }),
            (e.exports = u);
    },
    function(e, t, n) {
        var i = n(0),
            r = n(38),
            s = n(7),
            o = n(1).Buffer,
            a = new Array(64);
        function u() {
            this.init(), (this._w = a), s.call(this, 64, 56);
        }
        i(u, r),
            (u.prototype.init = function() {
                return (
                    (this._a = 3238371032),
                    (this._b = 914150663),
                    (this._c = 812702999),
                    (this._d = 4144912697),
                    (this._e = 4290775857),
                    (this._f = 1750603025),
                    (this._g = 1694076839),
                    (this._h = 3204075428),
                    this
                );
            }),
            (u.prototype._hash = function() {
                var e = o.allocUnsafe(28);
                return (
                    e.writeInt32BE(this._a, 0),
                    e.writeInt32BE(this._b, 4),
                    e.writeInt32BE(this._c, 8),
                    e.writeInt32BE(this._d, 12),
                    e.writeInt32BE(this._e, 16),
                    e.writeInt32BE(this._f, 20),
                    e.writeInt32BE(this._g, 24),
                    e
                );
            }),
            (e.exports = u);
    },
    function(e, t, n) {
        var i = n(0),
            r = n(39),
            s = n(7),
            o = n(1).Buffer,
            a = new Array(160);
        function u() {
            this.init(), (this._w = a), s.call(this, 128, 112);
        }
        i(u, r),
            (u.prototype.init = function() {
                return (
                    (this._ah = 3418070365),
                    (this._bh = 1654270250),
                    (this._ch = 2438529370),
                    (this._dh = 355462360),
                    (this._eh = 1731405415),
                    (this._fh = 2394180231),
                    (this._gh = 3675008525),
                    (this._hh = 1203062813),
                    (this._al = 3238371032),
                    (this._bl = 914150663),
                    (this._cl = 812702999),
                    (this._dl = 4144912697),
                    (this._el = 4290775857),
                    (this._fl = 1750603025),
                    (this._gl = 1694076839),
                    (this._hl = 3204075428),
                    this
                );
            }),
            (u.prototype._hash = function() {
                var e = o.allocUnsafe(48);
                function t(t, n, i) {
                    e.writeInt32BE(t, i), e.writeInt32BE(n, i + 4);
                }
                return (
                    t(this._ah, this._al, 0),
                    t(this._bh, this._bl, 8),
                    t(this._ch, this._cl, 16),
                    t(this._dh, this._dl, 24),
                    t(this._eh, this._el, 32),
                    t(this._fh, this._fl, 40),
                    e
                );
            }),
            (e.exports = u);
    },
    function(e, t, n) {
        'use strict';
        var i = n(0),
            r = n(73),
            s = n(19),
            o = n(1).Buffer,
            a = n(74),
            u = n(36),
            c = n(37),
            l = o.alloc(128);
        function f(e, t) {
            s.call(this, 'digest'), 'string' == typeof t && (t = o.from(t));
            var n = 'sha512' === e || 'sha384' === e ? 128 : 64;
            ((this._alg = e), (this._key = t), t.length > n)
                ? (t = ('rmd160' === e ? new u() : c(e)).update(t).digest())
                : t.length < n && (t = o.concat([t, l], n));
            for (
                var i = (this._ipad = o.allocUnsafe(n)), r = (this._opad = o.allocUnsafe(n)), a = 0;
                a < n;
                a++
            )
                (i[a] = 54 ^ t[a]), (r[a] = 92 ^ t[a]);
            (this._hash = 'rmd160' === e ? new u() : c(e)), this._hash.update(i);
        }
        i(f, s),
            (f.prototype._update = function(e) {
                this._hash.update(e);
            }),
            (f.prototype._final = function() {
                var e = this._hash.digest();
                return ('rmd160' === this._alg ? new u() : c(this._alg))
                    .update(this._opad)
                    .update(e)
                    .digest();
            }),
            (e.exports = function(e, t) {
                return 'rmd160' === (e = e.toLowerCase()) || 'ripemd160' === e
                    ? new f('rmd160', t)
                    : 'md5' === e
                    ? new r(a, t)
                    : new f(e, t);
            });
    },
    function(e, t, n) {
        'use strict';
        var i = n(0),
            r = n(1).Buffer,
            s = n(19),
            o = r.alloc(128),
            a = 64;
        function u(e, t) {
            s.call(this, 'digest'),
                'string' == typeof t && (t = r.from(t)),
                (this._alg = e),
                (this._key = t),
                t.length > a ? (t = e(t)) : t.length < a && (t = r.concat([t, o], a));
            for (
                var n = (this._ipad = r.allocUnsafe(a)), i = (this._opad = r.allocUnsafe(a)), u = 0;
                u < a;
                u++
            )
                (n[u] = 54 ^ t[u]), (i[u] = 92 ^ t[u]);
            this._hash = [n];
        }
        i(u, s),
            (u.prototype._update = function(e) {
                this._hash.push(e);
            }),
            (u.prototype._final = function() {
                var e = this._alg(r.concat(this._hash));
                return this._alg(r.concat([this._opad, e]));
            }),
            (e.exports = u);
    },
    function(e, t, n) {
        var i = n(29);
        e.exports = function(e) {
            return new i().update(e).digest();
        };
    },
    function(e, t, n) {
        'use strict';
        (function(t, i) {
            var r = 65536,
                s = 4294967295;
            var o = n(1).Buffer,
                a = t.crypto || t.msCrypto;
            a && a.getRandomValues
                ? (e.exports = function(e, t) {
                      if (e > s) throw new RangeError('requested too many random bytes');
                      var n = o.allocUnsafe(e);
                      if (e > 0)
                          if (e > r)
                              for (var u = 0; u < e; u += r) a.getRandomValues(n.slice(u, u + r));
                          else a.getRandomValues(n);
                      if ('function' == typeof t)
                          return i.nextTick(function() {
                              t(null, n);
                          });
                      return n;
                  })
                : (e.exports = function() {
                      throw new Error(
                          'Secure random number generation is not supported by this browser.\nUse Chrome, Firefox or Internet Explorer 11'
                      );
                  });
        }.call(this, n(3), n(4)));
    },
    function(e, t) {
        e.exports = function() {
            return ['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'md5', 'rmd160'];
        };
    },
    function(e, t) {
        var n = (function(e) {
            function t() {
                this.fetch = !1;
            }
            return (t.prototype = e), new t();
        })('undefined' != typeof self ? self : this);
        !(function(e) {
            !(function(t) {
                var n = {
                    searchParams: 'URLSearchParams' in e,
                    iterable: 'Symbol' in e && 'iterator' in Symbol,
                    blob:
                        'FileReader' in e &&
                        'Blob' in e &&
                        (function() {
                            try {
                                return new Blob(), !0;
                            } catch (e) {
                                return !1;
                            }
                        })(),
                    formData: 'FormData' in e,
                    arrayBuffer: 'ArrayBuffer' in e
                };
                if (n.arrayBuffer)
                    var i = [
                            '[object Int8Array]',
                            '[object Uint8Array]',
                            '[object Uint8ClampedArray]',
                            '[object Int16Array]',
                            '[object Uint16Array]',
                            '[object Int32Array]',
                            '[object Uint32Array]',
                            '[object Float32Array]',
                            '[object Float64Array]'
                        ],
                        r =
                            ArrayBuffer.isView ||
                            function(e) {
                                return e && i.indexOf(Object.prototype.toString.call(e)) > -1;
                            };
                function s(e) {
                    if (
                        ('string' != typeof e && (e = String(e)),
                        /[^a-z0-9\-#$%&'*+.^_`|~]/i.test(e))
                    )
                        throw new TypeError('Invalid character in header field name');
                    return e.toLowerCase();
                }
                function o(e) {
                    return 'string' != typeof e && (e = String(e)), e;
                }
                function a(e) {
                    var t = {
                        next: function() {
                            var t = e.shift();
                            return { done: void 0 === t, value: t };
                        }
                    };
                    return (
                        n.iterable &&
                            (t[Symbol.iterator] = function() {
                                return t;
                            }),
                        t
                    );
                }
                function u(e) {
                    (this.map = {}),
                        e instanceof u
                            ? e.forEach(function(e, t) {
                                  this.append(t, e);
                              }, this)
                            : Array.isArray(e)
                            ? e.forEach(function(e) {
                                  this.append(e[0], e[1]);
                              }, this)
                            : e &&
                              Object.getOwnPropertyNames(e).forEach(function(t) {
                                  this.append(t, e[t]);
                              }, this);
                }
                function c(e) {
                    if (e.bodyUsed) return Promise.reject(new TypeError('Already read'));
                    e.bodyUsed = !0;
                }
                function l(e) {
                    return new Promise(function(t, n) {
                        (e.onload = function() {
                            t(e.result);
                        }),
                            (e.onerror = function() {
                                n(e.error);
                            });
                    });
                }
                function f(e) {
                    var t = new FileReader(),
                        n = l(t);
                    return t.readAsArrayBuffer(e), n;
                }
                function d(e) {
                    if (e.slice) return e.slice(0);
                    var t = new Uint8Array(e.byteLength);
                    return t.set(new Uint8Array(e)), t.buffer;
                }
                function h() {
                    return (
                        (this.bodyUsed = !1),
                        (this._initBody = function(e) {
                            var t;
                            (this._bodyInit = e),
                                e
                                    ? 'string' == typeof e
                                        ? (this._bodyText = e)
                                        : n.blob && Blob.prototype.isPrototypeOf(e)
                                        ? (this._bodyBlob = e)
                                        : n.formData && FormData.prototype.isPrototypeOf(e)
                                        ? (this._bodyFormData = e)
                                        : n.searchParams &&
                                          URLSearchParams.prototype.isPrototypeOf(e)
                                        ? (this._bodyText = e.toString())
                                        : n.arrayBuffer &&
                                          n.blob &&
                                          ((t = e) && DataView.prototype.isPrototypeOf(t))
                                        ? ((this._bodyArrayBuffer = d(e.buffer)),
                                          (this._bodyInit = new Blob([this._bodyArrayBuffer])))
                                        : n.arrayBuffer &&
                                          (ArrayBuffer.prototype.isPrototypeOf(e) || r(e))
                                        ? (this._bodyArrayBuffer = d(e))
                                        : (this._bodyText = e = Object.prototype.toString.call(e))
                                    : (this._bodyText = ''),
                                this.headers.get('content-type') ||
                                    ('string' == typeof e
                                        ? this.headers.set(
                                              'content-type',
                                              'text/plain;charset=UTF-8'
                                          )
                                        : this._bodyBlob && this._bodyBlob.type
                                        ? this.headers.set('content-type', this._bodyBlob.type)
                                        : n.searchParams &&
                                          URLSearchParams.prototype.isPrototypeOf(e) &&
                                          this.headers.set(
                                              'content-type',
                                              'application/x-www-form-urlencoded;charset=UTF-8'
                                          ));
                        }),
                        n.blob &&
                            ((this.blob = function() {
                                var e = c(this);
                                if (e) return e;
                                if (this._bodyBlob) return Promise.resolve(this._bodyBlob);
                                if (this._bodyArrayBuffer)
                                    return Promise.resolve(new Blob([this._bodyArrayBuffer]));
                                if (this._bodyFormData)
                                    throw new Error('could not read FormData body as blob');
                                return Promise.resolve(new Blob([this._bodyText]));
                            }),
                            (this.arrayBuffer = function() {
                                return this._bodyArrayBuffer
                                    ? c(this) || Promise.resolve(this._bodyArrayBuffer)
                                    : this.blob().then(f);
                            })),
                        (this.text = function() {
                            var e,
                                t,
                                n,
                                i = c(this);
                            if (i) return i;
                            if (this._bodyBlob)
                                return (
                                    (e = this._bodyBlob),
                                    (t = new FileReader()),
                                    (n = l(t)),
                                    t.readAsText(e),
                                    n
                                );
                            if (this._bodyArrayBuffer)
                                return Promise.resolve(
                                    (function(e) {
                                        for (
                                            var t = new Uint8Array(e),
                                                n = new Array(t.length),
                                                i = 0;
                                            i < t.length;
                                            i++
                                        )
                                            n[i] = String.fromCharCode(t[i]);
                                        return n.join('');
                                    })(this._bodyArrayBuffer)
                                );
                            if (this._bodyFormData)
                                throw new Error('could not read FormData body as text');
                            return Promise.resolve(this._bodyText);
                        }),
                        n.formData &&
                            (this.formData = function() {
                                return this.text().then(g);
                            }),
                        (this.json = function() {
                            return this.text().then(JSON.parse);
                        }),
                        this
                    );
                }
                (u.prototype.append = function(e, t) {
                    (e = s(e)), (t = o(t));
                    var n = this.map[e];
                    this.map[e] = n ? n + ', ' + t : t;
                }),
                    (u.prototype.delete = function(e) {
                        delete this.map[s(e)];
                    }),
                    (u.prototype.get = function(e) {
                        return (e = s(e)), this.has(e) ? this.map[e] : null;
                    }),
                    (u.prototype.has = function(e) {
                        return this.map.hasOwnProperty(s(e));
                    }),
                    (u.prototype.set = function(e, t) {
                        this.map[s(e)] = o(t);
                    }),
                    (u.prototype.forEach = function(e, t) {
                        for (var n in this.map)
                            this.map.hasOwnProperty(n) && e.call(t, this.map[n], n, this);
                    }),
                    (u.prototype.keys = function() {
                        var e = [];
                        return (
                            this.forEach(function(t, n) {
                                e.push(n);
                            }),
                            a(e)
                        );
                    }),
                    (u.prototype.values = function() {
                        var e = [];
                        return (
                            this.forEach(function(t) {
                                e.push(t);
                            }),
                            a(e)
                        );
                    }),
                    (u.prototype.entries = function() {
                        var e = [];
                        return (
                            this.forEach(function(t, n) {
                                e.push([n, t]);
                            }),
                            a(e)
                        );
                    }),
                    n.iterable && (u.prototype[Symbol.iterator] = u.prototype.entries);
                var p = ['DELETE', 'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT'];
                function m(e, t) {
                    var n,
                        i,
                        r = (t = t || {}).body;
                    if (e instanceof m) {
                        if (e.bodyUsed) throw new TypeError('Already read');
                        (this.url = e.url),
                            (this.credentials = e.credentials),
                            t.headers || (this.headers = new u(e.headers)),
                            (this.method = e.method),
                            (this.mode = e.mode),
                            (this.signal = e.signal),
                            r || null == e._bodyInit || ((r = e._bodyInit), (e.bodyUsed = !0));
                    } else this.url = String(e);
                    if (
                        ((this.credentials = t.credentials || this.credentials || 'same-origin'),
                        (!t.headers && this.headers) || (this.headers = new u(t.headers)),
                        (this.method = ((n = t.method || this.method || 'GET'),
                        (i = n.toUpperCase()),
                        p.indexOf(i) > -1 ? i : n)),
                        (this.mode = t.mode || this.mode || null),
                        (this.signal = t.signal || this.signal),
                        (this.referrer = null),
                        ('GET' === this.method || 'HEAD' === this.method) && r)
                    )
                        throw new TypeError('Body not allowed for GET or HEAD requests');
                    this._initBody(r);
                }
                function g(e) {
                    var t = new FormData();
                    return (
                        e
                            .trim()
                            .split('&')
                            .forEach(function(e) {
                                if (e) {
                                    var n = e.split('='),
                                        i = n.shift().replace(/\+/g, ' '),
                                        r = n.join('=').replace(/\+/g, ' ');
                                    t.append(decodeURIComponent(i), decodeURIComponent(r));
                                }
                            }),
                        t
                    );
                }
                function b(e, t) {
                    t || (t = {}),
                        (this.type = 'default'),
                        (this.status = void 0 === t.status ? 200 : t.status),
                        (this.ok = this.status >= 200 && this.status < 300),
                        (this.statusText = 'statusText' in t ? t.statusText : 'OK'),
                        (this.headers = new u(t.headers)),
                        (this.url = t.url || ''),
                        this._initBody(e);
                }
                (m.prototype.clone = function() {
                    return new m(this, { body: this._bodyInit });
                }),
                    h.call(m.prototype),
                    h.call(b.prototype),
                    (b.prototype.clone = function() {
                        return new b(this._bodyInit, {
                            status: this.status,
                            statusText: this.statusText,
                            headers: new u(this.headers),
                            url: this.url
                        });
                    }),
                    (b.error = function() {
                        var e = new b(null, { status: 0, statusText: '' });
                        return (e.type = 'error'), e;
                    });
                var y = [301, 302, 303, 307, 308];
                (b.redirect = function(e, t) {
                    if (-1 === y.indexOf(t)) throw new RangeError('Invalid status code');
                    return new b(null, { status: t, headers: { location: e } });
                }),
                    (t.DOMException = e.DOMException);
                try {
                    new t.DOMException();
                } catch (e) {
                    (t.DOMException = function(e, t) {
                        (this.message = e), (this.name = t);
                        var n = Error(e);
                        this.stack = n.stack;
                    }),
                        (t.DOMException.prototype = Object.create(Error.prototype)),
                        (t.DOMException.prototype.constructor = t.DOMException);
                }
                function v(e, i) {
                    return new Promise(function(r, s) {
                        var o = new m(e, i);
                        if (o.signal && o.signal.aborted)
                            return s(new t.DOMException('Aborted', 'AbortError'));
                        var a = new XMLHttpRequest();
                        function c() {
                            a.abort();
                        }
                        (a.onload = function() {
                            var e,
                                t,
                                n = {
                                    status: a.status,
                                    statusText: a.statusText,
                                    headers: ((e = a.getAllResponseHeaders() || ''),
                                    (t = new u()),
                                    e
                                        .replace(/\r?\n[\t ]+/g, ' ')
                                        .split(/\r?\n/)
                                        .forEach(function(e) {
                                            var n = e.split(':'),
                                                i = n.shift().trim();
                                            if (i) {
                                                var r = n.join(':').trim();
                                                t.append(i, r);
                                            }
                                        }),
                                    t)
                                };
                            n.url =
                                'responseURL' in a ? a.responseURL : n.headers.get('X-Request-URL');
                            var i = 'response' in a ? a.response : a.responseText;
                            r(new b(i, n));
                        }),
                            (a.onerror = function() {
                                s(new TypeError('Network request failed'));
                            }),
                            (a.ontimeout = function() {
                                s(new TypeError('Network request failed'));
                            }),
                            (a.onabort = function() {
                                s(new t.DOMException('Aborted', 'AbortError'));
                            }),
                            a.open(o.method, o.url, !0),
                            'include' === o.credentials
                                ? (a.withCredentials = !0)
                                : 'omit' === o.credentials && (a.withCredentials = !1),
                            'responseType' in a && n.blob && (a.responseType = 'blob'),
                            o.headers.forEach(function(e, t) {
                                a.setRequestHeader(t, e);
                            }),
                            o.signal &&
                                (o.signal.addEventListener('abort', c),
                                (a.onreadystatechange = function() {
                                    4 === a.readyState && o.signal.removeEventListener('abort', c);
                                })),
                            a.send(void 0 === o._bodyInit ? null : o._bodyInit);
                    });
                }
                (v.polyfill = !0),
                    e.fetch || ((e.fetch = v), (e.Headers = u), (e.Request = m), (e.Response = b)),
                    (t.Headers = u),
                    (t.Request = m),
                    (t.Response = b),
                    (t.fetch = v);
            })({});
        })(n),
            delete n.fetch.polyfill,
            ((t = n.fetch).default = n.fetch),
            (t.fetch = n.fetch),
            (t.Headers = n.Headers),
            (t.Request = n.Request),
            (t.Response = n.Response),
            (e.exports = t);
    },
    function(e, t, n) {
        (function(e, n, i, r) {
            (function(t) {
                'use strict';
                function s(e, t) {
                    t |= 0;
                    for (var n = Math.max(e.length - t, 0), i = Array(n), r = 0; r < n; r++)
                        i[r] = e[t + r];
                    return i;
                }
                var o = function(e) {
                        var t = s(arguments, 1);
                        return function() {
                            var n = s(arguments);
                            return e.apply(null, t.concat(n));
                        };
                    },
                    a = function(e) {
                        return function() {
                            var t = s(arguments),
                                n = t.pop();
                            e.call(this, t, n);
                        };
                    };
                function u(e) {
                    var t = typeof e;
                    return null != e && ('object' == t || 'function' == t);
                }
                var c = 'function' == typeof e && e,
                    l = 'object' == typeof n && 'function' == typeof n.nextTick;
                function f(e) {
                    setTimeout(e, 0);
                }
                function d(e) {
                    return function(t) {
                        var n = s(arguments, 1);
                        e(function() {
                            t.apply(null, n);
                        });
                    };
                }
                var h = d(c ? e : l ? n.nextTick : f);
                function p(e) {
                    return a(function(t, n) {
                        var i;
                        try {
                            i = e.apply(this, t);
                        } catch (e) {
                            return n(e);
                        }
                        u(i) && 'function' == typeof i.then
                            ? i.then(
                                  function(e) {
                                      m(n, null, e);
                                  },
                                  function(e) {
                                      m(n, e.message ? e : new Error(e));
                                  }
                              )
                            : n(null, i);
                    });
                }
                function m(e, t, n) {
                    try {
                        e(t, n);
                    } catch (e) {
                        h(g, e);
                    }
                }
                function g(e) {
                    throw e;
                }
                var b = 'function' == typeof Symbol;
                function y(e) {
                    return b && 'AsyncFunction' === e[Symbol.toStringTag];
                }
                function v(e) {
                    return y(e) ? p(e) : e;
                }
                function x(e) {
                    return function(t) {
                        var n = s(arguments, 1),
                            i = a(function(n, i) {
                                var r = this;
                                return e(
                                    t,
                                    function(e, t) {
                                        v(e).apply(r, n.concat(t));
                                    },
                                    i
                                );
                            });
                        return n.length ? i.apply(this, n) : i;
                    };
                }
                var w = 'object' == typeof i && i && i.Object === Object && i,
                    _ = 'object' == typeof self && self && self.Object === Object && self,
                    S = w || _ || Function('return this')(),
                    A = S.Symbol,
                    E = Object.prototype,
                    I = E.hasOwnProperty,
                    j = E.toString,
                    k = A ? A.toStringTag : void 0,
                    T = Object.prototype.toString,
                    C = '[object Null]',
                    R = '[object Undefined]',
                    P = A ? A.toStringTag : void 0;
                function O(e) {
                    return null == e
                        ? void 0 === e
                            ? R
                            : C
                        : P && P in Object(e)
                        ? (function(e) {
                              var t = I.call(e, k),
                                  n = e[k];
                              try {
                                  e[k] = void 0;
                                  var i = !0;
                              } catch (e) {}
                              var r = j.call(e);
                              return i && (t ? (e[k] = n) : delete e[k]), r;
                          })(e)
                        : (function(e) {
                              return T.call(e);
                          })(e);
                }
                var L = '[object AsyncFunction]',
                    M = '[object Function]',
                    B = '[object GeneratorFunction]',
                    D = '[object Proxy]',
                    N = 9007199254740991;
                function q(e) {
                    return 'number' == typeof e && e > -1 && e % 1 == 0 && e <= N;
                }
                function F(e) {
                    return (
                        null != e &&
                        q(e.length) &&
                        !(function(e) {
                            if (!u(e)) return !1;
                            var t = O(e);
                            return t == M || t == B || t == L || t == D;
                        })(e)
                    );
                }
                var U = {};
                function z() {}
                function X(e) {
                    return function() {
                        if (null !== e) {
                            var t = e;
                            (e = null), t.apply(this, arguments);
                        }
                    };
                }
                var Q = 'function' == typeof Symbol && Symbol.iterator,
                    Y = function(e) {
                        return Q && e[Q] && e[Q]();
                    };
                function G(e) {
                    return null != e && 'object' == typeof e;
                }
                var $ = '[object Arguments]';
                function H(e) {
                    return G(e) && O(e) == $;
                }
                var K = Object.prototype,
                    W = K.hasOwnProperty,
                    V = K.propertyIsEnumerable,
                    J = H(
                        (function() {
                            return arguments;
                        })()
                    )
                        ? H
                        : function(e) {
                              return G(e) && W.call(e, 'callee') && !V.call(e, 'callee');
                          },
                    Z = Array.isArray,
                    ee = 'object' == typeof t && t && !t.nodeType && t,
                    te = ee && 'object' == typeof r && r && !r.nodeType && r,
                    ne = te && te.exports === ee ? S.Buffer : void 0,
                    ie =
                        (ne ? ne.isBuffer : void 0) ||
                        function() {
                            return !1;
                        },
                    re = 9007199254740991,
                    se = /^(?:0|[1-9]\d*)$/;
                function oe(e, t) {
                    var n = typeof e;
                    return (
                        !!(t = null == t ? re : t) &&
                        ('number' == n || ('symbol' != n && se.test(e))) &&
                        e > -1 &&
                        e % 1 == 0 &&
                        e < t
                    );
                }
                var ae = {};
                (ae['[object Float32Array]'] = ae['[object Float64Array]'] = ae[
                    '[object Int8Array]'
                ] = ae['[object Int16Array]'] = ae['[object Int32Array]'] = ae[
                    '[object Uint8Array]'
                ] = ae['[object Uint8ClampedArray]'] = ae['[object Uint16Array]'] = ae[
                    '[object Uint32Array]'
                ] = !0),
                    (ae['[object Arguments]'] = ae['[object Array]'] = ae[
                        '[object ArrayBuffer]'
                    ] = ae['[object Boolean]'] = ae['[object DataView]'] = ae['[object Date]'] = ae[
                        '[object Error]'
                    ] = ae['[object Function]'] = ae['[object Map]'] = ae['[object Number]'] = ae[
                        '[object Object]'
                    ] = ae['[object RegExp]'] = ae['[object Set]'] = ae['[object String]'] = ae[
                        '[object WeakMap]'
                    ] = !1);
                var ue,
                    ce = 'object' == typeof t && t && !t.nodeType && t,
                    le = ce && 'object' == typeof r && r && !r.nodeType && r,
                    fe = le && le.exports === ce && w.process,
                    de = (function() {
                        try {
                            var e = le && le.require && le.require('util').types;
                            return e || (fe && fe.binding && fe.binding('util'));
                        } catch (e) {}
                    })(),
                    he = de && de.isTypedArray,
                    pe = he
                        ? ((ue = he),
                          function(e) {
                              return ue(e);
                          })
                        : function(e) {
                              return G(e) && q(e.length) && !!ae[O(e)];
                          },
                    me = Object.prototype.hasOwnProperty;
                function ge(e, t) {
                    var n = Z(e),
                        i = !n && J(e),
                        r = !n && !i && ie(e),
                        s = !n && !i && !r && pe(e),
                        o = n || i || r || s,
                        a = o
                            ? (function(e, t) {
                                  for (var n = -1, i = Array(e); ++n < e; ) i[n] = t(n);
                                  return i;
                              })(e.length, String)
                            : [],
                        u = a.length;
                    for (var c in e)
                        (!t && !me.call(e, c)) ||
                            (o &&
                                ('length' == c ||
                                    (r && ('offset' == c || 'parent' == c)) ||
                                    (s &&
                                        ('buffer' == c ||
                                            'byteLength' == c ||
                                            'byteOffset' == c)) ||
                                    oe(c, u))) ||
                            a.push(c);
                    return a;
                }
                var be = Object.prototype,
                    ye = (function(e, t) {
                        return function(n) {
                            return e(t(n));
                        };
                    })(Object.keys, Object),
                    ve = Object.prototype.hasOwnProperty;
                function xe(e) {
                    if (
                        ((n = (t = e) && t.constructor),
                        t !== (('function' == typeof n && n.prototype) || be))
                    )
                        return ye(e);
                    var t,
                        n,
                        i = [];
                    for (var r in Object(e)) ve.call(e, r) && 'constructor' != r && i.push(r);
                    return i;
                }
                function we(e) {
                    return F(e) ? ge(e) : xe(e);
                }
                function _e(e) {
                    if (F(e))
                        return (function(e) {
                            var t = -1,
                                n = e.length;
                            return function() {
                                return ++t < n ? { value: e[t], key: t } : null;
                            };
                        })(e);
                    var t,
                        n,
                        i,
                        r,
                        s = Y(e);
                    return s
                        ? (function(e) {
                              var t = -1;
                              return function() {
                                  var n = e.next();
                                  return n.done ? null : (t++, { value: n.value, key: t });
                              };
                          })(s)
                        : ((n = we((t = e))),
                          (i = -1),
                          (r = n.length),
                          function() {
                              var e = n[++i];
                              return i < r ? { value: t[e], key: e } : null;
                          });
                }
                function Se(e) {
                    return function() {
                        if (null === e) throw new Error('Callback was already called.');
                        var t = e;
                        (e = null), t.apply(this, arguments);
                    };
                }
                function Ae(e) {
                    return function(t, n, i) {
                        if (((i = X(i || z)), e <= 0 || !t)) return i(null);
                        var r = _e(t),
                            s = !1,
                            o = 0,
                            a = !1;
                        function u(e, t) {
                            if (((o -= 1), e)) (s = !0), i(e);
                            else {
                                if (t === U || (s && o <= 0)) return (s = !0), i(null);
                                a || c();
                            }
                        }
                        function c() {
                            for (a = !0; o < e && !s; ) {
                                var t = r();
                                if (null === t) return (s = !0), void (o <= 0 && i(null));
                                (o += 1), n(t.value, t.key, Se(u));
                            }
                            a = !1;
                        }
                        c();
                    };
                }
                function Ee(e, t, n, i) {
                    Ae(t)(e, v(n), i);
                }
                function Ie(e, t) {
                    return function(n, i, r) {
                        return e(n, t, i, r);
                    };
                }
                function je(e, t, n) {
                    n = X(n || z);
                    var i = 0,
                        r = 0,
                        s = e.length;
                    function o(e, t) {
                        e ? n(e) : (++r !== s && t !== U) || n(null);
                    }
                    for (0 === s && n(null); i < s; i++) t(e[i], i, Se(o));
                }
                var ke = Ie(Ee, 1 / 0),
                    Te = function(e, t, n) {
                        (F(e) ? je : ke)(e, v(t), n);
                    };
                function Ce(e) {
                    return function(t, n, i) {
                        return e(Te, t, v(n), i);
                    };
                }
                function Re(e, t, n, i) {
                    (i = i || z), (t = t || []);
                    var r = [],
                        s = 0,
                        o = v(n);
                    e(
                        t,
                        function(e, t, n) {
                            var i = s++;
                            o(e, function(e, t) {
                                (r[i] = t), n(e);
                            });
                        },
                        function(e) {
                            i(e, r);
                        }
                    );
                }
                var Pe = Ce(Re),
                    Oe = x(Pe);
                function Le(e) {
                    return function(t, n, i, r) {
                        return e(Ae(n), t, v(i), r);
                    };
                }
                var Me = Le(Re),
                    Be = Ie(Me, 1),
                    De = x(Be);
                function Ne(e, t) {
                    for (
                        var n = -1, i = null == e ? 0 : e.length;
                        ++n < i && !1 !== t(e[n], n, e);

                    );
                    return e;
                }
                var qe,
                    Fe = function(e, t, n) {
                        for (var i = -1, r = Object(e), s = n(e), o = s.length; o--; ) {
                            var a = s[qe ? o : ++i];
                            if (!1 === t(r[a], a, r)) break;
                        }
                        return e;
                    };
                function Ue(e, t) {
                    return e && Fe(e, t, we);
                }
                function ze(e) {
                    return e != e;
                }
                function Xe(e, t, n) {
                    return t == t
                        ? (function(e, t, n) {
                              for (var i = n - 1, r = e.length; ++i < r; ) if (e[i] === t) return i;
                              return -1;
                          })(e, t, n)
                        : (function(e, t, n, i) {
                              for (var r = e.length, s = n + (i ? 1 : -1); i ? s-- : ++s < r; )
                                  if (t(e[s], s, e)) return s;
                              return -1;
                          })(e, ze, n);
                }
                var Qe = function(e, t, n) {
                    'function' == typeof t && ((n = t), (t = null)), (n = X(n || z));
                    var i = we(e).length;
                    if (!i) return n(null);
                    t || (t = i);
                    var r = {},
                        o = 0,
                        a = !1,
                        u = Object.create(null),
                        c = [],
                        l = [],
                        f = {};
                    function d(e, t) {
                        c.push(function() {
                            !(function(e, t) {
                                if (a) return;
                                var i = Se(function(t, i) {
                                    if ((o--, arguments.length > 2 && (i = s(arguments, 1)), t)) {
                                        var c = {};
                                        Ue(r, function(e, t) {
                                            c[t] = e;
                                        }),
                                            (c[e] = i),
                                            (a = !0),
                                            (u = Object.create(null)),
                                            n(t, c);
                                    } else
                                        (r[e] = i),
                                            Ne(u[e] || [], function(e) {
                                                e();
                                            }),
                                            h();
                                });
                                o++;
                                var c = v(t[t.length - 1]);
                                t.length > 1 ? c(r, i) : c(i);
                            })(e, t);
                        });
                    }
                    function h() {
                        if (0 === c.length && 0 === o) return n(null, r);
                        for (; c.length && o < t; ) {
                            c.shift()();
                        }
                    }
                    function p(t) {
                        var n = [];
                        return (
                            Ue(e, function(e, i) {
                                Z(e) && Xe(e, t, 0) >= 0 && n.push(i);
                            }),
                            n
                        );
                    }
                    Ue(e, function(t, n) {
                        if (!Z(t)) return d(n, [t]), void l.push(n);
                        var i = t.slice(0, t.length - 1),
                            r = i.length;
                        if (0 === r) return d(n, t), void l.push(n);
                        (f[n] = r),
                            Ne(i, function(s) {
                                if (!e[s])
                                    throw new Error(
                                        'async.auto task `' +
                                            n +
                                            '` has a non-existent dependency `' +
                                            s +
                                            '` in ' +
                                            i.join(', ')
                                    );
                                !(function(e, t) {
                                    var n = u[e];
                                    n || (n = u[e] = []);
                                    n.push(t);
                                })(s, function() {
                                    0 === --r && d(n, t);
                                });
                            });
                    }),
                        (function() {
                            var e,
                                t = 0;
                            for (; l.length; )
                                (e = l.pop()),
                                    t++,
                                    Ne(p(e), function(e) {
                                        0 == --f[e] && l.push(e);
                                    });
                            if (t !== i)
                                throw new Error(
                                    'async.auto cannot execute tasks due to a recursive dependency'
                                );
                        })(),
                        h();
                };
                function Ye(e, t) {
                    for (var n = -1, i = null == e ? 0 : e.length, r = Array(i); ++n < i; )
                        r[n] = t(e[n], n, e);
                    return r;
                }
                var Ge = '[object Symbol]',
                    $e = 1 / 0,
                    He = A ? A.prototype : void 0,
                    Ke = He ? He.toString : void 0;
                function We(e) {
                    if ('string' == typeof e) return e;
                    if (Z(e)) return Ye(e, We) + '';
                    if (
                        (function(e) {
                            return 'symbol' == typeof e || (G(e) && O(e) == Ge);
                        })(e)
                    )
                        return Ke ? Ke.call(e) : '';
                    var t = e + '';
                    return '0' == t && 1 / e == -$e ? '-0' : t;
                }
                function Ve(e, t, n) {
                    var i = e.length;
                    return (
                        (n = void 0 === n ? i : n),
                        !t && n >= i
                            ? e
                            : (function(e, t, n) {
                                  var i = -1,
                                      r = e.length;
                                  t < 0 && (t = -t > r ? 0 : r + t),
                                      (n = n > r ? r : n) < 0 && (n += r),
                                      (r = t > n ? 0 : (n - t) >>> 0),
                                      (t >>>= 0);
                                  for (var s = Array(r); ++i < r; ) s[i] = e[i + t];
                                  return s;
                              })(e, t, n)
                    );
                }
                var Je = RegExp(
                        '[\\u200d\\ud800-\\udfff\\u0300-\\u036f\\ufe20-\\ufe2f\\u20d0-\\u20ff\\ufe0e\\ufe0f]'
                    ),
                    Ze = '[\\ud800-\\udfff]',
                    et = '[\\u0300-\\u036f\\ufe20-\\ufe2f\\u20d0-\\u20ff]',
                    tt = '\\ud83c[\\udffb-\\udfff]',
                    nt = '[^\\ud800-\\udfff]',
                    it = '(?:\\ud83c[\\udde6-\\uddff]){2}',
                    rt = '[\\ud800-\\udbff][\\udc00-\\udfff]',
                    st = '(?:' + et + '|' + tt + ')' + '?',
                    ot =
                        '[\\ufe0e\\ufe0f]?' +
                        st +
                        ('(?:\\u200d(?:' +
                            [nt, it, rt].join('|') +
                            ')[\\ufe0e\\ufe0f]?' +
                            st +
                            ')*'),
                    at = '(?:' + [nt + et + '?', et, it, rt, Ze].join('|') + ')',
                    ut = RegExp(tt + '(?=' + tt + ')|' + at + ot, 'g');
                function ct(e) {
                    return (function(e) {
                        return Je.test(e);
                    })(e)
                        ? (function(e) {
                              return e.match(ut) || [];
                          })(e)
                        : (function(e) {
                              return e.split('');
                          })(e);
                }
                var lt = /^\s+|\s+$/g;
                function ft(e, t, n) {
                    var i;
                    if ((e = null == (i = e) ? '' : We(i)) && (n || void 0 === t))
                        return e.replace(lt, '');
                    if (!e || !(t = We(t))) return e;
                    var r = ct(e),
                        s = ct(t);
                    return Ve(
                        r,
                        (function(e, t) {
                            for (var n = -1, i = e.length; ++n < i && Xe(t, e[n], 0) > -1; );
                            return n;
                        })(r, s),
                        (function(e, t) {
                            for (var n = e.length; n-- && Xe(t, e[n], 0) > -1; );
                            return n;
                        })(r, s) + 1
                    ).join('');
                }
                var dt = /^(?:async\s+)?(function)?\s*[^\(]*\(\s*([^\)]*)\)/m,
                    ht = /,/,
                    pt = /(=.+)?(\s*)$/,
                    mt = /((\/\/.*$)|(\/\*[\s\S]*?\*\/))/gm;
                function gt(e, t) {
                    var n = {};
                    Ue(e, function(e, t) {
                        var i,
                            r,
                            s = y(e),
                            o = (!s && 1 === e.length) || (s && 0 === e.length);
                        if (Z(e))
                            (i = e.slice(0, -1)),
                                (e = e[e.length - 1]),
                                (n[t] = i.concat(i.length > 0 ? a : e));
                        else if (o) n[t] = e;
                        else {
                            if (
                                ((i = r = (r = (r = (r = (r = e).toString().replace(mt, ''))
                                    .match(dt)[2]
                                    .replace(' ', ''))
                                    ? r.split(ht)
                                    : []).map(function(e) {
                                    return ft(e.replace(pt, ''));
                                })),
                                0 === e.length && !s && 0 === i.length)
                            )
                                throw new Error(
                                    'autoInject task functions require explicit parameters.'
                                );
                            s || i.pop(), (n[t] = i.concat(a));
                        }
                        function a(t, n) {
                            var r = Ye(i, function(e) {
                                return t[e];
                            });
                            r.push(n), v(e).apply(null, r);
                        }
                    }),
                        Qe(n, t);
                }
                function bt() {
                    (this.head = this.tail = null), (this.length = 0);
                }
                function yt(e, t) {
                    (e.length = 1), (e.head = e.tail = t);
                }
                function vt(e, t, n) {
                    if (null == t) t = 1;
                    else if (0 === t) throw new Error('Concurrency must not be zero');
                    var i = v(e),
                        r = 0,
                        s = [],
                        o = !1;
                    function a(e, t, n) {
                        if (null != n && 'function' != typeof n)
                            throw new Error('task callback must be a function');
                        if (((l.started = !0), Z(e) || (e = [e]), 0 === e.length && l.idle()))
                            return h(function() {
                                l.drain();
                            });
                        for (var i = 0, r = e.length; i < r; i++) {
                            var s = { data: e[i], callback: n || z };
                            t ? l._tasks.unshift(s) : l._tasks.push(s);
                        }
                        o ||
                            ((o = !0),
                            h(function() {
                                (o = !1), l.process();
                            }));
                    }
                    function u(e) {
                        return function(t) {
                            r -= 1;
                            for (var n = 0, i = e.length; n < i; n++) {
                                var o = e[n],
                                    a = Xe(s, o, 0);
                                0 === a ? s.shift() : a > 0 && s.splice(a, 1),
                                    o.callback.apply(o, arguments),
                                    null != t && l.error(t, o.data);
                            }
                            r <= l.concurrency - l.buffer && l.unsaturated(),
                                l.idle() && l.drain(),
                                l.process();
                        };
                    }
                    var c = !1,
                        l = {
                            _tasks: new bt(),
                            concurrency: t,
                            payload: n,
                            saturated: z,
                            unsaturated: z,
                            buffer: t / 4,
                            empty: z,
                            drain: z,
                            error: z,
                            started: !1,
                            paused: !1,
                            push: function(e, t) {
                                a(e, !1, t);
                            },
                            kill: function() {
                                (l.drain = z), l._tasks.empty();
                            },
                            unshift: function(e, t) {
                                a(e, !0, t);
                            },
                            remove: function(e) {
                                l._tasks.remove(e);
                            },
                            process: function() {
                                if (!c) {
                                    for (
                                        c = !0;
                                        !l.paused && r < l.concurrency && l._tasks.length;

                                    ) {
                                        var e = [],
                                            t = [],
                                            n = l._tasks.length;
                                        l.payload && (n = Math.min(n, l.payload));
                                        for (var o = 0; o < n; o++) {
                                            var a = l._tasks.shift();
                                            e.push(a), s.push(a), t.push(a.data);
                                        }
                                        (r += 1),
                                            0 === l._tasks.length && l.empty(),
                                            r === l.concurrency && l.saturated();
                                        var f = Se(u(e));
                                        i(t, f);
                                    }
                                    c = !1;
                                }
                            },
                            length: function() {
                                return l._tasks.length;
                            },
                            running: function() {
                                return r;
                            },
                            workersList: function() {
                                return s;
                            },
                            idle: function() {
                                return l._tasks.length + r === 0;
                            },
                            pause: function() {
                                l.paused = !0;
                            },
                            resume: function() {
                                !1 !== l.paused && ((l.paused = !1), h(l.process));
                            }
                        };
                    return l;
                }
                function xt(e, t) {
                    return vt(e, 1, t);
                }
                (bt.prototype.removeLink = function(e) {
                    return (
                        e.prev ? (e.prev.next = e.next) : (this.head = e.next),
                        e.next ? (e.next.prev = e.prev) : (this.tail = e.prev),
                        (e.prev = e.next = null),
                        (this.length -= 1),
                        e
                    );
                }),
                    (bt.prototype.empty = function() {
                        for (; this.head; ) this.shift();
                        return this;
                    }),
                    (bt.prototype.insertAfter = function(e, t) {
                        (t.prev = e),
                            (t.next = e.next),
                            e.next ? (e.next.prev = t) : (this.tail = t),
                            (e.next = t),
                            (this.length += 1);
                    }),
                    (bt.prototype.insertBefore = function(e, t) {
                        (t.prev = e.prev),
                            (t.next = e),
                            e.prev ? (e.prev.next = t) : (this.head = t),
                            (e.prev = t),
                            (this.length += 1);
                    }),
                    (bt.prototype.unshift = function(e) {
                        this.head ? this.insertBefore(this.head, e) : yt(this, e);
                    }),
                    (bt.prototype.push = function(e) {
                        this.tail ? this.insertAfter(this.tail, e) : yt(this, e);
                    }),
                    (bt.prototype.shift = function() {
                        return this.head && this.removeLink(this.head);
                    }),
                    (bt.prototype.pop = function() {
                        return this.tail && this.removeLink(this.tail);
                    }),
                    (bt.prototype.toArray = function() {
                        for (var e = Array(this.length), t = this.head, n = 0; n < this.length; n++)
                            (e[n] = t.data), (t = t.next);
                        return e;
                    }),
                    (bt.prototype.remove = function(e) {
                        for (var t = this.head; t; ) {
                            var n = t.next;
                            e(t) && this.removeLink(t), (t = n);
                        }
                        return this;
                    });
                var wt = Ie(Ee, 1);
                function _t(e, t, n, i) {
                    i = X(i || z);
                    var r = v(n);
                    wt(
                        e,
                        function(e, n, i) {
                            r(t, e, function(e, n) {
                                (t = n), i(e);
                            });
                        },
                        function(e) {
                            i(e, t);
                        }
                    );
                }
                function St() {
                    var e = Ye(arguments, v);
                    return function() {
                        var t = s(arguments),
                            n = this,
                            i = t[t.length - 1];
                        'function' == typeof i ? t.pop() : (i = z),
                            _t(
                                e,
                                t,
                                function(e, t, i) {
                                    t.apply(
                                        n,
                                        e.concat(function(e) {
                                            var t = s(arguments, 1);
                                            i(e, t);
                                        })
                                    );
                                },
                                function(e, t) {
                                    i.apply(n, [e].concat(t));
                                }
                            );
                    };
                }
                var At = function() {
                        return St.apply(null, s(arguments).reverse());
                    },
                    Et = Array.prototype.concat,
                    It = function(e, t, n, i) {
                        i = i || z;
                        var r = v(n);
                        Me(
                            e,
                            t,
                            function(e, t) {
                                r(e, function(e) {
                                    return e ? t(e) : t(null, s(arguments, 1));
                                });
                            },
                            function(e, t) {
                                for (var n = [], r = 0; r < t.length; r++)
                                    t[r] && (n = Et.apply(n, t[r]));
                                return i(e, n);
                            }
                        );
                    },
                    jt = Ie(It, 1 / 0),
                    kt = Ie(It, 1),
                    Tt = function() {
                        var e = s(arguments),
                            t = [null].concat(e);
                        return function() {
                            return arguments[arguments.length - 1].apply(this, t);
                        };
                    };
                function Ct(e) {
                    return e;
                }
                function Rt(e, t) {
                    return function(n, i, r, s) {
                        s = s || z;
                        var o,
                            a = !1;
                        n(
                            i,
                            function(n, i, s) {
                                r(n, function(i, r) {
                                    i
                                        ? s(i)
                                        : e(r) && !o
                                        ? ((a = !0), (o = t(!0, n)), s(null, U))
                                        : s();
                                });
                            },
                            function(e) {
                                e ? s(e) : s(null, a ? o : t(!1));
                            }
                        );
                    };
                }
                function Pt(e, t) {
                    return t;
                }
                var Ot = Ce(Rt(Ct, Pt)),
                    Lt = Le(Rt(Ct, Pt)),
                    Mt = Ie(Lt, 1);
                function Bt(e) {
                    return function(t) {
                        var n = s(arguments, 1);
                        n.push(function(t) {
                            var n = s(arguments, 1);
                            'object' == typeof console &&
                                (t
                                    ? console.error && console.error(t)
                                    : console[e] &&
                                      Ne(n, function(t) {
                                          console[e](t);
                                      }));
                        }),
                            v(t).apply(null, n);
                    };
                }
                var Dt = Bt('dir');
                function Nt(e, t, n) {
                    n = Se(n || z);
                    var i = v(e),
                        r = v(t);
                    function o(e) {
                        if (e) return n(e);
                        var t = s(arguments, 1);
                        t.push(a), r.apply(this, t);
                    }
                    function a(e, t) {
                        return e ? n(e) : t ? void i(o) : n(null);
                    }
                    a(null, !0);
                }
                function qt(e, t, n) {
                    n = Se(n || z);
                    var i = v(e),
                        r = function(e) {
                            if (e) return n(e);
                            var o = s(arguments, 1);
                            if (t.apply(this, o)) return i(r);
                            n.apply(null, [null].concat(o));
                        };
                    i(r);
                }
                function Ft(e, t, n) {
                    qt(
                        e,
                        function() {
                            return !t.apply(this, arguments);
                        },
                        n
                    );
                }
                function Ut(e, t, n) {
                    n = Se(n || z);
                    var i = v(t),
                        r = v(e);
                    function s(e) {
                        if (e) return n(e);
                        r(o);
                    }
                    function o(e, t) {
                        return e ? n(e) : t ? void i(s) : n(null);
                    }
                    r(o);
                }
                function zt(e) {
                    return function(t, n, i) {
                        return e(t, i);
                    };
                }
                function Xt(e, t, n) {
                    Te(e, zt(v(t)), n);
                }
                function Qt(e, t, n, i) {
                    Ae(t)(e, zt(v(n)), i);
                }
                var Yt = Ie(Qt, 1);
                function Gt(e) {
                    return y(e)
                        ? e
                        : a(function(t, n) {
                              var i = !0;
                              t.push(function() {
                                  var e = arguments;
                                  i
                                      ? h(function() {
                                            n.apply(null, e);
                                        })
                                      : n.apply(null, e);
                              }),
                                  e.apply(this, t),
                                  (i = !1);
                          });
                }
                function $t(e) {
                    return !e;
                }
                var Ht = Ce(Rt($t, $t)),
                    Kt = Le(Rt($t, $t)),
                    Wt = Ie(Kt, 1);
                function Vt(e) {
                    return function(t) {
                        return null == t ? void 0 : t[e];
                    };
                }
                function Jt(e, t, n, i) {
                    var r = new Array(t.length);
                    e(
                        t,
                        function(e, t, i) {
                            n(e, function(e, n) {
                                (r[t] = !!n), i(e);
                            });
                        },
                        function(e) {
                            if (e) return i(e);
                            for (var n = [], s = 0; s < t.length; s++) r[s] && n.push(t[s]);
                            i(null, n);
                        }
                    );
                }
                function Zt(e, t, n, i) {
                    var r = [];
                    e(
                        t,
                        function(e, t, i) {
                            n(e, function(n, s) {
                                n ? i(n) : (s && r.push({ index: t, value: e }), i());
                            });
                        },
                        function(e) {
                            e
                                ? i(e)
                                : i(
                                      null,
                                      Ye(
                                          r.sort(function(e, t) {
                                              return e.index - t.index;
                                          }),
                                          Vt('value')
                                      )
                                  );
                        }
                    );
                }
                function en(e, t, n, i) {
                    (F(t) ? Jt : Zt)(e, t, v(n), i || z);
                }
                var tn = Ce(en),
                    nn = Le(en),
                    rn = Ie(nn, 1);
                function sn(e, t) {
                    var n = Se(t || z),
                        i = v(Gt(e));
                    !(function e(t) {
                        if (t) return n(t);
                        i(e);
                    })();
                }
                var on = function(e, t, n, i) {
                        i = i || z;
                        var r = v(n);
                        Me(
                            e,
                            t,
                            function(e, t) {
                                r(e, function(n, i) {
                                    return n ? t(n) : t(null, { key: i, val: e });
                                });
                            },
                            function(e, t) {
                                for (
                                    var n = {}, r = Object.prototype.hasOwnProperty, s = 0;
                                    s < t.length;
                                    s++
                                )
                                    if (t[s]) {
                                        var o = t[s].key,
                                            a = t[s].val;
                                        r.call(n, o) ? n[o].push(a) : (n[o] = [a]);
                                    }
                                return i(e, n);
                            }
                        );
                    },
                    an = Ie(on, 1 / 0),
                    un = Ie(on, 1),
                    cn = Bt('log');
                function ln(e, t, n, i) {
                    i = X(i || z);
                    var r = {},
                        s = v(n);
                    Ee(
                        e,
                        t,
                        function(e, t, n) {
                            s(e, t, function(e, i) {
                                if (e) return n(e);
                                (r[t] = i), n();
                            });
                        },
                        function(e) {
                            i(e, r);
                        }
                    );
                }
                var fn = Ie(ln, 1 / 0),
                    dn = Ie(ln, 1);
                function hn(e, t) {
                    return t in e;
                }
                function pn(e, t) {
                    var n = Object.create(null),
                        i = Object.create(null);
                    t = t || Ct;
                    var r = v(e),
                        o = a(function(e, o) {
                            var a = t.apply(null, e);
                            hn(n, a)
                                ? h(function() {
                                      o.apply(null, n[a]);
                                  })
                                : hn(i, a)
                                ? i[a].push(o)
                                : ((i[a] = [o]),
                                  r.apply(
                                      null,
                                      e.concat(function() {
                                          var e = s(arguments);
                                          n[a] = e;
                                          var t = i[a];
                                          delete i[a];
                                          for (var r = 0, o = t.length; r < o; r++)
                                              t[r].apply(null, e);
                                      })
                                  ));
                        });
                    return (o.memo = n), (o.unmemoized = e), o;
                }
                var mn = d(l ? n.nextTick : c ? e : f);
                function gn(e, t, n) {
                    n = n || z;
                    var i = F(t) ? [] : {};
                    e(
                        t,
                        function(e, t, n) {
                            v(e)(function(e, r) {
                                arguments.length > 2 && (r = s(arguments, 1)), (i[t] = r), n(e);
                            });
                        },
                        function(e) {
                            n(e, i);
                        }
                    );
                }
                function bn(e, t) {
                    gn(Te, e, t);
                }
                function yn(e, t, n) {
                    gn(Ae(t), e, n);
                }
                var vn = function(e, t) {
                        var n = v(e);
                        return vt(
                            function(e, t) {
                                n(e[0], t);
                            },
                            t,
                            1
                        );
                    },
                    xn = function(e, t) {
                        var n = vn(e, t);
                        return (
                            (n.push = function(e, t, i) {
                                if ((null == i && (i = z), 'function' != typeof i))
                                    throw new Error('task callback must be a function');
                                if (((n.started = !0), Z(e) || (e = [e]), 0 === e.length))
                                    return h(function() {
                                        n.drain();
                                    });
                                t = t || 0;
                                for (var r = n._tasks.head; r && t >= r.priority; ) r = r.next;
                                for (var s = 0, o = e.length; s < o; s++) {
                                    var a = { data: e[s], priority: t, callback: i };
                                    r ? n._tasks.insertBefore(r, a) : n._tasks.push(a);
                                }
                                h(n.process);
                            }),
                            delete n.unshift,
                            n
                        );
                    };
                function wn(e, t) {
                    if (((t = X(t || z)), !Z(e)))
                        return t(
                            new TypeError('First argument to race must be an array of functions')
                        );
                    if (!e.length) return t();
                    for (var n = 0, i = e.length; n < i; n++) v(e[n])(t);
                }
                function _n(e, t, n, i) {
                    _t(s(e).reverse(), t, n, i);
                }
                function Sn(e) {
                    var t = v(e);
                    return a(function(e, n) {
                        return (
                            e.push(function(e, t) {
                                var i;
                                e
                                    ? n(null, { error: e })
                                    : ((i = arguments.length <= 2 ? t : s(arguments, 1)),
                                      n(null, { value: i }));
                            }),
                            t.apply(this, e)
                        );
                    });
                }
                function An(e) {
                    var t;
                    return (
                        Z(e)
                            ? (t = Ye(e, Sn))
                            : ((t = {}),
                              Ue(e, function(e, n) {
                                  t[n] = Sn.call(this, e);
                              })),
                        t
                    );
                }
                function En(e, t, n, i) {
                    en(
                        e,
                        t,
                        function(e, t) {
                            n(e, function(e, n) {
                                t(e, !n);
                            });
                        },
                        i
                    );
                }
                var In = Ce(En),
                    jn = Le(En),
                    kn = Ie(jn, 1);
                function Tn(e) {
                    return function() {
                        return e;
                    };
                }
                function Cn(e, t, n) {
                    var i = 5,
                        r = 0,
                        s = { times: i, intervalFunc: Tn(r) };
                    if (
                        (arguments.length < 3 && 'function' == typeof e
                            ? ((n = t || z), (t = e))
                            : (!(function(e, t) {
                                  if ('object' == typeof t)
                                      (e.times = +t.times || i),
                                          (e.intervalFunc =
                                              'function' == typeof t.interval
                                                  ? t.interval
                                                  : Tn(+t.interval || r)),
                                          (e.errorFilter = t.errorFilter);
                                  else {
                                      if ('number' != typeof t && 'string' != typeof t)
                                          throw new Error('Invalid arguments for async.retry');
                                      e.times = +t || i;
                                  }
                              })(s, e),
                              (n = n || z)),
                        'function' != typeof t)
                    )
                        throw new Error('Invalid arguments for async.retry');
                    var o = v(t),
                        a = 1;
                    !(function e() {
                        o(function(t) {
                            t &&
                            a++ < s.times &&
                            ('function' != typeof s.errorFilter || s.errorFilter(t))
                                ? setTimeout(e, s.intervalFunc(a))
                                : n.apply(null, arguments);
                        });
                    })();
                }
                var Rn = function(e, t) {
                    t || ((t = e), (e = null));
                    var n = v(t);
                    return a(function(t, i) {
                        function r(e) {
                            n.apply(null, t.concat(e));
                        }
                        e ? Cn(e, r, i) : Cn(r, i);
                    });
                };
                function Pn(e, t) {
                    gn(wt, e, t);
                }
                var On = Ce(Rt(Boolean, Ct)),
                    Ln = Le(Rt(Boolean, Ct)),
                    Mn = Ie(Ln, 1);
                function Bn(e, t, n) {
                    var i = v(t);
                    function r(e, t) {
                        var n = e.criteria,
                            i = t.criteria;
                        return n < i ? -1 : n > i ? 1 : 0;
                    }
                    Pe(
                        e,
                        function(e, t) {
                            i(e, function(n, i) {
                                if (n) return t(n);
                                t(null, { value: e, criteria: i });
                            });
                        },
                        function(e, t) {
                            if (e) return n(e);
                            n(null, Ye(t.sort(r), Vt('value')));
                        }
                    );
                }
                function Dn(e, t, n) {
                    var i = v(e);
                    return a(function(r, s) {
                        var o,
                            a = !1;
                        r.push(function() {
                            a || (s.apply(null, arguments), clearTimeout(o));
                        }),
                            (o = setTimeout(function() {
                                var t = e.name || 'anonymous',
                                    i = new Error('Callback function "' + t + '" timed out.');
                                (i.code = 'ETIMEDOUT'), n && (i.info = n), (a = !0), s(i);
                            }, t)),
                            i.apply(null, r);
                    });
                }
                var Nn = Math.ceil,
                    qn = Math.max;
                function Fn(e, t, n, i) {
                    var r = v(n);
                    Me(
                        (function(e, t, n, i) {
                            for (var r = -1, s = qn(Nn((t - e) / (n || 1)), 0), o = Array(s); s--; )
                                (o[i ? s : ++r] = e), (e += n);
                            return o;
                        })(0, e, 1),
                        t,
                        r,
                        i
                    );
                }
                var Un = Ie(Fn, 1 / 0),
                    zn = Ie(Fn, 1);
                function Xn(e, t, n, i) {
                    arguments.length <= 3 && ((i = n), (n = t), (t = Z(e) ? [] : {})),
                        (i = X(i || z));
                    var r = v(n);
                    Te(
                        e,
                        function(e, n, i) {
                            r(t, e, n, i);
                        },
                        function(e) {
                            i(e, t);
                        }
                    );
                }
                function Qn(e, t) {
                    var n,
                        i = null;
                    (t = t || z),
                        Yt(
                            e,
                            function(e, t) {
                                v(e)(function(e, r) {
                                    (n = arguments.length > 2 ? s(arguments, 1) : r),
                                        (i = e),
                                        t(!e);
                                });
                            },
                            function() {
                                t(i, n);
                            }
                        );
                }
                function Yn(e) {
                    return function() {
                        return (e.unmemoized || e).apply(null, arguments);
                    };
                }
                function Gn(e, t, n) {
                    n = Se(n || z);
                    var i = v(t);
                    if (!e()) return n(null);
                    var r = function(t) {
                        if (t) return n(t);
                        if (e()) return i(r);
                        var o = s(arguments, 1);
                        n.apply(null, [null].concat(o));
                    };
                    i(r);
                }
                function $n(e, t, n) {
                    Gn(
                        function() {
                            return !e.apply(this, arguments);
                        },
                        t,
                        n
                    );
                }
                var Hn = function(e, t) {
                        if (((t = X(t || z)), !Z(e)))
                            return t(
                                new Error(
                                    'First argument to waterfall must be an array of functions'
                                )
                            );
                        if (!e.length) return t();
                        var n = 0;
                        function i(t) {
                            var i = v(e[n++]);
                            t.push(Se(r)), i.apply(null, t);
                        }
                        function r(r) {
                            if (r || n === e.length) return t.apply(null, arguments);
                            i(s(arguments, 1));
                        }
                        i([]);
                    },
                    Kn = {
                        apply: o,
                        applyEach: Oe,
                        applyEachSeries: De,
                        asyncify: p,
                        auto: Qe,
                        autoInject: gt,
                        cargo: xt,
                        compose: At,
                        concat: jt,
                        concatLimit: It,
                        concatSeries: kt,
                        constant: Tt,
                        detect: Ot,
                        detectLimit: Lt,
                        detectSeries: Mt,
                        dir: Dt,
                        doDuring: Nt,
                        doUntil: Ft,
                        doWhilst: qt,
                        during: Ut,
                        each: Xt,
                        eachLimit: Qt,
                        eachOf: Te,
                        eachOfLimit: Ee,
                        eachOfSeries: wt,
                        eachSeries: Yt,
                        ensureAsync: Gt,
                        every: Ht,
                        everyLimit: Kt,
                        everySeries: Wt,
                        filter: tn,
                        filterLimit: nn,
                        filterSeries: rn,
                        forever: sn,
                        groupBy: an,
                        groupByLimit: on,
                        groupBySeries: un,
                        log: cn,
                        map: Pe,
                        mapLimit: Me,
                        mapSeries: Be,
                        mapValues: fn,
                        mapValuesLimit: ln,
                        mapValuesSeries: dn,
                        memoize: pn,
                        nextTick: mn,
                        parallel: bn,
                        parallelLimit: yn,
                        priorityQueue: xn,
                        queue: vn,
                        race: wn,
                        reduce: _t,
                        reduceRight: _n,
                        reflect: Sn,
                        reflectAll: An,
                        reject: In,
                        rejectLimit: jn,
                        rejectSeries: kn,
                        retry: Cn,
                        retryable: Rn,
                        seq: St,
                        series: Pn,
                        setImmediate: h,
                        some: On,
                        someLimit: Ln,
                        someSeries: Mn,
                        sortBy: Bn,
                        timeout: Dn,
                        times: Un,
                        timesLimit: Fn,
                        timesSeries: zn,
                        transform: Xn,
                        tryEach: Qn,
                        unmemoize: Yn,
                        until: $n,
                        waterfall: Hn,
                        whilst: Gn,
                        all: Ht,
                        allLimit: Kt,
                        allSeries: Wt,
                        any: On,
                        anyLimit: Ln,
                        anySeries: Mn,
                        find: Ot,
                        findLimit: Lt,
                        findSeries: Mt,
                        forEach: Xt,
                        forEachSeries: Yt,
                        forEachLimit: Qt,
                        forEachOf: Te,
                        forEachOfSeries: wt,
                        forEachOfLimit: Ee,
                        inject: _t,
                        foldl: _t,
                        foldr: _n,
                        select: tn,
                        selectLimit: nn,
                        selectSeries: rn,
                        wrapSync: p
                    };
                (t.default = Kn),
                    (t.apply = o),
                    (t.applyEach = Oe),
                    (t.applyEachSeries = De),
                    (t.asyncify = p),
                    (t.auto = Qe),
                    (t.autoInject = gt),
                    (t.cargo = xt),
                    (t.compose = At),
                    (t.concat = jt),
                    (t.concatLimit = It),
                    (t.concatSeries = kt),
                    (t.constant = Tt),
                    (t.detect = Ot),
                    (t.detectLimit = Lt),
                    (t.detectSeries = Mt),
                    (t.dir = Dt),
                    (t.doDuring = Nt),
                    (t.doUntil = Ft),
                    (t.doWhilst = qt),
                    (t.during = Ut),
                    (t.each = Xt),
                    (t.eachLimit = Qt),
                    (t.eachOf = Te),
                    (t.eachOfLimit = Ee),
                    (t.eachOfSeries = wt),
                    (t.eachSeries = Yt),
                    (t.ensureAsync = Gt),
                    (t.every = Ht),
                    (t.everyLimit = Kt),
                    (t.everySeries = Wt),
                    (t.filter = tn),
                    (t.filterLimit = nn),
                    (t.filterSeries = rn),
                    (t.forever = sn),
                    (t.groupBy = an),
                    (t.groupByLimit = on),
                    (t.groupBySeries = un),
                    (t.log = cn),
                    (t.map = Pe),
                    (t.mapLimit = Me),
                    (t.mapSeries = Be),
                    (t.mapValues = fn),
                    (t.mapValuesLimit = ln),
                    (t.mapValuesSeries = dn),
                    (t.memoize = pn),
                    (t.nextTick = mn),
                    (t.parallel = bn),
                    (t.parallelLimit = yn),
                    (t.priorityQueue = xn),
                    (t.queue = vn),
                    (t.race = wn),
                    (t.reduce = _t),
                    (t.reduceRight = _n),
                    (t.reflect = Sn),
                    (t.reflectAll = An),
                    (t.reject = In),
                    (t.rejectLimit = jn),
                    (t.rejectSeries = kn),
                    (t.retry = Cn),
                    (t.retryable = Rn),
                    (t.seq = St),
                    (t.series = Pn),
                    (t.setImmediate = h),
                    (t.some = On),
                    (t.someLimit = Ln),
                    (t.someSeries = Mn),
                    (t.sortBy = Bn),
                    (t.timeout = Dn),
                    (t.times = Un),
                    (t.timesLimit = Fn),
                    (t.timesSeries = zn),
                    (t.transform = Xn),
                    (t.tryEach = Qn),
                    (t.unmemoize = Yn),
                    (t.until = $n),
                    (t.waterfall = Hn),
                    (t.whilst = Gn),
                    (t.all = Ht),
                    (t.allLimit = Kt),
                    (t.allSeries = Wt),
                    (t.any = On),
                    (t.anyLimit = Ln),
                    (t.anySeries = Mn),
                    (t.find = Ot),
                    (t.findLimit = Lt),
                    (t.findSeries = Mt),
                    (t.forEach = Xt),
                    (t.forEachSeries = Yt),
                    (t.forEachLimit = Qt),
                    (t.forEachOf = Te),
                    (t.forEachOfSeries = wt),
                    (t.forEachOfLimit = Ee),
                    (t.inject = _t),
                    (t.foldl = _t),
                    (t.foldr = _n),
                    (t.select = tn),
                    (t.selectLimit = nn),
                    (t.selectSeries = rn),
                    (t.wrapSync = p),
                    Object.defineProperty(t, '__esModule', { value: !0 });
            })(t);
        }.call(this, n(34).setImmediate, n(4), n(3), n(40)(e)));
    },
    function(e, t, n) {
        (function(e, i) {
            var r;
            /*! https://mths.be/punycode v1.4.1 by @mathias */ !(function(s) {
                t && t.nodeType, e && e.nodeType;
                var o = 'object' == typeof i && i;
                o.global !== o && o.window !== o && o.self;
                var a,
                    u = 2147483647,
                    c = 36,
                    l = 1,
                    f = 26,
                    d = 38,
                    h = 700,
                    p = 72,
                    m = 128,
                    g = '-',
                    b = /^xn--/,
                    y = /[^\x20-\x7E]/,
                    v = /[\x2E\u3002\uFF0E\uFF61]/g,
                    x = {
                        overflow: 'Overflow: input needs wider integers to process',
                        'not-basic': 'Illegal input >= 0x80 (not a basic code point)',
                        'invalid-input': 'Invalid input'
                    },
                    w = c - l,
                    _ = Math.floor,
                    S = String.fromCharCode;
                function A(e) {
                    throw new RangeError(x[e]);
                }
                function E(e, t) {
                    for (var n = e.length, i = []; n--; ) i[n] = t(e[n]);
                    return i;
                }
                function I(e, t) {
                    var n = e.split('@'),
                        i = '';
                    return (
                        n.length > 1 && ((i = n[0] + '@'), (e = n[1])),
                        i + E((e = e.replace(v, '.')).split('.'), t).join('.')
                    );
                }
                function j(e) {
                    for (var t, n, i = [], r = 0, s = e.length; r < s; )
                        (t = e.charCodeAt(r++)) >= 55296 && t <= 56319 && r < s
                            ? 56320 == (64512 & (n = e.charCodeAt(r++)))
                                ? i.push(((1023 & t) << 10) + (1023 & n) + 65536)
                                : (i.push(t), r--)
                            : i.push(t);
                    return i;
                }
                function k(e) {
                    return E(e, function(e) {
                        var t = '';
                        return (
                            e > 65535 &&
                                ((t += S((((e -= 65536) >>> 10) & 1023) | 55296)),
                                (e = 56320 | (1023 & e))),
                            (t += S(e))
                        );
                    }).join('');
                }
                function T(e, t) {
                    return e + 22 + 75 * (e < 26) - ((0 != t) << 5);
                }
                function C(e, t, n) {
                    var i = 0;
                    for (e = n ? _(e / h) : e >> 1, e += _(e / t); e > (w * f) >> 1; i += c)
                        e = _(e / w);
                    return _(i + ((w + 1) * e) / (e + d));
                }
                function R(e) {
                    var t,
                        n,
                        i,
                        r,
                        s,
                        o,
                        a,
                        d,
                        h,
                        b,
                        y,
                        v = [],
                        x = e.length,
                        w = 0,
                        S = m,
                        E = p;
                    for ((n = e.lastIndexOf(g)) < 0 && (n = 0), i = 0; i < n; ++i)
                        e.charCodeAt(i) >= 128 && A('not-basic'), v.push(e.charCodeAt(i));
                    for (r = n > 0 ? n + 1 : 0; r < x; ) {
                        for (
                            s = w, o = 1, a = c;
                            r >= x && A('invalid-input'),
                                ((d =
                                    (y = e.charCodeAt(r++)) - 48 < 10
                                        ? y - 22
                                        : y - 65 < 26
                                        ? y - 65
                                        : y - 97 < 26
                                        ? y - 97
                                        : c) >= c ||
                                    d > _((u - w) / o)) &&
                                    A('overflow'),
                                (w += d * o),
                                !(d < (h = a <= E ? l : a >= E + f ? f : a - E));
                            a += c
                        )
                            o > _(u / (b = c - h)) && A('overflow'), (o *= b);
                        (E = C(w - s, (t = v.length + 1), 0 == s)),
                            _(w / t) > u - S && A('overflow'),
                            (S += _(w / t)),
                            (w %= t),
                            v.splice(w++, 0, S);
                    }
                    return k(v);
                }
                function P(e) {
                    var t,
                        n,
                        i,
                        r,
                        s,
                        o,
                        a,
                        d,
                        h,
                        b,
                        y,
                        v,
                        x,
                        w,
                        E,
                        I = [];
                    for (v = (e = j(e)).length, t = m, n = 0, s = p, o = 0; o < v; ++o)
                        (y = e[o]) < 128 && I.push(S(y));
                    for (i = r = I.length, r && I.push(g); i < v; ) {
                        for (a = u, o = 0; o < v; ++o) (y = e[o]) >= t && y < a && (a = y);
                        for (
                            a - t > _((u - n) / (x = i + 1)) && A('overflow'),
                                n += (a - t) * x,
                                t = a,
                                o = 0;
                            o < v;
                            ++o
                        )
                            if (((y = e[o]) < t && ++n > u && A('overflow'), y == t)) {
                                for (
                                    d = n, h = c;
                                    !(d < (b = h <= s ? l : h >= s + f ? f : h - s));
                                    h += c
                                )
                                    (E = d - b),
                                        (w = c - b),
                                        I.push(S(T(b + (E % w), 0))),
                                        (d = _(E / w));
                                I.push(S(T(d, 0))), (s = C(n, x, i == r)), (n = 0), ++i;
                            }
                        ++n, ++t;
                    }
                    return I.join('');
                }
                (a = {
                    version: '1.4.1',
                    ucs2: { decode: j, encode: k },
                    decode: R,
                    encode: P,
                    toASCII: function(e) {
                        return I(e, function(e) {
                            return y.test(e) ? 'xn--' + P(e) : e;
                        });
                    },
                    toUnicode: function(e) {
                        return I(e, function(e) {
                            return b.test(e) ? R(e.slice(4).toLowerCase()) : e;
                        });
                    }
                }),
                    void 0 ===
                        (r = function() {
                            return a;
                        }.call(t, n, t, e)) || (e.exports = r);
            })();
        }.call(this, n(40)(e), n(3)));
    },
    function(e, t) {},
    function(e, t) {}
]);
