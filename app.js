(function () {
/*LOGIC-START*/

// ==========================================================================
// 1. DATASETS & TOKEN PARSERS (Preserved from core lab)
// ==========================================================================
var COMMON = ['password','passw0rd','123456','12345678','123456789','1q2w3e','qwerty','qwertyuiop','asdfgh','zxcvbn','qazwsx','letmein','welcome','admin','administrator','iloveyou','monkey','dragon','football','baseball','sunshine','princess','shadow','superman','batman','trustno1','abc123','starwars','freedom','whatever','mustang','secret','changeme','cricket'];
var LEET = { '0':'o','1':'i','3':'e','4':'a','5':'s','7':'t','8':'b','@':'a','$':'s','!':'i','|':'l','+':'t' };

function norm(s, alt) {
  var out = '';
  var low = s.toLowerCase();
  for (var i = 0; i < low.length; i++) {
    var ch = low[i], c = ch;
    if (LEET[ch]) c = (alt && ch === '1') ? 'l' : LEET[ch];
    out += c;
  }
  return out.replace(/[^a-z0-9]/g, '');
}

function personalTokens(name, email) {
  var seen = {}, order = [];
  function add(t) {
    if (!t || t.length < 3) return;
    var k = t.toLowerCase();
    if (!seen[k]) { seen[k] = true; order.push(k); }
  }
  (name || '').split(/[^a-zA-Z0-9]+/).forEach(add);
  var handle = (email || '').split('@')[0] || '';
  handle.split(/[^a-zA-Z0-9]+/).forEach(add);
  add(handle);
  return { set: seen, order: order };
}

function checkIdentityLeak(pwStr, name, email) {
  var toks = personalTokens(name, email).order;
  if (!toks.length) return null;
  var pNorm1 = norm(pwStr, false);
  var pNorm2 = norm(pwStr, true);
  for (var i = 0; i < toks.length; i++) {
    var t = toks[i];
    var tNorm = norm(t, false);
    if (!tNorm || tNorm.length < 3) continue;
    if (pNorm1.indexOf(tNorm) !== -1 || pNorm2.indexOf(tNorm) !== -1) {
      return t;
    }
    var rev = tNorm.split('').reverse().join('');
    if (pNorm1.indexOf(rev) !== -1 || pNorm2.indexOf(rev) !== -1) {
      return t + ' (reversed)';
    }
  }
  return null;
}

// Composition & Entropy calculation
function composition(s) {
  return {
    len: s.length,
    hasLower: /[a-z]/.test(s),
    hasUpper: /[A-Z]/.test(s),
    hasDigit: /[0-9]/.test(s),
    hasSymbol: /[^a-zA-Z0-9]/.test(s),
    hasSpace: /\s/.test(s)
  };
}

function calcEntropy(s) {
  if (!s) return 0;
  var c = composition(s);
  var R = 0;
  if (c.hasLower) R += 26;
  if (c.hasUpper) R += 26;
  if (c.hasDigit) R += 10;
  if (c.hasSymbol) R += 33;
  if (R === 0) return 0;
  var bits = s.length * (Math.log(R) / Math.LN2);
  var pLow = s.toLowerCase();
  for (var i = 0; i < COMMON.length; i++) {
    if (pLow === COMMON[i]) return Math.min(bits, 10);
  }
  return Math.round(bits * 10) / 10;
}

function timeToCrack(entropy) {
  var combos = Math.pow(2, entropy);
  function fmt(sec) {
    if (sec < 0.001) return 'Instantly';
    if (sec < 1) return '< 1 second';
    if (sec < 60) return Math.round(sec) + ' seconds';
    if (sec < 3600) return Math.round(sec / 60) + ' minutes';
    if (sec < 86400) return Math.round(sec / 3600) + ' hours';
    if (sec < 31536000) return Math.round(sec / 86400) + ' days';
    var yrs = sec / 31536000;
    if (yrs < 1000) return Math.round(yrs) + ' years';
    if (yrs < 1000000) return Math.round(yrs / 1000) + ' thousand yrs';
    if (yrs < 1000000000) return Math.round(yrs / 1000000) + ' million yrs';
    return '> 1 billion yrs';
  }
  return {
    online: fmt(combos / 100),
    bcrypt: fmt(combos / 10000),
    gpu: fmt(combos / 100000000000)
  };
}

// Pure JavaScript Cryptographic Hashing Functions
function md5(string) {
  function rotateLeft(lValue, iShiftBits) { return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits)); }
  function addUnsigned(lX, lY) {
    var lX4 = (lX & 0x40000000), lY4 = (lY & 0x40000000);
    var lX8 = (lX & 0x80000000), lY8 = (lY & 0x80000000);
    var lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
    if (lX4 & lY4) return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
    if (lX4 | lY4) {
      if (lResult & 0x40000000) return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
      else return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
    } else return (lResult ^ lX8 ^ lY8);
  }
  function F(x, y, z) { return (x & y) | ((~x) & z); }
  function G(x, y, z) { return (x & z) | (y & (~z)); }
  function H(x, y, z) { return (x ^ y ^ z); }
  function I(x, y, z) { return (y ^ (x | (~z))); }
  function FF(a, b, c, d, x, s, ac) { a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac)); return addUnsigned(rotateLeft(a, s), b); }
  function GG(a, b, c, d, x, s, ac) { a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac)); return addUnsigned(rotateLeft(a, s), b); }
  function HH(a, b, c, d, x, s, ac) { a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac)); return addUnsigned(rotateLeft(a, s), b); }
  function II(a, b, c, d, x, s, ac) { a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac)); return addUnsigned(rotateLeft(a, s), b); }

  var x = [];
  var k, AA, BB, CC, DD, a, b, c, d;
  var S11=7, S12=12, S13=17, S14=22;
  var S21=5, S22=9 , S23=14, S24=20;
  var S31=4, S32=11, S33=16, S34=23;
  var S41=6, S42=10, S43=15, S44=21;

  var str = unescape(encodeURIComponent(string));
  var nWords = ((str.length + 8) >> 6) + 1;
  for (var i = 0; i < nWords * 16; i++) x[i] = 0;
  for (var i = 0; i < str.length; i++) x[i >> 2] |= (str.charCodeAt(i) & 255) << ((i % 4) * 8);
  x[str.length >> 2] |= 0x80 << ((str.length % 4) * 8);
  x[nWords * 16 - 2] = str.length * 8;

  a = 0x67452301; b = 0xEFCDAB89; c = 0x98BADCFE; d = 0x10325476;
  for (k = 0; k < x.length; k += 16) {
    AA = a; BB = b; CC = c; DD = d;
    a = FF(a, b, c, d, x[k+0], S11, 0xD76AA478); d = FF(d, a, b, c, x[k+1], S12, 0xE8C7B756);
    c = FF(c, d, a, b, x[k+2], S13, 0x242070DB); b = FF(b, c, d, a, x[k+3], S14, 0xC1BDCEEE);
    a = FF(a, b, c, d, x[k+4], S11, 0xF57C0FAF); d = FF(d, a, b, c, x[k+5], S12, 0x4787C62A);
    c = FF(c, d, a, b, x[k+6], S13, 0xA8304613); b = FF(b, c, d, a, x[k+7], S14, 0xFD469501);
    a = FF(a, b, c, d, x[k+8], S11, 0x698098D8); d = FF(d, a, b, c, x[k+9], S12, 0x8B44F7AF);
    c = FF(c, d, a, b, x[k+10], S13, 0xFFFF5BB1); b = FF(b, c, d, a, x[k+11], S14, 0x895CD7BE);
    a = FF(a, b, c, d, x[k+12], S11, 0x6B901122); d = FF(d, a, b, c, x[k+13], S12, 0xFD987193);
    c = FF(c, d, a, b, x[k+14], S13, 0xA679438E); b = FF(b, c, d, a, x[k+15], S14, 0x49B40821);

    a = GG(a, b, c, d, x[k+1], S21, 0xF61E2562); d = GG(d, a, b, c, x[k+6], S22, 0xC040B340);
    c = GG(c, d, a, b, x[k+11], S23, 0x265E5A51); b = GG(b, c, d, a, x[k+0], S24, 0xE9B6C7AA);
    a = GG(a, b, c, d, x[k+5], S21, 0xD62F105D); d = GG(d, a, b, c, x[k+10], S22, 0x02441453);
    c = GG(c, d, a, b, x[k+15], S23, 0xD8A1E681); b = GG(b, c, d, a, x[k+4], S24, 0xE7D3FBC8);
    a = GG(a, b, c, d, x[k+9], S21, 0x21E1CDE6); d = GG(d, a, b, c, x[k+14], S22, 0xC33707D6);
    c = GG(c, d, a, b, x[k+3], S23, 0xF4D50D87); b = GG(b, c, d, a, x[k+8], S24, 0x455A14ED);
    a = GG(a, b, c, d, x[k+13], S21, 0xA9E3E905); d = GG(d, a, b, c, x[k+2], S22, 0xFCEFA3F8);
    c = GG(c, d, a, b, x[k+7], S23, 0x676F02D9); b = GG(b, c, d, a, x[k+12], S24, 0x8D2A4C8A);

    a = HH(a, b, c, d, x[k+5], S31, 0xFFFA3942); d = HH(d, a, b, c, x[k+8], S32, 0x8771F681);
    c = HH(c, d, a, b, x[k+11], S33, 0x6D9D6122); b = HH(b, c, d, a, x[k+14], S34, 0xFDE5380C);
    a = HH(a, b, c, d, x[k+1], S31, 0xA4BEEA44); d = HH(d, a, b, c, x[k+4], S32, 0x4BDECFA9);
    c = HH(c, d, a, b, x[k+7], S33, 0xF6BB4B60); b = HH(b, c, d, a, x[k+10], S34, 0xBEBFBC70);
    a = HH(a, b, c, d, x[k+13], S31, 0x289B7EC6); d = HH(d, a, b, c, x[k+0], S32, 0xEAA127FA);
    c = HH(c, d, a, b, x[k+3], S33, 0xD4EF3085); b = HH(b, c, d, a, x[k+6], S34, 0x04881D05);
    a = HH(a, b, c, d, x[k+9], S31, 0xD9D4D039); d = HH(d, a, b, c, x[k+12], S32, 0xE6DB99E5);
    c = HH(c, d, a, b, x[k+15], S33, 0x1FA27CF8); b = HH(b, c, d, a, x[k+2], S34, 0xC4AC5665);

    a = II(a, b, c, d, x[k+0], S41, 0xF4292244); d = II(d, a, b, c, x[k+7], S42, 0x432AFF97);
    c = II(c, d, a, b, x[k+14], S43, 0xAB9423A7); b = II(b, c, d, a, x[k+5], S44, 0xFC93A039);
    a = II(a, b, c, d, x[k+12], S41, 0x655B59C3); d = II(d, a, b, c, x[k+3], S42, 0x8F0CCC92);
    c = II(c, d, a, b, x[k+10], S43, 0xFFEFF47D); b = II(b, c, d, a, x[k+1], S44, 0x85845DD1);
    a = II(a, b, c, d, x[k+8], S41, 0x6FA87E4F); d = II(d, a, b, c, x[k+15], S42, 0xFE2CE6E0);
    c = II(c, d, a, b, x[k+6], S43, 0xA3014314); b = II(b, c, d, a, x[k+13], S44, 0x4E0811A1);
    a = II(a, b, c, d, x[k+4], S41, 0xF7537E82); d = II(d, a, b, c, x[k+11], S42, 0xBD3AF235);
    c = II(c, d, a, b, x[k+2], S43, 0x2AD7D2BB); b = II(b, c, d, a, x[k+9], S44, 0xEB86D391);
    a = addUnsigned(a, AA); b = addUnsigned(b, BB); c = addUnsigned(c, CC); d = addUnsigned(d, DD);
  }
  function wordToHex(lValue) {
    var WordToHexValue='', WordToHexValue_temp='', lByte, lCount;
    for (lCount = 0; lCount <= 3; lCount++) {
      lByte = (lValue >>> (lCount * 8)) & 255;
      WordToHexValue_temp = '0' + lByte.toString(16);
      WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
    }
    return WordToHexValue;
  }
  return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

function sha1(str) {
  function rotl(n, s) { return (n << s) | (n >>> (32 - s)); }
  function toHex(val) {
    var s = '';
    for (var i = 7; i >= 0; i--) { var v = (val >>> (i * 4)) & 0x0f; s += v.toString(16); }
    return s;
  }
  var s = unescape(encodeURIComponent(str));
  var nwords = ((s.length + 8) >> 6) + 1;
  var w = new Array(nwords * 16);
  for (var i = 0; i < nwords * 16; i++) w[i] = 0;
  for (var i = 0; i < s.length; i++) w[i >> 2] |= (s.charCodeAt(i) & 0xff) << ((3 - (i % 4)) * 8);
  w[s.length >> 2] |= 0x80 << ((3 - (s.length % 4)) * 8);
  w[nwords * 16 - 1] = s.length * 8;

  var H0 = 0x67452301, H1 = 0xefcdab89, H2 = 0x98badcfe, H3 = 0x10325476, H4 = 0xc3d2e1f0;
  var W = new Array(80);

  for (var i = 0; i < w.length; i += 16) {
    for (var t = 0; t < 16; t++) W[t] = w[i + t];
    for (var t = 16; t < 80; t++) W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    var A = H0, B = H1, C = H2, D = H3, E = H4;
    for (var t = 0; t < 80; t++) {
      var s = Math.floor(t / 20);
      var f = (s === 0) ? ((B & C) | ((~B) & D)) : (s === 1 || s === 3) ? (B ^ C ^ D) : ((B & C) | (B & D) | (C & D));
      var K = (s === 0) ? 0x5a827999 : (s === 1) ? 0x6ed9eba1 : (s === 2) ? 0x8f1bbcdc : 0xca62c1d6;
      var T = (rotl(A, 5) + f + E + K + W[t]) & 0xffffffff;
      E = D; D = C; C = rotl(B, 30); B = A; A = T;
    }
    H0 = (H0 + A) & 0xffffffff; H1 = (H1 + B) & 0xffffffff; H2 = (H2 + C) & 0xffffffff; H3 = (H3 + D) & 0xffffffff; H4 = (H4 + E) & 0xffffffff;
  }
  return (toHex(H0) + toHex(H1) + toHex(H2) + toHex(H3) + toHex(H4)).toLowerCase();
}

function sha256(ascii) {
  function rightRotate(value, amount) { return (value >>> amount) | (value << (32 - amount)); }
  var mathPow = Math.pow;
  var maxWord = mathPow(2, 32);
  var lengthProperty = 'length';
  var i, j;
  var result = '';
  var words = [];
  var asciiBitLength = ascii[lengthProperty] * 8;
  var hash = [];
  var k = [];
  var primeCounter = 0;
  var isComposite = {};
  for (var candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (i = 0; i < 300; i += candidate) isComposite[i] = candidate;
      hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }
  ascii += '\x80';
  while (ascii[lengthProperty] % 64 - 56) ascii += '\x00';
  for (i = 0; i < ascii[lengthProperty]; i++) {
    j = ascii.charCodeAt(i);
    if (j >> 8) return;
    words[i >> 2] |= j << ((3 - i) % 4) * 8;
  }
  words[words[lengthProperty]] = ((asciiBitLength / maxWord) | 0);
  words[words[lengthProperty]] = (asciiBitLength);
  for (j = 0; j < words[lengthProperty];) {
    var w = words.slice(j, j += 16);
    var oldHash = hash;
    hash = hash.slice(0, 8);
    for (i = 0; i < 64; i++) {
      var w15 = w[i - 15], w2 = w[i - 2];
      var s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
      var s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
      w[i] = (i < 16) ? w[i] : (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      var s1_maj = rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22);
      var maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
      var t2 = (s1_maj + maj) | 0;
      var s1_ch = rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25);
      var ch = (hash[4] & hash[5]) ^ ((~hash[4]) & hash[6]);
      var t1 = (hash[7] + s1_ch + ch + k[i] + w[i]) | 0;
      hash = [(t1 + t2) | 0].concat(hash);
      hash[4] = (hash[4] + t1) | 0;
    }
    for (i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
  }
  for (i = 0; i < 8; i++) {
    for (var i2 = 3; i2 >= 0; i2--) {
      var b = (hash[i] >> (8 * i2)) & 255;
      result += (b < 16 ? '0' : '') + b.toString(16);
    }
  }
  return result;
}

async function sha512Async(str) {
  if (window.crypto && window.crypto.subtle) {
    try {
      var buf = new TextEncoder().encode(str);
      var hash = await window.crypto.subtle.digest('SHA-512', buf);
      return Array.from(new Uint8Array(hash)).map(function(b){ return b.toString(16).padStart(2, '0'); }).join('');
    } catch(e) {}
  }
  return 'Unavailable in this browser';
}

// PBKDF2 Key Derivation Function (Web Crypto)
async function pbkdf2Derive(password, saltHex, iterations) {
  iterations = iterations || 100000;
  if (!window.crypto || !window.crypto.subtle) return 'WebCrypto PBKDF2 unavailable';
  try {
    var enc = new TextEncoder();
    var keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
    );
    var saltBytes = new Uint8Array(saltHex.match(/.{1,2}/g).map(function(byte){ return parseInt(byte, 16); }));
    var derivedBits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: saltBytes, iterations: iterations, hash: 'SHA-256' },
      keyMaterial,
      256
    );
    var hashHex = Array.from(new Uint8Array(derivedBits)).map(function(b){ return b.toString(16).padStart(2, '0'); }).join('');
    return hashHex;
  } catch (err) {
    return 'PBKDF2 Error: ' + err.message;
  }
}

// Helper to log user session activity
function logActivity(text, icon) {
  icon = icon || '⚡';
  var list = document.getElementById('activity-feed-list');
  if (!list) return;
  var item = document.createElement('div');
  item.className = 'activity-item';
  item.innerHTML = '<div class="activity-title"><span>' + icon + '</span> <span>' + text + '</span></div><span class="activity-time">Just now</span>';
  list.insertBefore(item, list.firstChild);
  while (list.children.length > 20) {
    list.removeChild(list.lastChild);
  }
}

// ==========================================================================
// 2. SPA NAVIGATION ROUTER & THEME MANAGER
// ==========================================================================
var pages = {
  '#dashboard': { id: 'page-dashboard', name: 'Dashboard' },
  '#strength-checker': { id: 'page-strength', name: 'Password Strength Checker' },
  '#salt-hash': { id: 'page-salt-hash', name: 'Salt to Hash Lab' },
  '#dict-simulator': { id: 'page-dict-sim', name: 'Dictionary Attack Simulator' },
  '#hash-generator': { id: 'page-hash-gen', name: 'Cryptographic Hash Generator' },
  '#hash-checker': { id: 'page-hash-check', name: 'Hash Checker & Reverse Lookup' },
  '#security-info': { id: 'page-security-info', name: 'Security Knowledge Base' }
};

function navigateTo(hash) {
  var route = pages[hash] || pages['#dashboard'];
  window.location.hash = hash;

  // Toggle page visibility
  document.querySelectorAll('.page-view').forEach(function(view) {
    view.classList.remove('active');
  });
  var targetView = document.getElementById(route.id);
  if (targetView) targetView.classList.add('active');

  // Update sidebar active link
  document.querySelectorAll('.nav-item').forEach(function(item) {
    item.classList.toggle('active', item.getAttribute('href') === hash);
  });

  // Update header breadcrumb
  var breadcrumb = document.getElementById('breadcrumb-current-page');
  if (breadcrumb) breadcrumb.textContent = route.name;

  // Close mobile sidebar if open
  var sidebar = document.getElementById('sidebar');
  if (sidebar) sidebar.classList.remove('open');

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

window.addEventListener('hashchange', function() {
  navigateTo(window.location.hash || '#dashboard');
});

// Mobile menu toggle
var btnToggleMenu = document.getElementById('btn-toggle-menu');
if (btnToggleMenu) {
  btnToggleMenu.addEventListener('click', function() {
    var sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.toggle('open');
  });
}

// Theme Manager
function initTheme() {
  var saved = localStorage.getItem('cy-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  updateThemeButton(saved);
}

function updateThemeButton(theme) {
  var icon = document.getElementById('theme-toggle-icon');
  var text = document.getElementById('theme-toggle-text');
  if (theme === 'light') {
    if (icon) icon.textContent = '🌙';
    if (text) text.textContent = 'Dark Mode';
  } else {
    if (icon) icon.textContent = '☀️';
    if (text) text.textContent = 'Light Mode';
  }
}

var btnToggleTheme = document.getElementById('btn-toggle-theme');
if (btnToggleTheme) {
  btnToggleTheme.addEventListener('click', function() {
    var curr = document.documentElement.getAttribute('data-theme') || 'dark';
    var next = (curr === 'dark') ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('cy-theme', next);
    updateThemeButton(next);
    logActivity('Switched theme to ' + next + ' mode', '🎨');
  });
}

// Clear activity button
var btnClearAct = document.getElementById('btn-clear-activity');
if (btnClearAct) {
  btnClearAct.addEventListener('click', function() {
    var list = document.getElementById('activity-feed-list');
    if (list) list.innerHTML = '<div class="activity-item"><div class="activity-title"><span>🧹</span> <span>Log cleared.</span></div><span class="activity-time">Just now</span></div>';
  });
}

// ==========================================================================
// 3. SALT TO HASH MODULE & TWO USERS VISUAL DEMO
// ==========================================================================
function generateRandomHexSalt(numBytes) {
  numBytes = numBytes || 16;
  var bytes = new Uint8Array(numBytes);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes).map(function(b){ return b.toString(16).padStart(2, '0'); }).join('');
}

function updateSaltLab() {
  var pwInput = document.getElementById('salt-pw-input');
  var saltInput = document.getElementById('salt-manual-input');
  var algoSelect = document.getElementById('salt-algo-select');
  if (!pwInput || !saltInput || !algoSelect) return;

  var pw = pwInput.value;
  var salt = saltInput.value.trim();
  var algo = algoSelect.value;

  if (!salt) {
    salt = generateRandomHexSalt(16);
    saltInput.value = salt;
  }

  // Update bit length label
  var bitLenEl = document.getElementById('salt-bit-len');
  if (bitLenEl) bitLenEl.textContent = (salt.length * 4) + '-bit (' + (salt.length / 2) + ' bytes)';

  // Compute Unsalted & Salted
  var unsalted = '';
  var salted = '';

  if (algo === 'md5') {
    unsalted = md5(pw);
    salted = md5(salt + pw);
  } else if (algo === 'sha1') {
    unsalted = sha1(pw);
    salted = sha1(salt + pw);
  } else if (algo === 'sha256') {
    unsalted = sha256(pw);
    salted = sha256(salt + pw);
  } else if (algo === 'pbkdf2') {
    unsalted = sha256(pw) + ' (fast hash without KDF)';
    pbkdf2Derive(pw, salt, 100000).then(function(res) {
      var saltedEl = document.getElementById('out-salted-hash');
      if (saltedEl) saltedEl.textContent = res;
      var dbEl = document.getElementById('out-db-record');
      if (dbEl) dbEl.textContent = '$pbkdf2-sha256$i=100000$' + salt + '$' + res;
    });
  }

  var unsaltedEl = document.getElementById('out-unsalted-hash');
  var saltedEl = document.getElementById('out-salted-hash');
  var dbEl = document.getElementById('out-db-record');

  if (unsaltedEl) unsaltedEl.textContent = unsalted;
  if (saltedEl && algo !== 'pbkdf2') saltedEl.textContent = salted;
  if (dbEl && algo !== 'pbkdf2') {
    dbEl.textContent = '$algo=' + algo + '$salt=' + salt + '$hash=' + salted;
  }
}

// Two Users Same Password Comparison Demo
function updateTwoUsersComparison() {
  var sharedPw = 'ExamplePassword123!';
  var saltA = generateRandomHexSalt(16);
  var saltB = generateRandomHexSalt(16);

  // Guarantee distinct salts
  while (saltB === saltA) { saltB = generateRandomHexSalt(16); }

  var hashA = sha256(saltA + sharedPw);
  var hashB = sha256(saltB + sharedPw);

  var elSaltA = document.getElementById('comp-salt-a');
  var elSaltB = document.getElementById('comp-salt-b');
  var elHashA = document.getElementById('comp-hash-a');
  var elHashB = document.getElementById('comp-hash-b');

  if (elSaltA) elSaltA.textContent = saltA;
  if (elSaltB) elSaltB.textContent = saltB;
  if (elHashA) elHashA.textContent = hashA;
  if (elHashB) elHashB.textContent = hashB;

  var flowSaltA = document.getElementById('flow-salt-a-preview');
  var flowSaltB = document.getElementById('flow-salt-b-preview');
  var flowHashA = document.getElementById('flow-hash-a-preview');
  var flowHashB = document.getElementById('flow-hash-b-preview');

  if (flowSaltA) flowSaltA.textContent = saltA.slice(0, 10) + '...';
  if (flowSaltB) flowSaltB.textContent = saltB.slice(0, 10) + '...';
  if (flowHashA) flowHashA.textContent = hashA.slice(0, 16) + '...';
  if (flowHashB) flowHashB.textContent = hashB.slice(0, 16) + '...';
}

function initSaltLabListeners() {
  var btnGen = document.getElementById('btn-gen-salt');
  if (btnGen) {
    btnGen.addEventListener('click', function() {
      var inp = document.getElementById('salt-manual-input');
      if (inp) inp.value = generateRandomHexSalt(16);
      updateSaltLab();
      logActivity('Generated new random cryptographic salt', '🧂');
    });
  }

  var btnCopy = document.getElementById('btn-copy-salt');
  if (btnCopy) {
    btnCopy.addEventListener('click', function() {
      var inp = document.getElementById('salt-manual-input');
      if (inp && inp.value) {
        navigator.clipboard.writeText(inp.value).then(function() {
          var orig = btnCopy.textContent;
          btnCopy.textContent = 'Copied!';
          setTimeout(function(){ btnCopy.textContent = orig; }, 1500);
        });
      }
    });
  }

  var btnReset = document.getElementById('btn-reset-salt');
  if (btnReset) {
    btnReset.addEventListener('click', function() {
      var pw = document.getElementById('salt-pw-input');
      var salt = document.getElementById('salt-manual-input');
      if (pw) pw.value = 'ExamplePassword123!';
      if (salt) salt.value = generateRandomHexSalt(16);
      updateSaltLab();
    });
  }

  var btnCompute = document.getElementById('btn-compute-salted-hash');
  if (btnCompute) {
    btnCompute.addEventListener('click', function() {
      updateSaltLab();
      logActivity('Generated salted hash for demonstration', '⚡');
    });
  }

  var btnSync = document.getElementById('btn-sync-salt-pw');
  if (btnSync) {
    btnSync.addEventListener('click', function() {
      var src = document.getElementById('pw');
      var dest = document.getElementById('salt-pw-input');
      if (src && dest && src.value) {
        dest.value = src.value;
        updateSaltLab();
        logActivity('Synced password from Strength Checker to Salt Lab', '🔄');
      }
    });
  }

  var toggleSaltPw = document.getElementById('toggle-salt-pw');
  if (toggleSaltPw) {
    toggleSaltPw.addEventListener('click', function() {
      var inp = document.getElementById('salt-pw-input');
      if (!inp) return;
      var isPw = inp.type === 'password';
      inp.type = isPw ? 'text' : 'password';
      toggleSaltPw.textContent = isPw ? '🙈' : '👁️';
    });
  }

  var btnRegenComp = document.getElementById('btn-regen-comparison');
  if (btnRegenComp) {
    btnRegenComp.addEventListener('click', function() {
      updateTwoUsersComparison();
      logActivity('Regenerated salts for Two-User comparison', '👥');
    });
  }

  var algoSel = document.getElementById('salt-algo-select');
  if (algoSel) algoSel.addEventListener('change', updateSaltLab);

  var saltManual = document.getElementById('salt-manual-input');
  if (saltManual) saltManual.addEventListener('input', updateSaltLab);

  var pwInp = document.getElementById('salt-pw-input');
  if (pwInp) pwInp.addEventListener('input', updateSaltLab);

  updateSaltLab();
  updateTwoUsersComparison();
}

// ==========================================================================
// 4. PASSWORD STRENGTH CHECKER ENGINE (Preserved intact)
// ==========================================================================
var nameEl = document.getElementById('name');
var emailEl = document.getElementById('email');
var pw = document.getElementById('pw');
var toggleBtn = document.getElementById('toggle');
var genBtn = document.getElementById('gen');
var copyBtn = document.getElementById('copy');
var clearBtn = document.getElementById('clear');

function renderStrength() {
  if (!pw) return;
  var s = pw.value;
  var nameVal = nameEl ? nameEl.value.trim() : '';
  var emailVal = emailEl ? emailEl.value.trim() : '';

  // Char count
  var cc = document.getElementById('char-count');
  if (cc) cc.textContent = s.length + ' char' + (s.length === 1 ? '' : 's');

  var comp = composition(s);
  var entropy = calcEntropy(s);
  var leak = checkIdentityLeak(s, nameVal, emailVal);

  // Identity alert
  var alertEl = document.getElementById('alert');
  var alertText = document.getElementById('alert-text');
  if (alertEl && alertText) {
    if (leak) {
      alertEl.style.display = 'flex';
      alertText.textContent = 'Identity leak detected: Contains "' + leak + '" from your personal name or email!';
    } else {
      alertEl.style.display = 'none';
    }
  }

  // Verdict & bits
  var wordEl = document.getElementById('word');
  var bitsEl = document.getElementById('bits');
  var segs = document.querySelectorAll('#segs .seg');

  var tier = 0;
  var tierName = 'Waiting for input';
  var tierColor = 'var(--muted)';

  if (s.length > 0) {
    if (leak || entropy < 28) {
      tier = 1; tierName = leak ? 'Compromised (Leak)' : 'Critical'; tierColor = 'var(--crit)';
    } else if (entropy < 45) {
      tier = 2; tierName = 'Weak'; tierColor = 'var(--weak)';
    } else if (entropy < 65) {
      tier = 3; tierName = 'Fair'; tierColor = 'var(--fair)';
    } else if (entropy < 85) {
      tier = 4; tierName = 'Strong'; tierColor = 'var(--strong)';
    } else {
      tier = 5; tierName = 'Hardened'; tierColor = 'var(--hard)';
    }
  }

  if (wordEl) {
    wordEl.textContent = tierName;
    wordEl.style.color = tierColor;
  }
  if (bitsEl) bitsEl.textContent = entropy > 0 ? (entropy + ' bits entropy') : '0 bits';

  segs.forEach(function(seg, idx) {
    if (idx < tier) {
      seg.style.background = tierColor;
    } else {
      seg.style.background = '#172330';
    }
  });

  // Rules checklist
  var rules = [
    { text: 'At least 12 characters long', pass: comp.len >= 12 },
    { text: 'Contains uppercase letter (A-Z)', pass: comp.hasUpper },
    { text: 'Contains lowercase letter (a-z)', pass: comp.hasLower },
    { text: 'Contains numerical digit (0-9)', pass: comp.hasDigit },
    { text: 'Contains special symbol (!@#$...)', pass: comp.hasSymbol },
    { text: 'No personal identity tokens from name or email', pass: !leak && (comp.len > 0) }
  ];

  var rulesList = document.getElementById('rules');
  var passedCount = 0;
  if (rulesList) {
    rulesList.innerHTML = '';
    rules.forEach(function(r) {
      if (r.pass) passedCount++;
      var li = document.createElement('li');
      li.className = r.pass ? 'pass' : '';
      li.innerHTML = '<span class="rule-icon">' + (r.pass ? '✓' : '✗') + '</span><span>' + r.text + '</span>';
      rulesList.appendChild(li);
    });
  }

  var countBadge = document.getElementById('count');
  if (countBadge) countBadge.textContent = passedCount + ' / ' + rules.length + ' Rules';

  // Recommendations
  var tipsList = document.getElementById('tips');
  if (tipsList) {
    tipsList.innerHTML = '';
    if (comp.len < 12) tipsList.innerHTML += '<li>Increase length to 12 or more characters. Length provides the greatest exponential protection.</li>';
    if (!comp.hasSymbol) tipsList.innerHTML += '<li>Add special characters ($%@#!) to expand the character set to 95 possible symbols.</li>';
    if (leak) tipsList.innerHTML += '<li>Remove personal names and email fragments. Attackers build custom wordlists based on target profiles.</li>';
    if (tipsList.children.length === 0) {
      tipsList.innerHTML = '<li style="color:var(--strong);">Excellent credential hygiene! This password meets all core defensive standards.</li>';
    }
  }

  // Crack times
  var attacksGrid = document.getElementById('attacks');
  if (attacksGrid) {
    var times = timeToCrack(entropy);
    attacksGrid.innerHTML =
      '<div class="attack-cell"><span class="attack-lbl">Online Rate-Limited</span><span class="attack-val">' + times.online + '</span><span class="attack-rate">100 guesses/sec</span></div>' +
      '<div class="attack-cell"><span class="attack-lbl">Stolen DB · bcrypt</span><span class="attack-val">' + times.bcrypt + '</span><span class="attack-rate">10k guesses/sec</span></div>' +
      '<div class="attack-cell"><span class="attack-lbl">GPU Fast Hash</span><span class="attack-val" style="color:' + (tier <= 2 ? 'var(--crit)' : 'var(--fg-strong)') + '">' + times.gpu + '</span><span class="attack-rate">100B guesses/sec</span></div>';
  }
}

function initStrengthChecker() {
  if (pw) pw.addEventListener('input', renderStrength);
  if (nameEl) nameEl.addEventListener('input', renderStrength);
  if (emailEl) emailEl.addEventListener('input', renderStrength);

  if (toggleBtn && pw) {
    toggleBtn.addEventListener('click', function() {
      var isPw = pw.type === 'password';
      pw.type = isPw ? 'text' : 'password';
      toggleBtn.textContent = isPw ? '🙈' : '👁️';
    });
  }

  if (genBtn && pw) {
    genBtn.addEventListener('click', function() {
      var words = ['Quantum', 'Cipher', 'Vortex', 'Sentinel', 'Falcon', 'Orbit', 'Kernel', 'Beacon', 'Matrix', 'Tunnel'];
      var chosen = words[Math.floor(Math.random() * words.length)] + '-' +
                   words[Math.floor(Math.random() * words.length)] + '-' +
                   Math.floor(10 + Math.random() * 89) + '!';
      pw.value = chosen;
      pw.type = 'text';
      if (toggleBtn) toggleBtn.textContent = '🙈';
      renderStrength();
      var hint = document.getElementById('hint');
      if (hint) hint.textContent = 'Generated high-entropy passphrase. Passes all security checks.';
      logActivity('Generated secure passphrase in Strength Checker', '🎲');
    });
  }

  if (copyBtn && pw) {
    copyBtn.addEventListener('click', function() {
      if (!pw.value) return;
      navigator.clipboard.writeText(pw.value).then(function() {
        var hint = document.getElementById('hint');
        if (hint) hint.textContent = 'Password copied to clipboard.';
      });
    });
  }

  if (clearBtn && pw) {
    clearBtn.addEventListener('click', function() {
      pw.value = '';
      if (nameEl) nameEl.value = '';
      if (emailEl) emailEl.value = '';
      renderStrength();
    });
  }

  document.querySelectorAll('[data-preset]').forEach(function(b) {
    b.addEventListener('click', function() {
      var p = b.getAttribute('data-preset');
      if (p === 'common') pw.value = 'Password123!';
      else if (p === 'phrase') pw.value = 'Quantum-Sentinel-84!';
      else {
        var n = nameEl ? nameEl.value.trim() : 'Ravi';
        pw.value = (n.split(' ')[0] || 'Ravi') + '@2024';
      }
      renderStrength();
      logActivity('Loaded preset: "' + pw.value + '"', '📋');
    });
  });

  renderStrength();
}

// ==========================================================================
// 5. DICTIONARY ATTACK SIMULATOR (Preserved & Modularized)
// ==========================================================================
var simState = 'idle'; // 'idle', 'running', 'paused', 'stopped'
var simMode = 'dictionary';
var simRafId = null;
var simGuesses = 0;
var simIdx = 0;
var simElapsed = 0;
var simLastTs = 0;
var customDictionary = null;
var activeDictFileName = 'Built-in Common Wordlist';

var BUILTIN_DICT = [
  'password', '123456', '12345678', '1234', 'qwerty', '12345', 'dragon', 'pussy', 'baseball',
  'football', 'football', 'master', 'monkey', 'shadow', 'superman', 'trustno1', 'welcome',
  'login', 'princess', 'solo', 'admin', 'administrator', 'root', 'changeme', 'secret',
  'iloveyou', 'starwars', 'letmein', 'default', 'pass', 'access', 'network', 'router',
  'ravi', 'ravi123', 'ravi@2024', 'ravi2024', 'patel', 'patel123', 'patel@2024'
];

var TOP_COMMON = ['123456','password','123456789','12345','qwerty','12345678','111111','1234567','123123','admin','root','login','pass','welcome','secret'];

function getCandidatesForMode() {
  if (simMode === 'common') return TOP_COMMON.slice();
  if (simMode === 'hybrid') {
    var base = customDictionary || BUILTIN_DICT;
    var hybrid = [];
    for (var i = 0; i < base.length; i++) {
      hybrid.push(base[i]);
      hybrid.push(base[i] + '123');
      hybrid.push(base[i] + '@2024');
      hybrid.push(base[i] + '!');
    }
    return hybrid;
  }
  return (customDictionary && customDictionary.length > 0) ? customDictionary.slice() : BUILTIN_DICT.slice();
}

function simTermLog(text, cls) {
  var term = document.getElementById('sim-term-log');
  if (!term) return;
  var div = document.createElement('div');
  div.className = 'term-line' + (cls ? (' ' + cls) : '');
  div.textContent = text;
  term.appendChild(div);
  while (term.children.length > 60) { term.removeChild(term.firstChild); }
  term.scrollTop = term.scrollHeight;
}

function updateSimTelemetry(guesses, elapsedMs, pct, total, currentGuess, currentHash) {
  var elG = document.getElementById('stat-attempts');
  var elT = document.getElementById('stat-elapsed');
  var elS = document.getElementById('stat-speed');
  var elP = document.getElementById('sim-pct-label');
  var elF = document.getElementById('sim-prog-fill');
  var elGuess = document.getElementById('sim-disp-guess');
  var elHash = document.getElementById('sim-disp-hash');

  if (elG) elG.textContent = guesses.toLocaleString();
  var sec = elapsedMs / 1000;
  if (elT) elT.textContent = sec.toFixed(2) + 's';
  var rate = sec > 0.05 ? Math.round(guesses / sec) : 0;
  if (elS) elS.textContent = rate.toLocaleString() + '/s';

  var boundedPct = Math.min(100, Math.max(0, pct));
  if (elP) elP.textContent = boundedPct.toFixed(1) + '%';
  if (elF) elF.style.width = boundedPct + '%';

  if (elGuess) elGuess.textContent = '"' + currentGuess + '"';
  if (elHash) elHash.textContent = currentHash ? ('Hash: ' + currentHash) : '';
}

function finishSimulation(result, hitWord, totalGuesses, elapsedMs) {
  simState = result;
  if (simRafId) cancelAnimationFrame(simRafId);
  simRafId = null;

  var btnStart = document.getElementById('btn-sim-start');
  var btnPause = document.getElementById('btn-sim-pause');
  var btnStop = document.getElementById('btn-sim-stop');
  var btnReset = document.getElementById('btn-sim-reset');

  if (btnStart) { btnStart.disabled = false; btnStart.textContent = '⚡ Start Attack Simulation'; }
  if (btnPause) { btnPause.disabled = true; btnPause.textContent = 'Pause'; }
  if (btnStop) btnStop.disabled = true;
  if (btnReset) btnReset.disabled = false;

  var banner = document.getElementById('sim-result-banner');
  var resTitle = document.getElementById('sim-res-title');
  var resMeta = document.getElementById('sim-res-meta');
  var resReveal = document.getElementById('sim-res-reveal');
  var resDesc = document.getElementById('sim-res-desc');
  var progFill = document.getElementById('sim-prog-fill');

  var sec = (elapsedMs / 1000).toFixed(2);

  if (banner) banner.setAttribute('data-state', result);

  if (result === 'cracked') {
    if (resTitle) resTitle.textContent = 'MATCH FOUND · CRACKED!';
    if (resMeta) resMeta.textContent = totalGuesses.toLocaleString() + ' guesses in ' + sec + 's';
    if (resReveal) {
      resReveal.style.display = 'block';
      resReveal.textContent = 'Plaintext: "' + hitWord + '"';
      resReveal.style.color = 'var(--crit)';
    }
    if (resDesc) resDesc.textContent = 'Vulnerability Confirmed: The target password or hash was found in the candidate wordlist. Real adversaries crack weak and dictionary credentials instantly.';
    if (progFill) progFill.className = 'prog-fill cracked';
    simTermLog('>>> [MATCH FOUND!] Cracked at candidate #' + totalGuesses + ' in ' + sec + 's!', 'hit');
    simTermLog('>>> [REVEAL] Password: "' + hitWord + '"', 'hit');
    logActivity('Simulation: Cracked password "' + hitWord + '" in ' + totalGuesses + ' guesses', '💥');
  } else if (result === 'nomatch') {
    if (resTitle) resTitle.textContent = 'NO MATCH IN ACTIVE WORDLIST';
    if (resMeta) resMeta.textContent = 'Tested ' + totalGuesses.toLocaleString() + ' entries in ' + sec + 's';
    if (resReveal) resReveal.style.display = 'none';
    if (resDesc) resDesc.innerHTML = '<strong>Security Note:</strong> The candidate was not in this demo list. <em>WARNING:</em> This does NOT mean the password is safe. Real-world adversaries use breach databases containing billions of leaked credentials.';
    if (progFill) progFill.className = 'prog-fill survived';
    simTermLog('>>> [EXHAUSTED] Search finished without match in ' + totalGuesses + ' candidates.', 'notice');
    simTermLog('>>> Lack of match in a demo dictionary does not guarantee security.', 'info');
    logActivity('Simulation: Tested ' + totalGuesses + ' candidates without match', '🛡️');
  } else if (result === 'stopped') {
    if (resTitle) resTitle.textContent = 'Simulation Stopped';
    if (resMeta) resMeta.textContent = 'Halted at ' + totalGuesses + ' attempts';
    if (resDesc) resDesc.textContent = 'Simulation halted by user control.';
    simTermLog('[STOP] Simulation stopped by user.', 'notice');
  }
}

function simLoop(ts) {
  if (simState !== 'running') return;
  if (!simLastTs) simLastTs = ts;
  var delta = ts - simLastTs;
  simLastTs = ts;
  simElapsed += delta;

  var candidates = getCandidatesForMode();
  var total = candidates.length;
  var targetAlgo = document.getElementById('sim-target-algo') ? document.getElementById('sim-target-algo').value : 'sha256';
  var targetVal = document.getElementById('sim-target-val') ? document.getElementById('sim-target-val').value.trim().toLowerCase() : '';

  var batchSize = 120;
  var found = false;
  var hitWord = '';
  var currentGuess = '';
  var currentHash = '';

  for (var i = 0; i < batchSize && simIdx < total; i++) {
    var cand = candidates[simIdx];
    simGuesses++;
    simIdx++;

    var candHash = '';
    if (targetAlgo === 'md5') candHash = md5(cand);
    else if (targetAlgo === 'sha1') candHash = sha1(cand);
    else if (targetAlgo === 'sha256') candHash = sha256(cand);
    else candHash = cand;

    currentGuess = cand;
    currentHash = candHash;

    if (i === 0 && Math.random() < 0.3) {
      simTermLog('[TRY #' + simGuesses + '] "' + cand + '"' + (targetAlgo !== 'plaintext' ? (' -> ' + candHash.slice(0, 8) + '...') : '') + ' ... FAIL', 'try');
    }

    var isMatch = (targetAlgo === 'plaintext') ? (cand === targetVal) : (candHash.toLowerCase() === targetVal);
    if (isMatch) {
      found = true;
      hitWord = cand;
      break;
    }
  }

  var pct = total > 0 ? ((simIdx / total) * 100) : 100;
  updateSimTelemetry(simGuesses, simElapsed, pct, total, currentGuess, currentHash);

  if (found) {
    finishSimulation('cracked', hitWord, simGuesses, simElapsed);
    return;
  }
  if (simIdx >= total) {
    finishSimulation('nomatch', '', simGuesses, simElapsed);
    return;
  }

  simRafId = requestAnimationFrame(simLoop);
}

function startSimulation() {
  if (simState === 'running') return;
  var targetInp = document.getElementById('sim-target-val');
  if (!targetInp || !targetInp.value.trim()) {
    alert('Please provide a target password or hash to attack.');
    return;
  }

  simState = 'running';
  simGuesses = 0;
  simIdx = 0;
  simElapsed = 0;
  simLastTs = 0;

  var btnStart = document.getElementById('btn-sim-start');
  var btnPause = document.getElementById('btn-sim-pause');
  var btnStop = document.getElementById('btn-sim-stop');
  var btnReset = document.getElementById('btn-sim-reset');

  if (btnStart) { btnStart.disabled = true; btnStart.textContent = 'Attacking...'; }
  if (btnPause) { btnPause.disabled = false; btnPause.textContent = 'Pause'; }
  if (btnStop) btnStop.disabled = false;
  if (btnReset) btnReset.disabled = false;

  var cands = getCandidatesForMode();
  var elTotal = document.getElementById('stat-total');
  if (elTotal) elTotal.textContent = cands.length.toLocaleString();

  var banner = document.getElementById('sim-result-banner');
  if (banner) banner.setAttribute('data-state', 'running');
  var resTitle = document.getElementById('sim-res-title');
  if (resTitle) resTitle.textContent = 'Attack Simulation Running...';
  var resReveal = document.getElementById('sim-res-reveal');
  if (resReveal) resReveal.style.display = 'none';

  simTermLog('------------------------------------------------------------', 'info');
  simTermLog('[START] ' + simMode.toUpperCase() + ' attack initiated against target.', 'info');

  logActivity('Started dictionary attack simulation', '⚡');
  simRafId = requestAnimationFrame(simLoop);
}

function pauseSimulation() {
  var btnPause = document.getElementById('btn-sim-pause');
  if (simState === 'running') {
    simState = 'paused';
    if (simRafId) cancelAnimationFrame(simRafId);
    simRafId = null;
    if (btnPause) btnPause.textContent = 'Resume';
    simTermLog('[PAUSE] Simulation paused by user.', 'notice');
  } else if (simState === 'paused') {
    simState = 'running';
    simLastTs = 0;
    if (btnPause) btnPause.textContent = 'Pause';
    simTermLog('[RESUME] Simulation resumed.', 'info');
    simRafId = requestAnimationFrame(simLoop);
  }
}

function stopSimulation() {
  finishSimulation('stopped', '', simGuesses, simElapsed);
}

function resetSimulation() {
  if (simRafId) cancelAnimationFrame(simRafId);
  simRafId = null;
  simState = 'idle';
  simGuesses = 0;
  simIdx = 0;
  simElapsed = 0;

  var btnStart = document.getElementById('btn-sim-start');
  var btnPause = document.getElementById('btn-sim-pause');
  var btnStop = document.getElementById('btn-sim-stop');
  var btnReset = document.getElementById('btn-sim-reset');

  if (btnStart) { btnStart.disabled = false; btnStart.textContent = '⚡ Start Attack Simulation'; }
  if (btnPause) { btnPause.disabled = true; btnPause.textContent = 'Pause'; }
  if (btnStop) btnStop.disabled = true;
  if (btnReset) btnReset.disabled = true;

  var cands = getCandidatesForMode();
  updateSimTelemetry(0, 0, 0, cands.length, 'Waiting for simulation to start...', '');

  var banner = document.getElementById('sim-result-banner');
  if (banner) banner.setAttribute('data-state', 'idle');
  var resTitle = document.getElementById('sim-res-title');
  if (resTitle) resTitle.textContent = 'Ready';
  var resDesc = document.getElementById('sim-res-desc');
  if (resDesc) resDesc.textContent = 'Simulation reset. Ready to test.';

  simTermLog('[RESET] Simulator state cleared.', 'info');
}

function initDictSimulator() {
  var btnStart = document.getElementById('btn-sim-start');
  var btnPause = document.getElementById('btn-sim-pause');
  var btnStop = document.getElementById('btn-sim-stop');
  var btnReset = document.getElementById('btn-sim-reset');

  if (btnStart) btnStart.addEventListener('click', startSimulation);
  if (btnPause) btnPause.addEventListener('click', pauseSimulation);
  if (btnStop) btnStop.addEventListener('click', stopSimulation);
  if (btnReset) btnReset.addEventListener('click', resetSimulation);

  // File upload
  var fileInp = document.getElementById('file-dict-upload');
  var btnUpload = document.getElementById('btn-trigger-upload');
  if (btnUpload && fileInp) {
    btnUpload.addEventListener('click', function() { fileInp.click(); });
    fileInp.addEventListener('change', function(e) {
      var file = e.target.files && e.target.files[0];
      if (!file) return;
      if (file.size === 0) {
        alert('Selected file is empty (0 bytes).');
        return;
      }
      var reader = new FileReader();
      reader.onload = function(evt) {
        var lines = evt.target.result.split(/\r?\n/).map(function(s){ return s.trim(); }).filter(Boolean);
        if (lines.length === 0) {
          alert('No valid candidate words found in file.');
          return;
        }
        var unique = [];
        var seen = {};
        for (var i = 0; i < lines.length; i++) {
          if (!seen[lines[i]]) { seen[lines[i]] = true; unique.push(lines[i]); }
        }
        customDictionary = unique;
        activeDictFileName = file.name;
        document.getElementById('dict-cand-count').textContent = unique.length.toLocaleString() + ' LOADED';
        document.getElementById('dict-source-label').textContent = file.name;
        document.getElementById('dict-upload-status').textContent = unique.length.toLocaleString() + ' words loaded';
        document.getElementById('stat-total').textContent = unique.length.toLocaleString();
        document.getElementById('dash-stat-dict-count').textContent = unique.length.toLocaleString() + ' Words';
        simTermLog('[FILE] Successfully loaded ' + unique.length + ' candidates from "' + file.name + '"', 'info');
        logActivity('Loaded custom dictionary: "' + file.name + '" (' + unique.length + ' words)', '📁');
        resetSimulation();
      };
      reader.readAsText(file);
    });
  }

  var btnBuiltin = document.getElementById('btn-use-builtin');
  if (btnBuiltin) {
    btnBuiltin.addEventListener('click', function() {
      customDictionary = null;
      activeDictFileName = 'Built-in Common Wordlist';
      document.getElementById('dict-cand-count').textContent = BUILTIN_DICT.length + ' LOADED';
      document.getElementById('dict-source-label').textContent = 'Built-in Wordlist';
      document.getElementById('dict-upload-status').textContent = BUILTIN_DICT.length + ' words ready';
      document.getElementById('stat-total').textContent = BUILTIN_DICT.length;
      document.getElementById('dash-stat-dict-count').textContent = BUILTIN_DICT.length + ' Words';
      simTermLog('[DICT] Restored built-in common wordlist.', 'info');
      resetSimulation();
    });
  }

  // Mode tabs
  document.querySelectorAll('.mode-tab').forEach(function(tab) {
    tab.addEventListener('click', function() {
      document.querySelectorAll('.mode-tab').forEach(function(t){ t.classList.remove('active'); });
      tab.classList.add('active');
      simMode = tab.getAttribute('data-mode');

      var callTitle = document.getElementById('dict-mode-title');
      var callDesc = document.getElementById('dict-mode-desc');
      if (simMode === 'dictionary') {
        if (callTitle) callTitle.textContent = 'Dictionary Attack:';
        if (callDesc) callDesc.textContent = 'Tests candidate words from loaded list sequentially against target.';
      } else if (simMode === 'common') {
        if (callTitle) callTitle.textContent = 'Top Weak Passwords Demo:';
        if (callDesc) callDesc.textContent = 'Demonstrates cracking the top 15 most common breach passwords (123456, password, admin, etc.).';
      } else if (simMode === 'bruteforce') {
        if (callTitle) callTitle.textContent = 'Pure Brute Force:';
        if (callDesc) callDesc.textContent = 'Exhaustively tests permutations across character space.';
      } else if (simMode === 'hybrid') {
        if (callTitle) callTitle.textContent = 'Hybrid Attack (Dictionary + Mutations):';
        if (callDesc) callDesc.textContent = 'Mutates dictionary words with common trailing numbers and symbols (123, @2024, !).';
      }

      resetSimulation();
      logActivity('Switched simulator mode to ' + simMode, '⚙️');
    });
  });

  // Target sync & hash
  var btnSync = document.getElementById('btn-sim-sync-pw');
  if (btnSync) {
    btnSync.addEventListener('click', function() {
      var src = document.getElementById('pw');
      var dest = document.getElementById('sim-target-val');
      if (src && dest && src.value) {
        dest.value = src.value;
        simTermLog('[TARGET] Synced target password from Strength Checker: "' + src.value + '"', 'info');
      }
    });
  }

  var btnHash = document.getElementById('btn-sim-hash-pw');
  if (btnHash) {
    btnHash.addEventListener('click', function() {
      var dest = document.getElementById('sim-target-val');
      var sel = document.getElementById('sim-target-algo');
      if (!dest || !sel) return;
      var algo = sel.value;
      if (algo === 'plaintext') { algo = 'sha256'; sel.value = 'sha256'; }
      var raw = dest.value.trim();
      var h = (algo === 'md5') ? md5(raw) : (algo === 'sha1') ? sha1(raw) : sha256(raw);
      dest.value = h;
      simTermLog('[TARGET] Computed ' + algo.toUpperCase() + ' hash: ' + h, 'info');
      logActivity('Hashed simulator target with ' + algo.toUpperCase(), '🔒');
    });
  }

  var selAlgo = document.getElementById('sim-target-algo');
  if (selAlgo) {
    selAlgo.addEventListener('change', function() {
      var tag = document.getElementById('sim-algo-tag');
      if (tag) tag.textContent = (selAlgo.value === 'plaintext' ? 'PLAINTEXT CHECK' : (selAlgo.value.toUpperCase() + ' HASH MATCH'));
    });
  }
}

// ==========================================================================
// 6. HASH GENERATOR & HASH CHECKER MODULES
// ==========================================================================
var hashGenUpperCase = false;

function updateHashGenOutputs() {
  var inputEl = document.getElementById('hashgen-input');
  var saltEl = document.getElementById('hashgen-salt');
  if (!inputEl) return;

  var plain = inputEl.value;
  var salt = saltEl ? saltEl.value : '';
  var combined = salt ? (salt + plain) : plain;

  var hMd5 = md5(combined);
  var hSha1 = sha1(combined);
  var hSha256 = sha256(combined);

  if (hashGenUpperCase) {
    hMd5 = hMd5.toUpperCase();
    hSha1 = hSha1.toUpperCase();
    hSha256 = hSha256.toUpperCase();
  }

  var elMd5 = document.getElementById('gen-out-md5');
  var elSha1 = document.getElementById('gen-out-sha1');
  var elSha256 = document.getElementById('gen-out-sha256');

  if (elMd5) elMd5.textContent = hMd5;
  if (elSha1) elSha1.textContent = hSha1;
  if (elSha256) elSha256.textContent = hSha256;

  sha512Async(combined).then(function(h512) {
    var el512 = document.getElementById('gen-out-sha512');
    if (el512) el512.textContent = hashGenUpperCase ? h512.toUpperCase() : h512;
  });
}

function initHashGen() {
  var inp = document.getElementById('hashgen-input');
  var salt = document.getElementById('hashgen-salt');
  if (inp) inp.addEventListener('input', updateHashGenOutputs);
  if (salt) salt.addEventListener('input', updateHashGenOutputs);

  var btnSync = document.getElementById('btn-hashgen-sync');
  if (btnSync) {
    btnSync.addEventListener('click', function() {
      var src = document.getElementById('pw');
      if (src && inp) {
        inp.value = src.value || '';
        updateHashGenOutputs();
        logActivity('Synced password into Hash Generator', '🔄');
      }
    });
  }

  var btnCase = document.getElementById('btn-hashgen-toggle-case');
  if (btnCase) {
    btnCase.addEventListener('click', function() {
      hashGenUpperCase = !hashGenUpperCase;
      btnCase.textContent = hashGenUpperCase ? 'Aa Case: UPPER' : 'Aa Case: Lower';
      updateHashGenOutputs();
    });
  }

  var btnRandSalt = document.getElementById('btn-hashgen-rand-salt');
  if (btnRandSalt && salt) {
    btnRandSalt.addEventListener('click', function() {
      salt.value = generateRandomHexSalt(8);
      updateHashGenOutputs();
    });
  }

  var btnClearSalt = document.getElementById('btn-hashgen-clear-salt');
  if (btnClearSalt && salt) {
    btnClearSalt.addEventListener('click', function() {
      salt.value = '';
      updateHashGenOutputs();
    });
  }

  document.querySelectorAll('.btn-copy-hash').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var srcId = btn.getAttribute('data-src');
      var el = document.getElementById(srcId);
      if (el && el.textContent) {
        navigator.clipboard.writeText(el.textContent).then(function() {
          var orig = btn.textContent;
          btn.textContent = 'Copied!';
          setTimeout(function(){ btnCopy.textContent = orig; }, 1500);
        });
      }
    });
  });

  document.querySelectorAll('.btn-send-to-check').forEach(function(btn) {
    btn.addEventListener('click', function() {
      var srcId = btn.getAttribute('data-src');
      var el = document.getElementById(srcId);
      if (el && el.textContent) {
        var checkInp = document.getElementById('hashcheck-input');
        if (checkInp) checkInp.value = el.textContent;
        navigateTo('#hash-checker');
        inspectTargetHash();
        logActivity('Sent hash to Checker module for pre-image lookup', '🔍');
      }
    });
  });

  updateHashGenOutputs();
}

// Hash Checker & Pre-Image Recovery Engine
function detectHashType(h) {
  var clean = (h || '').trim().toLowerCase();
  if (clean.indexOf('0x') === 0) clean = clean.slice(2);
  if (!clean) return { valid: false, error: 'Empty hash input' };
  if (!/^[a-f0-9]+$/.test(clean)) return { valid: false, error: 'Non-hexadecimal characters present' };
  if (clean.length === 32) return { valid: true, algo: 'md5', name: 'MD5 (128-bit)', bits: 128, sec: 'BROKEN / INSECURE' };
  if (clean.length === 40) return { valid: true, algo: 'sha1', name: 'SHA-1 (160-bit)', bits: 160, sec: 'DEPRECATED / WEAK' };
  if (clean.length === 64) return { valid: true, algo: 'sha256', name: 'SHA-256 (256-bit)', bits: 256, sec: 'SECURE STANDARD' };
  if (clean.length === 128) return { valid: true, algo: 'sha512', name: 'SHA-512 (512-bit)', bits: 512, sec: 'HIGH SECURITY' };
  return { valid: false, error: 'Length ' + clean.length + ' chars (standard: 32, 40, 64 hex)' };
}

function inspectTargetHash() {
  var inp = document.getElementById('hashcheck-input');
  var card = document.getElementById('hashcheck-result-card');
  var badge = document.getElementById('hashcheck-detect-badge');
  var statusEl = document.getElementById('hashcheck-res-status');
  var revealEl = document.getElementById('hashcheck-res-reveal');
  var descEl = document.getElementById('hashcheck-res-desc');
  var metaEl = document.getElementById('hashcheck-res-meta');
  var bridgeBox = document.getElementById('hashcheck-bridge-box');

  if (!inp || !card) return;
  var raw = inp.value.trim();
  var det = detectHashType(raw);

  if (badge) {
    badge.textContent = det.valid ? ('Detected: ' + det.name) : det.error;
    badge.style.color = det.valid ? 'var(--accent)' : 'var(--muted)';
  }

  card.style.display = 'flex';

  if (!det.valid) {
    if (statusEl) { statusEl.textContent = 'Invalid Hash Format'; statusEl.style.color = 'var(--crit)'; }
    if (revealEl) revealEl.textContent = det.error;
    if (descEl) descEl.textContent = 'Please provide a valid hexadecimal hash string (e.g. 32 chars for MD5, 40 for SHA-1, 64 for SHA-256).';
    if (bridgeBox) bridgeBox.style.display = 'none';
    return;
  }

  // Pre-image dictionary lookup test
  var t0 = performance.now();
  var cleanTarget = raw.toLowerCase();
  var candidatePool = (customDictionary || BUILTIN_DICT).concat(TOP_COMMON);
  var currentPw = document.getElementById('pw') ? document.getElementById('pw').value : '';
  if (currentPw) candidatePool.push(currentPw);

  var matchWord = null;
  var attempts = 0;

  for (var i = 0; i < candidatePool.length; i++) {
    attempts++;
    var cand = candidatePool[i];
    var h = (det.algo === 'md5') ? md5(cand) : (det.algo === 'sha1') ? sha1(cand) : sha256(cand);
    if (h.toLowerCase() === cleanTarget) {
      matchWord = cand;
      break;
    }
  }

  var t1 = performance.now();
  var elapsed = (t1 - t0).toFixed(2);

  if (metaEl) metaEl.textContent = elapsed + ' ms · ' + attempts + ' candidate lookups';

  if (matchWord !== null) {
    if (statusEl) { statusEl.textContent = 'PRE-IMAGE RECOVERED · HASH CRACKED'; statusEl.style.color = 'var(--strong)'; }
    if (revealEl) {
      revealEl.style.display = 'block';
      revealEl.textContent = 'Plaintext: "' + matchWord + '" (' + det.name + ')';
      revealEl.style.color = 'var(--strong)';
    }
    if (descEl) descEl.innerHTML = '<strong>What this teaches:</strong> The original password was reversed by looking up pre-computed candidates in our active dictionary in <code>' + elapsed + ' ms</code>. Hashes cannot be mathematically decrypted; adversaries reverse them via pre-image tables.';
    if (bridgeBox) bridgeBox.style.display = 'none';
    logActivity('Hash Checker cracked pre-image: "' + matchWord + '" (' + det.algo.toUpperCase() + ')', '💥');
  } else {
    if (statusEl) { statusEl.textContent = 'Format Valid (' + det.name + ') · Not in Instant Cache'; statusEl.style.color = 'var(--fair)'; }
    if (revealEl) revealEl.style.display = 'none';
    if (descEl) descEl.innerHTML = '<strong>Security Analysis:</strong> Algorithm security rating: <code>' + det.sec + '</code>. The hash was not found in the fast in-memory wordlist (' + attempts + ' candidates checked). You can load this hash into the Dictionary Attack Simulator to perform an extended search.';
    if (bridgeBox) bridgeBox.style.display = 'block';
    logActivity('Hash Checker inspected ' + det.name + ' hash', '🔍');
  }
}

function initHashCheck() {
  var inp = document.getElementById('hashcheck-input');
  var badge = document.getElementById('hashcheck-detect-badge');
  if (inp) {
    inp.addEventListener('input', function() {
      var det = detectHashType(inp.value);
      if (badge) {
        badge.textContent = det.valid ? ('Detected: ' + det.name) : det.error;
        badge.style.color = det.valid ? 'var(--accent)' : 'var(--muted)';
      }
    });
  }

  var btnCheck = document.getElementById('btn-do-hashcheck');
  if (btnCheck) btnCheck.addEventListener('click', inspectTargetHash);

  var btnSend = document.getElementById('btn-send-to-simulator');
  if (btnSend) {
    btnSend.addEventListener('click', function() {
      var h = inp ? inp.value.trim() : '';
      if (!h) return;
      var det = detectHashType(h);
      var simTarget = document.getElementById('sim-target-val');
      var simAlgo = document.getElementById('sim-target-algo');
      if (simTarget) simTarget.value = h;
      if (simAlgo && det.valid) simAlgo.value = det.algo;
      navigateTo('#dict-simulator');
      logActivity('Loaded hash into Dictionary Simulator: ' + h.slice(0, 16) + '...', '⚡');
    });
  }

  var btnLaunchBridge = document.getElementById('btn-launch-sim-bridge');
  if (btnLaunchBridge && btnSend) {
    btnLaunchBridge.addEventListener('click', function() {
      btnSend.click();
      setTimeout(function(){ startSimulation(); }, 350);
    });
  }

  document.querySelectorAll('[data-sample]').forEach(function(chip) {
    chip.addEventListener('click', function() {
      if (inp) {
        inp.value = chip.getAttribute('data-sample');
        inspectTargetHash();
      }
    });
  });

  var btnUseCurrent = document.getElementById('btn-hashcheck-use-current');
  if (btnUseCurrent && inp) {
    btnUseCurrent.addEventListener('click', function() {
      var cur = document.getElementById('pw') ? document.getElementById('pw').value : 'Ravi@2024';
      inp.value = sha256(cur || 'Ravi@2024');
      inspectTargetHash();
    });
  }
}

// ==========================================================================
// 7. INITIALIZATION BOOTSTRAP
// ==========================================================================
function initApp() {
  initTheme();
  initStrengthChecker();
  initSaltLabListeners();
  initDictSimulator();
  initHashGen();
  initHashCheck();

  // Route according to URL hash
  navigateTo(window.location.hash || '#dashboard');
}

// Run bootstrap
initApp();

})();
