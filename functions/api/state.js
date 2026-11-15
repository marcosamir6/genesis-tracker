// Cloudflare Pages Function: /api/state  (يحتاج KV binding باسم READS)
const enc = new TextEncoder();
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const err = (m, s = 400) => json({ error: m }, s);
const getUser = (env, u) => env.READS.get("user:" + u, "json");

async function hashPw(pw, salt) {
  const k = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  return b64(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: unb64(salt), iterations: 100000 }, k, 256));
}
async function hmac(env, msg) {
  let sec = await env.READS.get("secret");
  if (!sec) { sec = b64(crypto.getRandomValues(new Uint8Array(32))); await env.READS.put("secret", sec); }
  const k = await crypto.subtle.importKey("raw", enc.encode(sec), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
async function makeToken(env, u) { const exp = Date.now() + 30 * 864e5; return `${u}.${exp}.${await hmac(env, u + "." + exp)}`; }
async function auth(env, request) {
  const [u, exp, sig] = (request.headers.get("authorization") || "").replace("Bearer ", "").split(".");
  if (!u || !sig || Date.now() > +exp || sig !== (await hmac(env, u + "." + exp))) return null;
  const r = await getUser(env, u);
  return r ? { username: u, ...r } : null;
}
async function state(env) {
  const idx = (await env.READS.get("users", "json")) || [];
  const recs = await Promise.all(idx.map((u) => getUser(env, u)));
  const users = idx.map((u, i) => recs[i] && { username: u, name: recs[i].name, admin: !!recs[i].admin, reads: recs[i].reads || {}, prayers: recs[i].prayers || {} }).filter(Boolean);
  return { needsSetup: idx.length === 0, users };
}
async function mkUser(env, b, admin) {
  const username = String(b.username || "").toLowerCase().trim(), name = String(b.name || "").trim().slice(0, 30), pw = String(b.password || "");
  if (!/^[a-z0-9_]{3,20}$/.test(username)) return "اسم المستخدم لازم يكون من 3 لـ 20 حرف إنجليزي صغير أو أرقام";
  if (!name) return "اكتب الاسم";
  if (pw.length < 4) return "كلمة السر لازم تكون 4 حروف على الأقل";
  if (await getUser(env, username)) return "اسم المستخدم موجود قبل كده";
  const salt = b64(crypto.getRandomValues(new Uint8Array(16)));
  await env.READS.put("user:" + username, JSON.stringify({ name, salt, hash: await hashPw(pw, salt), admin, reads: {}, prayers: {} }));
  return { username };
}

export async function onRequestGet({ env }) { return json(await state(env)); }

export async function onRequestPost({ request, env }) {
  let b; try { b = await request.json(); } catch { return err("طلب غلط"); }
  const idx = (await env.READS.get("users", "json")) || [];
  const reply = async (x = {}) => json({ ...(await state(env)), ...x });

  if (b.action === "setup") {
    if (idx.length) return err("الموقع متجهز قبل كده", 403);
    const r = await mkUser(env, b, true); if (typeof r === "string") return err(r);
    await env.READS.put("users", JSON.stringify([r.username]));
    const u = await getUser(env, r.username);
    return reply({ token: await makeToken(env, r.username), me: { username: r.username, name: u.name, admin: true } });
  }
  if (b.action === "login") {
    const u = String(b.username || "").toLowerCase().trim(), r = await getUser(env, u);
    if (!r || r.hash !== (await hashPw(String(b.password || ""), r.salt))) return err("اسم المستخدم أو كلمة السر غلط", 401);
    return reply({ token: await makeToken(env, u), me: { username: u, name: r.name, admin: !!r.admin } });
  }

  const me = await auth(env, request);
  if (!me) return err("سجّل الدخول الأول", 401);
  const { username, ...rec } = me;

  if (b.action === "set") {
    const ok = b.kind === "read" ? /^(\d|[1-6]\d|7[0-2])\|\d{1,3}$/.test(b.key)
      : b.kind === "pray" ? /^\d{4}-\d{2}-\d{2}\|(morning|evening|liturgy|confession|service)$/.test(b.key) : false;
    if (!ok) return err("بيانات غلط");
    const f = b.kind === "read" ? "reads" : "prayers";
    rec[f] = rec[f] || {};
    if (b.done) { if (!rec[f][b.key]) rec[f][b.key] = new Date().toISOString(); } else delete rec[f][b.key];
    await env.READS.put("user:" + username, JSON.stringify(rec));
    return reply();
  }
  if (b.action === "passwd") {
    const t = String(b.username || username).toLowerCase();
    if (t !== username && !me.admin) return err("مش مسموح", 403);
    const r = await getUser(env, t); if (!r) return err("الحساب مش موجود", 404);
    if (String(b.password || "").length < 4) return err("كلمة السر لازم تكون 4 حروف على الأقل");
    r.salt = b64(crypto.getRandomValues(new Uint8Array(16))); r.hash = await hashPw(String(b.password), r.salt);
    await env.READS.put("user:" + t, JSON.stringify(r));
    return reply();
  }
  if (!me.admin) return err("للمدير فقط", 403);
  if (b.action === "addUser") {
    if (idx.length >= 30) return err("وصلت للحد الأقصى (30 حساب)");
    const r = await mkUser(env, b, !!b.admin); if (typeof r === "string") return err(r);
    idx.push(r.username); await env.READS.put("users", JSON.stringify(idx));
    return reply();
  }
  if (b.action === "delUser") {
    const t = String(b.username || "").toLowerCase();
    if (t === username) return err("مينفعش تمسح حسابك");
    await env.READS.put("users", JSON.stringify(idx.filter((x) => x !== t)));
    await env.READS.delete("user:" + t);
    return reply();
  }
  return err("أمر غير معروف");
}
