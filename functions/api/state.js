// Cloudflare Pages Function: /api/state  (يحتاج KV binding باسم READS)
const enc = new TextEncoder();
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const err = (m, s = 400) => json({ error: m }, s);
const validKey = (kind, key) => typeof key === "string" && (kind === "read" ? /^(\d|[1-6]\d|7[0-2])\|\d{1,3}$/.test(key)
  : kind === "pray" ? /^\d{4}-\d{2}-\d{2}\|(morning|evening|liturgy|confession|service)$/.test(key) : false);
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
  const users = idx.map((u, i) => recs[i] && { username: u, name: recs[i].name, admin: !!recs[i].admin, reads: recs[i].reads || {}, prayers: recs[i].prayers || {}, rx: recs[i].rx || {} }).filter(Boolean);
  return { needsSetup: idx.length === 0, users, reminders: (await env.READS.get("reminders", "json")) || [] };
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

// ---------- الإشعارات (Web Push بدون payload) ----------
const b64u = (b) => b64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function vapid(env) {
  let j = await env.READS.get("vapid", "json");
  if (!j) {
    const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    j = { priv: await crypto.subtle.exportKey("jwk", kp.privateKey), pub: b64u(await crypto.subtle.exportKey("raw", kp.publicKey)) };
    await env.READS.put("vapid", JSON.stringify(j));
  }
  return j;
}
async function vapidAuth(v, endpoint, sub) {
  const h = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const c = b64u(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 43200, sub })));
  const k = await crypto.subtle.importKey("jwk", v.priv, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = b64u(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, k, enc.encode(h + "." + c)));
  return `vapid t=${h}.${c}.${sig}, k=${v.pub}`;
}
async function notify(env, origin, from, text, to) {
  try {
    const ev = (await env.READS.get("events", "json")) || [];
    ev.push({ t: Date.now(), from, to: to || null, text });
    await env.READS.put("events", JSON.stringify(ev.slice(-20)));
  } catch {}
  const subs = (await env.READS.get("subs", "json")) || {};
  const targets = Object.entries(subs).filter(([, u]) => (to ? u === to : u !== from)).map(([e]) => e).slice(0, 40);
  if (!targets.length) return;
  const v = await vapid(env), dead = [];
  await Promise.all(targets.map(async (ep) => {
    try {
      const r = await fetch(ep, { method: "POST", headers: { authorization: await vapidAuth(v, ep, origin), ttl: "3600", urgency: "high" } });
      if (r.status === 404 || r.status === 410) dead.push(ep);
    } catch {}
  }));
  if (dead.length) { dead.forEach((e) => delete subs[e]); await env.READS.put("subs", JSON.stringify(subs)); }
}

// ---------- الجدولة (بيناديها خدمة cron خارجية كل دقيقة) ----------
async function cronKey(env) {
  let k = await env.READS.get("cronkey");
  if (!k) { k = b64u(crypto.getRandomValues(new Uint8Array(24))); await env.READS.put("cronkey", k); }
  return k;
}
function cairo(back = 0) {
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-GB", { timeZone: "Africa/Cairo", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", weekday: "short", hourCycle: "h23" }).formatToParts(new Date(Date.now() - back * 60000)).map((x) => [x.type, x.value]));
  return { date: `${p.year}-${p.month}-${p.day}`, time: `${p.hour}:${p.minute}`, dow: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(p.weekday) };
}
async function runReminders(env, origin) {
  const rems = (await env.READS.get("reminders", "json")) || [];
  if (!rems.length) return 0;
  const fired = (await env.READS.get("rfired", "json")) || {}, due = [];
  for (const back of [1, 0]) { // الدقيقة الحالية + اللي قبلها، لو الاستدعاء اتأخر ثواني
    const now = cairo(back), stamp = now.date + " " + now.time;
    for (const r of rems) {
      if (r.on === false || r.time !== now.time || fired[r.id] === stamp || due.some((d) => d.id === r.id)) continue;
      if (!(r.date ? r.date === now.date : (r.days || []).includes(now.dow))) continue;
      fired[r.id] = stamp; due.push(r);
    }
  }
  if (!due.length) return 0;
  for (const id of Object.keys(fired)) if (!rems.some((r) => r.id === id)) delete fired[id];
  await env.READS.put("rfired", JSON.stringify(fired));
  await notify(env, origin, "system", due.map((r) => r.text).join(" • "), null);
  return due.length;
}

export async function onRequestGet({ request, env }) {
  const q = new URL(request.url).searchParams;
  if (q.has("cron")) {
    if (q.get("cron") !== (await cronKey(env))) return err("مفتاح غلط", 403);
    return json({ ok: true, sent: await runReminders(env, new URL(request.url).origin) });
  }
  if (q.has("vapid")) return json({ key: (await vapid(env)).pub });
  if (q.has("last")) {
    const u = ((await env.READS.get("subs", "json")) || {})[q.get("ep") || ""];
    const ev = ((await env.READS.get("events", "json")) || []).reverse();
    const m = ev.find((e) => (u ? (e.to ? e.to === u : e.from !== u) : !e.to));
    return json(m ? { text: m.text } : {});
  }
  return json(await state(env));
}

export async function onRequestPost({ request, env, waitUntil }) {
  let b; try { b = await request.json(); } catch { return err("طلب غلط"); }
  const idx = (await env.READS.get("users", "json")) || [];
  let adm = false;
  const reply = async (x = {}) => json({ ...(await state(env)), ...(adm ? { cronKey: await cronKey(env) } : {}), ...x });

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
    if (!validKey(b.kind, b.key)) return err("بيانات غلط");
    const f = b.kind === "read" ? "reads" : "prayers";
    rec[f] = rec[f] || {};
    let added = false;
    if (b.done) { if (!rec[f][b.key]) { rec[f][b.key] = new Date().toISOString(); added = true; } } else delete rec[f][b.key];
    await env.READS.put("user:" + username, JSON.stringify(rec));
    if (added) waitUntil(notify(env, new URL(request.url).origin, username, `${me.name} ${String(b.label || "").slice(0, 80)}`.trim()));
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
  if (b.action === "react") {
    const owner = String(b.owner || ""), em = String(b.emoji || "");
    if (!["", "❤️", "👏", "🙏"].includes(em) || owner === username || !validKey(b.kind, b.key)) return err("بيانات غلط");
    const o = await getUser(env, owner), f = b.kind === "read" ? "reads" : "prayers";
    if (!o || !(o[f] || {})[b.key]) return err("العلامة دي مش موجودة");
    rec.rx = rec.rx || {};
    const rk = `${owner}|${b.kind}|${b.key}`, had = rec.rx[rk] === em;
    if (em) rec.rx[rk] = em; else delete rec.rx[rk];
    await env.READS.put("user:" + username, JSON.stringify(rec));
    if (em && !had) waitUntil(notify(env, new URL(request.url).origin, username, `${me.name} ${em} ${String(b.label || "").slice(0, 80)}`.trim(), owner));
    return reply();
  }
  if (b.action === "subscribe" || b.action === "unsubscribe") {
    const ep = String(b.endpoint || "");
    if (!/^https:\/\/.{10,600}$/.test(ep)) return err("بيانات غلط");
    const subs = (await env.READS.get("subs", "json")) || {};
    if (b.action === "subscribe") { if (Object.keys(subs).length >= 200) return err("كتير أوي"); subs[ep] = username; }
    else if (subs[ep] === username) delete subs[ep];
    await env.READS.put("subs", JSON.stringify(subs));
    return reply();
  }
  if (!me.admin) return err("للمدير فقط", 403);
  adm = true;
  if (b.action === "remInfo") return reply();
  if (b.action.startsWith("rem")) {
    const rems = (await env.READS.get("reminders", "json")) || [];
    if (b.action === "remAdd") {
      const text = String(b.text || "").trim().slice(0, 120), time = String(b.time || ""), date = String(b.date || "");
      const days = [...new Set((Array.isArray(b.days) ? b.days : []).map(Number).filter((d) => Number.isInteger(d) && d >= 0 && d <= 6))].sort();
      if (!text) return err("اكتب نص الرسالة");
      if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) return err("اختار الوقت");
      if (date && !/^\d{4}-\d{2}-\d{2}$/.test(date)) return err("التاريخ غلط");
      if (!date && !days.length) return err("اختار يوم أو تاريخ");
      if (rems.length >= 30) return err("وصلت للحد الأقصى (30 تذكير)");
      rems.push({ id: Date.now().toString(36), text, time, days: date ? [] : days, date, on: true });
    } else {
      const r = rems.find((x) => x.id === b.id);
      if (!r) return err("التذكير مش موجود", 404);
      if (b.action === "remToggle") r.on = r.on === false;
      else if (b.action === "remDel") rems.splice(rems.indexOf(r), 1);
      else if (b.action === "remNow") { waitUntil(notify(env, new URL(request.url).origin, "system", r.text, null)); return reply(); }
      else return err("أمر غير معروف");
    }
    await env.READS.put("reminders", JSON.stringify(rems));
    return reply();
  }
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
