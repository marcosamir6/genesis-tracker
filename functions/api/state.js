// Cloudflare Pages Function: /api/state
// يحتاج KV binding باسم READS

const KEY = "state";
const DEFAULT = {
  people: [
    { id: "p1", name: "جرجس" },
    { id: "p2", name: "مايكل" },
    { id: "p3", name: "ماركو" },
  ],
  checks: {}, // "personId:chapter" -> وقت القراءة ISO
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

async function load(env) {
  return (await env.READS.get(KEY, "json")) || structuredClone(DEFAULT);
}

export async function onRequestGet({ env }) {
  return json(await load(env));
}

export async function onRequestPost({ request, env }) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "bad request" }, 400); }

  const state = await load(env);

  if (body.action === "set") {
    const person = state.people.find((p) => p.id === body.person);
    const ch = Number(body.chapter);
    if (!person || !Number.isInteger(ch) || ch < 1 || ch > 150) return json({ error: "bad input" }, 400);
    const k = `${person.id}:${ch}`;
    if (body.done) { if (!state.checks[k]) state.checks[k] = new Date().toISOString(); }
    else delete state.checks[k];
  } else if (body.action === "addPerson") {
    const name = String(body.name || "").trim().slice(0, 30);
    if (!name) return json({ error: "name required" }, 400);
    if (state.people.length >= 30) return json({ error: "too many" }, 400);
    state.people.push({ id: "p" + Date.now().toString(36), name });
  } else {
    return json({ error: "unknown action" }, 400);
  }

  await env.READS.put(KEY, JSON.stringify(state));
  return json(state);
}
