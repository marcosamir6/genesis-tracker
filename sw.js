// Service worker: يستقبل الإشعارات ويعرضها بصوت
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("fetch", () => {});

self.addEventListener("push", (e) => e.waitUntil((async () => {
  let text = "فيه تحديث جديد";
  try {
    const s = await self.registration.pushManager.getSubscription();
    const j = await (await fetch("/api/state?last=1&ep=" + encodeURIComponent(s ? s.endpoint : ""), { cache: "no-store" })).json();
    if (j.text) text = j.text;
  } catch {}
  await self.registration.showNotification("المتابعة الروحية", { body: text, icon: "/icon-192.png", badge: "/icon-192.png", lang: "ar", dir: "rtl", vibrate: [120, 60, 120] });
  for (const c of await self.clients.matchAll({ type: "window" })) c.postMessage("refresh");
})()));

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil((async () => {
    const all = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    if (all.length) { await all[0].focus(); all[0].postMessage("refresh"); } else await self.clients.openWindow("/");
  })());
});
