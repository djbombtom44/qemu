/* Adds COOP/COEP headers to same-origin responses so SharedArrayBuffer (pthreads) works on static hosts. */
self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('fetch',e=>{
  const r=e.request;
  if(r.cache==='only-if-cached'&&r.mode!=='same-origin')return;
  if(new URL(r.url).origin!==self.location.origin)return;
  e.respondWith(fetch(r).then(res=>{
    if(!res.status||res.type==='opaque')return res;
    const h=new Headers(res.headers);
    h.set('Cross-Origin-Embedder-Policy','require-corp');
    h.set('Cross-Origin-Opener-Policy','same-origin');
    h.set('Cross-Origin-Resource-Policy','same-origin');
    return new Response(res.body,{status:res.status,statusText:res.statusText,headers:h});
  }).catch(err=>{console.error(err);return Response.error()}));
});
