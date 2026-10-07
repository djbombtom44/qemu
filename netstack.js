/* In-browser user-mode network for QEMU-wasm (no server needed).
   QEMU's `-netdev socket,connect=...` opens a "WebSocket" via Emscripten; we replace WebSocket with
   FakeWS, which hands Ethernet frames (4-byte length prefix) to a JS stack that answers ARP/DHCP/DNS
   (DNS-over-HTTPS) and turns guest HTTP requests into fetch() calls. Browsers cannot open raw TCP/UDP
   sockets, so only HTTP (port 80 etc.) works, and only for sites that allow CORS (or via a CORS proxy). */
(()=>{
const GW=[10,0,2,2],DNS=[10,0,2,3],GUEST=[10,0,2,15],GWMAC=[0x52,0x54,0,0x12,0x35,2],BC=[255,255,255,255,255,255];
const FIN=1,SYN=2,RST=4,PSH=8,ACK=16, MSS=1400, MAXFLIGHT=12*MSS;
const cfg={proxy:'',https:true,relay:''};
const cat=(...a)=>{const o=new Uint8Array(a.reduce((x,y)=>x+y.length,0));let p=0;for(const x of a){o.set(x,p);p+=x.length}return o};
const u16=v=>[v>>8&255,v&255], u32=v=>[v>>>24&255,v>>>16&255,v>>>8&255,v&255], U8=a=>Uint8Array.from(a);
const eqb=(a,o,b)=>b.every((x,i)=>a[o+i]===x);
function csum(b){let s=0,n=b.length;for(let i=0;i+1<n;i+=2)s+=b[i]<<8|b[i+1];if(n&1)s+=b[n-1]<<8;while(s>>>16)s=(s&0xffff)+(s>>>16);return ~s&0xffff}
const eth=(d,s,t,p)=>cat(U8(d),U8(s),U8(u16(t)),p);
function ip4(src,dst,proto,p){const h=U8([0x45,0,...u16(20+p.length),...u16(Math.random()*65536|0),0x40,0,64,proto,0,0,...src,...dst]);const c=csum(h);h[10]=c>>8;h[11]=c&255;return cat(h,p)}
function l4(src,dst,proto,seg,off){let c=csum(cat(U8([...src,...dst,0,proto,...u16(seg.length)]),seg));if(proto===17&&!c)c=0xffff;seg[off]=c>>8;seg[off+1]=c&255;return seg}
const tcp=(s,d,sp,dp,seq,ack,fl,data=new Uint8Array(0),opts=[])=>l4(s,d,6,cat(U8([...u16(sp),...u16(dp),...u32(seq>>>0),...u32(ack>>>0),(5+opts.length/4)<<4,fl,255,255,0,0,0,0,...opts]),data),16);
const udp=(s,d,sp,dp,data)=>l4(s,d,17,cat(U8([...u16(sp),...u16(dp),...u16(8+data.length),0,0]),data),6);
const latin=b=>{let s='';for(let i=0;i<b.length;i+=8192)s+=String.fromCharCode.apply(null,b.subarray(i,i+8192));return s};
const ipstr=a=>[...a].join('.');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));

const dnsCache=new Map();
async function doh(name){
  const c=dnsCache.get(name); if(c&&c.t>Date.now()) return c.v;
  let last;
  for(const u of ['https://cloudflare-dns.com/dns-query?name=','https://dns.google/resolve?name=']){
    try{ const r=await fetch(u+encodeURIComponent(name)+'&type=A',{headers:{accept:'application/dns-json'}}); const j=await r.json();
      const v={rc:j.Status|0,ips:(j.Answer||[]).filter(a=>a.type===1).map(a=>a.data.split('.').map(Number))};
      dnsCache.set(name,{v,t:Date.now()+60000}); return v }catch(e){last=e}
  } throw last;
}
async function dnsReply(q){
  let i=12,l=[]; while(q[i]){l.push(latin(q.subarray(i+1,i+1+q[i])));i+=q[i]+1} i++;
  const qt=q[i]<<8|q[i+1], qend=i+4; let ips=[],rc=0;
  if(qt===1){ try{ ({rc,ips}=await doh(l.join('.'))) }catch(e){rc=2} }
  const an=ips.flatMap(ip=>[0xc0,0x0c,0,1,0,1,...u32(60),0,4,...ip]);
  return cat(q.subarray(0,2),U8([0x81,0x80|rc,0,1,...u16(ips.length),0,0,0,0]),q.subarray(12,qend),U8(an));
}

async function http(f,req){
  const he=latin(req).indexOf('\r\n\r\n'), lines=latin(req.subarray(0,he)).split('\r\n');
  const [method,path]=lines[0].split(' '); const h={};
  for(const l of lines.slice(1)){const k=l.indexOf(':'); if(k>0)h[l.slice(0,k).trim().toLowerCase()]=l.slice(k+1).trim()}
  const host=h.host||ipstr(f.dip), body=req.subarray(he+4);
  let url=(cfg.https?'https':'http')+'://'+host.replace(/:80$/,'')+path; if(!h.host&&f.dp!==80)url=url.replace(host,host+':'+f.dp);
  const init={method,redirect:'follow'};
  if(!/^(GET|HEAD)$/.test(method)&&body.length){init.body=body; if(h['content-type'])init.headers={'content-type':h['content-type']}}
  try{
    const r=await fetch(cfg.proxy?cfg.proxy+encodeURIComponent(url):url,init), b=new Uint8Array(await r.arrayBuffer());
    let head='HTTP/1.1 '+r.status+' '+(r.statusText||'OK')+'\r\n';
    r.headers.forEach((v,k)=>{ if(!/^(content-encoding|transfer-encoding|content-length|connection|keep-alive)$/.test(k)) head+=k+': '+v+'\r\n' });
    return cat(U8([...head+'Content-Length: '+b.length+'\r\nConnection: close\r\n\r\n'].map(c=>c.charCodeAt(0)&255)),method==='HEAD'?new Uint8Array(0):b);
  }catch(e){
    const m='502 Bad Gateway: '+e.message+'\n(the browser could only fetch '+url+' if the site allows CORS; set a CORS proxy on the launcher)\n';
    return U8([...('HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: '+m.length+'\r\nConnection: close\r\n\r\n'+m)].map(c=>c.charCodeAt(0)&255));
  }
}

class Flow{
  constructor(r,sp,dip,dp,isn){Object.assign(this,{r,sp,dip,dp,rcv:(isn+1)>>>0,snd:crypto.getRandomValues(new Uint32Array(1))[0],q:[],pend:[],finWanted:false,finSent:false,finRecv:false,req:new Uint8Array(0),handled:false,t:Date.now(),dead:false});
    this.una=this.snd; this.synack(); this.snd=(this.snd+1)>>>0}
  send(seq,fl,data,opts){this.r.out(eth(this.r.gmac,GWMAC,0x800,ip4(this.dip,GUEST,6,tcp(this.dip,GUEST,this.dp,this.sp,seq,this.rcv,fl,data,opts))))}
  synack(){this.send(this.snd,SYN|ACK,undefined,[2,4,5,0xb4])}
  kill(){this.dead=true;this.r.flows.delete(this.key)}
  pump(){
    while(this.pend.length&&((this.snd-this.una)>>>0)<MAXFLIGHT){
      const b=this.pend[0],c=b.subarray(0,MSS); if(b.length>MSS)this.pend[0]=b.subarray(MSS); else this.pend.shift();
      this.q.push({seq:this.snd,data:c,fl:PSH|ACK,t:Date.now()}); this.send(this.snd,PSH|ACK,c); this.snd=(this.snd+c.length)>>>0 }
    if(!this.pend.length&&this.finWanted&&!this.finSent){this.finSent=true;this.q.push({seq:this.snd,data:new Uint8Array(0),fl:FIN|ACK,t:Date.now()});this.send(this.snd,FIN|ACK);this.snd=(this.snd+1)>>>0}
  }
  rx(seq,ack,fl,data){
    this.t=Date.now();
    if(fl&RST){this.kill();return}
    if(fl&SYN){ if(this.una===((this.snd-1)>>>0)) this.send(this.una,SYN|ACK,undefined,[2,4,5,0xb4]); return }
    if(fl&ACK){
      if(((ack-this.una)>>>0)<=((this.snd-this.una)>>>0)) this.una=ack;
      while(this.q.length){const e=this.q[0],end=(e.seq+e.data.length+(e.fl&FIN?1:0))>>>0; if(((this.una-end)>>>0)<0x80000000)this.q.shift(); else break}
      this.pump();
      if(this.finSent&&this.una===this.snd&&this.finRecv){this.kill();return}
    }
    if(data.length){
      const off=(this.rcv-seq)>>>0; if(off<0x80000000&&off<data.length){data=data.subarray(off);seq=this.rcv}
      if(seq===this.rcv&&data.length){this.rcv=(this.rcv+data.length)>>>0;this.req=cat(this.req,data);this.tryHttp()}
      this.send(this.snd,ACK);
    }
    if(fl&FIN&&((seq+data.length)>>>0)===this.rcv&&!this.finRecv){this.finRecv=true;this.rcv=(this.rcv+1)>>>0;this.send(this.snd,ACK);this.tryHttp(true);if(this.finSent&&this.una===this.snd)this.kill()}
  }
  tryHttp(){
    if(this.handled)return; const t=latin(this.req), he=t.indexOf('\r\n\r\n'); if(he<0)return;
    const m=/content-length:\s*(\d+)/i.exec(t.slice(0,he)); if(this.req.length<he+4+(m?+m[1]:0))return;
    this.handled=true; http(this,this.req).then(b=>{this.pend.push(b);this.finWanted=true;this.pump()});
  }
  retx(now){for(const e of this.q.slice(0,6)) if(now-e.t>1000){e.t=now;this.send(e.seq,e.fl,e.data)}}
}

class Relay{
  constructor(send){this.sendRaw=send;this.flows=new Map();this.gmac=[0x52,0x54,0,0x12,0x34,0x56];
    this.timer=setInterval(()=>{const n=Date.now();for(const f of [...this.flows.values()]){f.retx(n);if(n-f.t>60000)f.kill()}},500)}
  out(f){const o=new Uint8Array(4+f.length);new DataView(o.buffer).setUint32(0,f.length);o.set(f,4);this.sendRaw(o)}
  close(){clearInterval(this.timer);this.flows.clear()}
  frame(f){
    if(f.length<14)return; const t=f[12]<<8|f[13], src=[...f.subarray(6,12)];
    if(t===0x806&&f.length>=42){
      this.gmac=src; const tpa=[...f.subarray(38,42)];
      if(f[21]===1&&!eqb(tpa,0,GUEST)&&tpa[0]===10&&tpa[1]===0&&tpa[2]===2)
        this.out(eth(src,GWMAC,0x806,U8([0,1,8,0,6,4,0,2,...GWMAC,...tpa,...f.subarray(22,28),...f.subarray(28,32)])));
    }else if(t===0x800&&f.length>=34){
      this.gmac=src; const ihl=(f[14]&15)*4, pr=f[23], sip=[...f.subarray(26,30)], dip=f.subarray(30,34), tot=f[16]<<8|f[17], p=f.subarray(14+ihl,14+tot);
      if(pr===1&&p.length>=8&&p[0]===8&&(eqb(dip,0,GW)||eqb(dip,0,DNS))){
        const r=U8(p);r[0]=0;r[2]=r[3]=0;const c=csum(r);r[2]=c>>8;r[3]=c&255;this.out(eth(this.gmac,GWMAC,0x800,ip4([...dip],sip,1,r)))
      }else if(pr===17&&p.length>=8) this.udp(dip,p);
      else if(pr===6&&p.length>=20) this.tcp([...dip],p);
    }
  }
  udp(dip,p){
    const sp=p[0]<<8|p[1], dp=p[2]<<8|p[3], data=p.subarray(8,p[4]<<8|p[5]);
    if(dp===67)this.dhcp(data); else if(dp===53&&eqb(dip,0,DNS)) dnsReply(data).then(r=>this.out(eth(this.gmac,GWMAC,0x800,ip4(DNS,GUEST,17,udp(DNS,GUEST,53,sp,r)))));
  }
  dhcp(d){
    if(d.length<240||d[0]!==1)return; let mt=0,i=240;
    while(i<d.length&&d[i]!==255){ if(d[i]===0){i++;continue} if(d[i]===53)mt=d[i+2]; i+=2+d[i+1] }
    if(mt!==1&&mt!==3)return;
    const o=[53,1,mt===1?2:5,54,4,...GW,51,4,0,1,0x51,0x80,1,4,255,255,255,0,3,4,...GW,6,4,...DNS,255];
    const r=cat(U8([2,1,6,0]),d.subarray(4,8),new Uint8Array(8),U8(GUEST),U8(GW),d.subarray(24,28),d.subarray(28,44),new Uint8Array(192),U8([0x63,0x82,0x53,0x63,...o]));
    const bc=[255,255,255,255]; this.out(eth(BC,GWMAC,0x800,ip4(GW,bc,17,udp(GW,bc,67,68,r))));
  }
  tcp(dip,p){
    const sp=p[0]<<8|p[1], dp=p[2]<<8|p[3], dv=new DataView(p.buffer,p.byteOffset), seq=dv.getUint32(4), ack=dv.getUint32(8), fl=p[13], data=p.subarray((p[12]>>4)*4);
    const key=sp+':'+dip.join('.')+':'+dp, f=this.flows.get(key);
    if(f)f.rx(seq,ack,fl,data);
    else if(fl&SYN&&!(fl&ACK)){
      if(dp===443||(dp<1024&&dp!==80)) this.out(eth(this.gmac,GWMAC,0x800,ip4(dip,GUEST,6,tcp(dip,GUEST,dp,sp,0,seq+1,RST|ACK))));
      else{const n=new Flow(this,sp,dip,dp,seq);n.key=key;this.flows.set(key,n)}
    }else if(!(fl&RST)) this.out(eth(this.gmac,GWMAC,0x800,ip4(dip,GUEST,6,tcp(dip,GUEST,dp,sp,ack,(seq+data.length)>>>0,RST|ACK))));
  }
}

class FakeWS{
  constructor(){this.CONNECTING=0;this.OPEN=1;this.CLOSING=2;this.CLOSED=3;this.readyState=0;this.binaryType='arraybuffer';this.protocol='binary';this.bufferedAmount=0;this.buf=new Uint8Array(0);
    this.relay=new Relay(b=>setTimeout(()=>{if(this.readyState===1&&this.onmessage)this.onmessage({data:b.buffer})},0));
    setTimeout(()=>{this.readyState=1;this.onopen&&this.onopen({})},0)}
  send(d){
    this.buf=cat(this.buf,d instanceof ArrayBuffer?new Uint8Array(d):new Uint8Array(d.buffer,d.byteOffset,d.byteLength));
    while(this.buf.length>=4){const L=new DataView(this.buf.buffer,this.buf.byteOffset).getUint32(0); if(this.buf.length<4+L)break;
      this.relay.frame(this.buf.slice(4,4+L)); this.buf=this.buf.slice(4+L)}
  }
  close(){if(this.readyState===3)return;this.readyState=3;this.relay.close();this.onclose&&this.onclose({code:1000})}
}
const RealWS=self.WebSocket;
// Bridges QEMU's length-prefixed stream to a relay that sends one raw Ethernet frame per WebSocket message
// (the v86-style protocol used by wss://relay.widgetry.org/).
class BridgeWS{
  constructor(){this.CONNECTING=0;this.OPEN=1;this.CLOSING=2;this.CLOSED=3;this.readyState=0;this.binaryType='arraybuffer';this.protocol='';this.bufferedAmount=0;this.buf=new Uint8Array(0);
    const w=this.ws=new RealWS(cfg.relay); w.binaryType='arraybuffer';
    w.onopen=()=>{this.readyState=1;this.onopen&&this.onopen({})};
    w.onerror=e=>{this.onerror&&this.onerror(e)};
    w.onclose=e=>{this.readyState=3;this.onclose&&this.onclose(e)};
    w.onmessage=e=>{ if(!(e.data instanceof ArrayBuffer)||!this.onmessage)return; const o=new Uint8Array(4+e.data.byteLength);
      new DataView(o.buffer).setUint32(0,e.data.byteLength);o.set(new Uint8Array(e.data),4);this.onmessage({data:o.buffer}) };
  }
  send(d){
    this.buf=cat(this.buf,d instanceof ArrayBuffer?new Uint8Array(d):new Uint8Array(d.buffer,d.byteOffset,d.byteLength));
    while(this.buf.length>=4){const L=new DataView(this.buf.buffer,this.buf.byteOffset).getUint32(0); if(this.buf.length<4+L)break;
      if(this.ws.readyState===1)this.ws.send(this.buf.slice(4,4+L)); this.buf=this.buf.slice(4+L)}
  }
  close(){this.readyState=2;try{this.ws.close()}catch(e){}}
}
const api={FakeWS,BridgeWS,Relay,config:cfg,install(opts){Object.assign(cfg,opts||{});self.WebSocket=cfg.relay?BridgeWS:FakeWS},
  _t:{eth,ip4,tcp,udp,csum,GW,DNS,GUEST,GWMAC}};
if(typeof module!=='undefined')module.exports=api; else self.NetStack=api;
})();
