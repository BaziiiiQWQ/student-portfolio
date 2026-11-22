// /functions/api/guestbook.js - Cloudflare Pages Function + D1
// Environment binding: DB (D1 database). Legacy GUESTBOOK_DB also supported.
// Secret environment variable required: GUESTBOOK_PEPPER (random private string)
const PAGE_ORIGINS = new Set([
  'https://student-portfolio-dh4.pages.dev',
  'https://baziiiiqwq.github.io'
]);
const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' };
function corsHeaders(request) {
  const origin = request.headers.get('origin');
  if (!origin || !PAGE_ORIGINS.has(origin.toLowerCase())) return {};
  return { 'access-control-allow-origin': origin, 'vary': 'Origin',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'Content-Type' };
}
function send(request, payload, status = 200, headers = {}) {
  return new Response(JSON.stringify(payload), {
    status, headers: { ...JSON_HEADERS, ...corsHeaders(request), ...headers }
  });
}
const clean = (value, limit) => (typeof value === 'string' ? value.trim().slice(0, limit) : '');
async function hashIp(ip, pepper) {
  const bytes = new TextEncoder().encode(`${pepper}:${ip}`);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), x=>x.toString(16).padStart(2, '0')).join('');
}
function getDB(context) { return context.env?.DB ?? context.env?.GUESTBOOK_DB; }
export async function onRequestOptions({ request }) {
  const o = request.headers.get('origin')?.toLowerCase();
  return new Response(null, {status: o && PAGE_ORIGINS.has(o) ? 204 : 403, headers: corsHeaders(request)});
}
export async function onRequestGet(context) {
  const {request}=context;const db=getDB(context);
  if(!db) return send(request,{error:'Database not configured'},503);
  const limit=Math.max(1,Math.min(30,Number(new URL(request.url).searchParams.get('limit'))||30));
  try {
    const q=await db.prepare(
      "SELECT id, nickname, message, created_at FROM guestbook_messages WHERE status = 'visible' ORDER BY id DESC LIMIT ?"
    ).bind(limit).all();
    return send(request,{messages:q.results || []});
  } catch(e){return send(request,{error:'Could not read guestbook'},503);}
}
export async function onRequestPost(context) {
  const {request,env}=context;const db=getDB(context);
  if(!db||!env.GUESTBOOK_PEPPER)return send(request,{error:'Guestbook is not configured'},503);
  if((Number(request.headers.get('content-length'))||0)>4000)return send(request,{error:'Payload too long'},413);
  const origin=request.headers.get('origin');
  if(origin && !PAGE_ORIGINS.has(origin.toLowerCase()))return send(request,{error:'Origin not allowed'},403);
  let obj;try{obj=await request.json();}catch(e){return send(request,{error:'Invalid JSON'},400);}
  if(typeof obj!=='object'||obj===null)return send(request,{error:'Invalid input'},400);
  if(obj.website)return send(request,{error:'Invalid request'},400);
  const nickname=clean(obj.nickname,25),message=clean(obj.message,301);
  if(nickname.length<1||nickname.length>24||message.length<2||message.length>300)return send(request,{error:'Enter 1-24 character nickname and 2-300 character message'},400);
  if(/[<>\x00-\x08\x0b\x0c\x0e-\x1f]/.test(nickname+message))return send(request,{error:'Some characters are not allowed'},400);
  if(/(?:https?:\/\/|www\.|(?:@|\b)(?:gmail|outlook|qq)\.)/i.test(message))return send(request,{error:'Links/contact information not allowed'},400);
  const ip=request.headers.get('cf-connecting-ip') || 'unknown';
  const hash=await hashIp(ip,env.GUESTBOOK_PEPPER);
  try {
    const usage=await db.prepare(
      "SELECT COUNT(*) AS daily, SUM(CASE WHEN created_at >= datetime('now', '-2 minutes') THEN 1 ELSE 0 END) AS recent FROM guestbook_messages WHERE ip_hash = ? AND created_at >= datetime('now', '-1 day')"
    ).bind(hash).first();
    if((usage?.daily||0)>=6||(usage?.recent||0)>0)return send(request,{error:'Rate limit', retry:true},429,{'retry-after':'120'});
    await db.prepare('INSERT INTO guestbook_messages(nickname,message,ip_hash) VALUES (?,?,?)').bind(nickname,message,hash).run();
    return send(request,{ok:true},201);
  } catch(e){return send(request,{error:'Could not save message'},503);}
}
