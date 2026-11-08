// @ts-nocheck
/* 班務通 AI 函式（Supabase Edge Function，名稱：ai）
 *   POST {SUPABASE_URL}/functions/v1/ai
 *     body: {action:'ocr', image:<base64>, mime}  → {students:[{order,name,phone,school,note}]}
 *           {action:'polish', text, tone:'warm'|'formal', kind}  → {text}
 *           {action:'status'}  → {ok:true, v}（只檢查設定，不呼叫 Gemini）
 *           {action:'ping'}    → {ok:true, v, results:[{model,ok,s,ms,note}]}（用一句短文字測試每個模型能不能用、各花幾秒；不含任何照片或資料）
 * - Gemini 金鑰只讀密鑰 GEMINI_API_KEY（Supabase → Edge Functions → Secrets），不會出現在網頁或回應裡。
 * - 只有「已登入班務通（Supabase）」的使用者能呼叫；可再用密鑰 AI_ALLOWED_EMAILS（逗號分隔）限定帳號。
 * - 部署時保持預設的「Verify JWT」開啟即可：Supabase 閘道先擋掉沒有有效登入憑證的請求，函式內再驗證一次並取得使用者信箱。
 *   若閘道因金鑰設定拒絕 App 的登入憑證（401 Invalid JWT），才需要關閉（supabase/config.toml 的 [functions.ai] verify_jwt = false，或 CLI --no-verify-jwt），函式自己的驗證仍然有效。
 * 可選密鑰：GEMINI_MODEL（優先使用的模型）、AI_ALLOWED_EMAILS、SB_URL、SB_KEY
 */

const env = (k) => {
  try { if (typeof Deno !== 'undefined' && Deno.env) return Deno.env.get(k) || ''; } catch (e) { /* 沒有權限就當作沒設定 */ }
  return (typeof process !== 'undefined' && process.env && process.env[k]) || '';
};

const SUPABASE_URL = (env('SB_URL') || env('SUPABASE_URL') || 'https://nfkzuoswgjnnxlgzonpx.supabase.co').replace(/\/+$/, '');
const SUPABASE_KEY = env('SB_KEY') || 'sb_publishable_xjyXcER2x_KGtUh9EYaZXw_X6m6RJGb';
const VERSION = 4;                     // 函式版本（status 會回傳；改程式時加一）
const GEMINI_BASE = 'https://generativelanguage.googleapis.com/v1beta/models/';
/* 模型清單與思考等級，依 Google 官方文件 ai.google.dev/gemini-api/docs/models、/thinking（2026-11-08 核對）：
   3.6-flash、3.5-flash-lite、3-flash-preview 有 minimal；gemini-3.8-flash 只有 low／medium／high（預設 medium，關不掉）。
   順序依使用者 2026-11-08 的「測試 Gemini 連線」實測排列：3.6-flash 約 1.1 秒、3-flash-preview 約 1.5 秒、3.5-flash-lite 約 1.0 秒，
   gemini-3.8-flash 等了 20 秒沒回應（所以排到最後，不要讓它拖慢每一次辨識）；gemini-2.5-flash 回 404「已不開放給新使用者」，已移除。
   依序嘗試，逾時或不可用就換下一個。想改優先順序，不用改程式：在 Secrets 設 GEMINI_MODEL=模型名稱，就會排最前面。 */
const MODELS = [
  { id: 'gemini-3.6-flash', think: 'minimal' },
  { id: 'gemini-3-flash-preview', think: 'minimal' },
  { id: 'gemini-3.5-flash-lite', think: 'minimal' },   // 最快，品質稍低，當備援
  { id: 'gemini-3.8-flash', think: 'low' },            // 實測曾經 20 秒沒回應，放最後
];
const ATTEMPT_MS = 24000;              // 單一模型最多等 24 秒，太慢就換下一個
const MAX_BODY = 6 * 1024 * 1024;      // App 會先把照片縮到約 3 MB 以內；這裡再擋一次
const MAX_IMAGE_B64 = 5.2 * 1024 * 1024;
const MAX_TEXT = 4000;
const BUDGET_MS = 52000;               // 單次請求最多花 52 秒（Edge Function 的牆鐘上限更長，這裡讓 App 不會等太久）
const RATE_N = 40, RATE_MS = 10 * 60 * 1000;
const hits = new Map();                // userId → 時間戳（同一個執行個體內的簡易限流）

/* 網頁（Firebase 網站）和這個函式不同網域，要允許跨網域呼叫。
   用的是 Authorization 標頭裡的登入憑證、沒有 cookie，所以允許任何來源不會多出風險；沒登入的一律 401。 */
const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-headers': 'authorization, content-type, apikey, x-client-info',
  'access-control-allow-methods': 'POST, OPTIONS',
  'access-control-max-age': '86400',
};
const J = (status, obj) => new Response(JSON.stringify(obj), {
  status,
  headers: Object.assign({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }, CORS),
});
const fail = (status, code, message, trace) => J(status, { error: Object.assign({ code, message }, trace && trace.length ? { trace } : {}) });
class Fail extends Error { constructor(status, code, message) { super(message); this.status = status; this.code = code; this.trace = null; } }
const withTrace = (e, trace) => { if (e instanceof Fail) e.trace = trace; return e; };

/* ---------- 驗證登入 ---------- */
async function whoami(req) {
  const h = req.headers.get('authorization') || '';
  const m = h.match(/^Bearer\s+(\S+)$/i);
  if (!m) throw new Fail(401, 'unauthorized', '請先登入');
  let r;
  try {
    r = await fetch(SUPABASE_URL + '/auth/v1/user', {
      headers: { apikey: SUPABASE_KEY, authorization: 'Bearer ' + m[1] },
      signal: AbortSignal.timeout(8000),
    });
  } catch (e) {
    throw new Fail(503, 'auth_unavailable', '無法確認登入狀態');
  }
  if (r.status === 401 || r.status === 403) throw new Fail(401, 'unauthorized', '登入已過期');
  if (!r.ok) throw new Fail(503, 'auth_unavailable', '無法確認登入狀態');
  let u = null;
  try { u = await r.json(); } catch (e) { /* ignore */ }
  if (!u || !u.id) throw new Fail(401, 'unauthorized', '登入已過期');
  const allow = String(env('AI_ALLOWED_EMAILS')).split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  if (allow.length && allow.indexOf(String(u.email || '').toLowerCase()) < 0) throw new Fail(403, 'forbidden', '這個帳號沒有使用 AI 的權限');
  return u;
}
function limited(uid) {
  const now = Date.now();
  const arr = (hits.get(uid) || []).filter(t => now - t < RATE_MS);
  if (arr.length >= RATE_N) { hits.set(uid, arr); return true; }
  arr.push(now); hits.set(uid, arr);
  if (hits.size > 500) for (const [k, v] of hits) if (!v.some(t => now - t < RATE_MS)) hits.delete(k);
  return false;
}

/* ---------- Gemini ---------- */
const thinkCfg = (t) => (typeof t === 'number' ? { thinkingBudget: t } : { thinkingLevel: t });
function errMsg(txt) {
  try { const j = JSON.parse(txt); return String((j.error && j.error.message) || ''); } catch (e) { return String(txt || '').slice(0, 200); }
}
function pickText(j) {
  const c = j && j.candidates && j.candidates[0];
  if (!c) {
    const br = j && j.promptFeedback && j.promptFeedback.blockReason;
    if (br) throw new Fail(422, 'blocked', 'AI 無法處理這份內容');
    throw new Fail(502, 'empty', 'AI 沒有回應內容');
  }
  const parts = (c.content && c.content.parts) || [];
  const t = parts.filter(p => p && typeof p.text === 'string' && !p.thought).map(p => p.text).join('');
  if (!t.trim()) {
    if (c.finishReason === 'SAFETY' || c.finishReason === 'PROHIBITED_CONTENT' || c.finishReason === 'RECITATION') throw new Fail(422, 'blocked', 'AI 無法處理這份內容');
    throw new Fail(502, 'empty', 'AI 沒有回應內容');
  }
  return t;
}
/* 模型清單：密鑰 GEMINI_MODEL 指定的排最前面（不帶思考設定），其餘照 MODELS */
function modelList() {
  const mine = String(env('GEMINI_MODEL') || '').trim();
  const known = MODELS.find(m => m.id === mine);
  const out = mine ? [{ id: mine, think: known ? known.think : undefined }] : [];
  for (const m of MODELS) if (m.id !== mine) out.push(m);
  return out;
}
/* 對單一模型送一次請求，回傳 {res, ms} 或 {err:'timeout'|'net', ms}；think 為 undefined 就不帶思考設定 */
async function once(key, model, body, think, ms) {
  const payload = JSON.parse(JSON.stringify(body));
  if (think !== undefined) payload.generationConfig = Object.assign({}, payload.generationConfig, { thinkingConfig: thinkCfg(think) });
  const t = Date.now();
  try {
    const res = await fetch(GEMINI_BASE + encodeURIComponent(model) + ':generateContent', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-goog-api-key': key },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(ms),
    });
    return { res, ms: Date.now() - t };
  } catch (e) {
    return { err: e && e.name === 'TimeoutError' ? 'timeout' : 'net', ms: Date.now() - t };
  }
}
/* 依序嘗試模型：單一模型最多等 ATTEMPT_MS；模型不存在／額度滿／暫時故障／太慢就換下一個；不接受思考設定就去掉再試一次。
   每次嘗試都記在 trace（模型、狀態碼或逾時、花幾秒），失敗時一起回給 App，方便知道是哪個模型出問題 */
async function gemini(key, body, deadline) {
  const trace = [];
  let last = null;
  for (const m of modelList()) {
    for (const useThink of (m.think === undefined ? [false] : [true, false])) {
      const left = deadline - Date.now();
      if (left < 4000) throw withTrace(last || new Fail(504, 'timeout', 'AI 回應逾時'), trace);
      const r = await once(key, m.id, body, useThink ? m.think : undefined, Math.min(left - 1000, ATTEMPT_MS));
      if (r.err) {
        trace.push({ m: m.id, s: r.err, ms: r.ms });
        last = new Fail(504, r.err === 'timeout' ? 'timeout' : 'upstream', 'AI 回應逾時或連線失敗');
        break; // 換下一個模型
      }
      const res = r.res, st = res.status;
      if (res.ok) {
        let j = null;
        try { j = await res.json(); } catch (e) { trace.push({ m: m.id, s: 'badjson', ms: r.ms }); last = new Fail(502, 'upstream', 'AI 回應格式錯誤'); break; }
        try {
          const text = pickText(j);
          trace.push({ m: m.id, s: 200, ms: r.ms });
          return { text, model: m.id, trace };
        } catch (e) { trace.push({ m: m.id, s: 'empty', ms: r.ms }); throw withTrace(e, trace); }
      }
      const msg = errMsg(await res.text());
      trace.push({ m: m.id, s: st, ms: r.ms, n: msg.slice(0, 80) });
      if (st === 400 && useThink && /thinking/i.test(msg)) continue;                 // 去掉思考設定再試
      if (st === 400 && /api key|API_KEY/i.test(msg)) throw withTrace(new Fail(500, 'bad_key', 'Gemini 金鑰無效'), trace);
      if (st === 401 || st === 403) throw withTrace(new Fail(500, 'bad_key', 'Gemini 金鑰無效或沒有權限'), trace);
      if (st === 404 || (st === 400 && /model/i.test(msg) && /not found|not supported|unsupported|invalid/i.test(msg))) {
        last = new Fail(502, 'upstream', '模型不可用：' + m.id); break;             // 換下一個模型
      }
      if (st === 429) { last = new Fail(429, 'quota', 'AI 額度暫時用完'); break; }
      if (st >= 500) { last = new Fail(502, 'upstream', 'AI 服務暫時忙碌'); break; }
      throw withTrace(new Fail(502, 'upstream', 'AI 無法處理這個請求（' + st + '）'), trace);
    }
  }
  throw withTrace(last || new Fail(502, 'upstream', 'AI 暫時無法使用'), trace);
}
/* 「測試 Gemini 連線」：用一句短文字同時測每個模型，不含任何照片或班務資料 */
async function doPing(key) {
  const body = { contents: [{ role: 'user', parts: [{ text: '請只回覆兩個字母：OK' }] }], generationConfig: { temperature: 0, maxOutputTokens: 512 } };
  const results = await Promise.all(modelList().map(async (m) => {
    const r = await once(key, m.id, body, m.think, 20000);
    if (r.err) return { model: m.id, ok: false, s: r.err, ms: r.ms, note: '' };
    const txt = await r.res.text();
    if (!r.res.ok) return { model: m.id, ok: false, s: r.res.status, ms: r.ms, note: errMsg(txt).slice(0, 100) };
    try { pickText(JSON.parse(txt)); return { model: m.id, ok: true, s: 200, ms: r.ms, note: '' }; }
    catch (e) { return { model: m.id, ok: false, s: 200, ms: r.ms, note: String((e && e.message) || '') }; }
  }));
  return { ok: true, v: VERSION, results };
}

/* ---------- 拍照辨識名冊 ---------- */
const OCR_PROMPT = `你是精通台灣學校與補習班點名冊、通訊錄的 OCR 專家。
請辨識這張照片中的學生名單（手寫或印刷的點名冊、座位表、簽到表、聯絡表、手機截圖皆可），依照片由上到下的順序，列出每一位學生：
1. order：照片上寫的座號或序號（整數）。如果照片上沒有座號，請填 0，不要自己編號。
2. name：學生姓名，務必是精確的繁體中文。
3. phone：家長或學生的電話／手機（例如 0912-345-678）。照片上沒有就填空字串 ""。
4. school：就讀學校、年級或班級（例如「仁愛國中 二年級」「明華110」）。沒有就填空字串 ""。
5. note：備註。若某位學生的姓名或電話字跡潦草、看不清楚，請在 note 寫「字跡不清，請核對」。沒有就填空字串 ""。
只列出學生資料列；標題、日期、導師姓名、合計人數等不是學生的內容請略過。看不清的字請盡力辨識，不要憑空編造。`;
const OCR_SYS = '你專精於繁體中文手寫與印刷名冊的 OCR 辨識，只輸出符合格式的 JSON，姓名、電話與學校務必精確。';
const OCR_SCHEMA = {
  type: 'ARRAY',
  items: {
    type: 'OBJECT',
    properties: {
      order: { type: 'INTEGER', description: '座號或序號；照片上沒有就填 0' },
      name: { type: 'STRING', description: '學生姓名（繁體中文）' },
      phone: { type: 'STRING', description: '電話；沒有就是空字串' },
      school: { type: 'STRING', description: '學校／年級／班級；沒有就是空字串' },
      note: { type: 'STRING', description: '備註；沒有就是空字串' },
    },
    required: ['order', 'name'],
  },
};
const clean = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n);

async function doOcr(key, b, deadline) {
  let img = String(b.image || '');
  const k = img.indexOf(',');
  if (img.slice(0, 5) === 'data:' && k > 0) img = img.slice(k + 1);
  img = img.replace(/\s+/g, '');
  if (!img) throw new Fail(400, 'bad_request', '沒有收到照片');
  if (img.length > MAX_IMAGE_B64) throw new Fail(413, 'too_large', '照片太大');
  if (!/^[A-Za-z0-9+/=]+$/.test(img)) throw new Fail(400, 'bad_request', '照片格式不正確');
  const mime = /^image\/(jpeg|png|webp|heic|heif)$/.test(String(b.mime || '')) ? b.mime : 'image/jpeg';
  const { text, model, trace } = await gemini(key, {
    systemInstruction: { parts: [{ text: OCR_SYS }] },
    contents: [{ role: 'user', parts: [{ inline_data: { mime_type: mime, data: img } }, { text: OCR_PROMPT }] }],
    generationConfig: { responseMimeType: 'application/json', responseSchema: OCR_SCHEMA, temperature: 0.1, maxOutputTokens: 8192 },
  }, deadline);
  let arr;
  try { arr = JSON.parse(text); } catch (e) {
    const m = text.match(/\[[\s\S]*\]/);
    try { arr = m ? JSON.parse(m[0]) : null; } catch (e2) { arr = null; }
  }
  if (!Array.isArray(arr)) throw new Fail(502, 'empty', 'AI 沒有辨識出名單');
  const students = [];
  for (const x of arr) {
    if (!x || typeof x !== 'object') continue;
    const name = clean(x.name, 30);
    if (!name) continue;
    const o = parseInt(x.order, 10);
    students.push({ order: o > 0 && o < 1000 ? o : 0, name, phone: clean(x.phone, 30), school: clean(x.school, 40), note: clean(x.note, 60) });
    if (students.length >= 150) break;
  }
  return { students, model, trace };
}

/* ---------- 訊息潤飾 ---------- */
const POLISH_SYS = `你是一位專業、細心的台灣補習班導師，負責潤飾要傳給家長的 LINE 訊息。
規則：
1. 保留原文所有事實：姓名、日期、時間、金額、分數、作業內容、課程名稱都不能更動、不能漏掉，也不能新增原文沒有的資訊或承諾。
2. 保留原本的段落與表情符號標題結構，讓家長一眼看得懂。
3. 使用台灣慣用的繁體中文，用詞自然、不官腔、不要過度客套。
4. 輸出純文字，不要使用 Markdown 符號（如 ** 或 #），不要加任何前言、說明或引號，只輸出潤飾後的訊息本身。
5. 長度與原文相近，最多不超過原文的 1.3 倍。`;
const TONE = {
  warm: '語氣：溫暖、親切、有同理心，像老師用心關心孩子，但仍保持專業。',
  formal: '語氣：正式、簡潔、有禮貌，像公文書信般清楚俐落，不使用表情符號以外的口語贅詞。',
};
const KIND = {
  hw: '這是一則「課堂聯絡簿／學習報告」訊息。',
  tuition: '這是一則「學費繳費提醒」訊息，請特別留意不要讓家長覺得被催促或責備。',
};
async function doPolish(key, b, deadline) {
  const src = String(b.text || '').trim();
  if (!src) throw new Fail(400, 'bad_request', '沒有內容可以潤飾');
  if (src.length > MAX_TEXT) throw new Fail(413, 'too_large', '內容太長');
  const tone = b.tone === 'formal' ? 'formal' : 'warm';
  const { text, model, trace } = await gemini(key, {
    systemInstruction: { parts: [{ text: POLISH_SYS + '\n' + TONE[tone] + '\n' + (KIND[b.kind] || '') }] },
    contents: [{ role: 'user', parts: [{ text: '請潤飾以下訊息：\n\n' + src }] }],
    generationConfig: { temperature: 0.5, maxOutputTokens: 4096 },
  }, deadline);
  const out = text.replace(/^```[a-z]*\n?/i, '').replace(/\n?```\s*$/, '').trim();
  if (!out) throw new Fail(502, 'empty', 'AI 沒有回應內容');
  return { text: out, model, trace };
}

/* ---------- 入口 ---------- */
export async function handle(req) {
  const t0 = Date.now();
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });   // 瀏覽器的預檢請求，不需要登入
  try {
    if (req.method !== 'POST') return fail(405, 'method', '只接受 POST');
    const user = await whoami(req);
    const key = env('GEMINI_API_KEY').trim();
    if (!key) throw new Fail(503, 'no_key', '尚未設定 GEMINI_API_KEY');
    if (limited(user.id)) throw new Fail(429, 'rate_limited', '使用太頻繁，請稍後再試');
    const cl = parseInt(req.headers.get('content-length') || '0', 10);
    if (cl > MAX_BODY) throw new Fail(413, 'too_large', '照片太大');
    const raw = await req.text();
    if (raw.length > MAX_BODY) throw new Fail(413, 'too_large', '照片太大');
    let b;
    try { b = JSON.parse(raw); } catch (e) { throw new Fail(400, 'bad_request', '資料格式不正確'); }
    if (!b || typeof b !== 'object') throw new Fail(400, 'bad_request', '資料格式不正確');
    const deadline = t0 + BUDGET_MS;
    if (b.action === 'status') return J(200, { ok: true, v: VERSION });   // App「AI 功能設定」的檢查：函式存在、登入驗證通過、金鑰已設定（不呼叫 Gemini）
    if (b.action === 'ping') return J(200, await doPing(key));
    if (b.action === 'ocr') return J(200, await doOcr(key, b, deadline));
    if (b.action === 'polish') return J(200, await doPolish(key, b, deadline));
    throw new Fail(400, 'bad_request', '不認得的動作');
  } catch (e) {
    if (e instanceof Fail) return fail(e.status, e.code, e.message, e.trace);
    console.error('[ai] unexpected', e && e.message);
    return fail(500, 'upstream', 'AI 暫時無法使用');
  }
}

if (typeof Deno !== 'undefined' && Deno.serve) Deno.serve(handle);
