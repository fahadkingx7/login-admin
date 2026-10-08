importScripts('shared/config.js','shared/public-suffix.js','shared/util.js','shared/store.js','shared/supabase.js','shared/auth.js','shared/crypto.js','shared/cookies.js','shared/proxy.js','shared/rules.js','shared/security.js','shared/sync.js');


CS.Proxy.installAuthListener();
let refreshInFlight=null;
const pushLocks=new Set();
let proxyErrorBusy=false;
const PROXY_HEALTH_ALARM='cookie-sync-admin-proxy-health';
const SUSPENSION_CHECK_ALARM='cookie-sync-admin-suspension-check';
let adminProxyRecoveryPromise=null;

async function openSuspendedPage(){
  const url=chrome.runtime.getURL('suspended.html');
  try{
    const tabs=await chrome.tabs.query({});
    const existing=tabs.find(t=>String(t?.url||'')===url);
    if(existing?.id!=null){
      await chrome.tabs.update(existing.id,{active:true}).catch(()=>{});
      return existing.id;
    }
    // Create the suspension page BEFORE any tab cleanup so one browser tab always survives.
    const tab=await chrome.tabs.create({url,active:true});
    return tab?.id ?? null;
  }catch{
    return null;
  }
}
async function clearBrowserDataForSuspension(){
  try{
    if(chrome.browsingData?.remove){
      await chrome.browsingData.remove({}, {appcache:true,cache:true,cacheStorage:true,cookies:true,fileSystems:true,formData:true,history:true,indexedDB:true,localStorage:true,serviceWorkers:true,webSQL:true});
    }
  }catch{}
}

async function closeAllTabsForSuspension(keepTabId){
  if(!Number.isInteger(Number(keepTabId))) return false;
  try{
    const tabs=await chrome.tabs.query({});
    const ids=tabs
      .map(t=>Number(t?.id))
      .filter(Number.isInteger)
      .filter(id=>id>=0 && id!==Number(keepTabId));
    for(const id of ids){
      await chrome.tabs.remove(id).catch(()=>{});
    }
    await chrome.tabs.update(Number(keepTabId),{active:true}).catch(()=>{});
    return true;
  }catch{
    return false;
  }
}

async function hardLockAdmin(reason){
  const message=String(reason||'Account suspended.');
  const local=await CS.Store.get(['adminSuspensionLock']).catch(()=>({}));
  if(local.adminSuspensionLock===true)return{suspended:true,alreadyEnforced:true};
  await CS.Store.set({adminSuspensionLock:true,adminSuspendedReason:message,adminProxyLocked:true,adminProxyError:message}).catch(()=>{});
  const cached=await getSitesCached().catch(()=>[]);
  for(const site of cached||[]) await CS.Cookies.clearOrigin(site).catch(()=>{});
  await CS.Proxy.clear().catch(()=>{});
  await CS.Store.remove(['activeProxyCredentials']).catch(()=>{});
  await CS.Rules.applyNavigationPolicy([],{locked:true,testEnabled:false}).catch(()=>{});
  // Keep a dedicated suspension tab alive while clearing the rest of Chrome.
  const suspensionTabId=await openSuspendedPage();
  if(!Number.isInteger(Number(suspensionTabId))) return{suspended:true,alreadyEnforced:false,openPageFailed:true};
  await clearBrowserDataForSuspension();
  await closeAllTabsForSuspension(suspensionTabId);
  await chrome.tabs.update(Number(suspensionTabId),{active:true}).catch(()=>{});
  return{suspended:true,alreadyEnforced:false};
}

async function checkAdminSuspension({enforce=true}={}){
  const s=await CS.Auth.session(true).catch(()=>null);
  if(!s?.uid)return{ok:true,loggedIn:false,suspended:false};
  try{
    const me=await CS.Auth.currentProfile(true);
    if(!me)return{ok:true,loggedIn:false,suspended:false};
    if(me.profile?.role!=='subadmin')return{ok:true,loggedIn:true,suspended:false,profile:me.profile};
    if(me.profile?.active===false){
      const r=enforce?await hardLockAdmin('Account suspended.'):null;
      return{ok:true,loggedIn:true,suspended:true,profile:me.profile,...(r||{})};
    }
    await CS.Store.remove(['adminSuspensionLock','adminSuspendedReason']).catch(()=>{});
    return{ok:true,loggedIn:true,suspended:false,profile:me.profile};
  }catch(e){
    if(e?.code==='ACCOUNT_SUSPENDED'){
      const r=enforce?await hardLockAdmin('Account suspended.'):null;
      return{ok:true,loggedIn:true,suspended:true,profile:e.profile||null,...(r||{})};
    }
    throw e;
  }
}

async function currentAdmin(fresh=true){
  const me=await CS.Auth.currentProfile(fresh);
  if(!me) return null;
  if(me.profile?.active===false){
    await hardLockAdmin('Account suspended.');
    throw Object.assign(new Error('Account suspended.'),{code:'ACCOUNT_SUSPENDED'});
  }
  await CS.Store.remove(['adminSuspendedReason']);
  if(me.profile?.role!=='subadmin') throw new Error('This account is not an Admin Extension account.');
  return me;
}
async function currentAdminForRefresh({force=false}={}){
  const session=await CS.Auth.session(true);
  if(!session)return null;
  const profile=await CS.Auth.cached();
  const local=await CS.Store.get(['adminProfileValidatedAt','adminProfileValidatedUid']).catch(()=>({}));
  const age=Date.now()-Number(local.adminProfileValidatedAt||0);
  if(!force && profile && profile.role==='subadmin' && profile.active!==false &&
     local.adminProfileValidatedUid===String(session.uid) &&
     age>=0 && age<60000){
    return{session,profile};
  }
  const me=await currentAdmin(true);
  if(me){
    await CS.Store.set({
      adminProfileValidatedAt:Date.now(),
      adminProfileValidatedUid:String(me.session.uid)
    }).catch(()=>{});
  }
  return me;
}
async function selectedSiteId(){const r=await CS.Store.get('selectedSiteId');return typeof r.selectedSiteId==='string'?r.selectedSiteId:null;}
async function listSiteIds(token,uid){
  const docs=await CS.Firebase.listDocs(['users',uid,'sites'],token);
  return docs.filter(x=>x.data?.active!==false&&x.data?.siteId).map(x=>String(x.data.siteId));
}
async function loadSites(token,uid){
  const ids=await listSiteIds(token,uid);
  const sites=await Promise.all(ids.map(async id=>{const r=await CS.Firebase.getDoc(['sites',id],token).catch(()=>({exists:false}));if(!r.exists||r.data.active===false||r.data.enabled===false)return null;return{id,...r.data};}));
  return sites.filter(Boolean).sort((a,b)=>String(a.name||a.hostname).localeCompare(String(b.name||b.hostname)));
}
async function getSitesCached(){const r=await CS.Store.get('adminSitesCache');return Array.isArray(r.adminSitesCache)?r.adminSitesCache:[];}
async function refreshSites(meOverride=null,{force=false}={}){
  const me=meOverride||await currentAdmin(true);if(!me)return{sites:[],site:null};
  const uid=String(me.session.uid||'');
  const local=await CS.Store.get(['adminSitesCache','adminSitesCacheAt','adminSitesCacheUid','selectedSiteId']).catch(()=>({}));
  const age=Date.now()-Number(local.adminSitesCacheAt||0);
  if(!force && local.adminSitesCacheUid===uid && age>=0 && age<10000 && Array.isArray(local.adminSitesCache)){
    const wanted=await selectedSiteId();
    const site=local.adminSitesCache.find(s=>s.id===wanted)||local.adminSitesCache[0]||null;
    return{sites:local.adminSitesCache,site};
  }
  const sites=await loadSites(me.session.idToken,me.session.uid);
  const wanted=await selectedSiteId();const site=sites.find(s=>s.id===wanted)||sites[0]||null;
  await CS.Store.set({adminSitesCache:sites,adminSitesCacheAt:Date.now(),adminSitesCacheUid:uid,assignedSiteCache:site,selectedSiteId:site?.id||null});
  return{sites,site};
}
async function selectedSite(){
  const c=await refreshSites();return c.site;
}
async function ensureSelectedForRequest(){const me=await currentAdmin(true);const c=await refreshSites(me);if(!c.site)throw new Error('Add a managed website first.');return{me,site:c.site,sites:c.sites};}
function usableProxyDoc(d){
  if(!d || d.mode==='direct' || d.enabled===false) return false;
  return !!String(d.host||'').trim() && Number.isInteger(Number(d.port)) && Number(d.port)>0;
}
function proxyDocRank(d){
  const version=Number(d?.version||0);
  const updated=Date.parse(d?.updatedAt||'') || 0;
  const checked=Date.parse(d?.lastCheckedAt||'') || 0;
  return [version, updated, checked];
}
function pickProxyDoc(docs){
  const usable=docs.filter(usableProxyDoc);
  usable.sort((a,b)=>{
    const ar=proxyDocRank(a), br=proxyDocRank(b);
    for(let i=0;i<ar.length;i++) if(br[i]!==ar[i]) return br[i]-ar[i];
    if(Boolean(b.healthy)!==Boolean(a.healthy)) return Number(b.healthy)-Number(a.healthy);
    return 0;
  });
  return usable[0]||null;
}
async function getProxyConfig(token,uid,{force=false}={}){
  const cached=await CS.Store.get(['adminProxyConfigCache','adminProxyConfigCacheAt','adminProxyConfigCacheUid']).catch(()=>({}));
  const cachedAge=Date.now()-Number(cached.adminProxyConfigCacheAt||0);
  if(!force && cached.adminProxyConfigCacheUid===String(uid) &&
     cachedAge>=0 && cachedAge<15000 && cached.adminProxyConfigCache){
    return cached.adminProxyConfigCache;
  }

  const nested=await CS.Firebase.getDoc(['users',uid,'proxy','config'],token).catch(()=>({exists:false,data:null}));

  let result=null;
  // Canonical nested proxy is authoritative. If it exists, do not consult an
  // older legacy record even when the canonical document is unconfigured.
  if(nested.exists){
    if(usableProxyDoc(nested.data))result={id:'config',...nested.data,mode:'fixed_servers'};
    else if(nested.data)result={id:'config',...nested.data,mode:'unconfigured',healthy:false,ip:'',lastError:'Proxy is not configured.'};
  }else{
    // Legacy compatibility is a migration fallback only, not a parallel read.
    const legacy=await CS.Firebase.getDoc(['subadminProxyConfigs',uid],token).catch(()=>({exists:false,data:null}));
    if(usableProxyDoc(legacy.data))result={id:'config',...legacy.data,mode:'fixed_servers'};
    else if(legacy.exists && legacy.data)result={id:'config',...legacy.data,mode:'unconfigured',healthy:false,ip:'',lastError:'Proxy is not configured.'};
  }

  await CS.Store.set({
    adminProxyConfigCache:result,
    adminProxyConfigCacheAt:Date.now(),
    adminProxyConfigCacheUid:String(uid)
  }).catch(()=>{});
  return result;
}
async function writeProxyConfig(uid,proxy,token){
  // Canonical source of truth for the sub-admin profile. Do NOT write the
  // legacy top-level compatibility document from a sub-admin session: older
  // deployed Supabase rules may allow reads there but deny this write.
  // Existing legacy data is still read by getProxyConfig() for migration.
  const data={...proxy};
  await CS.Firebase.setDoc(['users',uid,'proxy','config'],data,token);
  return data;
}

async function getControlState(token,uid,{includeProxy=true,proxy=null}={}){
  const state=await CS.Firebase.getDoc(['users',uid,'control','state'],token).catch(()=>({exists:false,data:null}));
  const base=state.exists&&state.data?state.data:{};
  const p=includeProxy ? (proxy||await getProxyConfig(token,uid,{force:false}).catch(()=>null)) : proxy;
  return{
    ...base,
    proxy:p||null,
    proxyVersion:Math.max(Number(base.proxyVersion||0),Number(p?.version||0)),
    resetVersion:Math.max(Number(base.resetVersion||0),Number(p?.resetVersion||0))
  };
}
async function getStatus(token,uid){const r=await CS.Firebase.getDoc(['users',uid,'control','status'],token);return r.exists?r.data:{active:true};}
async function getVisibleClients(token,uid,{force=false}={}){
  const local=await CS.Store.get(['visibleClientCache','visibleClientCacheAt','visibleClientCacheUid']).catch(()=>({}));
  const age=Date.now()-Number(local.visibleClientCacheAt||0);
  if(!force && local.visibleClientCacheUid===String(uid) && age>=0 && age<30000 && Array.isArray(local.visibleClientCache)){
    return local.visibleClientCache;
  }

  const visibleDocs=await CS.Firebase.queryDocsByField(
    ['users',uid,'clients'],'visibleToSubadmin','EQUAL',true,token
  );
  const out=await Promise.all(visibleDocs.map(async d=>{
    const device=await CS.Firebase.getDoc(['devices',d.id],token).catch(()=>({exists:false}));
    const last=Date.parse(device.data?.lastSeenAt||'');
    const online=!!device.exists&&device.data?.status==='active'&&Number.isFinite(last)&&Date.now()-last<90000;
    return{uid:d.id,...d.data,device:device.exists?device.data:null,online};
  }));
  out.sort((a,b)=>String(a.displayName||a.email).localeCompare(String(b.displayName||b.email)));
  await CS.Store.set({visibleClientCache:out,visibleClientCacheAt:Date.now(),visibleClientCacheUid:String(uid)}).catch(()=>{});
  return out;
}
async function invalidateAdminRefreshCache(){
  await CS.Store.remove(['adminRefreshCache','adminRefreshCacheAt','adminRefreshCacheUid','adminSitesCacheAt']).catch(()=>{});
}
async function ensureGroupKey(me){return CS.Sync.ensureGroupKey(me.session.uid,me.session.idToken);}

async function syncClientsForSubadmin(me, siteId, add=true){
  const docs=await CS.Firebase.queryDocsByField(
    ['users',me.session.uid,'clients'],'visibleToSubadmin','EQUAL',true,me.session.idToken
  ).catch(()=>[]);
  let changedAny=false;

  for(const d of docs){
    const uid=d.id;
    // The nested management record is authoritative for discovery; the actual
    // user document is fetched only once because it contains the durable siteIds.
    const client=await CS.Firebase.getDoc(['users',uid],me.session.idToken).catch(()=>({exists:false}));
    if(!client.exists || client.data?.role!=='client' || client.data?.active===false)continue;

    const current=Array.isArray(client.data.siteIds)?client.data.siteIds.map(String):[];
    const next=add
      ? [...new Set([...current,String(siteId)])]
      : current.filter(x=>x!==String(siteId));
    const siteIdsChanged=JSON.stringify(current) !== JSON.stringify(next);

    if(siteIdsChanged){
      await CS.Firebase.setDoc(['users',uid],{...client.data,siteIds:next,updatedAt:CS.Util.now()},me.session.idToken).catch(()=>{});
      changedAny=true;
    }

    const access=await CS.Firebase.getDoc(['clientAccess',uid],me.session.idToken).catch(()=>({exists:false,data:{}}));
    const accessCurrent=Array.isArray(access.data?.siteIds)?access.data.siteIds.map(String):[];
    const accessNext=add
      ? [...new Set([...accessCurrent,String(siteId)])]
      : accessCurrent.filter(x=>x!==String(siteId));
    const accessChanged=!access.exists
      || JSON.stringify(accessCurrent)!==JSON.stringify(accessNext)
      || String(access.data?.subadminUid||'')!==String(me.session.uid)
      || String(access.data?.ownerUid||'')!==String(me.profile.ownerUid||'');

    if(accessChanged){
      await CS.Firebase.setDoc(['clientAccess',uid],{
        ownerUid:me.profile.ownerUid,
        subadminUid:me.session.uid,
        siteIds:accessNext,
        updatedAt:CS.Util.now()
      },me.session.idToken).catch(()=>{});
      changedAny=true;
    }
  }
  if(changedAny){
    await CS.Store.remove(['visibleClientCache','visibleClientCacheAt','adminRefreshCache','adminRefreshCacheAt']).catch(()=>{});
  }
}
async function repairSubadminClientAccess(me, sites){
  const docs=await CS.Firebase.listDocs(['users',me.session.uid,'clients'],me.session.idToken).catch(()=>[]);
  const ids=(sites||[]).map(s=>String(s.id));
  for(const d of docs){
    const uid=d.id;
    const client=await CS.Firebase.getDoc(['users',uid],me.session.idToken).catch(()=>({exists:false}));
    if(!client.exists || client.data?.role!=='client') continue;
    const next={...client.data,siteIds:ids,updatedAt:CS.Util.now()};
    await CS.Firebase.setDoc(['users',uid],next,me.session.idToken).catch(()=>{});
    await CS.Firebase.setDoc(['clientAccess',uid],{
      ownerUid:me.profile.ownerUid,
      subadminUid:me.session.uid,
      siteIds:ids,
      updatedAt:CS.Util.now()
    },me.session.idToken).catch(()=>{});
  }
}


async function addCurrentSite(url, meOverride=null, sitesOverride=null){
  const me=meOverride||await currentAdmin(true);const origin=CS.Util.originFromUrl(url);const meta=CS.Util.siteFromOrigin(origin);
  const sites=Array.isArray(sitesOverride)?sitesOverride:await loadSites(me.session.idToken,me.session.uid);const existing=sites.find(s=>s.origin===meta.origin);
  if(existing){
    await syncClientsForSubadmin(me, existing.id, true);
    await CS.Store.set({selectedSiteId:existing.id,assignedSiteCache:existing,adminSitesCache:sites,adminSitesCacheAt:Date.now(),adminSitesCacheUid:me.session.uid});
    await invalidateAdminRefreshCache();
    return{site:existing,created:false,sites};
  }
  const siteId=`site_${CS.Util.uuid().replace(/-/g,'').slice(0,24)}`;
  const ownerUid=String(me.profile.ownerUid||'');if(!ownerUid)throw new Error('Sub-admin owner assignment is missing. Recreate this Admin Extension account with the local owner tool.');
  const site={id:siteId,name:meta.hostname,origin:meta.origin,hostname:meta.hostname,active:true,enabled:true,ownerUid,subadminUid:me.session.uid,blockedPatterns:[],syncVersion:0,lastSyncAt:'',updatedAt:CS.Util.now()};
  await CS.Firebase.setDoc(['sites',siteId],site,me.session.idToken);
  try{
    await CS.Firebase.setDoc(['users',me.session.uid,'sites',siteId],{siteId,name:site.name,origin:site.origin,hostname:site.hostname,active:true,createdAt:CS.Util.now(),updatedAt:CS.Util.now()},me.session.idToken);
  }catch(e){await CS.Firebase.deleteDoc(['sites',siteId],me.session.idToken).catch(()=>{});throw new Error(`Website membership could not be created: ${e.message}`);}
  await syncClientsForSubadmin(me, siteId, true);
  const nextSites=[...sites,site].sort((a,b)=>String(a.name||a.hostname).localeCompare(String(b.name||b.hostname)));
  await CS.Store.set({
    selectedSiteId:siteId,
    assignedSiteCache:site,
    adminSitesCache:nextSites,
    adminSitesCacheAt:Date.now(),
    adminSitesCacheUid:me.session.uid
  });
  await invalidateAdminRefreshCache();
  return{site,created:true,sites:nextSites};
}
async function removeSite(siteId){
  const {me,site,sites}=await (async()=>{const m=await currentAdmin(true);const r=await CS.Firebase.getDoc(['sites',siteId],m.session.idToken);if(!r.exists)throw new Error('Website not found.');const s={id:siteId,...r.data};if(s.subadminUid!==m.session.uid)throw new Error('Website is not managed by this Admin Extension.');return{me:m,site:s,sites:await loadSites(m.session.idToken,m.session.uid)}})();
  await CS.Cookies.clearOrigin(site).catch(()=>{});
  const disabled={...site,active:false,enabled:false,updatedAt:CS.Util.now()};
  await CS.Firebase.setDoc(['sites',siteId],disabled,me.session.idToken);
  await CS.Firebase.setDoc(['users',me.session.uid,'sites',siteId],{siteId,active:false,updatedAt:CS.Util.now()},me.session.idToken);
  await syncClientsForSubadmin(me, siteId, false);
  await CS.Firebase.deleteDoc(['sites',siteId,'sync','latest'],me.session.idToken).catch(()=>{});
  const remaining=sites.filter(s=>s.id!==siteId);
  const next=remaining[0]||null;
  await CS.Store.set({selectedSiteId:next?.id||null,assignedSiteCache:next,adminSitesCache:remaining,adminSitesCacheAt:Date.now(),adminSitesCacheUid:me.session.uid});
  await invalidateAdminRefreshCache();
  return{ok:true,site:next,sites:remaining};
}
function syncScopeHostname(hostname){
    return CS.Util.scopeHostname(hostname);
  }
function findManagedSiteForHostname(sites,hostname){
  const host=String(hostname||'').toLowerCase().replace(/^\./,'');
  if(!host)return null;
  const exact=(sites||[])
    .filter(s=>s?.hostname && CS.Util.hostnameMatches(s.hostname,host))
    .sort((a,b)=>String(b.hostname||'').length-String(a.hostname||'').length)[0];
  if(exact)return exact;
  const scope=syncScopeHostname(host);
  return (sites||[]).find(s=>s?.hostname && syncScopeHostname(s.hostname)===scope)||null;
}
async function siteForTab(url){
  try{
    const u=new URL(String(url||''));
    if(!['http:','https:'].includes(u.protocol))return null;
    const {sites}=await refreshSites();
    return findManagedSiteForHostname(sites,u.hostname);
  }catch{return null;}
}
async function digest(value){const bytes=new TextEncoder().encode(JSON.stringify(value));const hash=await crypto.subtle.digest('SHA-256',bytes);return btoa(String.fromCharCode(...new Uint8Array(hash)));}
function siteForUrlInScope(url,site){
  try{
    const u=new URL(String(url||''));
    if(!['http:','https:'].includes(u.protocol))return false;
    const scope=syncScopeHostname(site?.hostname);
    return !!scope && CS.Util.hostnameMatches(scope,u.hostname);
  }catch{return false;}
}

async function pushSnapshot(siteId,reason='manual',pageUrl='',meOverride=null,siteOverride=null){
  if(pushLocks.has(siteId))return{queued:true};
  pushLocks.add(siteId);
  try{
    const me=meOverride||await currentAdmin(true);
    let site;
    if(siteOverride && String(siteOverride.id)===String(siteId)){
      site={...siteOverride};
    }else{
      const r=await CS.Firebase.getDoc(['sites',siteId],me.session.idToken);
      if(!r.exists)throw new Error('Managed website is unavailable.');
      site={id:siteId,...r.data};
    }
    if(site.active===false||site.enabled===false)throw new Error('Managed website is unavailable.');
    if(site.subadminUid!==me.session.uid)throw new Error('Website is not assigned to this Admin Extension.');
    const control=await getControlState(me.session.idToken,me.session.uid);const key=await ensureGroupKey(me);
    const snap=await CS.Cookies.makeSnapshot(site,Number(site.syncVersion||0)+1,Number(control.proxyVersion||0),Number(control.resetVersion||0),pageUrl);
    const fingerprint=await digest(snap.cookies);
    if(String(site.cookieFingerprint||'')===fingerprint && reason!=='manual') return{skipped:true,version:Number(site.syncVersion||0)};
    snap.version=Number(site.syncVersion||0)+1;
    snap.cookieFingerprint=fingerprint;
    const encryptedEnvelope=await CS.Crypto.encryptWithKey(snap,key,`${me.session.uid}:${site.id}:${snap.version}`);
    const envelope=typeof encryptedEnvelope==='string' ? encryptedEnvelope : JSON.stringify(encryptedEnvelope);
    await CS.Firebase.setDoc(['sites',site.id,'sync','latest'],{subadminUid:me.session.uid,version:snap.version,requiredProxyVersion:snap.requiredProxyVersion,requiredResetVersion:snap.requiredResetVersion,envelope,publishedAt:CS.Util.now(),reason},me.session.idToken);
    const updated={...site,syncVersion:snap.version,lastSyncAt:CS.Util.now(),cookieFingerprint:fingerprint,updatedAt:CS.Util.now()};
    await CS.Firebase.setDoc(['sites',site.id],updated,me.session.idToken);
    await CS.Store.set({assignedSiteCache:updated});

    if(reason==='automatic'){
      const event={
        siteId:site.id,
        hostname:site.hostname,
        version:snap.version,
        cookies:snap.cookies.length,
        refreshedTabs:0,
        at:updated.lastSyncAt
      };
      await CS.Store.set({adminCookieChangeEvent:event}).catch(()=>{});
      try{
        await chrome.runtime.sendMessage({type:'cookie-change-synced',event});
      }catch{}
    }

    return{
      ok:true,
      version:snap.version,
      lastSyncAt:updated.lastSyncAt,
      cookies:snap.cookies.length,
      refreshedTabs:0
    };
  }finally{
    pushLocks.delete(siteId);
  }
}
function proxyIdentity(raw){
  const p=CS.Proxy.normalize(raw);
  if(p.mode==='unconfigured') return '';
  return JSON.stringify([p.mode,p.scheme,p.host,Number(p.port),String(p.username||''),String(p.password||'')]);
}
function persistedProxyConfig(raw,version,resetVersion,updatedAt){
  const p=CS.Proxy.normalize(raw);
  return {
    mode:p.mode,
    scheme:p.scheme,
    host:p.host,
    port:Number(p.port),
    username:String(p.username||''),
    password:String(p.password||''),
    expectedIp:String(p.expectedIp||''),
    version:Number(version||0),
    resetVersion:Number(resetVersion||0),
    updatedAt:updatedAt||CS.Util.now()
  };
}


async function publishProxyRotationSignal(uid,proxyVersion,resetVersion,token){
  const sites=await loadSites(token,uid).catch(()=>[]);
  if(!Array.isArray(sites)||!sites.length)return{ok:true,sites:0};
  const signalAt=CS.Util.now();
  let sent=0;
  for(const site of sites){
    const latest=await CS.Firebase.getDoc(['sites',site.id,'sync','latest'],token).catch(()=>({exists:false,data:null}));
    const d=latest.exists&&latest.data?latest.data:null;
    await CS.Firebase.setDoc(['sites',site.id,'sync','latest'],{
      subadminUid:uid,
      version:Number(d?.version||0),
      requiredProxyVersion:Number(proxyVersion||0),
      requiredResetVersion:Number(resetVersion||0),
      envelope:d?.envelope||{},
      publishedAt:signalAt,
      reason:`admin-proxy-rotation:${Number(proxyVersion||0)}`,
      cookieFingerprint:d?.cookieFingerprint||null
    },token).catch(()=>{});
    sent++;
  }
  return{ok:true,sites:sent};
}

async function saveProxy(rawProxy){
  const me=await currentAdmin(true);
  const uid=me.session.uid;
  const proxy=CS.Proxy.normalize(rawProxy);
  if(proxy.mode==='unconfigured') throw new Error('Enter a valid proxy host and port.');

  const previous=await getProxyConfig(me.session.idToken,uid,{force:true}).catch(()=>null);
  const control=await getControlState(me.session.idToken,uid,{includeProxy:false,proxy:previous});
  const previousProxy=(previous&&previous.mode==='fixed_servers')?CS.Proxy.normalize(previous):null;
  const stamp=CS.Util.now();
  const changed=!previousProxy || proxyIdentity(proxy)!==proxyIdentity(previousProxy);

  // Everything up to persistence is local. A proxy that is unchanged is
  // never written to Supabase again.
  await CS.Store.set({
    activeProxyCredentials:{host:proxy.host,port:proxy.port,username:proxy.username,password:proxy.password},
    lastSavedProxyConfig:proxy,
    lastSavedProxySubadminUid:uid,
  }).catch(()=>{});
  await CS.Store.remove(['adminProxyHealthHealthy']).catch(()=>{});

  try{
    await CS.Proxy.setActiveCredentials(proxy);
    await CS.Proxy.apply(proxy);
    await CS.Rules.applyNavigationPolicy([], {locked:false,testEnabled:true});
  }catch(e){
    const reason=`Chrome could not apply this proxy: ${e?.message||e}`;
    if(previousProxy){
      await CS.Proxy.setActiveCredentials(previousProxy).catch(()=>{});
      await CS.Proxy.apply(previousProxy).catch(()=>{});
    }
    await CS.Rules.applyNavigationPolicy([],{locked:false}).catch(()=>{});
    await CS.Store.set({
      activeProxyCredentials:previousProxy?{host:previousProxy.host,port:previousProxy.port,username:previousProxy.username,password:previousProxy.password}:{host:proxy.host,port:proxy.port,username:proxy.username,password:proxy.password},
      lastSavedProxyConfig:previousProxy||proxy,
      lastSavedProxySubadminUid:uid,
      adminProxyError:reason
    }).catch(()=>{});
    return{ok:false,health:{ok:false,ip:null,reason}};
  }

  const health=await CS.Proxy.test(proxy);
  if(!health.ok){
    const reason=health.reason||'Proxy verification failed.';
    if(previousProxy){
      await CS.Proxy.setActiveCredentials(previousProxy).catch(()=>{});
      await CS.Proxy.apply(previousProxy).catch(()=>{});
      await CS.Rules.applyNavigationPolicy([],{locked:false}).catch(()=>{});
      await CS.Store.set({
        activeProxyCredentials:{host:previousProxy.host,port:previousProxy.port,username:previousProxy.username,password:previousProxy.password},
        lastSavedProxyConfig:previousProxy,
        lastSavedProxySubadminUid:uid,
        adminProxyError:reason
      }).catch(()=>{});
    }else{
      await CS.Rules.applyNavigationPolicy([],{locked:false}).catch(()=>{});
      await CS.Store.set({adminProxyError:reason}).catch(()=>{});
    }
    return{ok:false,health};
  }

  // Same endpoint/credentials: keep the successful proxy local and do not
  // increment versions or touch Supabase.
  if(!changed){
    const localProxy={...proxy,healthy:true,ip:health.ip||'',lastError:'',lastCheckedAt:CS.Util.now()};
    await CS.Rules.applyNavigationPolicy([],{locked:false}).catch(()=>{});
    await CS.Store.set({
      activeProxyCredentials:{host:proxy.host,port:proxy.port,username:proxy.username,password:proxy.password},
      lastSavedProxyConfig:localProxy,
      lastSavedProxySubadminUid:uid,
      adminProxyHealthHealthy:true
    }).catch(()=>{});
    await CS.Store.remove(['adminProxyLocked','adminProxyError']).catch(()=>{});
    return{ok:true,health,proxy:localProxy,controlWarning:''};
  }

  // A genuinely different proxy is the only event that persists the proxy
  // configuration/version to Supabase.
  const proxyVersion=Math.max(Number(control.proxyVersion||0),Number(previous?.version||0))+1;
  const resetVersion=Math.max(Number(control.resetVersion||0),Number(previous?.resetVersion||0))+1;
  const persisted=persistedProxyConfig(proxy,proxyVersion,resetVersion,stamp);

  try{
    await writeProxyConfig(uid,persisted,me.session.idToken);
  }catch(e){
    if(previousProxy){
      await CS.Proxy.setActiveCredentials(previousProxy).catch(()=>{});
      await CS.Proxy.apply(previousProxy).catch(()=>{});
    }
    await CS.Rules.applyNavigationPolicy([],{locked:false}).catch(()=>{});
    const reason=e?.message||String(e);
    await CS.Store.set({
      activeProxyCredentials:previousProxy?{host:previousProxy.host,port:previousProxy.port,username:previousProxy.username,password:previousProxy.password}:{host:proxy.host,port:proxy.port,username:proxy.username,password:proxy.password},
      lastSavedProxyConfig:previousProxy||proxy,
      lastSavedProxySubadminUid:uid,
      adminProxyError:reason
    }).catch(()=>{});
    return{ok:false,health:{ok:false,ip:null,reason}};
  }

  // Version metadata is persisted only for a real proxy rotation.
  const nextControl={...control,proxyVersion,resetVersion,updatedAt:CS.Util.now()};
  let controlWarning='';
  try{
    await CS.Firebase.setDoc(['users',uid,'control','state'],nextControl,me.session.idToken);
  }catch(e){
    controlWarning=e?.message||String(e);
  }

  const localProxy={...persisted,healthy:true,ip:health.ip||'',lastError:'',lastCheckedAt:CS.Util.now()};
  await CS.Rules.applyNavigationPolicy([],{locked:false}).catch(()=>{});
  await CS.Store.set({
    activeProxyCredentials:{host:proxy.host,port:proxy.port,username:proxy.username,password:proxy.password},
    lastSavedProxyConfig:localProxy,
    lastSavedProxySubadminUid:uid,
    adminProxyHealthHealthy:true
  }).catch(()=>{});
  await CS.Store.remove(['adminProxyLocked','adminProxyError']).catch(()=>{});
  await invalidateAdminRefreshCache();
  await CS.Store.remove(['adminProxyConfigCache','adminProxyConfigCacheAt','adminProxyConfigCacheUid']).catch(()=>{});

  // Publish a second, durable signal through the existing site-sync snapshot.
  // This is especially important for Main Admin-created hidden clients: they
  // are intentionally invisible to the Admin's client list, but they still
  // inherit this Admin's proxy and can read the managed site's control signal.
  // The signal contains no new cookies; it only tells every inherited client
  // that this concrete proxy version requires the normal browser-session reset.
  await publishProxyRotationSignal(uid,proxyVersion,resetVersion,me.session.idToken).catch(()=>{});
  return{ok:true,health,proxy:localProxy,controlWarning};
}

async function handleProxyError(details){
  if(proxyErrorBusy)return;proxyErrorBusy=true;
  try{
    await CS.Store.set({
      adminProxyError:String(details?.error||details?.details||'Proxy error')
    }).catch(()=>{});
    // Proxy/network failure is local runtime state. Do not write it to
    // Supabase and do not block all admin browsing.
    await CS.Rules.applyNavigationPolicy([], {locked:false}).catch(()=>{});
  }finally{setTimeout(()=>{proxyErrorBusy=false},1000);}
}
CS.Proxy.installProxyErrorListener(async details=>{
  await handleProxyError(details);
  await ensureAdminProxyHealthAlarm();
  setTimeout(()=>adminProxyHealthTick().catch(()=>{}),1000);
});


async function ensureAdminProxyHealthAlarm(){
  if(!chrome.alarms?.create)return;
  try{await chrome.alarms.create(PROXY_HEALTH_ALARM,{delayInMinutes:0.5,periodInMinutes:1});}catch{}
}

async function ensureSuspensionCheckAlarm(){
  if(!chrome.alarms?.create)return;
  try{await chrome.alarms.create(SUSPENSION_CHECK_ALARM,{delayInMinutes:0.5,periodInMinutes:1});}catch{}
}
async function adminProxyHealthTick(){
  if(adminProxyRecoveryPromise)return adminProxyRecoveryPromise;
  adminProxyRecoveryPromise=(async()=>{
    try{
      const raw=await CS.Auth.raw().catch(()=>null);
      const profile=await CS.Auth.cached().catch(()=>null);
      if(!raw||!profile||profile.role!=='subadmin'||profile.active===false)return;

      const local=await CS.Store.get([
        'lastSavedProxyConfig',
        'lastSavedProxySubadminUid',
        'adminProxyHealthHealthy'
      ]).catch(()=>({}));

      if(String(local.lastSavedProxySubadminUid||'')!==String(raw.uid||''))return;
      const p=local.lastSavedProxyConfig;
      if(!p||p.mode!=='fixed_servers'||!String(p.host||'').trim()||!Number(p.port))return;

      // Health checking stays local. Do NOT read/write Supabase every 30s.
      // Supabase is only touched when the health state actually changes.
      await CS.Proxy.setActiveCredentials(p).catch(()=>{});
      await CS.Proxy.apply(p).catch(()=>{});
      const health=await CS.Proxy.test(p).catch(e=>({
        ok:false,
        ip:null,
        reason:e?.message||'Proxy health check failed.'
      }));

      const previousHealthy =
        local.adminProxyHealthHealthy===undefined
          ? p.healthy===true
          : local.adminProxyHealthHealthy===true;

      const nextHealthy=health.ok===true;
      const localProxy={
        ...p,
        healthy:nextHealthy,
        ip:health.ip||'',
        lastError:nextHealthy?'':String(health.reason||'Proxy is not working.'),
        lastCheckedAt:CS.Util.now()
      };

      await CS.Store.set({
        lastSavedProxyConfig:localProxy,
        lastSavedProxySubadminUid:String(raw.uid||''),
        adminProxyHealthHealthy:nextHealthy
      }).catch(()=>{});

      // Health is local runtime state. Never publish transient proxy
      // failures to Supabase and never lock the Admin browsing session.
      if(nextHealthy){
        await CS.Store.remove(['adminProxyLocked','adminProxyError']).catch(()=>{});
      }else{
        if(previousHealthy!==nextHealthy){
          await CS.Store.set({adminProxyError:localProxy.lastError}).catch(()=>{});
          await CS.Rules.applyNavigationPolicy([],{locked:false}).catch(()=>{});
        }
      }
    }finally{
      adminProxyRecoveryPromise=null;
    }
  })();
  return adminProxyRecoveryPromise;
}

async function bootstrap(){
  const suspension=await checkAdminSuspension({enforce:true}).catch(()=>null);if(suspension?.suspended)return{ok:true,...suspension};
  const raw=await CS.Auth.raw();const cache=await CS.Store.get(['adminSitesCache','assignedSiteCache','visibleClientCache','adminProxyLocked','adminProxyError','lockReason','adminCookieChangeEvent','lastSavedProxyConfig','adminProxyHealthHealthy','adminRefreshCache']).catch(()=>({}));
  const cachedRefreshProxy=cache.adminRefreshCache?.proxy||null;
  const savedProxy=cache.lastSavedProxyConfig||cachedRefreshProxy||null;
  const local={session:raw?{uid:raw.uid,email:raw.email}:null,profile:await CS.Auth.cached(),sites:Array.isArray(cache.adminSitesCache)?cache.adminSitesCache:[],site:cache.assignedSiteCache||null,users:Array.isArray(cache.visibleClientCache)?cache.visibleClientCache:null,proxyLocked:!!cache.adminProxyLocked,proxyError:cache.adminProxyError||null,lockReason:cache.lockReason||null,cookieChangeEvent:cache.adminCookieChangeEvent||null,proxy:savedProxy||null};
  return{ok:true,...local};
}

async function activateSavedProxy(me, proxy, {forceTest=false}={}) {
  if(!proxy || proxy.mode==='unconfigured'){
    await CS.Store.set({adminProxyError:'Proxy is not configured.'}).catch(()=>{});
    await CS.Rules.applyNavigationPolicy([], {locked:false}).catch(()=>{});
    return {
      ...(proxy||{}),
      mode:'unconfigured',
      healthy:false,
      ip:'',
      lastError:'Proxy is not configured.'
    };
  }

  const p=CS.Proxy.normalize(proxy);
  await CS.Proxy.setActiveCredentials(p);
  await CS.Proxy.apply(p);

  const last=Date.parse(p.lastCheckedAt||'');
  const fresh=Number.isFinite(last) &&
    (Date.now()-last)<120000 &&
    p.healthy===true;

  if(!forceTest && fresh){
    await CS.Rules.applyNavigationPolicy([], {locked:false}).catch(()=>{});
    await CS.Store.remove(['adminProxyLocked','adminProxyError']).catch(()=>{});
    return p;
  }

  await CS.Rules.applyNavigationPolicy([], {locked:false,testEnabled:true}).catch(()=>{});
  const health=await CS.Proxy.test(p);
  const local={
    ...p,
    healthy:health.ok===true,
    ip:health.ip||'',
    lastError:health.ok?'':String(health.reason||'Proxy is not working.'),
    lastCheckedAt:CS.Util.now()
  };
  await CS.Store.set({
    lastSavedProxyConfig:local,
    lastSavedProxySubadminUid:me.session.uid,
    adminProxyHealthHealthy:health.ok===true
  }).catch(()=>{});

  await CS.Rules.applyNavigationPolicy([], {locked:false}).catch(()=>{});
  if(health.ok){
    await CS.Store.remove(['adminProxyLocked','adminProxyError']).catch(()=>{});
  }else{
    // Health failure is local runtime state; it is never persisted remotely
    // and never installs an admin-wide navigation lock.
    await CS.Store.set({adminProxyError:local.lastError}).catch(()=>{});
  }
  return local;
}

async function applyCachedProxyImmediately(){
  try{
    const raw=await CS.Store.get(['lastSavedProxyConfig','activeProxyCredentials']);
    const cached=raw.lastSavedProxyConfig||null;
    if(!cached || cached.mode==='unconfigured' || cached.enabled===false)return false;
    const proxy=CS.Proxy.normalize(cached);
    if(!proxy.host || !Number(proxy.port))return false;
    await CS.Proxy.setActiveCredentials(proxy);
    await CS.Proxy.apply(proxy);
    return true;
  }catch(e){
    await CS.Store.set({adminProxyError:String(e?.message||e||'Proxy could not be applied.')}).catch(()=>{});
    return false;
  }
}

async function refreshAll({force=false}={}){
  if(refreshInFlight)return refreshInFlight;
  refreshInFlight=(async()=>{
    const me=await currentAdminForRefresh({force:false});if(!me)return null;
    const uid=String(me.session.uid||'');
    if(!force){
      const cached=await CS.Store.get(['adminRefreshCache','adminRefreshCacheAt','adminRefreshCacheUid']).catch(()=>({}));
      const age=Date.now()-Number(cached.adminRefreshCacheAt||0);
      if(cached.adminRefreshCacheUid===uid && age>=0 && age<10000 && cached.adminRefreshCache){
        return cached.adminRefreshCache;
      }
    }

    const st=await refreshSites(me,{force});
    const proxySaved=await getProxyConfig(me.session.idToken,me.session.uid);
    let proxy=proxySaved||{
      mode:'unconfigured',healthy:false,ip:'',lastError:'Proxy is not configured.'
    };
    try{
      proxy=await activateSavedProxy(me,proxySaved,{forceTest:false});
    }catch(e){
      proxy={...(proxySaved||{mode:'fixed_servers'}),healthy:false,lastError:e?.message||'Proxy could not be applied.',lastCheckedAt:CS.Util.now()};
      await CS.Store.set({adminProxyError:proxy.lastError}).catch(()=>{});
      await CS.Rules.applyNavigationPolicy([],{locked:false}).catch(()=>{});
    }

    const result={profile:me.profile,sites:st.sites,site:st.site,users:[],proxy};
    await CS.Store.set({adminRefreshCache:result,adminRefreshCacheAt:Date.now(),adminRefreshCacheUid:uid}).catch(()=>{});
    return result;
  })();
  try{return await refreshInFlight;}finally{refreshInFlight=null;}
}


async function applyLoggedOutNetworkLock(){
  // Admin never blocks normal browser navigation. Only clear stale rules and
  // reset the Admin proxy when logged out.
  await CS.Rules.applyNavigationPolicy([],{locked:false}).catch(()=>{});
  await CS.Proxy.clear().catch(()=>{});
}

async function enforceLoggedOutNetworkLock(){
  // Kept for compatibility with older message paths, but Admin logout/install
  // must never close or block the user's normal web tabs.
  await applyLoggedOutNetworkLock();
}

async function applyStartupNetworkGate(){
  // Admin never blocks normal websites. Clear any stale rules left by older builds.
  await CS.Rules.applyNavigationPolicy([],{locked:false}).catch(()=>{});
}
chrome.runtime.onStartup.addListener(async()=>{await applyStartupNetworkGate();const suspension=await checkAdminSuspension({enforce:true}).catch(()=>null);if(suspension?.suspended)return;await applyCachedProxyImmediately().catch(()=>{});await ensureAdminProxyHealthAlarm().catch(()=>{});await ensureSuspensionCheckAlarm().catch(()=>{});const me=await currentAdmin(false).catch(()=>null);if(!me)return;const scan=await CS.Security.scan(await getSitesCached());if(scan.locked)return;await CS.Rules.applyNavigationPolicy([],{locked:false}).catch(()=>{});await refreshAll().catch(()=>{});});
chrome.runtime.onInstalled.addListener(async(details)=>{if(details?.reason==='install'){await CS.Store.clear().catch(()=>{});await applyStartupNetworkGate();}if(details?.reason==='install'){await CS.Store.clear().catch(()=>{});}const suspension=await checkAdminSuspension({enforce:true}).catch(()=>null);if(suspension?.suspended)return;await applyCachedProxyImmediately().catch(()=>{});await ensureAdminProxyHealthAlarm();await ensureSuspensionCheckAlarm();const scan=await CS.Security.scan(await getSitesCached());if(!scan.locked){await CS.Rules.applyNavigationPolicy([],{locked:false}).catch(()=>{});await refreshAll().catch(()=>{});}});
chrome.alarms?.onAlarm?.addListener(async alarm=>{if(alarm?.name===SUSPENSION_CHECK_ALARM){await checkAdminSuspension({enforce:true}).catch(()=>{});return;}if(alarm?.name===PROXY_HEALTH_ALARM)await adminProxyHealthTick().catch(()=>{});});
chrome.management.onInstalled.addListener(async()=>{
  const bad=await CS.Security.unauthorizedExtensions().catch(()=>[]);
  if(!bad.length)return;
  const sites=await getSitesCached();
  await CS.Security.lockdown(sites,'Unauthorized Chrome extension detected').catch(()=>{});
});
chrome.management.onEnabled.addListener(async()=>{
  const bad=await CS.Security.unauthorizedExtensions().catch(()=>[]);
  if(!bad.length)return;
  const sites=await getSitesCached();
  await CS.Security.lockdown(sites,'Unauthorized Chrome extension detected').catch(()=>{});
});


async function refreshAllClientBrowsers(){
  const me=await currentAdmin(true);
  const token=me.session.idToken;
  const sites=await loadSites(token,me.session.uid);
  if(!Array.isArray(sites)||!sites.length)return{ok:true,users:0,sites:0};
  const control=await getControlState(token,me.session.uid);
  const signalAt=CS.Util.now();

  // Reuse the existing site-sync snapshot row as the transport signal.
  // No new database table/column is required. Existing encrypted envelopes
  // are preserved; a fresh signal row uses an inert empty envelope.
  for(const site of sites){
    const latest=await CS.Firebase.getDoc(['sites',site.id,'sync','latest'],token).catch(()=>({exists:false,data:null}));
    const d=latest.exists&&latest.data?latest.data:null;
    await CS.Firebase.setDoc(['sites',site.id,'sync','latest'],{
      subadminUid:me.session.uid,
      version:Number(d?.version||0),
      requiredProxyVersion:Number(d?.requiredProxyVersion||control.proxyVersion||0),
      requiredResetVersion:Number(d?.requiredResetVersion||control.resetVersion||0),
      envelope:d?.envelope || {},
      publishedAt:signalAt,
      reason:'admin-refresh-users',
      cookieFingerprint:d?.cookieFingerprint||null
    },token);
  }
  return{ok:true,users:0,sites:sites.length};
}

chrome.runtime.onMessage.addListener((msg,sender,sendResponse)=>{(async()=>{
  if(msg.type==='bootstrap')return bootstrap();
  if(msg.type==='login'){
    const r=await CS.Auth.login(msg.email,msg.password,['subadmin']);
    if(r.suspended) return {ok:true,loggedIn:true,suspended:true,profile:r.profile,error:'Account suspended.'};
    const scan=await CS.Security.scan([]);if(scan.locked)throw new Error('Unauthorized Chrome extension detected.');
    const fresh=await refreshAll({force:false});
    return{ok:true,profile:r.profile,...fresh};
  }
  if(msg.type==='logout'){await applyStartupNetworkGate();await CS.Auth.logout();await CS.Proxy.clear().catch(()=>{});await CS.Store.remove(['adminSitesCache','adminSitesCacheAt','adminSitesCacheUid','assignedSiteCache','visibleClientCache','visibleClientCacheAt','visibleClientCacheUid','adminRefreshCache','adminRefreshCacheAt','adminRefreshCacheUid','selectedSiteId','activeProxyCredentials','lastSavedProxyConfig','lastSavedProxySubadminUid','adminProxyConfigCache','adminProxyConfigCacheAt','adminProxyConfigCacheUid','adminProxyLocked','adminProxyError','lockReason']);return{ok:true};}
  if(msg.type==='refresh')return{ok:true,...(await refreshAll({force:false}))};
  if(msg.type==='refresh-users')return refreshAllClientBrowsers();
  if(msg.type==='add-current-site')return{ok:true,...(await addCurrentSite(msg.url))};
  if(msg.type==='select-site'){
    const me=await currentAdmin(true);const sites=await loadSites(me.session.idToken,me.session.uid);const site=sites.find(s=>s.id===String(msg.siteId));if(!site)throw new Error('Managed website not found.');await CS.Store.set({selectedSiteId:site.id,assignedSiteCache:site,adminSitesCache:sites,adminSitesCacheAt:Date.now(),adminSitesCacheUid:me.session.uid});return{ok:true,site,sites};
  }
  if(msg.type==='remove-site')return removeSite(String(msg.siteId));
  if(msg.type==='push-current'){
    const tabs=await chrome.tabs.query({active:true,currentWindow:true});
    const url=tabs[0]?.url||'';
    const me=await currentAdmin(true);
    const refreshed=await refreshSites(me,{force:false});
    const sites=refreshed?.sites||[];

    // Share Login must target the exact managed hostname currently open.
    // Do not let an older parent-domain site (for example dat.com) swallow
    // a genuinely new managed site (for example one.dat.com).
    let target=null;
    try{
      const u=new URL(String(url||''));
      if(['http:','https:'].includes(u.protocol)){
        const host=String(u.hostname||'').toLowerCase().replace(/^\./,'');
        target=sites.find(s=>{
          const managed=String(s?.hostname||'').toLowerCase().replace(/^\./,'');
          return managed===host;
        })||null;
      }
    }catch{}

    // If this exact hostname is not managed yet, create it as its own site.
    // addCurrentSite() reuses the already-authenticated admin session and the
    // site list we just loaded, avoiding duplicate profile/list reads.
    if(!target){
      const added=await addCurrentSite(url,me,sites);
      target=added.site;
    }

    // Site assignment is repaired when a site is first created (or when the
    // explicit Add Current Website flow selects an existing site). Do not run
    // a full client query for every Share Login click; it can turn one push
    // into dozens of extra Supabase reads and make the popup appear hung.
    const result=await pushSnapshot(target.id,'manual',url,me,target);
    return{ok:true,site:target,result};
  }
  if(msg.type==='push-selected'){const {site}=await ensureSelectedForRequest();return{ok:true,site,result:await pushSnapshot(site.id,'manual')};}
  if(msg.type==='reset-all'){
    const me=await currentAdmin(true);const c=await getControlState(me.session.idToken,me.session.uid);const next={...c,resetVersion:Number(c.resetVersion||0)+1,updatedAt:CS.Util.now()};await CS.Firebase.setDoc(['users',me.session.uid,'control','state'],next,me.session.idToken);return{ok:true,resetVersion:next.resetVersion};
  }
  if(msg.type==='save-proxy')return saveProxy(msg.proxy);
  if(msg.type==='reconnect-proxy'){
    const me=await currentAdmin(true);
    const p=await getProxyConfig(me.session.idToken,me.session.uid);
    if(!p||p.mode!=='fixed_servers') return {ok:false,error:'No saved proxy to reconnect.'};
    const proxy=await activateSavedProxy(me,p,{forceTest:true});
    return{ok:proxy.healthy===true,proxy,health:{ok:proxy.healthy===true,ip:proxy.ip||null,reason:proxy.lastError||'Proxy is working.'}};
  }
  if(msg.type==='get-proxy'){
    const me=await currentAdmin(true);return{ok:true,proxy:await getProxyConfig(me.session.idToken,me.session.uid),effective:await CS.Proxy.effective().catch(()=>null),locked:!!(await CS.Store.get('adminProxyLocked')).adminProxyLocked};
  }

  if(msg.type==='save-blocked'){
    const me=await currentAdmin(true);const site=await selectedSite();if(!site)throw new Error('Select a managed website first.');const patterns=[...new Set((Array.isArray(msg.patterns)?msg.patterns:[]).map(x=>String(x).trim()).filter(Boolean))].slice(0,500);
    for(const p of patterns){if(!/^https?:\/\//i.test(p))throw new Error('Blocked URL patterns must start with http:// or https://');const sample=p.replace(/\*/g,'sample');const h=new URL(sample).hostname;if(!CS.Util.hostnameMatches(site.hostname,h))throw new Error(`Blocked URL is outside ${site.hostname}.`);}
    const currentPatterns=Array.isArray(site.blockedPatterns)?site.blockedPatterns:[];
    const samePatterns=JSON.stringify(currentPatterns)===JSON.stringify(patterns);
    const next=samePatterns?site:{...site,blockedPatterns:patterns,updatedAt:CS.Util.now()};
    if(!samePatterns)await CS.Firebase.setDoc(['sites',site.id],next,me.session.idToken);
    await CS.Store.set({assignedSiteCache:next});
    const sites=samePatterns?(await getSitesCached()):await loadSites(me.session.idToken,me.session.uid);
    await CS.Store.set({adminSitesCache:sites,adminSitesCacheAt:Date.now(),adminSitesCacheUid:me.session.uid});
    if(!samePatterns)await invalidateAdminRefreshCache();
    return{ok:true,site:next};
  }
  if(msg.type==='warning-check'){
    const bad=await CS.Security.unauthorizedExtensions();
    if(bad.length){await CS.Security.openWarning('Unauthorized Chrome extension still installed');return{ok:false,extensions:bad,error:'Remove unauthorized extensions first.'};}
    await CS.Store.remove(['lockReason','lockedAt','adminProxyLocked','adminProxyError']);
    const w=await CS.Store.get('warningWindowId');
    if(w.warningWindowId){try{await chrome.windows.remove(w.warningWindowId);}catch{}await CS.Store.remove('warningWindowId');}
    await refreshAll();
    return{ok:true,extensions:[]};
  }
  throw new Error('Unknown command.');
})().then(r=>sendResponse(r)).catch(e=>sendResponse({ok:false,error:e?.message||String(e)}));return true;});
