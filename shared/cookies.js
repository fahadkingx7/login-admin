globalThis.CS = globalThis.CS || {};
CS.Cookies = (() => {
  function belongs(cookie, site) {
    // A managed site owns its host and its entire subdomain tree.
    // Include both:
    //   dat.com cookies when the managed site is auth.dat.com, and
    //   auth.dat.com cookies when the managed site is dat.com.
    // The second direction is the important part for full login/session
    // capture because authentication cookies are commonly scoped to a
    // dedicated subdomain.
    const d=String(cookie.domain||'').replace(/^\./,'').toLowerCase();
    const host=String(site?.hostname||'').replace(/^\./,'').toLowerCase();
    if(!d || !host) return false;
    return CS.Util.hostnameMatches(d,host) || CS.Util.hostnameMatches(host,d);
  }
  function cookieUrl(c) {
    const domain=String(c.domain||'').replace(/^\./,'');
    const scheme=c.secure?'https':'http';
    return `${scheme}://${domain}${c.path || '/'}`;
  }
  function key(c) {
    return JSON.stringify([c.name,c.domain,c.path,c.partitionKey||null,c.storeId||'']);
  }
  function syncScopeHostname(hostname) {
    const host=String(hostname||'').replace(/^\./,'').trim().toLowerCase();
    if(!host)return '';
    const parts=host.split('.').filter(Boolean);
    return parts.length>=3 ? parts.slice(-2).join('.') : host;
  }

  function getAllCookies(details={}) {
    return new Promise((resolve,reject)=>{
      try{
        chrome.cookies.getAll(details,rows=>{
          const err=chrome.runtime.lastError;
          if(err)reject(new Error(err.message||'Chrome cookies.getAll failed.'));
          else resolve(Array.isArray(rows)?rows:[]);
        });
      }catch(e){reject(e);}
    });
  }

  async function getForSite(site,pageUrl='') {
    const host=String(site?.hostname||'').replace(/^\./,'').trim().toLowerCase();
    const scope=syncScopeHostname(host);
    if(!scope)return [];
    const seen=new Map();
    const add=c=>{
      if(!c)return;
      const k=JSON.stringify([c.name||'',c.domain||'',c.path||'/',c.partitionKey||null,c.storeId||'']);
      if(!seen.has(k))seen.set(k,c);
    };

    // Proven legacy SyncMyCookies behavior: query the parent domain so all
    // dat.com subdomains participate when the configured site is one.dat.com.
    try{ for(const c of await getAllCookies({domain:scope})) add(c); }catch{}

    // Union URL-applicable cookies from the managed root and active page.
    try{
      const root=`${String(site.origin||'').replace(/\/$/,'')}/`;
      for(const c of await getAllCookies({url:root})) add(c);
    }catch{}
    try{
      const u=new URL(String(pageUrl||''));
      if(['http:','https:'].includes(u.protocol) &&
         (u.hostname===scope || u.hostname.endsWith(`.${scope}`))){
        for(const c of await getAllCookies({url:u.href})) add(c);
      }
    }catch{}

    return Array.from(seen.values()).map(c=>({
      name:c.name,value:c.value,domain:c.domain,path:c.path,
      hostOnly:c.hostOnly===true,secure:c.secure,httpOnly:c.httpOnly,
      sameSite:c.sameSite,expirationDate:c.expirationDate,session:c.session,
      storeId:c.storeId,partitionKey:c.partitionKey||undefined,url:cookieUrl(c)
    })).sort((a,b)=>key(a).localeCompare(key(b)));
  }

  async function clearOrigin(site) {
    if (!site) return;
    const current = await getForSite(site).catch(()=>[]);
    await Promise.all(current.map(c => chrome.cookies.remove({
      url:cookieUrl(c),name:c.name,storeId:c.storeId,partitionKey:c.partitionKey
    }).catch(()=>null)));
    const origins = [site.origin];
    try {
      const u = new URL(site.origin);
      const other = `${u.protocol === 'https:' ? 'http:' : 'https:'}//${u.host}`;
      if (other !== site.origin) origins.push(other);
    } catch {}
    return chrome.browsingData.remove({origins}, {
      cache:true,cookies:true,cacheStorage:true,fileSystems:true,indexedDB:true,localStorage:true,serviceWorkers:true
    });
  }
  async function reconcile(site, records) {
    const current=await getForSite(site);
    const desired=new Map(records.map(key));
    let removed=0, set=0, failed=0;
    const errors=[];

    for (const c of current) {
      if (!desired.has(key(c))) {
        try {
          await chrome.cookies.remove({
            url:cookieUrl(c),name:c.name,storeId:c.storeId,partitionKey:c.partitionKey
          });
          removed++;
        } catch {}
      }
    }

    for (const c of records) {
      const details={
        url:c.url,
        name:c.name,
        value:c.value,
        path:c.path,
        secure:!!c.secure,
        httpOnly:!!c.httpOnly,
        sameSite:c.sameSite
      };

      // Chrome requires host-only cookies (including __Host-* cookies) to
      // omit the Domain attribute. Domain cookies keep their original domain.
      if (c.hostOnly !== true && c.domain) details.domain=c.domain;
      if (c.expirationDate) details.expirationDate=c.expirationDate;
      if (c.storeId) details.storeId=c.storeId;
      if (c.partitionKey) details.partitionKey=c.partitionKey;

      try {
        await chrome.cookies.set(details);
        set++;
      } catch (e) {
        failed++;
        if(errors.length<12) {
          errors.push({
            name:c.name||'',
            domain:c.domain||'',
            message:String(e?.message||e||'Cookie restore failed.')
          });
        }
      }
    }

    return {removed,set,failed,errors};
  }
  async function makeSnapshot(site, version, requiredProxyVersion, requiredResetVersion, pageUrl='') {
    const cookies=await getForSite(site,pageUrl);
    const payload={siteId:site.id,origin:site.origin,version,requiredProxyVersion:Number(requiredProxyVersion||0),requiredResetVersion:Number(requiredResetVersion||0),createdAt:CS.Util.now(),cookies};
    const size=new TextEncoder().encode(JSON.stringify(payload)).byteLength;
    if(size>700000) throw new Error(`Cookie snapshot is too large (${Math.round(size/1024)} KB).`);
    return payload;
  }
  return {getForSite,clearOrigin,reconcile,makeSnapshot};
})();