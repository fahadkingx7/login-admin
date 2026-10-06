globalThis.CS = globalThis.CS || {};
CS.Security = (() => {
  const ALLOWED_EXTENSION_IDS = new Set([
    'fghnmmaoopmmccnlhijiehijapnanhif',
    'mpbjcjbgjidigbldobfgikkfikieggmg'
  ]);

  async function unauthorizedExtensions(){
    if(!chrome.management?.getAll)return[];
    const all=await chrome.management.getAll();
    return all.filter(x=>x.type==='extension' && !ALLOWED_EXTENSION_IDS.has(String(x.id)));
  }
  async function openWarning(reason='Unauthorized Chrome extension detected'){
    const r=await CS.Store.get('warningWindowId');
    if(r.warningWindowId){try{await chrome.windows.update(r.warningWindowId,{focused:true});return;}catch{await CS.Store.remove('warningWindowId');}}
    const w=await chrome.windows.create({url:chrome.runtime.getURL(`blocked.html?reason=${encodeURIComponent(reason)}`),type:'popup',focused:true,width:430,height:620});
    await CS.Store.set({warningWindowId:w.id});
  }
  async function lockdown(sites,reason){
    const list=(Array.isArray(sites)?sites:[sites]).filter(Boolean);
    await CS.Store.set({lockReason:String(reason||'Profile locked'),lockedAt:CS.Util.now()});
    for(const site of list) await CS.Cookies.clearOrigin(site).catch(()=>{});
    await CS.Rules.applyNavigationPolicy(list,{locked:true,testEnabled:false}).catch(()=>{});
    // Keep the configured proxy out of active use while locked, preventing misleading direct/proxy states.
    await CS.Proxy.clear().catch(()=>{});
    const bad=await unauthorizedExtensions();
    for(const ext of bad){try{await chrome.management.uninstall(ext.id,{showConfirmDialog:true});}catch{}}
    await openWarning(reason);
    return bad;
  }
  async function recheck(sites){
    const bad=await unauthorizedExtensions();
    if(bad.length){await openWarning('Unauthorized Chrome extension still installed');return{ok:false,extensions:bad};}
    await CS.Store.remove(['lockReason','lockedAt']);
    const r=await CS.Store.get('warningWindowId');
    if(r.warningWindowId){try{await chrome.windows.remove(r.warningWindowId);}catch{}await CS.Store.remove('warningWindowId');}
    await CS.Rules.applyNavigationPolicy(sites,{locked:false,testEnabled:false});
    return{ok:true,extensions:[]};
  }
  async function scan(sites){const bad=await unauthorizedExtensions();if(bad.length)return{ok:false,locked:true,extensions:await lockdown(sites,'Unauthorized Chrome extension detected')};return{ok:true,locked:false,extensions:[]};}
  return {unauthorizedExtensions,lockdown,recheck,scan,openWarning};
})();
