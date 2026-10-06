globalThis.CS = globalThis.CS || {};
CS.Rules = (() => {
  const FIREBASE_HOSTS=['thdxsonrjazeoadhidbx.supabase.co','thdxsonrjazeoadhidbx.supabase.co','thdxsonrjazeoadhidbx.supabase.co'];
  const HTTP_TYPES=['main_frame','sub_frame','xmlhttprequest','script','image','stylesheet','font','media','object','other','ping','websocket'];
  const MAIN=['main_frame'];
  async function clear(){const r=await chrome.declarativeNetRequest.getDynamicRules();if(r.length)await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds:r.map(x=>x.id)});}
  function allowHost(id,host,types=MAIN){return{id,priority:1000,action:{type:'allow'},condition:{urlFilter:`||${host.replace(/^\./,'')}^`,resourceTypes:types}};}
  function blockAllWeb(){return{id:1,priority:1,action:{type:'block'},condition:{regexFilter:'^https?://',resourceTypes:HTTP_TYPES}};}
  function blockOtherNavigations(){return{id:1,priority:1,action:{type:'block'},condition:{regexFilter:'^https?://',resourceTypes:MAIN}};}
  function infra(){return FIREBASE_HOSTS.map((h,i)=>allowHost(10+i,h,['xmlhttprequest','script','other']));}
  function ipTestRule(){return allowHost(20,'api.ipify.org',['main_frame','xmlhttprequest','script','other']);}
  function uniqueSites(sites){const seen=new Set();return(sites||[]).filter(s=>s&&s.hostname&&(!seen.has(s.id)&&(seen.add(s.id),true))).slice(0,100);}
  function siteAllows(sites){return uniqueSites(sites).map((s,i)=>allowHost(100+i,s.hostname,MAIN));}
  function blockedPatterns(sites){
    const rules=[];let id=2000;
    for(const site of uniqueSites(sites)) for(const pattern of (site.blockedPatterns||[]).slice(0,500)){
      rules.push({id:id++,priority:3000,action:{type:'block'},condition:{urlFilter:String(pattern),resourceTypes:MAIN}});
      if(id>=3900) return rules;
    }
    return rules;
  }
  async function applyNavigationPolicy(sites,{locked=false,testEnabled=false}={}){
    await clear();
    // Admin/sub-admin profile is intentionally allowed to browse normally.
    // Client profiles enforce the managed-site navigation policy. The admin
    // profile only gets a network-wide block when it is explicitly locked.
    if(!locked){
      await CS.Store.set({networkLockdown:false});
      return;
    }
    const rules=[blockAllWeb(),...infra()];
    if(testEnabled) rules.push(ipTestRule());
    await chrome.declarativeNetRequest.updateDynamicRules({addRules:rules});
    await CS.Store.set({networkLockdown:true});
  }
  return {applyNavigationPolicy};
})();
