globalThis.CS = globalThis.CS || {};
CS.Rules = (() => {
  const SUPABASE_HOSTS=['thdxsonrjazeoadhidbx.supabase.co','thdxsonrjazeoadhidbx.supabase.co','thdxsonrjazeoadhidbx.supabase.co'];
  const HTTP_TYPES=['main_frame','sub_frame','xmlhttprequest','script','image','stylesheet','font','media','object','other','ping','websocket'];
  const MAIN=['main_frame'];
  let updateQueue = Promise.resolve();
  async function applyDynamicRules(addRules){
    const run = async () => {
      const current = await chrome.declarativeNetRequest.getDynamicRules();
      const removeRuleIds = current.map(x=>x.id);
      await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds, addRules});
    };
    const next = updateQueue.then(run, run);
    updateQueue = next.catch(() => {});
    return next;
  }
  function allowHost(id,host,types=MAIN){return{id,priority:1000,action:{type:'allow'},condition:{urlFilter:`||${host.replace(/^\./,'')}^`,resourceTypes:types}};}
  function blockAllWeb(){return{id:1,priority:1,action:{type:'block'},condition:{regexFilter:'^https?://',resourceTypes:HTTP_TYPES}};}
  function blockOtherNavigations(){return{id:1,priority:1,action:{type:'block'},condition:{regexFilter:'^https?://',resourceTypes:MAIN}};}
  function infra(){return SUPABASE_HOSTS.map((h,i)=>allowHost(10+i,h,['xmlhttprequest','script','other']));}
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
    // Admin is never a browser-navigation blocker. Always clear any dynamic
    // navigation rules so the Admin profile can browse normally, including
    // while logged out or when security/suspension checks run.
    await applyDynamicRules([]);
    await CS.Store.set({networkLockdown:false});
  }
  return {applyNavigationPolicy};
})();
