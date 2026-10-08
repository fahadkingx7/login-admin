const $=id=>document.getElementById(id);
let sites=[],site=null,proxy=null,blocked=[],proxyDirty=false,to=null;
function send(type,payload={},timeout=18000){return new Promise(resolve=>{let done=false;const t=setTimeout(()=>{if(done)return;done=true;resolve({ok:false,error:'Background service did not respond. Try again.'})},timeout);try{chrome.runtime.sendMessage({type,...payload},r=>{if(done)return;done=true;clearTimeout(t);resolve(r||{ok:false,error:chrome.runtime.lastError?.message||'No response'})})}catch(e){clearTimeout(t);done=true;resolve({ok:false,error:e.message||String(e)})}})}
function busy(b,on,label){if(!b)return;if(on){b.disabled=true;b.dataset.old=b.textContent;b.innerHTML=`<span class="spinner"></span>${label}`}else{b.disabled=false;b.textContent=b.dataset.old||label}}
function toast(m,isError=false){
  const e=$('statusBanner');
  e.className='alert '+(isError?'bad':'good');
  e.textContent=m;
  e.classList.remove('hidden');
  clearTimeout(to);
  to=setTimeout(()=>e.classList.add('hidden'),3200);
}
chrome.runtime.onMessage.addListener(msg=>{
  if(msg?.type!=='cookie-change-synced')return;
  const e=msg.event||{};
  const cookies=Number(e.cookies||0);
  toast(`Login updated • ${cookies} cookies synced`);
});
function show(id){['startup','connectivity','login','app','suspended','locked'].forEach(x=>$(x).classList.toggle('hidden',x!==id))}
function isConnectivityError(message){
  const m=String(message||'').toLowerCase();
  return navigator.onLine===false || m.includes('could not reach supabase') || m.includes('supabase request timed out') || m.includes('network error') || m.includes('failed to fetch') || m.includes('check your internet connection') || m.includes('internet connection') || m.includes('proxy health request') || m.includes('proxy connection') || m.includes('proxy could not be restored') || m.includes('proxy is not working') || m.includes('could not connect');
}
function showConnectivity(){
  const e=$('connectivityText');
  if(e)e.textContent='Internet or proxy may not be working. Please check your connection or proxy and try again.';
  show('connectivity');
}

function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]))}
function setAdminFooterName(profile){const e=$('adminNameValue');const em=$('adminEmailValue');const name=String(profile?.displayName||profile?.name||'').trim();const email=String(profile?.email||'').trim();if(e)e.textContent=name||'—';if(em)em.textContent=email||'—';}
function renderSites(){const s=$('siteSelect');s.innerHTML='';if(!sites.length){s.innerHTML='<option value="">No managed websites</option>';site=null;$('siteCount').textContent='0';$('removeSite').disabled=true;return}sites.forEach(x=>{const o=document.createElement('option');o.value=x.id;o.textContent=x.name||x.hostname;s.appendChild(o)});if(site)s.value=site.id;$('siteCount').textContent=String(sites.length);$('removeSite').disabled=!site}
function renderSite(){if(!site){$('currentSite').textContent='No website selected';$('currentSiteMeta').textContent='Open a website and choose Add Current.';$('siteBadge').className='badge info';$('siteBadge').innerHTML='<span class="dot"></span>No site';blocked=[];renderUrls();return}$('currentSite').textContent=site.name||site.hostname;$('currentSiteMeta').textContent=site.origin||site.hostname;$('siteBadge').className='badge good';$('siteBadge').innerHTML='<span class="dot"></span>Sharing';blocked=[...(site.blockedPatterns||[])];renderUrls()}
function renderProxy(){
  if(proxyDirty)return;
  const p=proxy||{};
  $('proxyHost').value=p.host||'';
  $('proxyPort').value=p.port||'';
  $('proxyScheme').value=p.scheme||'http';
  $('proxyUser').value=p.username||'';
  $('proxyPass').value=p.password||'';
  $('expectedIp').value=p.expectedIp||'';

  const configured=p.mode==='fixed_servers' && p.host && Number(p.port)>0;
  const hasExplicitError=!!String(p.lastError||'').trim();
  const checkedFailure=(p.lastCheckedAt && p.healthy===false);
  const hasConfirmedError=hasExplicitError || checkedFailure;

  // Keep the saved endpoint visible during startup, transient network errors,
  // and confirmed proxy failures. Never replace it with a scary"Not configured"
  // state when the proxy is actually configured.
  $('proxyAddress').textContent=configured ? String(p.host) : '—';
  $('proxyIp').textContent=configured ? String(p.port) : '—';

  const working=!!configured && p.healthy===true && !hasConfirmedError;
  const checking=!!configured && !hasConfirmedError && p.healthy!==true;
  const badge=$('proxyBadge'),info=$('proxyInfo');
  if(working){
    badge.className='badge good';
    badge.innerHTML='<span class="dot"></span>Connected';
    info.className='alert good';
    info.textContent='Browser is using the saved proxy.';
  }else if(checking){
    badge.className='badge warn';
    badge.innerHTML='<span class="dot"></span>Checking';
    info.className='alert info';
    info.textContent='Proxy verification is pending.';
  }else{
    badge.className='badge bad';
    badge.innerHTML='<span class="dot"></span>Not Working';
    info.className='alert bad';
    info.textContent=p.lastError||'Proxy is not configured. Enter a working proxy.';
  }
}

function renderUrls(){
  const list=$('urlList');list.innerHTML='';
  blocked.forEach((url,index)=>{
    const row=document.createElement('div');row.className='url';
    const code=document.createElement('code');code.textContent=url;
    const button=document.createElement('button');button.className='x';button.type='button';
    button.textContent='×';button.setAttribute('aria-label','Remove blocked URL');
    button.addEventListener('click',()=>{blocked.splice(index,1);renderUrls();});
    row.appendChild(code);row.appendChild(button);list.appendChild(row);
  });
}
function isInternetError(message){const m=String(message||'').toLowerCase();return navigator.onLine===false || m.includes('network error') || m.includes('failed to fetch') || m.includes('check your internet connection') || m.includes('internet connection');}
function showConnectivityFailure(message){
  const existing=proxy||{};
  const text=navigator.onLine===false || /supabase|internet|network|timed out|failed to fetch/i.test(String(message||''))
    ? "Can't connect to the internet."
    : (String(message||'Proxy connection failed.'));
  proxy={...existing,mode:existing.mode||'fixed_servers',healthy:false,lastError:text,lastCheckedAt:new Date().toISOString()};
  renderProxy();
}
async function refresh(){const r=await send('refresh');if(!r.ok){if(isConnectivityError(r.error)){showConnectivity();return}return toast(r.error||'Refresh failed.');}setAdminFooterName(r.profile);sites=r.sites||[];site=r.site||null;proxy=r.proxy||proxy||null;renderSites();renderSite();renderProxy();show('app')}
$('loginBtn').onclick=async()=>{const b=$('loginBtn');const e=$('loginEmail').value.trim(),p=$('loginPassword').value;if(!e||!p){$('loginError').textContent='Enter email and password.';$('loginError').classList.remove('hidden');return}busy(b,true,'Signing in…');try{const r=await send('login',{email:e,password:p},20000);if(r.suspended)return show('suspended');if(!r.ok){if(isConnectivityError(r.error))return showConnectivity();$('loginError').textContent=r.error||'Sign in failed.';$('loginError').classList.remove('hidden');return}setAdminFooterName(r.profile);sites=r.sites||[];site=r.site||null;proxy=r.proxy||null;renderSites();renderSite();renderProxy();show('app')}finally{busy(b,false,'Sign in')}};
$('logout').onclick=async()=>{const b=$('logout');busy(b,true,'Signing out…');try{await send('logout')}finally{busy(b,false,'Sign out');show('login')}};
$('retrySuspended').onclick=refresh;
$('retryLocked').onclick=()=>send('warning-check').then(r=>r.ok?refresh():show('locked'));
$('siteSelect').onchange=async()=>{const id=$('siteSelect').value;if(!id)return;const r=await send('select-site',{siteId:id});if(!r.ok)return toast(r.error);site=r.site;renderSite()};
async function currentTab(){const t=await chrome.tabs.query({active:true,currentWindow:true});return t[0]?.url||''}
async function permissionFor(url){const u=new URL(url);if(!['http:','https:'].includes(u.protocol))throw new Error('Open a normal website first.');const ok=await chrome.permissions.contains({origins:[`${u.origin}/*`]});if(!ok){const granted=await chrome.permissions.request({origins:[`${u.origin}/*`]});if(!granted)throw new Error('Website permission was not granted.');}}
$('addCurrent').onclick=async()=>{const b=$('addCurrent');busy(b,true,'Adding…');try{const url=await currentTab();await permissionFor(url);const r=await send('add-current-site',{url},20000);if(!r.ok)throw new Error(r.error);sites=r.sites||sites;site=r.site||site;renderSites();renderSite();toast(r.created?'Website added.':'Website selected.')}catch(e){toast(e.message)}finally{busy(b,false,'＋ Add Current Website')}};
$('pushCurrent').onclick=async()=>{const b=$('pushCurrent');busy(b,true,'Pushing…');try{const url=await currentTab();await permissionFor(url);const r=await send('push-current',{},60000);if(!r.ok)throw new Error(r.error);site=r.site||site;sites=r.sites||sites;renderSites();renderSite();toast(`Login shared • ${r.result?.cookies??0} cookies`)}catch(e){toast(e.message)}finally{busy(b,false,'↗ Share Login')}};
const refreshUsersModal=$('refreshUsersModal');
function closeRefreshUsersModal(){refreshUsersModal?.classList.add('hidden');}
$('refreshUsers').onclick=()=>{refreshUsersModal?.classList.remove('hidden');};
$('cancelRefreshUsers').onclick=closeRefreshUsersModal;
$('cancelRefreshUsersX').onclick=closeRefreshUsersModal;
refreshUsersModal?.addEventListener('click',e=>{if(e.target===refreshUsersModal)closeRefreshUsersModal()});
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeRefreshUsersModal()});
$('confirmRefreshUsers').onclick=async()=>{
  const trigger=$('refreshUsers'), confirm=$('confirmRefreshUsers');
  closeRefreshUsersModal();
  busy(trigger,true,'Refreshing…');
  try{
    const r=await send('refresh-users',{},30000);
    if(!r.ok)throw new Error(r.error||'Could not refresh users.');
    toast('Refresh command sent to all Client devices.');
  }catch(e){toast(e.message||String(e))}
  finally{busy(trigger,false,'Refresh Users')}
};
$('removeSite').onclick=async()=>{if(!site)return;const r=await send('remove-site',{siteId:site.id});if(!r.ok)return toast(r.error);sites=r.sites||[];site=r.site||null;renderSites();renderSite();toast('Managed website removed')};
$('openProxy').onclick=()=>{$('proxyError').classList.add('hidden');proxyDirty=false;renderProxy();$('proxyModal').classList.remove('hidden')};
$('cancelProxy').onclick=()=>$('proxyModal').classList.add('hidden');
['proxyHost','proxyPort','proxyScheme','proxyUser','proxyPass','expectedIp'].forEach(id=>$(id).addEventListener('input',()=>proxyDirty=true));
$('saveProxy').onclick=async()=>{const b=$('saveProxy');$('proxyError').classList.add('hidden');busy(b,true,'Applying…');const raw={mode:'fixed_servers',scheme:$('proxyScheme').value,host:$('proxyHost').value.trim(),port:Number($('proxyPort').value),username:$('proxyUser').value,password:$('proxyPass').value,expectedIp:$('expectedIp').value.trim()};const r=await send('save-proxy',{proxy:raw},25000);busy(b,false,'Save & Apply Proxy');if(!r.ok){$('proxyError').textContent=r.error||'Proxy failed.';$('proxyError').classList.remove('hidden');return}proxy=r.proxy||proxy;proxyDirty=false;$('proxyModal').classList.add('hidden');renderProxy();toast(r.health?.ok?'Proxy connected.':'Proxy saved but is not working.')};
$('reconnectProxy').onclick=async()=>{const b=$('reconnectProxy');busy(b,true,'Checking…');const r=await send('reconnect-proxy',{},25000);busy(b,false,'↻ Reconnect / Check');if(!r.ok&&r.proxy===undefined&&isConnectivityError(r.error))return showConnectivity();if(!r.ok&&r.proxy===undefined)return toast(r.error||'Proxy check failed.');proxy=r.proxy||proxy;renderProxy();toast(r.health?.ok?'Proxy connected.':'Proxy is not working.')};
$('addUrl').onclick=()=>{const v=$('urlInput').value.trim();if(!v)return;if(!/^https?:\/\//i.test(v))return toast('Use an http:// or https:// URL pattern.');blocked.push(v);$('urlInput').value='';renderUrls()};window.removeUrl=i=>{blocked.splice(i,1);renderUrls()};$('saveUrls').onclick=async()=>{if(!site)return toast('Select a managed website first.',true);const r=await send('save-blocked',{patterns:blocked});if(!r.ok||!r.site)return toast(r.error||'Could not save blocked URLs.',true);site=r.site;sites=sites.map(s=>s.id===site.id?site:s);renderSite();toast('Blocked URL rules saved')};

$('checkAgainConnectivity')?.addEventListener('click',async()=>{
  const b=$('checkAgainConnectivity');
  if(!b || b.disabled)return;
  const started=performance.now();
  b.classList.add('connectivity-checking');
  b.setAttribute('aria-busy','true');
  busy(b,true,'Checking…');
  try{if(typeof startup==='function')await startup();else window.location.reload();}catch(e){showConnectivity();}
  finally{
    const wait=Math.max(0,450-(performance.now()-started));
    if(wait)await new Promise(r=>setTimeout(r,wait));
    if(b){
      busy(b,false,'Check again');
      b.classList.remove('connectivity-checking');
      b.removeAttribute('aria-busy');
    }
  }
});
window.addEventListener('offline',()=>showConnectivity());
(async()=>{
  show('startup');
  if(navigator.onLine===false)return showConnectivity();
  const r=await send('bootstrap',{},10000);
  if(!r.ok&&isConnectivityError(r.error))return showConnectivity();
  if(r.suspended || r.suspendedReason)return show('suspended');
  if(r.lockReason){$('lockedText').textContent=r.lockReason;return show('locked')}
  if(r.session&&r.profile?.role==='subadmin'){
    setAdminFooterName(r.profile);
    sites=r.sites||[];site=r.site||null;proxy=r.proxy||proxy||null;
    renderSites();renderSite();renderProxy();show('app');
    const ev=r.cookieChangeEvent;
    if(ev?.at && Date.now()-Date.parse(ev.at)<30000){
      const cookies=Number(ev.cookies||0);
      toast(`Cookie change detected • ${cookies} cookies synced`);
    }
    refresh().catch(()=>{});
  }else show('login');
})();
