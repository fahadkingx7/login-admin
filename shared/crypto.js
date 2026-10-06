globalThis.CS = globalThis.CS || {};
CS.Crypto = (() => {
  const enc = new TextEncoder(), dec = new TextDecoder();
  const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const unb64 = s => Uint8Array.from(atob(String(s)), c => c.charCodeAt(0));

  async function ensureDeviceIdentity(){
    const r=await CS.Store.get('deviceIdentity');
    if(r.deviceIdentity?.deviceId) return r.deviceIdentity;
    const identity={deviceId:CS.Util.uuid(),createdAt:CS.Util.now()};
    await CS.Store.set({deviceIdentity:identity});
    return identity;
  }
  async function newKeyBase64(){return b64(crypto.getRandomValues(new Uint8Array(32)));}
  async function importRawKey(base64){
    const raw=unb64(base64);
    if(raw.byteLength!==32) throw new Error('Invalid synchronization key.');
    return crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);
  }
  async function encryptWithKey(value,base64,aad=''){
    const key=await importRawKey(base64), iv=crypto.getRandomValues(new Uint8Array(12));
    const data=enc.encode(JSON.stringify(value)), additional=enc.encode(String(aad||''));
    const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:additional},key,data);
    return {v:1,iv:b64(iv),ciphertext:b64(ct),aad:String(aad||'')};
  }
  async function decryptWithKey(envelope,base64){
    if(!envelope||envelope.v!==1) throw new Error('Unsupported synchronization payload.');
    const key=await importRawKey(base64);
    const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(envelope.iv),additionalData:enc.encode(String(envelope.aad||''))},key,unb64(envelope.ciphertext));
    return JSON.parse(dec.decode(pt));
  }
  return {ensureDeviceIdentity,newKeyBase64,encryptWithKey,decryptWithKey};
})();
