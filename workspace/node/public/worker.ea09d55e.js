(()=>{function n(n,t,e,r){Object.defineProperty(n,t,{get:e,set:r,enumerable:!0,configurable:!0})}var t="undefined"!=typeof globalThis?globalThis:"undefined"!=typeof self?self:"undefined"!=typeof window?window:"undefined"!=typeof global?global:{},e={},r={},_=t.parcelRequiref247;null==_&&((_=function(n){if(n in e)return e[n].exports;if(n in r){var t=r[n];delete r[n];var _={id:n,exports:{}};return e[n]=_,t.call(_.exports,_,_.exports),_.exports}var o=new Error("Cannot find module '"+n+"'");throw o.code="MODULE_NOT_FOUND",o}).register=function(n,t){r[n]=t},t.parcelRequiref247=_),_.register("bGWGM",(function(t,e){var r,_;n(t.exports,"register",(()=>r),(n=>r=n)),n(t.exports,"resolve",(()=>_),(n=>_=n));var o={};r=function(n){for(var t=Object.keys(n),e=0;e<t.length;e++)o[t[e]]=n[t[e]]},_=function(n){var t=o[n];if(null==t)throw new Error("Could not resolve bundle with id "+n);return t}})),_.register("kdbmf",(function(e,r){let o;n(e.exports,"start",(()=>S),(n=>S=n)),n(e.exports,"generatePassphrase",(()=>E),(n=>E=n)),n(e.exports,"Signup",(()=>O),(n=>O=n)),n(e.exports,"WebCache",(()=>x),(n=>x=n)),n(e.exports,"initSync",(()=>M),(n=>M=n)),n(e.exports,"default",(()=>C),(n=>C=n));const a=new Array(32).fill(void 0);function i(n){return a[n]}a.push(void 0,null,!0,!1);let c=a.length;function s(n){const t=i(n);return function(n){n<36||(a[n]=c,c=n)}(n),t}const u=new TextDecoder("utf-8",{ignoreBOM:!0,fatal:!0});u.decode();let b=new Uint8Array;function d(){return 0===b.byteLength&&(b=new Uint8Array(o.memory.buffer)),b}function f(n,t){return u.decode(d().subarray(n,n+t))}function w(n){c===a.length&&a.push(a.length+1);const t=c;return c=a[t],a[t]=n,t}let g=0;const l=new TextEncoder("utf-8"),p="function"==typeof l.encodeInto?function(n,t){return l.encodeInto(n,t)}:function(n,t){const e=l.encode(n);return t.set(e),{read:n.length,written:e.length}};function h(n,t,e){if(void 0===e){const e=l.encode(n),r=t(e.length);return d().subarray(r,r+e.length).set(e),g=e.length,r}let r=n.length,_=t(r);const o=d();let a=0;for(;a<r;a++){const t=n.charCodeAt(a);if(t>127)break;o[_+a]=t}if(a!==r){0!==a&&(n=n.slice(a)),_=e(_,r,r=a+3*n.length);const t=d().subarray(_+a,_+r);a+=p(n,t).written}return g=a,_}let y=new Int32Array;function m(){return 0===y.byteLength&&(y=new Int32Array(o.memory.buffer)),y}function v(n){const t=typeof n;if("number"==t||"boolean"==t||null==n)return`${n}`;if("string"==t)return`"${n}"`;if("symbol"==t){const t=n.description;return null==t?"Symbol":`Symbol(${t})`}if("function"==t){const t=n.name;return"string"==typeof t&&t.length>0?`Function(${t})`:"Function"}if(Array.isArray(n)){const t=n.length;let e="[";t>0&&(e+=v(n[0]));for(let r=1;r<t;r++)e+=", "+v(n[r]);return e+="]",e}const e=/\[object ([^\]]+)\]/.exec(toString.call(n));let r;if(!(e.length>1))return toString.call(n);if(r=e[1],"Object"==r)try{return"Object("+JSON.stringify(n)+")"}catch(n){return"Object"}return n instanceof Error?`${n.name}: ${n.message}\n${n.stack}`:r}function k(n,t,e){o._dyn_core__ops__function__FnMut__A____Output___R_as_wasm_bindgen__closure__WasmClosure___describe__invoke__hf87b2e080f91788a(n,t,w(e))}function S(){o.start()}function E(n){try{const r=o.__wbindgen_add_to_stack_pointer(-16);o.generatePassphrase(r,n);var t=m()[r/4+0],e=m()[r/4+1];if(m()[r/4+2])throw s(e);return s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}function A(n,t){return d().subarray(n/1,n/1+t)}function R(n,t){try{return n.apply(this,t)}catch(n){o.__wbindgen_exn_store(w(n))}}class O{static __wrap(n){const t=Object.create(O.prototype);return t.ptr=n,t}__destroy_into_raw(){const n=this.ptr;return this.ptr=0,n}free(){const n=this.__destroy_into_raw();o.__wbg_signup_free(n)}constructor(){const n=o.signup_new();return O.__wrap(n)}setKeystorePassphrase(n){try{const e=o.__wbindgen_add_to_stack_pointer(-16);o.signup_setKeystorePassphrase(e,this.ptr,w(n));var t=m()[e/4+0];if(m()[e/4+1])throw s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}verifyKeyStorePassphrase(n){try{const e=o.__wbindgen_add_to_stack_pointer(-16);o.signup_verifyKeyStorePassphrase(e,this.ptr,w(n));var t=m()[e/4+0];if(m()[e/4+1])throw s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}setEncryptionPassphrase(n){try{const e=o.__wbindgen_add_to_stack_pointer(-16);o.signup_setEncryptionPassphrase(e,this.ptr,w(n));var t=m()[e/4+0];if(m()[e/4+1])throw s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}verifyEncryptionPassphrase(n){try{const e=o.__wbindgen_add_to_stack_pointer(-16);o.signup_verifyEncryptionPassphrase(e,this.ptr,w(n));var t=m()[e/4+0];if(m()[e/4+1])throw s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}getKeyStore(){try{const e=o.__wbindgen_add_to_stack_pointer(-16);o.signup_getKeyStore(e,this.ptr);var n=m()[e/4+0],t=m()[e/4+1];if(m()[e/4+2])throw s(t);return s(n)}finally{o.__wbindgen_add_to_stack_pointer(16)}}createClient(n){try{const r=o.__wbindgen_add_to_stack_pointer(-16);o.signup_createClient(r,this.ptr,w(n));var t=m()[r/4+0],e=m()[r/4+1];if(m()[r/4+2])throw s(e);return s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}createAccount(){try{const e=o.__wbindgen_add_to_stack_pointer(-16);o.signup_createAccount(e,this.ptr);var n=m()[e/4+0],t=m()[e/4+1];if(m()[e/4+2])throw s(t);return s(n)}finally{o.__wbindgen_add_to_stack_pointer(16)}}takeKeyStore(){try{const e=o.__wbindgen_add_to_stack_pointer(-16);o.signup_takeKeyStore(e,this.ptr);var n=m()[e/4+0],t=m()[e/4+1];if(m()[e/4+2])throw s(t);return s(n)}finally{o.__wbindgen_add_to_stack_pointer(16)}}dispose(){o.signup_dispose(this.ptr)}}class x{static __wrap(n){const t=Object.create(x.prototype);return t.ptr=n,t}__destroy_into_raw(){const n=this.ptr;return this.ptr=0,n}free(){const n=this.__destroy_into_raw();o.__wbg_webcache_free(n)}constructor(){const n=o.webcache_new();return x.__wrap(n)}connect(n,t,e){try{const a=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_connect(a,this.ptr,w(n),w(t),w(e));var r=m()[a/4+0],_=m()[a/4+1];if(m()[a/4+2])throw s(_);return s(r)}finally{o.__wbindgen_add_to_stack_pointer(16)}}changesFeedUrl(){try{const e=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_changesFeedUrl(e,this.ptr);var n=m()[e/4+0],t=m()[e/4+1];if(m()[e/4+2])throw s(t);return s(n)}finally{o.__wbindgen_add_to_stack_pointer(16)}}handleChange(n){try{const r=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_handleChange(r,this.ptr,w(n));var t=m()[r/4+0],e=m()[r/4+1];if(m()[r/4+2])throw s(e);return s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}pull(n){try{const r=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_pull(r,this.ptr,w(n));var t=m()[r/4+0],e=m()[r/4+1];if(m()[r/4+2])throw s(e);return s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}listVaults(){try{const e=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_listVaults(e,this.ptr);var n=m()[e/4+0],t=m()[e/4+1];if(m()[e/4+2])throw s(t);return s(n)}finally{o.__wbindgen_add_to_stack_pointer(16)}}createVault(n,t){try{const _=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_createVault(_,this.ptr,w(n),w(t));var e=m()[_/4+0],r=m()[_/4+1];if(m()[_/4+2])throw s(r);return s(e)}finally{o.__wbindgen_add_to_stack_pointer(16)}}openVault(n,t){try{const r=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_openVault(r,this.ptr,w(n),w(t));var e=m()[r/4+0];if(m()[r/4+1])throw s(e)}finally{o.__wbindgen_add_to_stack_pointer(16)}}closeVault(){try{const t=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_closeVault(t,this.ptr);var n=m()[t/4+0];if(m()[t/4+1])throw s(n)}finally{o.__wbindgen_add_to_stack_pointer(16)}}getVaultMeta(){try{const e=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_getVaultMeta(e,this.ptr);var n=m()[e/4+0],t=m()[e/4+1];if(m()[e/4+2])throw s(t);return s(n)}finally{o.__wbindgen_add_to_stack_pointer(16)}}findByLabel(n,t){try{const _=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_findByLabel(_,this.ptr,w(n),w(t));var e=m()[_/4+0],r=m()[_/4+1];if(m()[_/4+2])throw s(r);return s(e)}finally{o.__wbindgen_add_to_stack_pointer(16)}}queryMap(n){try{const r=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_queryMap(r,this.ptr,w(n));var t=m()[r/4+0],e=m()[r/4+1];if(m()[r/4+2])throw s(e);return s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}createSecret(n){try{const r=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_createSecret(r,this.ptr,w(n));var t=m()[r/4+0],e=m()[r/4+1];if(m()[r/4+2])throw s(e);return s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}readSecret(n){try{const r=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_readSecret(r,this.ptr,w(n));var t=m()[r/4+0],e=m()[r/4+1];if(m()[r/4+2])throw s(e);return s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}updateSecret(n){try{const r=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_updateSecret(r,this.ptr,w(n));var t=m()[r/4+0],e=m()[r/4+1];if(m()[r/4+2])throw s(e);return s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}deleteSecret(n){try{const r=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_deleteSecret(r,this.ptr,w(n));var t=m()[r/4+0],e=m()[r/4+1];if(m()[r/4+2])throw s(e);return s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}removeVault(n){try{const r=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_removeVault(r,this.ptr,w(n));var t=m()[r/4+0],e=m()[r/4+1];if(m()[r/4+2])throw s(e);return s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}renameVault(n,t){try{const _=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_renameVault(_,this.ptr,w(n),w(t));var e=m()[_/4+0],r=m()[_/4+1];if(m()[_/4+2])throw s(r);return s(e)}finally{o.__wbindgen_add_to_stack_pointer(16)}}changePassphrase(n,t){try{const _=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_changePassphrase(_,this.ptr,w(n),w(t));var e=m()[_/4+0],r=m()[_/4+1];if(m()[_/4+2])throw s(r);return s(e)}finally{o.__wbindgen_add_to_stack_pointer(16)}}verify(n){try{const e=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_verify(e,this.ptr,w(n));var t=m()[e/4+0];if(m()[e/4+1])throw s(t)}finally{o.__wbindgen_add_to_stack_pointer(16)}}buffer(){try{const _=o.__wbindgen_add_to_stack_pointer(-16);o.webcache_buffer(_,this.ptr);var n=m()[_/4+0],t=m()[_/4+1],e=m()[_/4+2];if(m()[_/4+3])throw s(e);var r=A(n,t).slice();return o.__wbindgen_free(n,1*t),r}finally{o.__wbindgen_add_to_stack_pointer(16)}}}function P(){const n={wbg:{}};return n.wbg.__wbindgen_object_drop_ref=function(n){s(n)},n.wbg.__wbindgen_cb_drop=function(n){const t=s(n).original;if(1==t.cnt--)return t.a=0,!0;return!1},n.wbg.__wbindgen_error_new=function(n,t){return w(new Error(f(n,t)))},n.wbg.__wbindgen_json_parse=function(n,t){return w(JSON.parse(f(n,t)))},n.wbg.__wbindgen_json_serialize=function(n,t){const e=i(t),r=h(JSON.stringify(void 0===e?null:e),o.__wbindgen_malloc,o.__wbindgen_realloc),_=g;m()[n/4+1]=_,m()[n/4+0]=r},n.wbg.__wbindgen_string_new=function(n,t){return w(f(n,t))},n.wbg.__wbg_new_693216e109162396=function(){return w(new Error)},n.wbg.__wbg_stack_0ddaca5d1abfb52f=function(n,t){const e=h(i(t).stack,o.__wbindgen_malloc,o.__wbindgen_realloc),r=g;m()[n/4+1]=r,m()[n/4+0]=e},n.wbg.__wbg_error_09919627ac0992f5=function(n,t){try{console.error(f(n,t))}finally{o.__wbindgen_free(n,t)}},n.wbg.__wbindgen_object_clone_ref=function(n){return w(i(n))},n.wbg.__wbg_fetch_b1379d93c1e2b015=function(n){return w(fetch(i(n)))},n.wbg.__wbg_debug_1dccd22b8a8988e1=function(n,t,e,r){console.debug(i(n),i(t),i(e),i(r))},n.wbg.__wbg_error_800b8d466653f7ea=function(n){console.error(i(n))},n.wbg.__wbg_error_d539c0f5eafe6a31=function(n,t,e,r){console.error(i(n),i(t),i(e),i(r))},n.wbg.__wbg_info_17d18b9f8eaab7d9=function(n,t,e,r){console.info(i(n),i(t),i(e),i(r))},n.wbg.__wbg_log_f286f3fe4aad906d=function(n,t,e,r){console.log(i(n),i(t),i(e),i(r))},n.wbg.__wbg_warn_3d6689f77cb29c86=function(n,t,e,r){console.warn(i(n),i(t),i(e),i(r))},n.wbg.__wbindgen_string_get=function(n,t){const e=i(t),r="string"==typeof e?e:void 0;var _=null==r?0:h(r,o.__wbindgen_malloc,o.__wbindgen_realloc),a=g;m()[n/4+1]=a,m()[n/4+0]=_},n.wbg.__wbg_fetch_17b968b9c79d3c56=function(n,t){return w(i(n).fetch(i(t)))},n.wbg.__wbg_instanceof_Response_240e67e5796c3c6b=function(n){return i(n)instanceof Response},n.wbg.__wbg_url_0f503b904b694ff5=function(n,t){const e=h(i(t).url,o.__wbindgen_malloc,o.__wbindgen_realloc),r=g;m()[n/4+1]=r,m()[n/4+0]=e},n.wbg.__wbg_status_9067c6a4fdd064c9=function(n){return i(n).status},n.wbg.__wbg_headers_aa309e800cf75016=function(n){return w(i(n).headers)},n.wbg.__wbg_arrayBuffer_ccd485f4d2929b08=function(){return R((function(n){return w(i(n).arrayBuffer())}),arguments)},n.wbg.__wbg_newwithstrandinit_de7c409ec8538105=function(){return R((function(n,t,e){return w(new Request(f(n,t),i(e)))}),arguments)},n.wbg.__wbg_new_4cba26249c1686cd=function(){return R((function(){return w(new Headers)}),arguments)},n.wbg.__wbg_append_9c6d4d7f71076e48=function(){return R((function(n,t,e,r,_){i(n).append(f(t,e),f(r,_))}),arguments)},n.wbg.__wbg_randomFillSync_91e2b39becca6147=function(){return R((function(n,t,e){i(n).randomFillSync(A(t,e))}),arguments)},n.wbg.__wbg_getRandomValues_b14734aa289bc356=function(){return R((function(n,t){i(n).getRandomValues(i(t))}),arguments)},n.wbg.__wbg_process_e56fd54cf6319b6c=function(n){return w(i(n).process)},n.wbg.__wbindgen_is_object=function(n){const t=i(n);return"object"==typeof t&&null!==t},n.wbg.__wbg_versions_77e21455908dad33=function(n){return w(i(n).versions)},n.wbg.__wbg_node_0dd25d832e4785d5=function(n){return w(i(n).node)},n.wbg.__wbindgen_is_string=function(n){return"string"==typeof i(n)},n.wbg.__wbg_static_accessor_NODE_MODULE_26b231378c1be7dd=function(){return w(e)},n.wbg.__wbg_require_0db1598d9ccecb30=function(){return R((function(n,t,e){return w(i(n).require(f(t,e)))}),arguments)},n.wbg.__wbg_crypto_b95d7173266618a9=function(n){return w(i(n).crypto)},n.wbg.__wbg_msCrypto_5a86d77a66230f81=function(n){return w(i(n).msCrypto)},n.wbg.__wbindgen_is_function=function(n){return"function"==typeof i(n)},n.wbg.__wbg_newnoargs_971e9a5abe185139=function(n,t){return w(new Function(f(n,t)))},n.wbg.__wbg_next_726d1c2255989269=function(n){return w(i(n).next)},n.wbg.__wbg_next_3d0c4cc33e7418c9=function(){return R((function(n){return w(i(n).next())}),arguments)},n.wbg.__wbg_done_e5655b169bb04f60=function(n){return i(n).done},n.wbg.__wbg_value_8f901bca1014f843=function(n){return w(i(n).value)},n.wbg.__wbg_iterator_22ed2b976832ff0c=function(){return w(Symbol.iterator)},n.wbg.__wbg_get_72332cd2bc57924c=function(){return R((function(n,t){return w(Reflect.get(i(n),i(t)))}),arguments)},n.wbg.__wbg_call_33d7bcddbbfa394a=function(){return R((function(n,t){return w(i(n).call(i(t)))}),arguments)},n.wbg.__wbg_new_e6a9fecc2bf26696=function(){return w(new Object)},n.wbg.__wbg_self_fd00a1ef86d1b2ed=function(){return R((function(){return w(self.self)}),arguments)},n.wbg.__wbg_window_6f6e346d8bbd61d7=function(){return R((function(){return w(window.window)}),arguments)},n.wbg.__wbg_globalThis_3348936ac49df00a=function(){return R((function(){return w(globalThis.globalThis)}),arguments)},n.wbg.__wbg_global_67175caf56f55ca9=function(){return R((function(){return w(t.global)}),arguments)},n.wbg.__wbindgen_is_undefined=function(n){return void 0===i(n)},n.wbg.__wbg_call_65af9f665ab6ade5=function(){return R((function(n,t,e){return w(i(n).call(i(t),i(e)))}),arguments)},n.wbg.__wbg_getTime_58b0bdbebd4ef11d=function(n){return i(n).getTime()},n.wbg.__wbg_new0_adda2d4bcb124f0a=function(){return w(new Date)},n.wbg.__wbg_new_52205195aa880fc2=function(n,t){try{var e={a:n,b:t};const r=new Promise(((n,t)=>{const r=e.a;e.a=0;try{return function(n,t,e,r){o.wasm_bindgen__convert__closures__invoke2_mut__h52648a0ee74be238(n,t,w(e),w(r))}(r,e.b,n,t)}finally{e.a=r}}));return w(r)}finally{e.a=e.b=0}},n.wbg.__wbg_resolve_0107b3a501450ba0=function(n){return w(Promise.resolve(i(n)))},n.wbg.__wbg_then_18da6e5453572fc8=function(n,t){return w(i(n).then(i(t)))},n.wbg.__wbg_then_e5489f796341454b=function(n,t,e){return w(i(n).then(i(t),i(e)))},n.wbg.__wbg_buffer_34f5ec9f8a838ba0=function(n){return w(i(n).buffer)},n.wbg.__wbg_newwithbyteoffsetandlength_88fdad741db1b182=function(n,t,e){return w(new Uint8Array(i(n),t>>>0,e>>>0))},n.wbg.__wbg_new_cda198d9dbc6d7ea=function(n){return w(new Uint8Array(i(n)))},n.wbg.__wbg_set_1a930cfcda1a8067=function(n,t,e){i(n).set(i(t),e>>>0)},n.wbg.__wbg_length_51f19f73d6d9eff3=function(n){return i(n).length},n.wbg.__wbg_newwithlength_66e5530e7079ea1b=function(n){return w(new Uint8Array(n>>>0))},n.wbg.__wbg_subarray_270ff8dd5582c1ac=function(n,t,e){return w(i(n).subarray(t>>>0,e>>>0))},n.wbg.__wbg_has_3be27932089d278e=function(){return R((function(n,t){return Reflect.has(i(n),i(t))}),arguments)},n.wbg.__wbg_set_2762e698c2f5b7e0=function(){return R((function(n,t,e){return Reflect.set(i(n),i(t),i(e))}),arguments)},n.wbg.__wbg_stringify_d8d1ee75d5b55ce4=function(){return R((function(n){return w(JSON.stringify(i(n)))}),arguments)},n.wbg.__wbindgen_debug_string=function(n,t){const e=h(v(i(t)),o.__wbindgen_malloc,o.__wbindgen_realloc),r=g;m()[n/4+1]=r,m()[n/4+0]=e},n.wbg.__wbindgen_throw=function(n,t){throw new Error(f(n,t))},n.wbg.__wbindgen_memory=function(){return w(o.memory)},n.wbg.__wbindgen_closure_wrapper1662=function(n,t,e){const r=function(n,t,e,r){const _={a:n,b:t,cnt:1,dtor:e},a=(...n)=>{_.cnt++;const t=_.a;_.a=0;try{return r(t,_.b,...n)}finally{0==--_.cnt?o.__wbindgen_export_2.get(_.dtor)(t,_.b):_.a=t}};return a.original=_,a}(n,t,539,k);return w(r)},n}function L(n,t){return o=n.exports,j.__wbindgen_wasm_module=t,y=new Int32Array,b=new Uint8Array,o.__wbindgen_start(),o}function M(n){const t=P(),e=new WebAssembly.Module(n);return L(new WebAssembly.Instance(e,t),e)}async function j(n){void 0===n&&(n=new URL(_("12KrP")));const t=P();("string"==typeof n||"function"==typeof Request&&n instanceof Request||"function"==typeof URL&&n instanceof URL)&&(n=fetch(n));const{instance:e,module:r}=await async function(n,t){if("function"==typeof Response&&n instanceof Response){if("function"==typeof WebAssembly.instantiateStreaming)try{return await WebAssembly.instantiateStreaming(n,t)}catch(t){if("application/wasm"==n.headers.get("Content-Type"))throw t;console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n",t)}const e=await n.arrayBuffer();return await WebAssembly.instantiate(e,t)}{const e=await WebAssembly.instantiate(n,t);return e instanceof WebAssembly.Instance?{instance:e,module:n}:e}}(await n,t);return L(e,r)}var C=j})),_.register("12KrP",(function(n,t){n.exports=_("8IoA4").getBundleURL("2WX22")+_("bGWGM").resolve("gOZR0")})),_.register("8IoA4",(function(t,e){var r;n(t.exports,"getBundleURL",(()=>r),(n=>r=n));var _={};function o(n){return(""+n).replace(/^((?:https?|file|ftp|(chrome|moz|safari-web)-extension):\/\/.+)\/[^/]+$/,"$1")+"/"}r=function(n){var t=_[n];return t||(t=function(){try{throw new Error}catch(t){var n=(""+t.stack).match(/(https?|file|ftp|(chrome|moz|safari-web)-extension):\/\/[^)\n]+/g);if(n)return o(n[2])}return"/"}(),_[n]=t),t}})),_("bGWGM").register(JSON.parse('{"2WX22":"worker.ea09d55e.js","gOZR0":"wasm_bindings_bg.bea386c6.wasm"}'));var o=_("kdbmf");const a=Symbol("Comlink.proxy"),i=Symbol("Comlink.endpoint"),c=Symbol("Comlink.releaseProxy"),s=Symbol("Comlink.thrown"),u=n=>"object"==typeof n&&null!==n||"function"==typeof n,b=new Map([["proxy",{canHandle:n=>u(n)&&n[a],serialize(n){const{port1:t,port2:e}=new MessageChannel;return d(n,t),[e,[e]]},deserialize(n){return n.start(),g(n,[],t);var t}}],["throw",{canHandle:n=>u(n)&&s in n,serialize({value:n}){let t;return t=n instanceof Error?{isError:!0,value:{message:n.message,name:n.name,stack:n.stack}}:{isError:!1,value:n},[t,[]]},deserialize(n){if(n.isError)throw Object.assign(new Error(n.value.message),n.value);throw n.value}}]]);function d(n,t=self){t.addEventListener("message",(function e(r){if(!r||!r.data)return;const{id:_,type:o,path:i}=Object.assign({path:[]},r.data),c=(r.data.argumentList||[]).map(y);let u;try{const t=i.slice(0,-1).reduce(((n,t)=>n[t]),n),e=i.reduce(((n,t)=>n[t]),n);switch(o){case"GET":u=e;break;case"SET":t[i.slice(-1)[0]]=y(r.data.value),u=!0;break;case"APPLY":u=e.apply(t,c);break;case"CONSTRUCT":{const n=new e(...c);b=n,u=Object.assign(b,{[a]:!0})}break;case"ENDPOINT":{const{port1:t,port2:e}=new MessageChannel;d(n,e),u=function(n,t){return p.set(n,t),n}(t,[t])}break;case"RELEASE":u=void 0;break;default:return}}catch(n){u={value:n,[s]:0}}var b;Promise.resolve(u).catch((n=>({value:n,[s]:0}))).then((n=>{const[r,a]=h(n);t.postMessage(Object.assign(Object.assign({},r),{id:_}),a),"RELEASE"===o&&(t.removeEventListener("message",e),f(t))}))})),t.start&&t.start()}function f(n){(function(n){return"MessagePort"===n.constructor.name})(n)&&n.close()}function w(n){if(n)throw new Error("Proxy has been released and is not useable")}function g(n,t=[],e=function(){}){let r=!1;const _=new Proxy(e,{get(e,o){if(w(r),o===c)return()=>m(n,{type:"RELEASE",path:t.map((n=>n.toString()))}).then((()=>{f(n),r=!0}));if("then"===o){if(0===t.length)return{then:()=>_};const e=m(n,{type:"GET",path:t.map((n=>n.toString()))}).then(y);return e.then.bind(e)}return g(n,[...t,o])},set(e,_,o){w(r);const[a,i]=h(o);return m(n,{type:"SET",path:[...t,_].map((n=>n.toString())),value:a},i).then(y)},apply(e,_,o){w(r);const a=t[t.length-1];if(a===i)return m(n,{type:"ENDPOINT"}).then(y);if("bind"===a)return g(n,t.slice(0,-1));const[c,s]=l(o);return m(n,{type:"APPLY",path:t.map((n=>n.toString())),argumentList:c},s).then(y)},construct(e,_){w(r);const[o,a]=l(_);return m(n,{type:"CONSTRUCT",path:t.map((n=>n.toString())),argumentList:o},a).then(y)}});return _}function l(n){const t=n.map(h);return[t.map((n=>n[0])),(e=t.map((n=>n[1])),Array.prototype.concat.apply([],e))];var e}const p=new WeakMap;function h(n){for(const[t,e]of b)if(e.canHandle(n)){const[r,_]=e.serialize(n);return[{type:"HANDLER",name:t,value:r},_]}return[{type:"RAW",value:n},p.get(n)||[]]}function y(n){switch(n.type){case"HANDLER":return b.get(n.name).deserialize(n.value);case"RAW":return n.value}}function m(n,t,e){return new Promise((r=>{const _=new Array(4).fill(0).map((()=>Math.floor(Math.random()*Number.MAX_SAFE_INTEGER).toString(16))).join("-");n.addEventListener("message",(function t(e){e.data&&e.data.id&&e.data.id===_&&(n.removeEventListener("message",t),r(e.data))})),n.start&&n.start(),n.postMessage(Object.assign({id:_},t),e)}))}!async function(){await(0,o.default)(),console.log("Worker finished initializing"),self.postMessage({ready:!0})}(),d({WebCache:o.WebCache,Signup:o.Signup,generatePassphrase:o.generatePassphrase})})();
//# sourceMappingURL=worker.ea09d55e.js.map
