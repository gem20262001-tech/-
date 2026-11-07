var $=function(i){return document.getElementById(i)};
function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,function(c){return{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]})}
function fmt(n){return Number(n||0).toLocaleString("ru-RU").replace(/\u00a0/g," ")+" ₸"}
var ROLE="";
async function api(path,o){o=o||{};var t=ROLE?localStorage.getItem("tok_"+ROLE):null;
  var r=await fetch("/api"+path,{method:o.method||"GET",headers:Object.assign({"Content-Type":"application/json"},t?{Authorization:"Bearer "+t}:{}),body:o.body?JSON.stringify(o.body):undefined});
  var d=await r.json().catch(function(){return{}});
  if(r.status===401&&ROLE){localStorage.removeItem("tok_"+ROLE);location.reload()}
  if(!r.ok)throw new Error(d.error||"Хато юз берди");return d}
var ST={new:["Янги","w"],accepted:["Қабул қилинди",""],ready:["Тайёр, курьер кутилмоқда","w"],picked:["Йўлда",""],delivered:["Етказилди","g"],cancelled:["Бекор қилинди","r"]};
function badge(s){var x=ST[s]||[s,""];return '<span class="badge '+x[1]+'">'+x[0]+'</span>'}
function mapLinks(o){if(o.lat==null||o.lng==null)return"";
  return ' <a target="_blank" rel="noopener" href="https://www.google.com/maps?q='+o.lat+','+o.lng+'">Google харита</a> · <a target="_blank" rel="noopener" href="https://2gis.kz/geo/'+o.lng+','+o.lat+'">2ГИС</a>'}
function orderBody(o){var h='';(o.items||[]).forEach(function(l){h+='<div class="meta">'+esc(l.n)+' × '+l.q+'</div>'});
  return h+'<p>'+esc(o.customer_name)+', <a href="tel:'+esc(o.phone)+'">'+esc(o.phone)+'</a><br>'+esc(o.address)+mapLinks(o)+(o.note?'<br><i>'+esc(o.note)+'</i>':'')+'</p>'}
// Вход в панель: panel("admin","Админ",start)
function panel(role,title,start){ROLE=role;document.title=title;
  var root=$("root");
  if(localStorage.getItem("tok_"+role)){root.hidden=false;$("login").hidden=true;start();return}
  root.hidden=true;$("login").hidden=false;
  $("login-form").onsubmit=async function(e){e.preventDefault();$("login-err").textContent="";
    try{var d=await api("/login",{method:"POST",body:{phone:$("l-phone").value,password:$("l-pass").value}});
      if(d.role!==role)throw new Error("Бу панелга кириш мумкин эмас");localStorage.setItem("tok_"+role,d.token);location.reload()}
    catch(x){$("login-err").textContent=x.message}}}
function logout(){localStorage.removeItem("tok_"+ROLE);location.reload()}
function loginHtml(title){return '<div class="mosaic"></div><div class="wrap" id="login"><h1 style="margin-top:24px">'+title+'</h1><form id="login-form" class="card" style="margin-top:16px"><label for="l-phone">Телефон / логин</label><input id="l-phone" autocomplete="username"><label for="l-pass">Парол</label><input id="l-pass" type="password" autocomplete="current-password"><p class="err" id="login-err" role="alert"></p><button class="btn" type="submit">Кириш</button></form></div>'}
