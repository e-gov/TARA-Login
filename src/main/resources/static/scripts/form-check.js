!function(){var t=5e3;try{var e=document.body.getAttribute("data-check-form-refresh-rate"),e=new Number(e);100<=e&&(t=e)}catch(t){}setTimeout(function(){clearInterval(n)},36e4);var s=document.querySelector("input[name='_csrf']").getAttribute("value");const n=setInterval(function(){var t=new XMLHttpRequest;t.onreadystatechange=function(){var t,e;4===this.readyState&&(200==this.status&&'{"status":"COMPLETED"}'==this.responseText?(clearInterval(n),(t=document.createElement("form")).method="POST",t.action="/auth/accept",(e=document.createElement("input")).setAttribute("type","hidden"),e.setAttribute("name","_csrf"),e.setAttribute("value",s),t.appendChild(e),document.body.appendChild(t),t.submit()):200==this.status&&'{"status":"PENDING"}'==this.responseText?console.log(this.responseText):"text/html;charset=UTF-8"==this.getResponseHeader("content-type")&&(clearInterval(n),document.write(this.responseText)))},t.open("GET","/auth/mid/poll",!0),t.setRequestHeader("Accept","application/json;charset=UTF-8"),t.send()},t)}();