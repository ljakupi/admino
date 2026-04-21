import{B as M,C as x}from"./ConfirmSheet-BRqpkaVO.js";import{c as l,d as b,o,a as d,n as C,b as t,f as u,r as T,t as h,e as w,_ as v,F as B,h as q,i as D,j as m}from"./index-CYsp7f4-.js";/**
 * @license lucide-vue-next v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const I=l("BrainIcon",[["path",{d:"M12 5a3 3 0 1 0-5.997.125 4 4 0 0 0-2.526 5.77 4 4 0 0 0 .556 6.588A4 4 0 1 0 12 18Z",key:"l5xja"}],["path",{d:"M12 5a3 3 0 1 1 5.997.125 4 4 0 0 1 2.526 5.77 4 4 0 0 1-.556 6.588A4 4 0 1 1 12 18Z",key:"ep3f8r"}],["path",{d:"M15 13a4.5 4.5 0 0 1-3-4 4.5 4.5 0 0 1-3 4",key:"1p4c4q"}],["path",{d:"M17.599 6.5a3 3 0 0 0 .399-1.375",key:"tmeiqw"}],["path",{d:"M6.003 5.125A3 3 0 0 0 6.401 6.5",key:"105sqy"}],["path",{d:"M3.477 10.896a4 4 0 0 1 .585-.396",key:"ql3yin"}],["path",{d:"M19.938 10.5a4 4 0 0 1 .585.396",key:"1qfode"}],["path",{d:"M6 18a4 4 0 0 1-1.967-.516",key:"2e4loj"}],["path",{d:"M19.967 17.484A4 4 0 0 1 18 18",key:"159ez6"}]]);/**
 * @license lucide-vue-next v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const y=l("CalendarIcon",[["path",{d:"M8 2v4",key:"1cmpym"}],["path",{d:"M16 2v4",key:"4m81vk"}],["rect",{width:"18",height:"18",x:"3",y:"4",rx:"2",key:"1hopcy"}],["path",{d:"M3 10h18",key:"8toen8"}]]);/**
 * @license lucide-vue-next v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const p=l("FileTextIcon",[["path",{d:"M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z",key:"1rqfz7"}],["path",{d:"M14 2v4a2 2 0 0 0 2 2h4",key:"tnqrlb"}],["path",{d:"M10 9H8",key:"b1mrlr"}],["path",{d:"M16 13H8",key:"t4e002"}],["path",{d:"M16 17H8",key:"z1uh3a"}]]);/**
 * @license lucide-vue-next v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const k=l("HardDriveIcon",[["line",{x1:"22",x2:"2",y1:"12",y2:"12",key:"1y58io"}],["path",{d:"M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z",key:"oot6mr"}],["line",{x1:"6",x2:"6.01",y1:"16",y2:"16",key:"sgf278"}],["line",{x1:"10",x2:"10.01",y1:"16",y2:"16",key:"1l4acy"}]]);/**
 * @license lucide-vue-next v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const g=l("MailIcon",[["rect",{width:"20",height:"16",x:"2",y:"4",rx:"2",key:"18n3k1"}],["path",{d:"m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7",key:"1ocrg3"}]]);/**
 * @license lucide-vue-next v0.468.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const $=l("SearchIcon",[["circle",{cx:"11",cy:"11",r:"8",key:"4ej97u"}],["path",{d:"m21 21-4.3-4.3",key:"1qie3q"}]]),R={class:"card-header"},H={class:"card-info"},S={class:"card-name body-strong"},V={class:"card-desc caption"},z={class:"card-status"},G={key:0,class:"status-locked caption"},A={key:1,class:"status-connected caption"},F={key:2,class:"status-disconnected caption"},j=b({__name:"ToolGroupCard",props:{icon:{},name:{},description:{},enabled:{type:Boolean},connected:{type:Boolean},locked:{type:Boolean}},emits:["toggle"],setup(a){return(s,e)=>(o(),d("div",{class:C(["tool-group-card",{locked:a.locked}])},[t("div",R,[(o(),u(T(a.icon),{size:20,"stroke-width":1.75,class:"card-icon"})),t("div",H,[t("span",S,h(a.name),1),t("span",V,h(a.description),1)]),w(M,{"model-value":a.enabled,disabled:a.locked,"aria-label":`Toggle ${a.name}`,"onUpdate:modelValue":e[0]||(e[0]=i=>s.$emit("toggle",i))},null,8,["model-value","disabled","aria-label"])]),t("div",z,[a.locked?(o(),d("span",G," Restricted by security policy ")):a.connected?(o(),d("span",A," Connected ")):(o(),d("span",F," Not connected "))])],2))}}),N=v(j,[["__scopeId","data-v-ff49ec6e"]]),O={class:"tools-page"},L={class:"page-content"},P={class:"tools-grid"},Z=b({__name:"ToolsPage",setup(a){const s=m([{id:"gmail",name:"Gmail",description:"Read, search your Gmail inbox",icon:g,enabled:!0,connected:!0},{id:"google_calendar",name:"Google Calendar",description:"Read, list, create calendar events",icon:y,enabled:!0,connected:!0},{id:"google_drive",name:"Google Drive",description:"Read, list, search, download files",icon:k,enabled:!0,connected:!0},{id:"outlook",name:"Outlook Mail",description:"Read, search your Outlook inbox",icon:g,enabled:!0,connected:!1},{id:"outlook_calendar",name:"Outlook Calendar",description:"Read, list, create calendar events",icon:y,enabled:!0,connected:!1},{id:"onedrive",name:"OneDrive",description:"Read, list, search, download files",icon:k,enabled:!0,connected:!1},{id:"documents",name:"Documents",description:"Store, classify, search, query local documents",icon:p,enabled:!0,connected:!0},{id:"files",name:"Files",description:"Read, list, search, write local files",icon:p,enabled:!0,connected:!0},{id:"web_search",name:"Web Search",description:"Search the web",icon:$,enabled:!1,connected:!0},{id:"memory",name:"Memory",description:"Persistent key-value notes",icon:I,enabled:!0,connected:!0}]),e=m(null);function i(r,c){c?r.enabled=c:e.value={tool:r,newValue:c}}function f(){e.value&&(e.value.tool.enabled=e.value.newValue,e.value=null)}return(r,c)=>(o(),d("div",O,[c[1]||(c[1]=t("header",{class:"page-header"},[t("h1",null,"Tools")],-1)),t("div",L,[t("div",P,[(o(!0),d(B,null,q(s.value,n=>(o(),u(N,{key:n.id,icon:n.icon,name:n.name,description:n.description,enabled:n.enabled,connected:n.connected,locked:n.locked,onToggle:_=>i(n,_)},null,8,["icon","name","description","enabled","connected","locked","onToggle"]))),128))])]),e.value?(o(),u(x,{key:0,heading:`Disable ${e.value.tool.name}?`,subtext:`The agent will no longer be able to use ${e.value.tool.name}.`,"confirm-label":"Disable",variant:"destructive",onConfirm:f,onCancel:c[0]||(c[0]=n=>e.value=null)},null,8,["heading","subtext"])):D("",!0)]))}}),W=v(Z,[["__scopeId","data-v-77d056b3"]]);export{W as default};
