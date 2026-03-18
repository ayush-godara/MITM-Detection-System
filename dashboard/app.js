const alertsContainer = document.getElementById("alerts");

const threatBox = document.getElementById("threat");
const packetBox = document.getElementById("packets");
const signalBox = document.getElementById("signal");
const uptimeBox = document.getElementById("uptime");

const rttCanvas = document.getElementById("rttChart").getContext("2d");
const rssCanvas = document.getElementById("rssChart").getContext("2d");
const riskCanvas = document.getElementById("riskChart").getContext("2d");

let packetCount = 0;
let startTime = Date.now();
let baseline = 0;

let alertRisk = 0;   // 🔥 dynamic risk

// -----------------------------
// GRAPHS
// -----------------------------

const rttGraph = new Chart(rttCanvas,{
type:"line",
data:{
labels:[],
datasets:[{
label:"RTT ms",
data:[],
borderColor:"red",
borderWidth:2,
tension:0.3
}]
},
options:{
plugins:{legend:{labels:{color:"white"}}},
scales:{
x:{ticks:{color:"white"},grid:{color:"#333"}},
y:{ticks:{color:"white"},grid:{color:"#333"}}
}
}
});

const rssGraph = new Chart(rssCanvas,{
type:"line",
data:{
labels:[],
datasets:[{
label:"Signal %",
data:[],
borderColor:"cyan",
borderWidth:2,
tension:0.3
}]
},
options:{
plugins:{legend:{labels:{color:"white"}}},
scales:{
x:{ticks:{color:"white"},grid:{color:"#333"}},
y:{ticks:{color:"white"},grid:{color:"#333"}}
}
}
});

const riskChart = new Chart(riskCanvas,{
type:"doughnut",
data:{
labels:["Risk","Safe"],
datasets:[{
data:[0,100],
backgroundColor:["red","#222"],
borderWidth:0
}]
},
options:{
cutout:"70%",
plugins:{legend:{display:false}}
}
});

// -----------------------------
// HELPERS
// -----------------------------

function average(arr){
return arr.reduce((a,b)=>a+b,0)/arr.length;
}

// -----------------------------
// METRICS LOAD
// -----------------------------

async function loadMetrics(){

const res = await fetch("http://127.0.0.1:5000/metrics");
const data = await res.json();

updateChart(rttGraph,data.rtt);
updateChart(rssGraph,data.rss);

// packets
packetCount += 5;
packetBox.innerText = packetCount;

// signal
if(data.rss.length>0){
signalBox.innerText=data.rss[data.rss.length-1]+"%";
}

// uptime
let uptime = Math.floor((Date.now()-startTime)/1000);
uptimeBox.innerText=uptime+" sec";

// -----------------------------
// RISK CALCULATION
// -----------------------------

let risk = 0;

// RTT based
if(data.rtt.length>0){

let current=data.rtt[data.rtt.length-1];

if(baseline===0){
baseline=average(data.rtt);
}

if(current > baseline * 1.5){
risk=((current-baseline)/baseline)*100;
}

}

// 🔥 combine with alert risk
risk = Math.max(risk, alertRisk);

// limit
risk = Math.min(100,risk);

// update chart
riskChart.data.datasets[0].data=[risk,100-risk];
riskChart.update();

// -----------------------------
// THREAT LEVEL
// -----------------------------

if(risk < 20){
threatBox.innerText="SAFE";
threatBox.className="safe";
}
else if(risk < 50){
threatBox.innerText="WARNING";
threatBox.className="warning";
}
else{
threatBox.innerText="ATTACK";
threatBox.className="attack";
}

}

// -----------------------------
// ALERTS LOAD
// -----------------------------

async function loadAlerts(){

const res = await fetch("http://127.0.0.1:5000/alerts");
const data = await res.json();

alertsContainer.innerHTML="";

// 🔥 reset every cycle
alertRisk = 0;

let hasAttack = false;

data.reverse().forEach(alert=>{

const div=document.createElement("div");

div.className="alert";

div.innerHTML=`<b>[${alert.type}]</b> ${alert.message} <span>${alert.time}</span>`;

alertsContainer.appendChild(div);

// 🔥 detect active attack
if(alert.type === "ARP"){
hasAttack = true;
}

});

// 🔥 dynamic risk logic
if(hasAttack){
alertRisk = 80;   // attack active
}
else{
alertRisk = Math.max(0, alertRisk - 20);  // decay
}

}

// -----------------------------
// CHART UPDATE
// -----------------------------

function updateChart(chart,data){

chart.data.labels=data.map((_,i)=>i+1);
chart.data.datasets[0].data=data;
chart.update();

}

// -----------------------------
// LOOP
// -----------------------------

setInterval(()=>{

loadMetrics();
loadAlerts();

},2000);