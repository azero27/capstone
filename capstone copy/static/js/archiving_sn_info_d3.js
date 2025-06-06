// archiving_sn_info_d3.js

// 아이콘 맵 (Flask 템플릿에서 실제 경로로 렌더)
const iconMap = {
  cloud:  "/static/icon/aws/cloud.svg",
  domain: "/static/icon/aws/domain.svg",
  ec2:    "/static/icon/aws/ec2.svg",
  lambda: "/static/icon/aws/lambda.svg",
  port:   "/static/icon/aws/port.svg",
  rds:    "/static/icon/aws/rds.svg",
  s3:     "/static/icon/aws/s3.svg"
};

const colorMap = {
  port: "#1976d2",
  s3: "#43a047",
  domain: "#ff9800",
  ec2: "#8e24aa",
  rds: "#e53935",
  lambda: "#009688",
  cloud: "#90a4ae",
  default: "#90a4ae"
};

function getScanIdFromUrl() {
  // /archiving/snapshot/info/<id>
  const match = window.location.pathname.match(/info\/(\d+)/);
  return match ? parseInt(match[1], 10) : 1;
}

async function fetchResourceData() {
  const scanId = getScanIdFromUrl();
  const res = await fetch(`/api/info/${scanId}`);
  return await res.json();
}

function toGraphData(resourceList) {
  const nodes = [{ id: "cloud-center", label: "CLOUD", type: "cloud", fx: 420, fy: 310 }];
  const links = [];
  resourceList.forEach(r => {
    nodes.push({
      id: `${r.type}-${r.value}`,
      label: r.value,
      type: r.type,
      is_shadow: r.is_shadow
    });
    links.push({
      source: "cloud-center",
      target: `${r.type}-${r.value}`,
      is_shadow: r.is_shadow
    });
  });
  return { nodes, links };
}

// Convex Hull 계산
function getHull(points) {
  return points.length > 2 ? d3.polygonHull(points) : null;
}
function centroid(points) {
  let x=0, y=0; points.forEach(([px,py])=>{x+=px;y+=py;});
  return [x/points.length, y/points.length];
}

async function drawResourceNetwork() {
  const data = await fetchResourceData();
  const graph = toGraphData(data);

  const width = 900, height = 660;
  const svg = d3.select("#networkVisualization")
    .attr("width", width)
    .attr("height", height)
    .style("background", "#fff")
    .html(""); // 초기화

  // 1. 클러스터 중심 위치 계산
  const groupKeys = Array.from(new Set(data.map(r=>r.type)));
  const groupCenter = {};
  groupKeys.forEach((type,i)=>{
    const theta = 2*Math.PI*i/groupKeys.length;
    groupCenter[type] = {
      x: width/2 + 270*Math.cos(theta),
      y: height/2 + 180*Math.sin(theta)
    };
  });

  // 2. Force 시뮬레이션
  const sim = d3.forceSimulation(graph.nodes)
    .force("charge", d3.forceManyBody().strength(-220))
    .force("link", d3.forceLink(graph.links).id(d=>d.id).distance(160))
    .force("center", d3.forceCenter(width/2, height/2))
    .force("collide", d3.forceCollide().radius(39))
    // 그룹별 중심점으로 모으는 힘 추가
    .force("groupX", d3.forceX().strength(0.23).x(d=>d.type==="cloud"?width/2:groupCenter[d.type].x))
    .force("groupY", d3.forceY().strength(0.23).y(d=>d.type==="cloud"?height/2:groupCenter[d.type].y))
    .on("tick", ticked);

  // 3. 링크(에지)
  const link = svg.append("g")
    .attr("stroke", "#aaa")
    .attr("stroke-width", 2)
    .selectAll("line")
    .data(graph.links)
    .join("line")
    .attr("stroke", d => d.is_shadow ? "#e74c3c" : "#bbb")
    .attr("stroke-width", d => d.is_shadow ? 3.5 : 1.7);

  // 4. 노드 (아이콘만, 동그라미X)
  const node = svg.append("g").selectAll("g")
    .data(graph.nodes)
    .join("g")
    .attr("class", d => "node" + (d.is_shadow ? " shadow-it" : ""))
    .on("click", (event, d) => showResourcePanel(d, data))
    .call(d3.drag()
      .on("start", dragstarted)
      .on("drag", dragged)
      .on("end", dragended)
    );

  node.append("image")
    .attr("class", d => "node-image" + (d.is_shadow ? " shadow-it" : ""))
    .attr("xlink:href", d => iconMap[d.type] || iconMap.cloud)
    .attr("width", d => d.type === "cloud" ? 70 : 44)
    .attr("height", d => d.type === "cloud" ? 70 : 44)
    .attr("x", d => d.type === "cloud" ? -35 : -22)
    .attr("y", d => d.type === "cloud" ? -35 : -22);

  node.append("text")
    .attr("class", "node-label")
    .attr("y", d => d.type === "cloud" ? 44 : 34)
    .text(d => d.type === "cloud" ? "CLOUD" : d.label);

  // 5. 그룹 배경 및 그룹명 Convex Hull로 표시
  function renderGroupBg() {
    svg.selectAll(".group-bg").remove();
    svg.selectAll(".group-label").remove();
    groupKeys.forEach(type=>{
      const nodesOfType = graph.nodes.filter(n=>n.type===type && n.x!=null);
      if (nodesOfType.length < 2) return;
      const hull = getHull(nodesOfType.map(n=>[n.x,n.y]));
      if (!hull) return;
      svg.append("path")
        .attr("class","group-bg")
        .attr("d","M"+hull.map(p=>p.join(",")).join("L")+"Z")
        .attr("fill",colorMap[type]||colorMap.default);
      const [cx,cy] = centroid(hull);
      svg.append("text")
        .attr("class","group-label")
        .attr("x",cx).attr("y",cy-60)
        .attr("fill",colorMap[type])
        .text(type.toUpperCase());
    });
  }

  function ticked() {
    link
      .attr("x1", d => d.source.x)
      .attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x)
      .attr("y2", d => d.target.y);
    node
      .attr("transform", d => `translate(${d.x},${d.y})`);
    renderGroupBg();
  }
  function dragstarted(event, d) {
    if (!event.active) sim.alphaTarget(0.23).restart();
    d.fx = d.x; d.fy = d.y;
  }
  function dragged(event, d) { d.fx = event.x; d.fy = event.y; }
  function dragended(event, d) {
    if (!event.active) sim.alphaTarget(0);
    d.fx = null; d.fy = null;
  }
}

function showResourcePanel(node, resourceList) {
  if (node.type === "cloud") {
    document.getElementById('resourceDetails').innerHTML = `<div class="info-tip">클라우드 전체 인프라 노드입니다.</div>`;
    return;
  }
  const resource = resourceList.find(r => node.id === `${r.type}-${r.value}`);
  if (!resource) {
    document.getElementById('resourceDetails').innerHTML = `<div class="info-tip">리소스 정보 없음</div>`;
    return;
  }
  document.getElementById('resourceDetails').innerHTML = `
    <div class="resource-summary">
      <table>
        <tr><th>종류</th><td>${resource.type.toUpperCase()}</td></tr>
        <tr><th>이름</th><td>${resource.value}</td></tr>
        <tr><th>대상</th><td>${resource.target}</td></tr>
        <tr><th>Shadow IT</th><td>${resource.is_shadow ? '<span style="color:red;font-weight:bold">O</span>' : 'X'}</td></tr>
      </table>
    </div>
    <div class="resource-content-tree" style="margin-top:18px;">
      ${createResourceTree(resource)}
    </div>
  `;
}

function createResourceTree(resource) {
  let html = `<b>${resource.value} 내용물</b><ul>`;
  if (resource.type === 's3') {
    html += `<li>file1.txt</li><li>backup.zip</li><li>image.png</li>`;
  } else if (resource.type === 'port') {
    html += `<li>Port: ${resource.value} (${getServiceName(resource.value)})</li>`;
  } else if (resource.type === 'domain') {
    html += `<li>IP: ${resource.target}</li>`;
  } else if (resource.type === 'lambda') {
    html += `<li>코드 파일: index.js</li><li>환경변수: prod</li>`;
  } else if (resource.type === 'ec2') {
    html += `<li>Private IP: 10.0.1.${Math.floor(Math.random()*200+10)}</li><li>AMI: ami-0ff8a91507f77f867</li>`;
  } else if (resource.type === 'rds') {
    html += `<li>DB 엔진: MySQL</li><li>Storage: 100GB</li>`;
  } else {
    html += `<li>상세 내용 없음</li>`;
  }
  html += `</ul>`;
  return html;
}

function getServiceName(port) {
  const services = {'22':'SSH','80':'HTTP','443':'HTTPS','3389':'RDP','21':'FTP','25':'SMTP','53':'DNS','3306':'MySQL','5432':'PostgreSQL'};
  return services[port] || 'Unknown';
}

// 실행
document.addEventListener('DOMContentLoaded', drawResourceNetwork);

