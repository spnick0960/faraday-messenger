const $ = (id) => document.getElementById(id);

function fmtTime(unix) {
  if (!unix) return "—";
  return new Date(unix * 1000).toLocaleTimeString();
}

async function refresh() {
  const res = await fetch("/v1/transparency", { cache: "no-store" });
  if (!res.ok) throw new Error("transparency " + res.status);
  const data = await res.json();
  $("mailboxes").textContent = data.mailboxes;
  $("pending").textContent = data.pendingEnvelopes;
  $("ondisk").textContent = data.ciphertextOnDisk;
  $("ttl").textContent = data.ttlHours;
  if ($("retention") && data.retention) {
    $("retention").textContent = data.retention;
  }

  const can = $("can");
  const cannot = $("cannot");
  can.innerHTML = "";
  cannot.innerHTML = "";
  (data.whatThisServerCanSee.can || []).forEach((t) => {
    const li = document.createElement("li");
    li.textContent = t;
    can.appendChild(li);
  });
  (data.whatThisServerCanSee.cannot || []).forEach((t) => {
    const li = document.createElement("li");
    li.textContent = t;
    cannot.appendChild(li);
  });

  const body = $("events");
  const events = data.recent || [];
  if (!events.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No envelopes yet. The store is empty — which is the happy path.</td></tr>';
    return;
  }
  body.innerHTML = "";
  events.slice().reverse().forEach((e) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${fmtTime(e.at)}</td><td>${e.kind}</td><td>${e.bytes ?? "—"}</td><td>${e.destHint ?? "—"}</td><td>${e.blobHead ?? "—"}</td>`;
    body.appendChild(tr);
  });
}

$("relay-url").textContent = `${location.protocol}//${location.host}`;
refresh();
setInterval(() => refresh().catch(() => {}), 2500);
