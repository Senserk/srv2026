const $ = (selector) => document.querySelector(selector);
const sourceIp = () => $("#source-ip").value.trim() || "203.0.113.77";
let toastTimer;

function showToast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.remove("show"), 2600);
}

async function request(path, {method = "GET", body, user, ip} = {}) {
  const headers = {"X-Forwarded-For": ip || sourceIp()};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (user) headers["X-User"] = user;
  const response = await fetch(path, {method, headers, body: body === undefined ? undefined : JSON.stringify(body)});
  const payload = await response.json();
  return {ok: response.ok, status: response.status, payload};
}

function setResponse(selector, result, okText, failText) {
  const node = $(selector);
  node.className = `response ${result.ok ? "ok" : "fail"}`;
  node.textContent = result.ok ? okText(result.payload) : failText(result.payload);
}

$(".wordlist").addEventListener("click", (event) => {
  if (!event.target.dataset.password) return;
  $("#login-form input[name=password]").value = event.target.dataset.password;
});

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  const result = await request("/login", {method: "POST", ip: data.get("source"), body: {username: data.get("username"), password: data.get("password")}});
  const state = await refreshState();
  if (result.ok && !state.missions.bruteforce) {
    const node = $("#login-response");
    node.className = "response warn";
    node.textContent = `Пароль верный, но миссия ещё не выполнена: сначала создайте 5 неудач (${state.progress.bruteforce_failures}/5), затем повторите успешный вход.`;
  } else {
    setResponse("#login-response", result,
      p => `МИССИЯ ВЫПОЛНЕНА · доступ как ${p.user}`,
      p => `ОТКАЗ · ${p.reason} · прогресс ${state.progress.bruteforce_failures}/5`);
  }
});

$("#spray-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  const result = await request("/login", {method: "POST", ip: data.get("source"), body: {username: data.get("username"), password: data.get("password")}});
  const state = await refreshState();
  setResponse("#spray-response", result, p => `Неожиданный успех: ${p.user}`,
    p => `Попытка записана · ${data.get("username")} · ${state.progress.spraying_accounts}/8 разных логинов`);
  const users = ["clara", "dmitry", "elena", "frank", "galina", "igor", "julia", "kirill", "larisa", "maxim", "nina", "oleg"];
  const input = event.currentTarget.elements.username;
  const index = users.indexOf(input.value);
  if (index >= 0 && index < users.length - 1) input.value = users[index + 1];
  await refreshState();
});

$("#order-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  const order = Number(data.get("order"));
  const result = await request(`/orders/${order}`, {user: data.get("user")});
  const state = await refreshState();
  setResponse("#order-response", result,
    p => `200 · заказ ${p.order} · владелец ${p.owner}`,
    p => `${result.status} · ${p.reason} · отказов ${state.progress.idor_denials}/5`);
  event.currentTarget.elements.order.value = order + 1;
  await refreshState();
});

$("#mfa-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = new FormData(event.currentTarget);
  const body = {target: data.get("user")};
  if (data.get("ticket")) body.ticket_id = data.get("ticket");
  const result = await request("/mfa/disable", {method: "POST", user: data.get("user"), body});
  setResponse("#mfa-response", result, p => `MFA отключён · ${p.target}`, p => `ОТКАЗ · ${p.reason}`);
  await refreshState();
});

function renderEvents(events) {
  const feed = $("#event-feed");
  feed.replaceChildren();
  if (!events.length) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = "Журнал пока пуст";
    feed.append(empty);
    return;
  }
  for (const event of events) {
    const card = document.createElement("article");
    card.className = `event ${event.outcome}`;
    const line = document.createElement("div");
    line.className = "event-line";
    const title = document.createElement("strong");
    title.textContent = `${event.event_type} · ${event.outcome}`;
    const time = document.createElement("time");
    time.textContent = event.timestamp.slice(11, 19);
    line.append(title, time);
    const meta = document.createElement("div");
    meta.className = "event-meta";
    meta.textContent = `actor=${event.actor?.id ?? "-"}  source=${event.source_ip}`;
    card.append(line, meta);
    feed.append(card);
  }
}

function updateMissions(state) {
  const labels = {
    bruteforce: state.missions.bruteforce ? "выполнено ✓" : `${state.progress.bruteforce_failures}/5 неудач, затем успех`,
    spraying: state.missions.spraying ? "выполнено ✓" : state.stage < 1 ? "заблокировано" : `${state.progress.spraying_accounts}/8 разных логинов`,
    idor: state.missions.idor ? "выполнено ✓" : state.stage < 2 ? "заблокировано" : `${state.progress.idor_denials}/5 отказов`,
    mfa: state.missions.mfa ? "выполнено ✓" : state.stage < 3 ? "заблокировано" : "можно выполнять",
  };
  for (const [name, done] of Object.entries(state.missions)) {
    const node = document.querySelector(`[data-mission="${name}"]`);
    if (!node) continue;
    node.classList.toggle("done", done);
    node.classList.toggle("current", !done && name === ["bruteforce", "spraying", "idor", "mfa"][state.stage]);
    node.querySelector("i").textContent = labels[name];
  }
}

function updateTools(stage) {
  const order = {bruteforce: 0, spraying: 1, idor: 2, mfa: 3};
  document.querySelectorAll("[data-tool]").forEach(node => {
    const required = order[node.dataset.tool];
    const active = stage === required;
    const completed = stage > required;
    node.classList.toggle("locked", !active);
    node.classList.toggle("active", active);
    node.classList.toggle("completed", completed);
    node.querySelectorAll("input, button").forEach(control => { control.disabled = !active; });
  });
}

function updateSignalBox(state) {
  const hints = [];
  if (state.highlights.anna_failures) hints.push(`anna: ${state.highlights.anna_failures} неудач`);
  if (state.highlights.spray_source) hints.push(`распыление: ${state.highlights.spray_source}`);
  if (state.highlights.anna_denials) hints.push(`отказы anna: ${state.highlights.anna_denials}`);
  if (state.mfa_disabled) hints.push(`MFA без заявки: ${state.mfa_disabled}`);
  $("#signal-box p").textContent = hints.length ? hints.join(" · ") : "Начните действовать слева. Здесь появятся признаки атаки, но окончательный вердикт дадут правила Sigma.";
}

async function refreshState() {
  try {
    const response = await fetch("/api/lab-state", {cache: "no-store"});
    const state = await response.json();
    $("#total-count").textContent = state.total;
    $("#failure-count").textContent = state.login_failures;
    $("#denial-count").textContent = state.access_denials;
    updateMissions(state);
    updateTools(state.stage);
    updateSignalBox(state);
    renderEvents(state.recent);
    return state;
  } catch {
    showToast("Не удалось обновить телеметрию");
    return null;
  }
}

$("#reset-lab").addEventListener("click", async () => {
  if (!window.confirm("Очистить журнал и вернуть исходное состояние MFA?")) return;
  await request("/lab/reset", {method: "POST", body: {}});
  document.querySelectorAll(".response").forEach(node => { node.className = "response"; node.textContent = "Стенд сброшен"; });
  showToast("Лаборатория сброшена");
  await refreshState();
});

$("#refresh-events").addEventListener("click", refreshState);
refreshState();
setInterval(refreshState, 2000);
