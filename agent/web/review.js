'use strict';
const $ = id => document.getElementById(id);
let selected = null;
const requests = new Map();
async function api(path, body) {
  const response = await fetch(path, {
    method: body ? 'POST' : 'GET',
    headers: {Authorization: 'Bearer ' + $('token').value, 'Content-Type': 'application/json'},
    body: body ? JSON.stringify(body) : undefined
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error);
  return result;
}
function show(value) { $('status').textContent = value; }
async function select(taskId) {
  selected = null;
  $('review').hidden = true;
  $('arbitration').hidden = true;
  const item = await api('/api/case?task_id=' + encodeURIComponent(taskId));
  selected = item;
  $('detail').replaceChildren();
  for (const [title, value] of [
    ['案件与修订', item.case], ['调查结论 / 事实校验 / 反证', item.result],
    ['证据快照与限制', item.snapshot], ['复核与仲裁记录', item.review_state]
  ]) {
    const panel = document.createElement('details');
    panel.open = title === '案件与修订' || title.startsWith('调查结论');
    const heading = document.createElement('summary'); heading.textContent = title;
    const pre = document.createElement('pre'); pre.textContent = JSON.stringify(value, null, 2);
    panel.append(heading, pre);
    $('detail').append(panel);
  }
  const current = (item.snapshot.revision || 1) === (item.case.current_revision || 1);
  $('review').hidden = item.status !== 'success' || !current;
  $('arbitration').hidden = $('review').hidden || !item.review_state.disputed;
  show(item.review_state.disputed ? '复核存在冲突：训练标签与策略导出已暂停，需独立仲裁。' : '已加载当前案件');
}
$('load').onclick = async () => {
  try {
    const result = await api('/api/cases');
    $('cases').replaceChildren();
    for (const item of result.cases) {
      const button = document.createElement('button');
      button.textContent = item.entity_ref + ' · 修订 ' + (item.current_revision || 1);
      button.onclick = () => select(item.task_id).catch(e => show(e.message));
      $('cases').append(button);
    }
    show('已加载 ' + result.cases.length + ' 个案件');
  } catch (e) { show(e.message); }
};
for (const [form, path, prefix] of [['review', '/api/reviews', ''], ['arbitration', '/api/arbitrations', 'arb-']]) {
  $(form).onsubmit = async event => {
    event.preventDefault();
    if (!selected) return;
    const taskId = selected.task_id;
    const payload = {task_id: taskId, result_digest: selected.result_digest,
      verdict: $(prefix + 'verdict').value, note: $(prefix + 'note').value,
      matures_at: new Date($(prefix + 'maturity').value).getTime() / 1000};
    if (prefix) payload.reviews_digest = selected.review_state.reviews_digest;
    // A network retry of identical content must not create a second review.
    const key = path + JSON.stringify(payload);
    if (!requests.has(key)) requests.set(key, crypto.randomUUID());
    payload.request_id = requests.get(key);
    const button = $(form).querySelector('button'); button.disabled = true;
    try {
      await api(path, payload);
      await select(taskId);
      show('已记录' + (prefix ? '仲裁' : '复核') + '；线上策略未变更');
    } catch (e) { show(e.message); }
    finally { button.disabled = false; }
  };
}
