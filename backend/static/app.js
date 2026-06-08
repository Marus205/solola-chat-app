const API = window.location.origin;
const WS = API.replace("http://", "ws://").replace("https://", "wss://");
const app = document.getElementById("app");

let state = {
  user: readJSON("solola_user"),
  token: localStorage.getItem("solola_token"),
  conversations: [],
  messages: [],
  statuses: [],
  onlineIds: new Set(),
  activeId: null,
  socket: null,
  section: "chats",
  filter: "all",
  modal: null,
  statusIndex: null,
  temporarySecure: {},
  securePins: {},
  decrypted: {},
  search: "",
  dark: localStorage.getItem("solola_dark") === "1"
};

const THEME_COLORS = ["#2563eb", "#10b981", "#7c3aed", "#f97316", "#e11d48"];

function readJSON(key) { try { return JSON.parse(localStorage.getItem(key)); } catch { return null; } }
function escapeHtml(value) { return String(value ?? "").replace(/[&<>"']/g, s => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[s])); }
function hour(value) { return value ? new Date(value).toLocaleTimeString([], { hour:"2-digit", minute:"2-digit" }) : ""; }
function dateTime(value) { return value ? new Date(value).toLocaleString() : ""; }
function setTheme(color) { document.documentElement.style.setProperty("--accent", color); document.documentElement.style.setProperty("--accent2", color); localStorage.setItem("solola_theme", color); }
function applyDark() { document.documentElement.classList.toggle("dark", state.dark); }
setTheme(localStorage.getItem("solola_theme") || "#2563eb"); applyDark();

function friendlyError(message) {
  const m = String(message || "");
  if (m.includes("Failed to fetch")) return "Serveur indisponible. Vérifie que le backend est lancé.";
  if (m.includes("401")) return "Session expirée ou accès refusé. Reconnecte-toi.";
  if (m.includes("403")) return "Action refusée : tu n’as pas les droits nécessaires.";
  if (m.includes("404")) return "Élément introuvable.";
  if (m.includes("413")) return "Fichier trop lourd.";
  if (m.includes("PIN")) return m;
  return m.replace(/^Exception:\s*/, "") || "Erreur inconnue.";
}

async function api(path, options = {}) {
  const headers = options.headers || {};
  if (!(options.body instanceof FormData)) headers["Content-Type"] = "application/json";
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  try {
    const res = await fetch(`${API}${path}`, { ...options, headers });
    const raw = await res.text();
    let data = null;
    try { data = raw ? JSON.parse(raw) : null; } catch { data = raw; }
    if (!res.ok) throw new Error(data?.detail || data || `Erreur HTTP ${res.status}`);
    return data;
  } catch (err) {
    throw new Error(friendlyError(err.message || err));
  }
}

window.addEventListener("unhandledrejection", event => {
  const msg = friendlyError(event.reason?.message || event.reason);
  if (msg) toast(msg);
});

function toast(message) {
  let box = document.getElementById("toastBox");
  if (!box) {
    box = document.createElement("div");
    box.id = "toastBox";
    document.body.appendChild(box);
  }
  const item = document.createElement("div");
  item.className = "toast";
  item.textContent = message;
  box.appendChild(item);
  setTimeout(() => item.remove(), 4200);
}

function currentConv() { return state.conversations.find(c => c.id === state.activeId) || null; }
function isTempSecure(convId) { return Boolean(state.temporarySecure[convId]?.enabled); }
function parseEncrypted(content) { try { const d = JSON.parse(content); if (d && d.encrypted) return d; } catch {} return null; }
function getSecurityForSend(conv) {
  if (!conv) return null;
  if (conv.is_secure) return { mode: "permanent_secure", hint: conv.security_hint || "", pin: state.securePins[conv.id]?.pin };
  if (isTempSecure(conv.id)) return { mode: "temporary_secure", hint: state.temporarySecure[conv.id]?.hint || "", pin: state.temporarySecure[conv.id]?.pin };
  return null;
}
function avatarHTML(user, sizeClass = "profile-avatar") {
  const url = user?.avatar_url ? `${API}${user.avatar_url}` : "";
  return url ? `<img class="${sizeClass}" src="${url}" alt="Photo de profil">` : `<div class="${sizeClass} avatar-fallback">${escapeHtml((user?.pseudo || "W").slice(0,2).toUpperCase())}</div>`;
}
function conversationTarget(conv) {
  if (!conv || !Array.isArray(conv.members)) return null;
  if (conv.type === "group") return null;
  return conv.members.find(m => m.id !== state.user.id) || conv.members[0] || null;
}
function conversationAvatarHTML(conv) {
  if (!conv) return `<div class="avatar">?</div>`;
  if (conv.is_secure) return `<div class="avatar secure-avatar">🔐</div>`;
  if (conv.type === "group") return `<div class="avatar group-avatar">👥</div>`;
  const target = conversationTarget(conv);
  if (target?.avatar_url) return `<img class="avatar avatar-img" src="${API}${target.avatar_url}" alt="Photo">`;
  return `<div class="avatar">${escapeHtml((conv.display_title || "?").slice(0,2).toUpperCase())}</div>`;
}
function privatePresence(conv) {
  const target = conversationTarget(conv);
  if (!target) return "";
  if (state.onlineIds.has(target.id)) return "En ligne";
  return target.last_seen ? `Vu ${dateTime(target.last_seen)}` : "Hors ligne";
}
function statusIcon(status) {
  if (status === "read") return "✓✓ lu";
  if (status === "delivered") return "✓✓ reçu";
  return "✓ envoyé";
}

function railHTML() {
  const items = [
    ["chats", "💬", "Discussions"], ["status", "◯", "Statuts"], ["calls", "📞", "Appels"],
    ["groups", "👥", "Groupes"], ["secure", "🔐", "Sécurisé"], ["about", "?", "Aide"], ["settings", "⚙", "Paramètres"]
  ];
  return `<nav class="rail"><div class="brand">W</div>${items.map(i => `<button class="${state.section === i[0] ? "active" : ""}" data-section="${i[0]}" title="${i[2]}">${i[1]}</button>`).join("")}<button id="feedbackBtn" class="feedback-btn" title="Envoyer un avis">✉️</button><div class="bottom"><button id="logoutMini" title="Déconnexion">⎋</button></div></nav>`;
}
function sideTitle() { return ({ chats:"Discussions", status:"Statuts", calls:"Appels", groups:"Groupes", secure:"Sécurisé", about:"Aide", settings:"Paramètres" })[state.section]; }
function sideHTML() {
  const list = state.conversations.filter(c => {
    if (state.section === "secure") return c.is_secure;
    if (state.section === "groups") return c.type === "group" && !c.is_secure;
    if (state.section === "chats") return !c.is_secure && (state.filter === "groups" ? c.type === "group" : true);
    return false;
  });
  if (["status", "calls", "settings", "about"].includes(state.section)) return `<aside class="sidebar"><div class="side-head"><h1>${sideTitle()}</h1></div>${sideSpecialHTML()}</aside>`;
  const secureActions = state.section === "secure";
  return `<aside class="sidebar"><div class="side-head"><h1>${sideTitle()}</h1><div class="search"><input placeholder="Rechercher"></div></div><div class="action-row"><button id="${secureActions ? "newSecurePrivate" : "newPrivate"}">${secureActions ? "+ Conversation sécurisée" : "+ Conversation"}</button><button id="${secureActions ? "newSecureGroup" : "newGroup"}">${secureActions ? "+ Groupe sécurisé" : "+ Groupe"}</button></div>${state.section === "chats" ? `<div class="filters"><button class="${state.filter === "all" ? "active" : ""}" data-filter="all">Toutes</button><button class="${state.filter === "groups" ? "active" : ""}" data-filter="groups">Groupes</button></div>` : ""}<div class="conversation-list">${list.length ? list.map(convHTML).join("") : `<div class="empty-list">Aucune conversation ici.</div>`}</div></aside>`;
}
function sideSpecialHTML() {
  if (state.section === "status") return `<div class="view-page"><button class="primary" id="postStatus">Poster un statut</button><p class="muted">Les statuts expirent après 24h dans l’application, mais restent tracés dans Solola Tracking.</p></div>`;
  if (state.section === "calls") return `<div class="view-page"><p class="muted">Structure d’appels disponible. Pour une vraie vidéo en ligne, il faut finaliser WebRTC côté production.</p></div>`;
  if (state.section === "about") return `<div class="view-page"><p class="muted">Aide, objectifs du TP, limites et logique de sécurité.</p></div>`;
  if (state.section === "settings") return `<div class="view-page"><button class="primary" id="editProfile">Profil</button><br><br><button class="secondary" id="changeAvatarSide">Photo de profil</button><br><br><button class="secondary" id="toggleDark">${state.dark ? "Mode clair" : "Mode sombre"}</button><br><br><button class="secondary" id="themeSettings">Couleur du site</button><br><br><button class="secondary" id="logoutBtn">Déconnexion</button></div>`;
  return "";
}
function convHTML(conv) {
  const unread = conv.unread_count || 0;
  return `<button class="conv ${state.activeId === conv.id ? "active" : ""}" data-conv="${conv.id}">${conversationAvatarHTML(conv)}<div class="conv-info"><div><strong>${escapeHtml(conv.display_title)}</strong><span>${hour(conv.last_message?.created_at)}</span></div><p>${lastPreview(conv.last_message)} ${conv.is_secure ? "· sécurisée" : ""}</p></div>${unread ? `<span class="unread-badge">${unread}</span>` : ""}</button>`;
}
function lastPreview(m) { if (!m) return "Aucun message"; if (m.deleted_at) return "Message supprimé"; if (m.message_type === "encrypted_text") return "🔐 Message chiffré"; if (m.message_type === "encrypted_file") return "🔐 Fichier chiffré"; if (m.file) return `📎 ${m.file.original_filename}`; return escapeHtml(m.content || ""); }
function mainHTML(active) { if (state.section === "status") return statusPageHTML(); if (state.section === "settings") return settingsPageHTML(); if (state.section === "calls") return callsPageHTML(); if (state.section === "about") return aboutPageHTML(); if (!active) return `<section class="empty-chat"><h3>Solola</h3><p>Sélectionne une discussion pour commencer.</p></section>`; return chatHTML(active); }

function chatHTML(active) {
  const sec = getSecurityForSend(active);
  const locked = active.is_secure && !state.securePins[active.id]?.pin;
  return `<header class="chat-top"><div class="chat-title-line">${conversationAvatarHTML(active)}<div><h2>${active.is_secure ? "🔐 " : ""}${escapeHtml(active.display_title)}</h2><p>${active.type === "group" ? "Groupe" : "Privé"} · ${active.type === "private" ? privatePresence(active) : `${active.members.length} membres`} ${active.is_secure ? "· 100 % chiffrée" : ""}</p></div></div><div class="chat-actions">${active.is_secure ? `<button class="icon-btn" id="unlockSecure">${locked ? "Déverrouiller" : "Verrouiller"}</button>` : `<button class="icon-btn ${isTempSecure(active.id) ? "active-secure" : ""}" id="toggleTempSecure">${isTempSecure(active.id) ? "🔓 Temporaire ON" : "🔐 Temporaire"}</button>`}${active.type === "group" ? `<button class="icon-btn" id="groupManage">Gérer</button>` : ""}<input class="message-search" id="messageSearch" placeholder="Rechercher" value="${escapeHtml(state.search)}"></div></header>${active.is_secure && locked ? `<section class="lock-panel"><h2>🔐 Conversation sécurisée</h2><p>Indice : <b>${escapeHtml(active.security_hint || "Aucun indice")}</b></p><button class="primary" id="unlockSecure2">Entrer le PIN</button></section>` : `${isTempSecure(active.id) ? `<div class="secure-strip">🔐 Chiffrement temporaire activé. Les messages envoyés maintenant seront chiffrés jusqu’à désactivation.</div>` : ""}<section class="messages" id="messageList">${filteredMessages().map(messageHTML).join("")}</section><footer class="composer"><input hidden type="file" id="fileInput"><button id="pickFile">📎</button><textarea id="messageInput" placeholder="${sec ? "Message automatiquement chiffré..." : "Écrire un message..."}"></textarea><button class="send" id="sendMessage">➤</button></footer>`}`;
}
function filteredMessages() {
  const q = state.search.trim().toLowerCase();
  if (!q) return state.messages;
  return state.messages.filter(m => {
    const clear = state.decrypted[m.id] || "";
    const fileName = m.file?.original_filename || "";
    return String(m.content || "").toLowerCase().includes(q) || clear.toLowerCase().includes(q) || fileName.toLowerCase().includes(q) || String(m.sender_pseudo || "").toLowerCase().includes(q);
  });
}
function messageHTML(msg) {
  const mine = msg.sender_id === state.user.id;
  if (msg.deleted_at) return `<div class="message ${mine ? "mine" : ""}"><div class="bubble deleted">Message supprimé · ${hour(msg.deleted_at)}</div></div>`;
  let content = "";
  if (msg.message_type === "encrypted_text") content = encryptedMessageHTML(msg);
  else if (msg.message_type === "encrypted_file") content = encryptedFileHTML(msg);
  else if (msg.file) content = `<a class="file-link" href="${API}${msg.file.download_url}" target="_blank">⬇ ${escapeHtml(msg.file.original_filename)}</a>`;
  else content = `<p>${escapeHtml(msg.content)}</p>`;
  return `<div class="message ${mine ? "mine" : ""}"><div class="bubble">${!mine ? `<strong class="sender">${escapeHtml(msg.sender_pseudo)}</strong>` : ""}${content}<div class="bubble-bottom"><span>${hour(msg.created_at)}</span>${mine ? `<span>${statusIcon(msg.status)}</span>` : ""}</div><div class="bubble-actions"><button data-forward="${msg.id}">↪</button>${mine ? `<button data-delete="${msg.id}">🗑</button>` : ""}</div></div></div>`;
}
function encryptedMessageHTML(msg) {
  const data = parseEncrypted(msg.content) || {};
  if (state.decrypted[msg.id]) return `<div class="encrypted-banner">🔓 Message déchiffré</div><p>${escapeHtml(state.decrypted[msg.id])}</p>`;
  const conv = state.conversations.find(c => c.id === msg.conversation_id);
  const stored = conv ? state.securePins[conv.id]?.pin || state.temporarySecure[conv.id]?.pin : null;
  if (stored) setTimeout(() => decryptMessage(msg.id, stored, true), 0);
  return `<div class="encrypted-banner">🔐 Message chiffré ${data.mode === "permanent_secure" ? "· sécurisé" : data.mode === "temporary_secure" ? "· temporaire" : ""}</div><p><b>Indice :</b> ${escapeHtml(data.hint || "Aucun indice")}</p><code class="cipher">${escapeHtml(data.ciphertext || msg.content)}</code><button class="secondary" data-decrypt="${msg.id}" style="margin-top:10px">Déchiffrer avec PIN</button>`;
}
function encryptedFileHTML(msg) {
  const meta = parseEncrypted(msg.content) || {};
  return `<div class="encrypted-banner">🔐 Fichier chiffré</div><p><b>Nom :</b> ${escapeHtml(meta.original_filename || msg.file?.original_filename || "fichier")}</p><p><b>Indice :</b> ${escapeHtml(meta.hint || "Aucun")}</p><button class="secondary" data-decrypt-file="${msg.id}">Déchiffrer et télécharger</button>`;
}

function statusPageHTML() {
  return `<section class="view-page"><div class="panel"><h2>Statuts</h2><p>Les statuts s’ouvrent en grand et expirent après 24h dans l’application.</p><button class="primary" id="postStatus2">Poster un statut</button></div><div class="status-grid">${state.statuses.length ? state.statuses.map((s,i) => `<button class="status-card" data-status="${i}"><img src="${API}${s.file.download_url}" alt=""><b>${escapeHtml(s.user.pseudo)}</b><span>${escapeHtml(s.caption || "")}</span><small>${hour(s.created_at)}</small></button>`).join("") : `<p>Aucun statut.</p>`}</div></section>`;
}
function callsPageHTML() { return `<section class="view-page"><div class="panel"><h2>Appels</h2><p>Base d’appel prête côté interface. WebRTC complet nécessite une configuration STUN/TURN en production.</p></div></section>`; }
function aboutPageHTML() { return `<section class="view-page"><div class="panel"><h2>À propos de Solola</h2><p>Projet TP : messagerie en temps réel, chiffrement par PIN, statuts, tracking séparé et traçabilité SHA-256.</p></div><div class="settings-grid"><div class="panel"><h2>Confidentialité</h2><p>Les conversations sécurisées chiffrent automatiquement les messages côté navigateur. Le PIN n’est jamais envoyé au serveur.</p></div><div class="panel"><h2>Traçabilité</h2><p>Solola Tracking conserve les preuves : expéditeur, heure, conversation, hash des fichiers et contenu chiffré.</p></div></div><div class="panel"><h2>Limites du prototype</h2><p>Pour une production réelle, il faudrait ajouter TURN pour les appels, stockage externe durable et authentification renforcée.</p></div></section>`; }
function settingsPageHTML() {
  const privacy = state.user.privacy || {show_online:true, allow_calls:true, allow_group_invites:true, show_avatar:true};
  return `
    <section class="view-page settings-page">
      <div class="settings-grid">
        <div class="panel profile-panel">
          <h2>Profil</h2>
          <div class="profile-photo-wrap">${avatarHTML(state.user)}<button class="photo-edit-btn" id="changeAvatar">📷 Modifier</button></div>
          <div class="profile-lines">
            <div class="profile-line"><span>About</span><b>${escapeHtml(state.user.info || "Disponible")}</b></div>
            <div class="profile-line"><span>Nom</span><b>${escapeHtml(state.user.pseudo)}</b></div>
            <div class="profile-line"><span>Téléphone</span><b>${escapeHtml(state.user.phone_number)}</b></div>
          </div>
          <button class="primary" id="editProfile2">Modifier profil</button>
        </div>

        <div class="panel">
          <h2>Couleur du site</h2>
          <p>Choisis la couleur principale de Solola.</p>
          <div class="color-row">${THEME_COLORS.map(c => `<button class="color-dot" data-color="${c}" style="background:${c}"></button>`).join("")}</div>
          <br><button class="secondary" id="toggleDark2">${state.dark ? "Passer en mode clair" : "Passer en mode sombre"}</button>
        </div>
      </div>

      <div class="panel">
        <h2>Confidentialité</h2>
        <p>Contrôle ce que les autres peuvent voir ou faire avec ton compte.</p>
        <div class="privacy-grid">
          <label><input id="privacyOnline" type="checkbox" ${privacy.show_online ? "checked" : ""}> Afficher mon statut en ligne</label>
          <label><input id="privacyCalls" type="checkbox" ${privacy.allow_calls ? "checked" : ""}> Autoriser les appels</label>
          <label><input id="privacyGroups" type="checkbox" ${privacy.allow_group_invites ? "checked" : ""}> Autoriser les invitations de groupe</label>
          <label><input id="privacyAvatar" type="checkbox" ${privacy.show_avatar ? "checked" : ""}> Afficher ma photo de profil</label>
        </div>
        <button class="primary" id="savePrivacy">Enregistrer confidentialité</button>
      </div>

      <div class="panel">
        <h2>Gestion des erreurs</h2>
        <p>Solola affiche maintenant des messages clairs pour les erreurs de serveur, session expirée, accès refusé, utilisateur introuvable, PIN incorrect et fichier trop lourd.</p>
      </div>
    </section>`;
}
function modalHTML() {
  if (state.modal === "private" || state.modal === "securePrivate") { const secure = state.modal === "securePrivate"; return `<div class="modal-bg"><section class="modal"><button class="close" data-close>×</button><h2>${secure ? "Conversation sécurisée" : "Nouvelle conversation"}</h2><label>Numéro de téléphone<input id="privatePhone" placeholder="Ex: 0993446835"></label>${secure ? `<label>Indice du PIN<input id="securityHint" placeholder="Ex: date du TP"></label><label>PIN local<input id="securityPin" type="password" placeholder="PIN partagé"></label>` : ""}<button class="primary" id="createPrivate">${secure ? "Créer conversation sécurisée" : "Créer"}</button></section></div>`; }
  if (state.modal === "group" || state.modal === "secureGroup") { const secure = state.modal === "secureGroup"; return `<div class="modal-bg"><section class="modal"><button class="close" data-close>×</button><h2>${secure ? "Groupe sécurisé" : "Nouveau groupe"}</h2><label>Nom du groupe<input id="groupTitle" placeholder="Ex: Groupe TP"></label><label>Numéros des membres<textarea id="groupMembers" placeholder="099..., 099..."></textarea></label>${secure ? `<label>Indice du PIN<input id="securityHint" placeholder="Ex: année académique"></label><label>PIN local<input id="securityPin" type="password" placeholder="PIN partagé"></label>` : ""}<button class="primary" id="createGroup">${secure ? "Créer groupe sécurisé" : "Créer groupe"}</button></section></div>`; }
  if (state.modal === "profile") return `<div class="modal-bg"><section class="modal"><button class="close" data-close>×</button><h2>Profil</h2><label>Pseudo<input id="profilePseudo" value="${escapeHtml(state.user.pseudo)}"></label><label>Infos<input id="profileInfo" value="${escapeHtml(state.user.info || "")}"></label><button class="primary" id="saveProfile">Enregistrer</button></section></div>`;
  if (state.modal === "avatar") return `<div class="modal-bg"><section class="modal"><button class="close" data-close>×</button><h2>Photo de profil</h2><div class="profile-photo-wrap modal-photo">${avatarHTML(state.user)}</div><label>Choisir une nouvelle photo<input id="avatarFile" type="file" accept="image/*"></label><button class="primary" id="saveAvatar">Enregistrer photo</button></section></div>`;
  if (state.modal === "status") return `<div class="modal-bg"><section class="modal"><button class="close" data-close>×</button><h2>Poster un statut</h2><label>Légende<input id="statusCaption" placeholder="Texte du statut"></label><label>Photo<input id="statusFile" type="file" accept="image/*"></label><button class="primary" id="publishStatus">Publier</button></section></div>`;
  if (state.modal === "tempSecure") return `<div class="modal-bg"><section class="modal"><button class="close" data-close>×</button><h2>Chiffrement temporaire</h2><p>Plusieurs messages seront chiffrés jusqu’à désactivation.</p><label>Indice du PIN<input id="tempHint" placeholder="Ex: date du TP"></label><label>PIN<input id="tempPin" type="password" placeholder="PIN partagé"></label><button class="primary" id="enableTempSecure">Activer</button></section></div>`;
  if (state.modal === "groupManage") return groupManageModal();
  return "";
}
function groupManageModal() {
  const conv = currentConv(); if (!conv) return "";
  const mine = conv.members.find(m => m.id === state.user.id); const isAdmin = mine?.role === "admin";
  return `<div class="modal-bg"><section class="modal"><button class="close" data-close>×</button><h2>Gérer le groupe</h2><p>${escapeHtml(conv.display_title)}</p><div class="member-list">${conv.members.map(m => `<div class="member-row">${avatarHTML(m, "mini-avatar")}<span><b>${escapeHtml(m.pseudo)}</b><small>${escapeHtml(m.phone_number)} · ${escapeHtml(m.role || "member")}</small></span>${isAdmin && m.id !== state.user.id ? `<button data-remove-member="${m.id}">Retirer</button>` : ""}</div>`).join("")}</div>${isAdmin ? `<label>Ajouter un membre par numéro<input id="newMemberPhone" placeholder="Numéro"></label><button class="primary" id="addMember">Ajouter</button>` : `<p class="muted">Seul l’admin peut ajouter ou retirer des membres.</p>`}</section></div>`;
}
function statusViewerHTML() { if (state.statusIndex === null || !state.statuses[state.statusIndex]) return ""; const s = state.statuses[state.statusIndex]; return `<div class="status-viewer-bg"><section class="status-viewer"><header><div><b>${escapeHtml(s.user.pseudo)}</b><span>${hour(s.created_at)}</span></div><button id="closeStatusViewer">×</button></header><img src="${API}${s.file.download_url}" alt=""><footer><button id="prevStatus">←</button><p>${escapeHtml(s.caption || "")}</p><button id="nextStatus">→</button></footer></section></div>`; }

function render() { if (!state.user) return renderAuth(); applyDark(); app.innerHTML = `<main class="shell">${railHTML()}${sideHTML()}<section class="main">${mainHTML(currentConv())}</section></main>${modalHTML()}${statusViewerHTML()}`; bindEvents(); scrollBottom(); }
function renderAuth(error = "") { app.innerHTML = `<main class="auth-screen"><form class="auth-card"><div class="logo">W</div><h1>Solola</h1><p>Messagerie avec tracking, statuts et espace sécurisé.</p>${error ? `<div class="error">${escapeHtml(error)}</div>` : ""}<input id="authPhone" placeholder="Numéro de téléphone"><input id="authPseudo" placeholder="Pseudo"><input id="authPassword" type="password" placeholder="Mot de passe, min. 6 caractères"><button class="primary" id="registerBtn">S'inscrire</button><button type="button" class="secondary" id="loginBtn">Connexion</button></form></main>`; document.getElementById("registerBtn").onclick = e => { e.preventDefault(); auth("register"); }; document.getElementById("loginBtn").onclick = e => { e.preventDefault(); auth("login"); }; }
async function auth(mode) { try { const phone = document.getElementById("authPhone").value.trim(); const pseudo = document.getElementById("authPseudo").value.trim(); const password = document.getElementById("authPassword").value; const payload = mode === "register" ? { phone_number: phone, pseudo, password } : { phone_number: phone, password }; const data = await api(`/auth/${mode}`, { method:"POST", body: JSON.stringify(payload) }); localStorage.setItem("solola_token", data.access_token); localStorage.setItem("solola_user", JSON.stringify(data.user)); state.token = data.access_token; state.user = data.user; await loadAll(); connectWs(); render(); } catch (err) { renderAuth(err.message); } }

function bindEvents() {
  const id = x => document.getElementById(x);
  document.querySelectorAll("[data-section]").forEach(b => b.onclick = () => { state.section = b.dataset.section; state.activeId = null; state.messages = []; state.search = ""; render(); });
  document.querySelectorAll("[data-filter]").forEach(b => b.onclick = () => { state.filter = b.dataset.filter; render(); });
  document.querySelectorAll("[data-conv]").forEach(b => b.onclick = async () => { state.activeId = Number(b.dataset.conv); state.search = ""; await loadMessages(state.activeId); await markRead(state.activeId); render(); });
  document.querySelectorAll("[data-close]").forEach(b => b.onclick = () => { state.modal = null; render(); });
  document.querySelectorAll("[data-color]").forEach(b => b.onclick = () => setTheme(b.dataset.color));
  document.querySelectorAll("[data-status]").forEach(b => b.onclick = () => { state.statusIndex = Number(b.dataset.status); render(); });
  document.querySelectorAll("[data-delete]").forEach(b => b.onclick = async () => { await api(`/messages/${b.dataset.delete}`, { method:"DELETE" }); state.messages = state.messages.filter(m => m.id !== Number(b.dataset.delete)); render(); });
  document.querySelectorAll("[data-forward]").forEach(b => b.onclick = async () => forwardMessage(b.dataset.forward));
  document.querySelectorAll("[data-decrypt]").forEach(b => b.onclick = async () => decryptMessage(Number(b.dataset.decrypt)));
  document.querySelectorAll("[data-decrypt-file]").forEach(b => b.onclick = async () => decryptFile(Number(b.dataset.decryptFile)));
  document.querySelectorAll("[data-remove-member]").forEach(b => b.onclick = async () => removeMember(b.dataset.removeMember));
  if (id("newPrivate")) id("newPrivate").onclick = () => { state.modal = "private"; render(); };
  if (id("newGroup")) id("newGroup").onclick = () => { state.modal = "group"; render(); };
  if (id("newSecurePrivate")) id("newSecurePrivate").onclick = () => { state.modal = "securePrivate"; render(); };
  if (id("newSecureGroup")) id("newSecureGroup").onclick = () => { state.modal = "secureGroup"; render(); };
  if (id("createPrivate")) id("createPrivate").onclick = createPrivate;
  if (id("createGroup")) id("createGroup").onclick = createGroup;
  if (id("editProfile")) id("editProfile").onclick = () => { state.modal = "profile"; render(); };
  if (id("editProfile2")) id("editProfile2").onclick = () => { state.modal = "profile"; render(); };
  if (id("changeAvatar")) id("changeAvatar").onclick = () => { state.modal = "avatar"; render(); };
  if (id("changeAvatarSide")) id("changeAvatarSide").onclick = () => { state.modal = "avatar"; render(); };
  if (id("saveAvatar")) id("saveAvatar").onclick = saveAvatar;
  if (id("saveProfile")) id("saveProfile").onclick = saveProfile;
  if (id("toggleDark")) id("toggleDark").onclick = toggleDark;
  if (id("toggleDark2")) id("toggleDark2").onclick = toggleDark;
  if (id("savePrivacy")) id("savePrivacy").onclick = savePrivacy;
  if (id("themeSettings")) id("themeSettings").onclick = () => { state.section = "settings"; render(); };
  if (id("feedbackBtn")) id("feedbackBtn").onclick = () => { window.location.href = "mailto:kalodave708@gmail.com?subject=Avis%20Solola&body=Bonjour,%20voici%20mon%20avis%20sur%20Solola%20:%20"; };
  if (id("logoutBtn")) id("logoutBtn").onclick = logout;
  if (id("logoutMini")) id("logoutMini").onclick = logout;
  if (id("postStatus")) id("postStatus").onclick = () => { state.modal = "status"; render(); };
  if (id("postStatus2")) id("postStatus2").onclick = () => { state.modal = "status"; render(); };
  if (id("publishStatus")) id("publishStatus").onclick = publishStatus;
  if (id("pickFile")) id("pickFile").onclick = () => id("fileInput").click();
  if (id("fileInput")) id("fileInput").onchange = () => uploadFile(id("fileInput").files[0]);
  if (id("sendMessage")) id("sendMessage").onclick = sendMessage;
  if (id("toggleTempSecure")) id("toggleTempSecure").onclick = toggleTempSecure;
  if (id("enableTempSecure")) id("enableTempSecure").onclick = enableTempSecure;
  if (id("unlockSecure")) id("unlockSecure").onclick = togglePermanentLock;
  if (id("unlockSecure2")) id("unlockSecure2").onclick = togglePermanentLock;
  if (id("groupManage")) id("groupManage").onclick = () => { state.modal = "groupManage"; render(); };
  if (id("addMember")) id("addMember").onclick = addMember;
  if (id("closeStatusViewer")) id("closeStatusViewer").onclick = () => { state.statusIndex = null; render(); };
  if (id("prevStatus")) id("prevStatus").onclick = () => { state.statusIndex = Math.max(0, state.statusIndex - 1); render(); };
  if (id("nextStatus")) id("nextStatus").onclick = () => { state.statusIndex = Math.min(state.statuses.length - 1, state.statusIndex + 1); render(); };
  const input = id("messageInput"); if (input) input.onkeydown = e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } };
  const search = id("messageSearch"); if (search) search.oninput = e => { state.search = e.target.value; render(); };
}

async function createPrivate() { const secure = state.modal === "securePrivate"; const phone = document.getElementById("privatePhone").value.trim(); const pin = document.getElementById("securityPin")?.value || ""; const hint = document.getElementById("securityHint")?.value || ""; if (secure && !pin) return alert("Le PIN est obligatoire pour une conversation sécurisée."); const conv = await api("/conversations/private", { method:"POST", body: JSON.stringify({ phone_number: phone, is_secure: secure, security_hint: hint }) }); if (secure) state.securePins[conv.id] = { pin, hint }; await loadConversations(); state.activeId = conv.id; state.section = secure ? "secure" : "chats"; state.modal = null; await loadMessages(conv.id); render(); }
async function createGroup() { const secure = state.modal === "secureGroup"; const title = document.getElementById("groupTitle").value.trim(); const members = document.getElementById("groupMembers").value.split(",").map(x => x.trim()).filter(Boolean); const pin = document.getElementById("securityPin")?.value || ""; const hint = document.getElementById("securityHint")?.value || ""; if (secure && !pin) return alert("Le PIN est obligatoire pour un groupe sécurisé."); const conv = await api("/conversations/group", { method:"POST", body: JSON.stringify({ title, member_phone_numbers: members, is_secure: secure, security_hint: hint }) }); if (secure) state.securePins[conv.id] = { pin, hint }; await loadConversations(); state.activeId = conv.id; state.section = secure ? "secure" : "groups"; state.modal = null; await loadMessages(conv.id); render(); }
async function sendMessage() { const input = document.getElementById("messageInput"); const content = input.value.trim(); const conv = currentConv(); if (!conv || !content) return; const sec = getSecurityForSend(conv); input.value = ""; if (sec) { if (!sec.pin) return alert("Entre d’abord le PIN pour chiffrer cette conversation."); const encrypted = await encryptWithPin(content, sec.pin, sec.hint, sec.mode); await api(`/conversations/${conv.id}/messages`, { method:"POST", body: JSON.stringify({ content: JSON.stringify(encrypted), message_type:"encrypted_text" }) }); } else { await api(`/conversations/${conv.id}/messages`, { method:"POST", body: JSON.stringify({ content, message_type:"text" }) }); } }
function toggleTempSecure() { const conv = currentConv(); if (!conv) return; if (isTempSecure(conv.id)) { delete state.temporarySecure[conv.id]; render(); } else { state.modal = "tempSecure"; render(); } }
function enableTempSecure() { const conv = currentConv(); const pin = document.getElementById("tempPin").value; const hint = document.getElementById("tempHint").value.trim(); if (!pin) return alert("PIN obligatoire."); state.temporarySecure[conv.id] = { enabled: true, pin, hint }; state.modal = null; render(); }
async function togglePermanentLock() { const conv = currentConv(); if (!conv) return; if (state.securePins[conv.id]?.pin) { delete state.securePins[conv.id]; Object.keys(state.decrypted).forEach(k => { const m = state.messages.find(x => String(x.id) === String(k)); if (m && m.conversation_id === conv.id) delete state.decrypted[k]; }); render(); return; } const pin = prompt(`PIN de la conversation\nIndice : ${conv.security_hint || "Aucun"}`); if (!pin) return; state.securePins[conv.id] = { pin, hint: conv.security_hint || "" }; await decryptAllVisible(conv.id, pin); render(); }
async function decryptAllVisible(convId, pin) { for (const msg of state.messages) { if (msg.conversation_id === convId && msg.message_type === "encrypted_text" && !state.decrypted[msg.id]) await decryptMessage(msg.id, pin, true); } }
async function encryptWithPin(text, pin, hint, mode) { const enc = new TextEncoder(); const salt = crypto.getRandomValues(new Uint8Array(16)); const iv = crypto.getRandomValues(new Uint8Array(12)); const baseKey = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveKey"]); const key = await crypto.subtle.deriveKey({ name:"PBKDF2", salt, iterations:200000, hash:"SHA-256" }, baseKey, { name:"AES-GCM", length:256 }, false, ["encrypt"]); const cipher = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, enc.encode(text)); return { encrypted:true, mode, algorithm:"AES-GCM", kdf:"PBKDF2", iterations:200000, hint, salt:bufToB64(salt), iv:bufToB64(iv), ciphertext:bufToB64(cipher) }; }
async function decryptMessage(id, suppliedPin = null, silent = false) { const msg = state.messages.find(m => m.id === id); if (!msg) return; const pin = suppliedPin || prompt("Entrer le PIN de déchiffrement :"); if (!pin) return; try { const data = JSON.parse(msg.content); const enc = new TextEncoder(); const dec = new TextDecoder(); const salt = b64ToBuf(data.salt); const iv = b64ToBuf(data.iv); const cipher = b64ToBuf(data.ciphertext); const baseKey = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveKey"]); const key = await crypto.subtle.deriveKey({ name:"PBKDF2", salt, iterations:data.iterations || 200000, hash:"SHA-256" }, baseKey, { name:"AES-GCM", length:256 }, false, ["decrypt"]); const clear = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, key, cipher); state.decrypted[id] = dec.decode(clear); if (!silent) render(); } catch { if (!silent) alert("PIN incorrect ou message impossible à déchiffrer."); } }
function bufToB64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); } function b64ToBuf(b64) { return Uint8Array.from(atob(b64), c => c.charCodeAt(0)); }
async function saveAvatar() { const input = document.getElementById("avatarFile"); const file = input?.files?.[0]; if (!file) return alert("Choisis une photo."); const form = new FormData(); form.append("upload", file); const user = await api("/auth/me/avatar", { method:"POST", body: form, headers: {} }); state.user = user; localStorage.setItem("solola_user", JSON.stringify(user)); state.modal = null; await loadConversations(); render(); }
async function savePrivacy() {
  try {
    const user = await api("/auth/me/privacy", {
      method: "PATCH",
      body: JSON.stringify({
        show_online: document.getElementById("privacyOnline").checked,
        allow_calls: document.getElementById("privacyCalls").checked,
        allow_group_invites: document.getElementById("privacyGroups").checked,
        show_avatar: document.getElementById("privacyAvatar").checked,
      })
    });
    state.user = user;
    localStorage.setItem("solola_user", JSON.stringify(user));
    toast("Paramètres de confidentialité enregistrés.");
    await loadConversations();
    render();
  } catch (err) {
    toast(err.message);
  }
}

async function saveProfile() { const user = await api("/auth/me/profile", { method:"PATCH", body: JSON.stringify({ pseudo: document.getElementById("profilePseudo").value, info: document.getElementById("profileInfo").value }) }); state.user = user; localStorage.setItem("solola_user", JSON.stringify(user)); state.modal = null; await loadConversations(); render(); }
async function publishStatus() { const file = document.getElementById("statusFile").files[0]; if (!file) return alert("Choisis une photo."); const form = new FormData(); form.append("caption", document.getElementById("statusCaption").value); form.append("upload", file); const status = await api("/statuses", { method:"POST", body: form, headers: {} }); upsertStatus(status); state.modal = null; render(); }
async function uploadFile(file) { const conv = currentConv(); if (!file || !conv) return; const sec = getSecurityForSend(conv); let encrypt = Boolean(sec); let pin = sec?.pin || ""; let hint = sec?.hint || ""; let mode = sec?.mode || "file_secure"; if (!encrypt) encrypt = confirm("Chiffrer ce fichier avec un PIN ?"); if (encrypt && !pin) { pin = prompt("PIN du fichier :"); if (!pin) return; hint = prompt("Indice du PIN :") || ""; } const form = new FormData(); if (encrypt) { const encrypted = await encryptFile(file, pin, hint, mode); form.append("upload", encrypted.file); form.append("message_type", "encrypted_file"); form.append("encrypted_meta", JSON.stringify(encrypted.meta)); } else { form.append("upload", file); form.append("message_type", "file"); } await api(`/conversations/${conv.id}/upload`, { method:"POST", body: form, headers: {} }); }
async function encryptFile(file, pin, hint, mode) { const salt = crypto.getRandomValues(new Uint8Array(16)); const iv = crypto.getRandomValues(new Uint8Array(12)); const enc = new TextEncoder(); const baseKey = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveKey"]); const key = await crypto.subtle.deriveKey({ name:"PBKDF2", salt, iterations:200000, hash:"SHA-256" }, baseKey, { name:"AES-GCM", length:256 }, false, ["encrypt"]); const cipher = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, await file.arrayBuffer()); const out = new File([cipher], `${file.name}.solola.enc`, { type:"application/octet-stream" }); const meta = { encrypted:true, kind:"file", mode, algorithm:"AES-GCM", kdf:"PBKDF2", iterations:200000, hint, salt:bufToB64(salt), iv:bufToB64(iv), original_filename:file.name, original_type:file.type || "application/octet-stream" }; return { file: out, meta }; }
async function decryptFile(id) { const msg = state.messages.find(m => m.id === id); if (!msg?.file) return; const meta = parseEncrypted(msg.content); if (!meta) return alert("Métadonnées absentes."); const conv = currentConv(); const savedPin = conv ? state.securePins[conv.id]?.pin || state.temporarySecure[conv.id]?.pin : ""; const pin = savedPin || prompt("PIN du fichier :"); if (!pin) return; try { const res = await fetch(`${API}${msg.file.download_url}`); const cipher = await res.arrayBuffer(); const enc = new TextEncoder(); const salt = b64ToBuf(meta.salt); const iv = b64ToBuf(meta.iv); const baseKey = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveKey"]); const key = await crypto.subtle.deriveKey({ name:"PBKDF2", salt, iterations:meta.iterations || 200000, hash:"SHA-256" }, baseKey, { name:"AES-GCM", length:256 }, false, ["decrypt"]); const clear = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, key, cipher); const blob = new Blob([clear], { type: meta.original_type || "application/octet-stream" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = meta.original_filename || "fichier_dechiffre"; a.click(); setTimeout(() => URL.revokeObjectURL(url), 2000); } catch { alert("PIN incorrect ou fichier impossible à déchiffrer."); } }
async function forwardMessage(id) { const list = state.conversations.map(c => `${c.id} - ${c.display_title}${c.is_secure ? " 🔐" : ""}`).join("\n"); const target = prompt(`ID de la conversation cible :\n\n${list}`); if (!target) return; await api(`/messages/${id}/forward`, { method:"POST", body: JSON.stringify({ conversation_id: Number(target) }) }); }
async function addMember() { const conv = currentConv(); const phone = document.getElementById("newMemberPhone")?.value.trim(); if (!conv || !phone) return; await api(`/conversations/${conv.id}/members`, { method:"POST", body: JSON.stringify({ phone_number: phone }) }); state.modal = null; await loadConversations(); render(); }
async function removeMember(uid) { const conv = currentConv(); if (!conv || !confirm("Retirer ce membre ?")) return; await api(`/conversations/${conv.id}/members/${uid}`, { method:"DELETE" }); state.modal = null; await loadConversations(); render(); }
async function markRead(cid) { try { await api(`/conversations/${cid}/read`, { method:"POST", body: JSON.stringify({}) }); const conv = state.conversations.find(c => c.id === cid); if (conv) conv.unread_count = 0; } catch {} }
function toggleDark() { state.dark = !state.dark; localStorage.setItem("solola_dark", state.dark ? "1" : "0"); applyDark(); render(); }
function logout() { localStorage.clear(); if (state.socket) state.socket.close(); location.reload(); }
async function loadConversations() { state.conversations = await api("/conversations"); }
async function loadMessages(id) { state.messages = await api(`/conversations/${id}/messages`); }
async function loadStatuses() { state.statuses = await api("/statuses"); }
async function loadPresence() { const p = await api("/presence"); state.onlineIds = new Set(p.online_ids || []); }
async function loadAll() { await loadConversations(); await loadStatuses(); await loadPresence(); }
function upsertMessage(message) { if (message.conversation_id !== state.activeId) return false; if (!state.messages.some(m => m.id === message.id)) state.messages.push(message); return true; }
function upsertConversation(conv) { const i = state.conversations.findIndex(c => c.id === conv.id); if (i >= 0) state.conversations[i] = conv; else state.conversations.unshift(conv); }
function upsertStatus(status) { if (!state.statuses.some(s => s.id === status.id)) state.statuses.unshift(status); }
function connectWs() { if (!state.token) return; if (state.socket) state.socket.close(); const ws = new WebSocket(`${WS}/ws?token=${encodeURIComponent(state.token)}`); state.socket = ws; ws.onopen = () => ws.send(JSON.stringify({ type:"ping" })); ws.onmessage = async event => { const data = JSON.parse(event.data); if (data.type === "pong") { state.onlineIds = new Set(data.online_ids || []); render(); } if (data.type === "presence_update") { state.onlineIds = new Set(data.payload.online_ids || []); render(); } if (data.type === "new_message") { const added = upsertMessage(data.payload); if (!added && data.payload.sender_id !== state.user.id) toast(`Nouveau message de ${data.payload.sender_pseudo}`); if (added && data.payload.sender_id !== state.user.id && data.payload.conversation_id === state.activeId) await markRead(state.activeId); await loadConversations(); render(); } if (data.type === "messages_read") { if (data.payload.conversation_id === state.activeId) state.messages.forEach(m => { if (m.sender_id === state.user.id) m.status = "read"; }); await loadConversations(); render(); } if (data.type === "message_deleted") { state.messages = state.messages.filter(m => m.id !== data.payload.id); await loadConversations(); render(); } if (data.type === "conversation_created" || data.type === "conversation_updated") { upsertConversation(data.payload); render(); } if (data.type === "conversation_removed") { state.conversations = state.conversations.filter(c => c.id !== data.payload.conversation_id); if (state.activeId === data.payload.conversation_id) state.activeId = null; render(); } if (data.type === "new_status") { upsertStatus(data.payload); toast(`Nouveau statut de ${data.payload.user?.pseudo || "un utilisateur"}`); render(); } }; ws.onclose = () => setTimeout(connectWs, 3000); }
function scrollBottom() { const list = document.getElementById("messageList"); if (list) list.scrollTop = list.scrollHeight; }
(async function init() { if (state.user && state.token) { try { await loadAll(); connectWs(); } catch { localStorage.clear(); state.user = null; state.token = null; } } render(); })();
