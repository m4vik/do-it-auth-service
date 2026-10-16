"use strict";

const element = id => document.getElementById(id);
const state = { tokens: null, profile: null, contact: null, login: null, factor: null, busy: false, response: null };

function notify(message, error = false) {
    element("notice").textContent = message;
    element("notice").classList.toggle("error", error);
}

function showResponse() {
    if (state.response === null) return;
    const showTokens = element("show-tokens").checked;
    element("response").textContent = JSON.stringify(state.response, (key, value) =>
        !showTokens && (key === "accessToken" || key === "refreshToken") ? "[скрыт]" : value, 2);
}

function render() {
    const hasTokens = Boolean(state.tokens);
    element("session-state").textContent = hasTokens ? "Токены получены" : "Вход не выполнен";
    element("session-state").classList.toggle("good", hasTokens);
    element("login-factor").hidden = !state.login;
    element("profile").hidden = !state.profile;
    if (state.profile) {
        element("profile-contact").textContent = state.profile.identifier;
        element("profile-verified").textContent = state.profile.isContactVerified ? "Контакт подтверждён" : "Контакт не подтверждён";
        element("profile-factor").textContent = state.profile.twoFactorEnabled ? "2FA включена" : "2FA выключена";
    }
    element("token-info").textContent = hasTokens
        ? `Access выдан на ${state.tokens.expiresIn} сек. Токены доступны только в этой вкладке.`
        : "Токены пока не получены.";
    document.querySelectorAll("input, select").forEach(input => { input.disabled = state.busy; });
    document.querySelectorAll("button[data-action]").forEach(button => {
        const action = button.dataset.action;
        button.disabled = state.busy || (button.hasAttribute("data-auth") && !hasTokens)
            || (action === "refresh" && !hasTokens)
            || (action === "verify-login" && !state.login)
            || (action === "confirm-contact" && (!hasTokens || !state.contact))
            || (action === "confirm-factor" && (!hasTokens || !state.factor));
    });
}

function clearSession() {
    state.tokens = null;
    state.profile = null;
    state.contact = null;
    state.login = null;
    state.factor = null;
    ["login-code", "contact-code", "factor-code"].forEach(id => { element(id).value = ""; });
}

function credentials() {
    if (!element("identifier").reportValidity() || !element("password").reportValidity()) return null;
    return { identifierType: element("identifier-type").value, identifier: element("identifier").value, password: element("password").value };
}

function codeBody(challenge, inputId) {
    const input = element(inputId);
    if (!/^[0-9]{6}$/.test(input.value)) throw new Error("Введи код из шести цифр, включая ведущие нули.");
    if (!challenge) throw new Error("Сначала запроси код.");
    return { challengeId: challenge.challengeId, code: input.value };
}

async function request(path, body = null, authorized = false, method = "POST") {
    const headers = {};
    if (body !== null) headers["Content-Type"] = "application/json";
    if (authorized) {
        if (!state.tokens) throw new Error("Сначала выполни вход.");
        headers.Authorization = `Bearer ${state.tokens.accessToken}`;
    }
    element("request-path").textContent = `${method} ${path}`;
    const response = await fetch(path, { method, headers, body: body === null ? undefined : JSON.stringify(body), cache: "no-store" });
    const text = await response.text();
    const result = text ? JSON.parse(text) : { message: "Операция выполнена. Тело ответа отсутствует." };
    state.response = result;
    element("http-status").textContent = String(response.status);
    element("http-status").className = `badge ${response.ok ? "good" : "bad"}`;
    showResponse();
    if (!response.ok) {
        const hints = { 401: "Проверь пароль, обнови токены или войди заново.", 409: "Проверь контакт и текущее состояние 2FA.", 429: "Подожди перед повторной попыткой." };
        throw new Error(`HTTP ${response.status}: ${result.error?.message ?? response.statusText} ${hints[response.status] ?? ""}`);
    }
    return result;
}

const actions = {
    async register() {
        const body = credentials();
        if (!body) return;
        const profile = await request("/auth/register", body);
        clearSession();
        state.profile = profile;
        notify("Аккаунт создан и активен. Нажми «Войти» — подтверждение контакта пока не требуется.");
    },
    async login() {
        const body = credentials();
        if (!body) return;
        const result = await request("/auth/login", body);
        clearSession();
        if (result.twoFactorRequired) {
            state.login = result;
            notify("Нужен второй фактор. Введи ниже код purpose=login из логов Docker.");
        } else {
            state.tokens = result;
            notify("Вход выполнен. Нажми «Профиль» или перейди к подтверждению контакта.");
        }
    },
    async "verify-login"() {
        state.tokens = await request("/auth/2fa/verify", codeBody(state.login, "login-code"));
        state.login = null;
        element("login-code").value = "";
        notify("Второй фактор принят, токены получены. Можно открыть профиль.");
    },
    async profile() {
        state.profile = await request("/users/me", null, true, "GET");
        notify("Профиль получен. Флаги подтверждения контакта и 2FA показаны в первом блоке.");
    },
    async "request-contact"() {
        state.contact = await request("/users/me/contact-verification/request", null, true);
        element("contact-code").value = "";
        notify("Код контакта отправлен в лог. Найди purpose=contact и challengeId из ответа.");
    },
    async "confirm-contact"() {
        state.profile = await request("/users/me/contact-verification/confirm", codeBody(state.contact, "contact-code"), true);
        state.contact = null;
        element("contact-code").value = "";
        notify("Контакт подтверждён. В профиле isContactVerified = true.");
    },
    async "request-factor"() {
        if (!element("password").reportValidity()) return;
        const action = element("factor-action").value;
        const challenge = await request("/users/me/2fa/request", { action, password: element("password").value }, true);
        state.factor = { ...challenge, action };
        element("factor-code").value = "";
        notify(`Код настройки 2FA отправлен. Введи код purpose=${action} из логов.`);
    },
    async "confirm-factor"() {
        const action = state.factor.action;
        await request(`/users/me/2fa/${action}`, codeBody(state.factor, "factor-code"), true);
        clearSession();
        notify(`2FA ${action === "enable" ? "включена" : "выключена"}. Старые сессии отозваны. Нажми «Войти» снова.`);
    },
    async refresh() {
        state.tokens = await request("/auth/refresh", { refreshToken: state.tokens.refreshToken });
        notify("Выдана новая пара токенов. Старый refresh больше не действует.");
    },
    async logout() {
        await request("/auth/logout", null, true);
        clearSession();
        notify("Выход выполнен. Токены этой сессии отозваны сервером.");
    }
};

document.querySelectorAll("button[data-action]").forEach(button => {
    button.addEventListener("click", async () => {
        if (state.busy) return;
        // Validate inputs before disabling them for the request.
        if (["register", "login"].includes(button.dataset.action) && !credentials()) return;
        state.busy = true;
        render();
        try { await actions[button.dataset.action](); }
        catch (error) { notify(error.message || "Не удалось связаться с API. Проверь Docker.", true); }
        finally { state.busy = false; render(); }
    });
});

element("identifier-type").addEventListener("change", () => {
    clearSession();
    const phone = element("identifier-type").value === "phone";
    element("identifier").type = phone ? "tel" : "email";
    element("identifier").value = phone ? "+12025550123" : `test-${Date.now()}@example.com`;
    notify("Выбран другой контакт. Зарегистрируй его или выполни вход.");
    render();
});
["identifier", "password"].forEach(id => element(id).addEventListener("input", () => {
    clearSession();
    notify("Данные входа изменены. Зарегистрируй аккаунт или войди заново.");
    render();
}));
element("factor-action").addEventListener("change", () => {
    state.factor = null;
    element("factor-code").value = "";
    element("factor-purpose").textContent = `purpose=${element("factor-action").value}`;
    render();
});
element("show-tokens").addEventListener("change", showResponse);
element("identifier").value = `test-${Date.now()}@example.com`;
render();
