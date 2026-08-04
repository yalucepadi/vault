// ==========================================
// 1. CAPA DE ALMACENAMIENTO (SOLID: D)
// ==========================================
class LocalStorageProvider {
    async loadData() {
        return localStorage.getItem('my_secure_vault_payload') || '[]';
    }
    async saveData(dataString) {
        localStorage.setItem('my_secure_vault_payload', dataString);
    }
    getName() { return "LocalStorage"; }
}

class GitHubJsonStorageProvider {
    constructor(token, repo, path) {
        this.token = token;
        this.repo = repo;
        this.path = path || "vault.json";
    }

    async loadData() {
        const url = `https://api.github.com/repos/${this.repo}/contents/${this.path}`;
        const response = await fetch(url, {
            headers: { 'Authorization': `token ${this.token}`, 'Accept': 'application/vnd.github.v3+json' }
        });
        if (response.status === 404) return '[]';
        if (!response.ok) throw new Error("Error al conectar con GitHub API");

        const data = await response.json();
        return decodeURIComponent(escape(atob(data.content.replace(/\s/g, ''))));
    }

    async saveData(dataString) {
        const url = `https://api.github.com/repos/${this.repo}/contents/${this.path}`;
        let sha = null;
        try {
            const checkRes = await fetch(url, {
                headers: { 'Authorization': `token ${this.token}`, 'Accept': 'application/vnd.github.v3+json' }
            });
            if (checkRes.ok) {
                const fileData = await checkRes.json();
                sha = fileData.sha;
            }
        } catch (e) { /* Archivo nuevo */ }

        const encodedContent = btoa(unescape(encodeURIComponent(dataString)));
        const body = {
            message: "Update password vault payload via MiniVault Pro",
            content: encodedContent
        };
        if (sha) body.sha = sha;

        const putRes = await fetch(url, {
            method: 'PUT',
            headers: {
                'Authorization': `token ${this.token}`,
                'Content-Type': 'application/json',
                'Accept': 'application/vnd.github.v3+json'
            },
            body: JSON.stringify(body)
        });

        if (!putRes.ok) {
            const errDetails = await putRes.json();
            throw new Error("GitHub Save Error: " + (errDetails.message || putRes.statusText));
        }
    }
    getName() { return "GitHub JSON"; }
}

// ==========================================
// 2. GESTIÓN DE CONFIGURACIÓN Y CRIPTOGRAFÍA (CONFIG.JSON)
// ==========================================
const STATIC_SALT_STRING = "minivault-static-salt-yalucepadi-kasd";
let storageService = null;
let cryptoKey = null;
let vaultCache = [];
let idleTimer = null;
const IDLE_LIMIT_MS = 5 * 60 * 1000;

function str2ab(str) { return new TextEncoder().encode(str); }
function ab2str(buffer) { return new TextDecoder().decode(buffer); }
function ab2b64(buf) {
    let binary = '';
    let bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}
function b642ab(base64) {
    let binary = atob(base64);
    let bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

// Función auxiliar para calcular SHA-256 de la contraseña maestra
async function calculateMasterHash(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password + STATIC_SALT_STRING);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Proveedor auxiliar específico para manejar config.json en GitHub o LocalStorage
class ConfigStorageHelper {
    constructor(providerType, storageInstance, token, repo) {
        this.providerType = providerType;
        this.storageInstance = storageInstance;
        this.token = token;
        this.repo = repo;
    }

    async getConfig() {
        if (this.providerType === 'github') {
            const url = `https://api.github.com/repos/${this.repo}/contents/config.json`;
            try {
                const res = await fetch(url, {
                    headers: { 'Authorization': `token ${this.token}`, 'Accept': 'application/vnd.github.v3+json' }
                });
                if (res.status === 404) return null;
                if (!res.ok) return null;
                const data = await res.json();
                const decoded = decodeURIComponent(escape(atob(data.content.replace(/\s/g, ''))));
                return JSON.parse(decoded);
            } catch (e) {
                return null;
            }
        } else {
            const val = localStorage.getItem('minivault_config');
            return val ? JSON.parse(val) : null;
        }
    }

    async saveConfig(configData) {
        const jsonStr = JSON.stringify(configData, null, 2);
        if (this.providerType === 'github') {
            const url = `https://api.github.com/repos/${this.repo}/contents/config.json`;
            let sha = null;
            try {
                const checkRes = await fetch(url, {
                    headers: { 'Authorization': `token ${this.token}`, 'Accept': 'application/vnd.github.v3+json' }
                });
                if (checkRes.ok) {
                    const fileData = await checkRes.json();
                    sha = fileData.sha;
                }
            } catch (e) { }

            const body = {
                message: "Initialize config.json via MiniVault Pro",
                content: btoa(unescape(encodeURIComponent(jsonStr)))
            };
            if (sha) body.sha = sha;

            await fetch(url, {
                method: 'PUT',
                headers: {
                    'Authorization': `token ${this.token}`,
                    'Content-Type': 'application/json',
                    'Accept': 'application/vnd.github.v3+json'
                },
                body: JSON.stringify(body)
            });
        } else {
            localStorage.setItem('minivault_config', jsonStr);
        }
    }
}

function toggleStorageConfig() {
    const provider = document.getElementById('storageProviderSelect').value;
    const ghSection = document.getElementById('githubConfigSection');
    if (provider === 'github') {
        ghSection.classList.remove('hidden');
    } else {
        ghSection.classList.add('hidden');
    }
}

async function unlockVault() {
    const masterPass = document.getElementById('masterPassword').value;
    if (!masterPass) {
        alert("Por favor ingresa una contraseña maestra.");
        return;
    }

    const providerType = document.getElementById('storageProviderSelect').value;
    let token, repo, path;

    if (providerType === 'github') {
        token = document.getElementById('ghToken').value;
        repo = document.getElementById('ghRepo').value;
        path = document.getElementById('ghPath').value || "vault.json";
        if (!token || !repo) {
            alert("Para usar GitHub necesitas ingresar tu Token y el Repositorio.");
            return;
        }
        storageService = new GitHubJsonStorageProvider(token, repo, path);
    } else {
        storageService = new LocalStorageProvider();
    }

    try {
        const configHelper = new ConfigStorageHelper(providerType, storageService, token, repo);
        let config = await configHelper.getConfig();
        const currentHash = await calculateMasterHash(masterPass);

        if (!config) {
            // PRIMER USO: Crear config.json automáticamente
            const newConfig = {
                version: "2.0",
                salt: STATIC_SALT_STRING,
                masterHash: currentHash
            };
            await configHelper.saveConfig(newConfig);
            config = newConfig;
        } else {
            // VALIDACIÓN: Comprobar el hash maestro
            if (config.masterHash !== currentHash) {
                alert("Contraseña maestra incorrecta.");
                return;
            }
        }

        // Derivar la llave AES-GCM con la sal estática compartida
        const saltBuffer = str2ab(config.salt || STATIC_SALT_STRING);
        const baseKey = await window.crypto.subtle.importKey(
            "raw", str2ab(masterPass), { name: "PBKDF2" }, false, ["deriveKey"]
        );

        cryptoKey = await window.crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: saltBuffer, iterations: 100000, hash: "SHA-256" },
            baseKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );

        document.getElementById('authCard').classList.add('hidden');
        document.getElementById('mainPanel').classList.remove('hidden');
        document.getElementById('storageStatusBadge').innerText = "Almacenamiento: " + storageService.getName();

        await loadVault();
        initIdleTimer();
    } catch (e) {
        alert("Error al desbloquear o conectar: " + e.message);
        cryptoKey = null;
    }
}

async function encryptData(plainText) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, cryptoKey, str2ab(plainText)
    );
    return { iv: ab2b64(iv), data: ab2b64(encrypted) };
}

async function decryptData(encryptedObj) {
    try {
        const iv = new Uint8Array(b642ab(encryptedObj.iv));
        const data = b642ab(encryptedObj.data);
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv }, cryptoKey, data
        );
        return ab2str(decrypted);
    } catch (e) {
        return "[Error de descifrado]";
    }
}

// ==========================================
// 3. GESTIÓN DE CREDENCIALES (CRUD)
// ==========================================
async function loadVault() {
    const vaultList = document.getElementById('vaultList');
    vaultList.innerHTML = '<p style="color: #777; text-align: center;">Cargando y descifrando vault...</p>';

    try {
        const rawPayload = await storageService.loadData();
        const encryptedVault = JSON.parse(rawPayload) || [];

        vaultCache = [];
        for (const item of encryptedVault) {
            // Ya no existen centinelas falsos, se leen directo
            const decSite = await decryptData(item.site);
            const decUser = await decryptData(item.username);
            const decPass = await decryptData(item.password);
            vaultCache.push({
                id: item.id,
                site: decSite,
                username: decUser,
                password: decPass
            });
        }
        renderVaultList(vaultCache);
    } catch (e) {
        vaultList.innerHTML = '<p style="color: red; text-align: center;">Error al cargar datos: ' + e.message + '</p>';
    }
}

function renderVaultList(items) {
    const vaultList = document.getElementById('vaultList');
    if (items.length === 0) {
        vaultList.innerHTML = '<p style="color: #777; text-align: center;">No hay contraseñas guardadas.</p>';
        return;
    }

    let html = '';
    items.forEach((item, index) => {
        html += `
            <div class="vault-item">
                <div class="item-info">
                    <strong>${escapeHtml(item.site)}</strong>
                    <div>Usuario: ${escapeHtml(item.username)}</div>
                    <div>Contraseña: <span class="password-display">${escapeHtml(item.password)}</span></div>
                </div>
                <div class="actions">
                    <button class="btn-success" onclick="copyToClipboard('${escapeQuotes(item.password)}')" style="padding: 6px 10px; font-size: 0.8rem;">Copiar</button>
                    <button class="btn-secondary" onclick="editItem(${index})" style="padding: 6px 10px; font-size: 0.8rem;">Editar</button>
                    <button class="btn-danger" onclick="deleteItem(${index})" style="padding: 6px 10px; font-size: 0.8rem;">Eliminar</button>
                </div>
            </div>
        `;
    });
    vaultList.innerHTML = html;
}

document.getElementById('vaultForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const site = document.getElementById('site').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const editIndex = parseInt(document.getElementById('editIndex').value);

    const encSite = await encryptData(site);
    const encUser = await encryptData(username);
    const encPass = await encryptData(password);

    const entry = {
        id: editIndex >= 0 ? vaultCache[editIndex].id : Date.now(),
        site: encSite,
        username: encUser,
        password: encPass
    };

    try {
        const rawPayload = await storageService.loadData();
        let encryptedVault = JSON.parse(rawPayload) || [];

        if (editIndex >= 0) {
            const targetId = vaultCache[editIndex].id;
            const pos = encryptedVault.findIndex(i => i.id === targetId);
            if (pos >= 0) encryptedVault[pos] = entry;
        } else {
            encryptedVault.push(entry);
        }

        await storageService.saveData(JSON.stringify(encryptedVault));
        resetForm();
        loadVault();
    } catch (err) {
        alert("Error al guardar: " + err.message);
    }
});

async function deleteItem(cacheIndex) {
    if (!confirm("¿Estás seguro de eliminar esta credencial?")) return;
    const targetId = vaultCache[cacheIndex].id;

    try {
        const rawPayload = await storageService.loadData();
        let encryptedVault = JSON.parse(rawPayload) || [];
        encryptedVault = encryptedVault.filter(i => i.id !== targetId);

        await storageService.saveData(JSON.stringify(encryptedVault));
        loadVault();
    } catch (err) {
        alert("Error al eliminar: " + err.message);
    }
}

function editItem(cacheIndex) {
    const item = vaultCache[cacheIndex];
    document.getElementById('site').value = item.site;
    document.getElementById('username').value = item.username;
    document.getElementById('password').value = item.password;
    document.getElementById('editIndex').value = cacheIndex;

    document.getElementById('formTitle').innerText = "Editar Credencial";
    document.getElementById('submitBtn').innerText = "Actualizar Credencial";
    document.getElementById('cancelEditBtn').classList.remove('hidden');
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function resetForm() {
    document.getElementById('vaultForm').reset();
    document.getElementById('editIndex').value = "-1";
    document.getElementById('formTitle').innerText = "Guardar Nueva Credencial";
    document.getElementById('submitBtn').innerText = "Guardar Credencial";
    document.getElementById('cancelEditBtn').classList.add('hidden');
}

async function syncStorage() {
    try {
        await loadVault();
        alert("Sincronizado correctamente.");
    } catch (e) {
        alert("Error de sincronización: " + e.message);
    }
}

// ==========================================
// 4. UTILIDADES Y SEGURIDAD
// ==========================================
function generatePassword() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%&*!_-+=.";
    let password = "";
    for (let i = 0; i < 16; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    document.getElementById('generatedPassword').value = password;
    document.getElementById('password').value = password;
    document.getElementById('password').type = 'text';
}

function togglePass() {
    const passInput = document.getElementById('password');
    passInput.type = passInput.type === 'password' ? 'text' : 'password';
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        setTimeout(() => { navigator.clipboard.writeText("").catch(() => { }); }, 30000);
    });
    alert("¡Contraseña copiada! Se limpiará en 30 segundos.");
}

function filterVault() {
    const query = document.getElementById('searchInput').value.toLowerCase();
    const filtered = vaultCache.filter(item =>
        item.site.toLowerCase().includes(query) || item.username.toLowerCase().includes(query)
    );
    renderVaultList(filtered);
}

function lockVault() {
    cryptoKey = null;
    vaultCache = [];
    document.getElementById('mainPanel').classList.add('hidden');
    document.getElementById('authCard').classList.remove('hidden');
    document.getElementById('masterPassword').value = '';
    if (idleTimer) clearInterval(idleTimer);
}

function initIdleTimer() {
    let timeLeft = IDLE_LIMIT_MS;
    if (idleTimer) clearInterval(idleTimer);

    const resetTimer = () => { timeLeft = IDLE_LIMIT_MS; };
    window.addEventListener('mousemove', resetTimer);
    window.addEventListener('keypress', resetTimer);

    idleTimer = setInterval(() => {
        timeLeft -= 1000;
        const minutes = Math.floor(timeLeft / 60000);
        const seconds = Math.floor((timeLeft % 60000) / 1000);
        document.getElementById('lockTimerBadge').innerText = `Inactividad: ${minutes}:${seconds < 10 ? '0' : ''}${seconds}`;

        if (timeLeft <= 0) {
            clearInterval(idleTimer);
            lockVault();
            alert("Vault bloqueado por inactividad.");
        }
    }, 1000);
}

function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
function escapeQuotes(str) {
    return str.replace(/'/g, "\\'");
}