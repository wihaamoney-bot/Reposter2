/**
 * API and Network Utilities
 */
const ApiClient = {
    getCsrfToken() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.getAttribute("content") : null;
    },

    async fetch(url, options = {}) {
        const csrfToken = this.getCsrfToken();
        const method = (options.method || "GET").toUpperCase();
        
        if (csrfToken && method !== "GET") {
            options.headers = {
                ...options.headers,
                "X-CSRFToken": csrfToken
            };
        }
        return window.fetch(url, options);
    },

    handleError(error, defaultMessage = "Произошла ошибка") {
        console.error("API Error:", error);
        let message = defaultMessage;
        if (error.response && error.response.data && error.response.data.error) {
            message = error.response.data.error;
        } else if (error.message) {
            message = error.message;
        }
        if (window.showAlert) window.showAlert(`Ошибка: ${message}`, "danger");
    }
};

/**
 * Менеджер идемпотентности для предотвращения дубликатов запросов
 */
const IdempotentRequestManager = {
    generateKey() {
        return 'idemp_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }
};

// Экспортируем в глобальную область видимости
window.IdempotentRequestManager = IdempotentRequestManager;

window.ApiClient = ApiClient;
window.getCsrfToken = ApiClient.getCsrfToken;
