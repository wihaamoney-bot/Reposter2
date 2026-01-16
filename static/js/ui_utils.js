/**
 * UI Utilities and Components
 */
const UIUtils = {
    showAlert(message, type = "info") {
        const alertDiv = document.createElement("div");
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.role = "alert";
        
        // SECURITY: Use textContent for message to prevent XSS
        const messageSpan = document.createElement("span");
        messageSpan.textContent = message;
        
        alertDiv.appendChild(messageSpan);
        
        const closeButton = document.createElement("button");
        closeButton.type = "button";
        closeButton.className = "btn-close";
        closeButton.setAttribute("data-bs-dismiss", "alert");
        closeButton.setAttribute("aria-label", "Close");
        
        alertDiv.appendChild(closeButton);

        const container = document.querySelector(".container");
        if (container) {
            container.insertBefore(alertDiv, container.firstChild);
            setTimeout(() => {
                alertDiv.classList.remove("show");
                setTimeout(() => alertDiv.remove(), 150);
            }, 5000);
        }
    },

    showLoading(text = "Загрузка...") {
        let overlay = document.getElementById("loadingOverlay");
        if (!overlay) {
            overlay = document.createElement("div");
            overlay.id = "loadingOverlay";
            overlay.style.cssText = `
                position: fixed; top: 0; left: 0; width: 100%; height: 100%;
                background: rgba(0, 0, 0, 0.7); display: flex;
                justify-content: center; align-items: center; z-index: 9999;
            `;
            overlay.innerHTML = `
                <div class="text-center text-white">
                    <div class="spinner-border mb-3" role="status" style="width: 3rem; height: 3rem;"></div>
                    <p class="fs-5">${text}</p>
                </div>
            `;
            document.body.appendChild(overlay);
        } else {
            overlay.style.display = "flex";
            overlay.querySelector("p").textContent = text;
        }
    },

    hideLoading() {
        const overlay = document.getElementById("loadingOverlay");
        if (overlay) overlay.style.display = "none";
    },

    escapeHtml(text) {
        if (text === null || text === undefined) return '';
        const map = {
            "&": "&amp;", "<": "&lt;", ">": "&gt;",
            '"': "&quot;", "'": "&#039;", "/": "&#47;"
        };
        return String(text).replace(/[&<>"'/]/g, m => map[m]);
    },

    renderRecipientBadges(recipientsInfo, onRemoveCallback) {
        if (!recipientsInfo || recipientsInfo.length === 0) {
            return '<p class="text-muted small mb-0 w-100">Никто не выбран</p>';
        }
        
        return recipientsInfo.map((recipient, index) => {
            let icon = 'person-circle';
            if (['group', 'groups'].includes(recipient.type)) icon = 'people-fill';
            else if (['channel', 'channels'].includes(recipient.type)) icon = 'broadcast';
            
            const topicInfo = recipient.topic_name 
                ? ` <span class="badge bg-warning text-dark p-1" style="font-size: 0.7em;">${this.escapeHtml(recipient.topic_name)}</span>` 
                : '';
            
            return `
                <div class="selected-recipient-badge d-flex align-items-center bg-primary text-white rounded-pill px-3 py-1 mb-2 me-2 shadow-sm">
                    <i class="bi bi-${icon} me-2"></i>
                    <span class="me-2 text-truncate" style="max-width: 150px;">${this.escapeHtml(recipient.name)}</span>
                    ${topicInfo}
                    <i class="bi bi-x-circle-fill cursor-pointer" onclick="${onRemoveCallback}(${index}, '${recipient.id}')"></i>
                </div>
            `;
        }).join('');
    }
};

window.showAlert = UIUtils.showAlert;
window.showLoadingOverlay = UIUtils.showLoading;
window.hideLoadingOverlay = UIUtils.hideLoading;
window.escapeHtml = UIUtils.escapeHtml;
window.renderRecipientBadges = UIUtils.renderRecipientBadges;
window.UIUtils = UIUtils;
