// Global utility functions and core logic

// ===== LOGGING SYSTEM =====
const AppLogger = {
  enabled: true,
  prefix: "🔷 [TelegramSender]",

  log(message, ...args) {
    if (!this.enabled) return;
    console.log(`${this.prefix} ℹ️ ${message}`, ...args);
  },

  info(message, ...args) {
    if (!this.enabled) return;
    console.info(`${this.prefix} ✅ ${message}`, ...args);
  },

  warn(message, ...args) {
    if (!this.enabled) return;
    console.warn(`${this.prefix} ⚠️ ${message}`, ...args);
  },

  error(message, ...args) {
    if (!this.enabled) return;
    console.error(`${this.prefix} ❌ ${message}`, ...args);
  },

  debug(message, ...args) {
    if (!this.enabled) return;
    console.debug(`${this.prefix} 🔍 ${message}`, ...args);
  },

  group(title) {
    if (!this.enabled) return;
    console.group(`${this.prefix} 📦 ${title}`);
  },

  groupEnd() {
    if (!this.enabled) return;
    console.groupEnd();
  },

  api(method, endpoint, data = null) {
    if (!this.enabled) return;
    this.group(`API: ${method} ${endpoint}`);
    console.log("🕐 Время:", new Date().toLocaleTimeString());
    if (data) console.log("📦 Данные:", data);
    this.groupEnd();
  },

  apiResponse(endpoint, status, data = null) {
    if (!this.enabled) return;
    const icon = status >= 200 && status < 300 ? "✅" : "❌";
    this.group(`${icon} Ответ от ${endpoint}`);
    console.log("📊 Статус:", status);
    console.log("🕐 Время:", new Date().toLocaleTimeString());
    if (data) console.log("📦 Данные:", data);
    this.groupEnd();
  },

  stage(stageName) {
    if (!this.enabled) return;
    console.log(`\n${"=".repeat(60)}`);
    console.log(`${this.prefix} 🎯 ЭТАП: ${stageName}`);
    console.log(`${"=".repeat(60)}\n`);
  },
};

// ===== SELECTION MANAGEMENT =====
if (typeof window.selectionOrder === 'undefined') {
  window.selectionOrder = [];
}
// Use the window property directly and avoid local declaration
// This prevents "Identifier 'selectionOrder' has already been declared"
window.selectionOrder = window.selectionOrder || [];
// We use selectionOrder as a shortcut to window.selectionOrder without 'let/var'
selectionOrder = window.selectionOrder;

/**
 * Update selected count and list UI
 */
function updateSelectedCount() {
  const selectedCheckboxes = document.querySelectorAll(
    'input[type="checkbox"]:checked:not(#selectAllContacts):not(#selectAllGroups):not(#selectAllChannels)'
  );
  
  const uniqueEntities = new Map();
  const seenRealIds = new Set();
  const newSelectionOrder = [];

  selectedCheckboxes.forEach((cb) => {
    const realId = String(cb.value);
    if (!uniqueEntities.has(realId)) {
      uniqueEntities.set(realId, {
        elementId: cb.id,
        realId: realId,
        name: cb.closest(".entity-item")?.querySelector(".fw-bold")?.textContent || "Unknown",
        type: cb.id.split('_')[0]
      });
    }
  });

  if (typeof selectionOrder !== 'undefined') {
    selectionOrder.forEach(val => {
      val = String(val);
      if (uniqueEntities.has(val) && !seenRealIds.has(val)) {
        seenRealIds.add(val);
        newSelectionOrder.push(val);
      }
    });
    
    uniqueEntities.forEach((entity, realId) => {
      if (!seenRealIds.has(realId)) {
        seenRealIds.add(realId);
        newSelectionOrder.push(realId);
      }
    });
    
    selectionOrder = newSelectionOrder;
  }

  const countBadge = document.getElementById("selectedCount");
  if (countBadge) {
    countBadge.textContent = uniqueEntities.size;
  }

  updateSelectedListUI(uniqueEntities);
}

/**
 * Update the UI list of selected recipients
 */
function updateSelectedListUI(uniqueEntitiesMap) {
  const container = document.getElementById("selectedRecipientsContent");
  if (!container) return;

  if (uniqueEntitiesMap.size === 0) {
    container.innerHTML = '<p class="text-muted w-100 text-center py-2">Ничего не выбрано</p>';
    return;
  }

  let html = "";
  selectionOrder.forEach((realId) => {
    const entity = uniqueEntitiesMap.get(String(realId));
    if (!entity) return;

    const iconMap = {
      contact: "person",
      group: "people",
      channel: "broadcast",
      folder: "folder"
    };
    const icon = iconMap[entity.type] || "chat-dots";

    html += `
            <div class="selected-recipient-badge d-flex align-items-center bg-primary text-white rounded-pill px-3 py-1 mb-2 me-2">
                <i class="bi bi-${icon} me-2"></i>
                <span class="me-2 text-truncate" style="max-width: 150px;">${UIUtils.escapeHtml(entity.name)}</span>
                <i class="bi bi-x-circle-fill cursor-pointer" onclick="toggleEntitySelectionByRealId('${entity.realId}')"></i>
            </div>
        `;
  });

  container.innerHTML = html;
}

/**
 * Toggle selection of an entity by its real Telegram ID
 */
function toggleEntitySelectionByRealId(realId) {
  const checkboxes = document.querySelectorAll(`input[type="checkbox"][value="${realId}"]`);
  if (checkboxes.length > 0) {
    const newState = !checkboxes[0].checked;
    checkboxes.forEach(cb => {
      cb.checked = newState;
    });
    
    if (newState) {
      if (!selectionOrder.includes(String(realId))) {
        selectionOrder.push(String(realId));
      }
    } else {
      selectionOrder = selectionOrder.filter(id => String(id) !== String(realId));
    }
    updateSelectedCount();
  }
}

/**
 * Handle selection change with global synchronization
 */
function handleSelectionChange(checkbox) {
  const realId = String(checkbox.value);
  const isChecked = checkbox.checked;
  
  document.querySelectorAll(`input[type="checkbox"][value="${realId}"]`).forEach(cb => {
    cb.checked = isChecked;
  });

  if (isChecked) {
    if (!selectionOrder.includes(realId)) {
      selectionOrder.push(realId);
    }
  } else {
    selectionOrder = selectionOrder.filter(id => String(id) !== realId);
  }
  
  updateSelectedCount();
}

/**
 * Initialize image position persistence
 */
function initImagePositionPersistence() {
  const positionInputs = document.querySelectorAll('input[name="imagePosition"]');
  const savedPosition = localStorage.getItem('telegram_image_position') || 'top';
  
  positionInputs.forEach(input => {
    if (input.value === savedPosition) {
      input.checked = true;
    }
    input.addEventListener('change', (e) => {
      localStorage.setItem('telegram_image_position', e.target.value);
    });
  });
}

// ===== INITIALIZATION =====
document.addEventListener("DOMContentLoaded", function () {
  AppLogger.stage("Инициализация DOM");
  initImagePositionPersistence();
  
  // Auto-dismiss alerts
  document.querySelectorAll(".alert:not(.alert-permanent)").forEach((alert) => {
    setTimeout(() => {
      if (typeof bootstrap !== 'undefined' && bootstrap.Alert) {
          const bsAlert = new bootstrap.Alert(alert);
          bsAlert.close();
      } else {
          alert.classList.remove('show');
          setTimeout(() => alert.remove(), 150);
      }
    }, 5000);
  });

  // Initialize tooltips
  if (typeof bootstrap !== "undefined" && bootstrap.Tooltip) {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(el => new bootstrap.Tooltip(el));
  }

  // Sync status
  if (!navigator.onLine) UIUtils.showAlert("Нет подключения к интернету", "warning");
  window.addEventListener("online", () => {
    AppLogger.info("🌐 Подключение к интернету восстановлено");
    UIUtils.showAlert("Соединение восстановлено", "success");
  });
  window.addEventListener("offline", () => {
    AppLogger.warn("📵 Потеряно подключение к интернету");
    UIUtils.showAlert("Потеряно соединение с интернетом", "warning");
  });
});

/**
 * 3️⃣ UI hardening: Cancel/Start task with idempotency and button disabling
 */
async function toggleTaskStatus(taskId, action) {
  const btn = document.querySelector(`.btn-${action}[data-task-id="${taskId}"]`);
  if (btn) btn.disabled = true;

  try {
    const response = await fetch(`/api/scheduler/task/${taskId}/${action}`, {
      method: 'POST'
    });
    const result = await response.json();
    
    if (result.status === 'already_cancelled' || result.status === 'cancelled') {
        UIUtils.showAlert("Задача отменена", "info");
    } else if (result.status === 'already_executing' || result.status === 'started') {
        UIUtils.showAlert("Задача запущена", "success");
    } else if (result.error) {
        UIUtils.showAlert(result.error, "danger");
    }
    
    // Refresh the task list to reflect changes
    if (typeof loadTasks === 'function') loadTasks();
  } catch (err) {
    AppLogger.error(`Error ${action}ing task:`, err);
    UIUtils.showAlert("Ошибка при изменении статуса задачи", "danger");
  } finally {
    if (btn) btn.disabled = false;
  }
}

// Export to global scope
window.AppLogger = AppLogger;
window.toggleTaskStatus = toggleTaskStatus;
window.selectionOrder = selectionOrder;
window.updateSelectedCount = updateSelectedCount;
window.toggleEntitySelectionByRealId = toggleEntitySelectionByRealId;
window.handleSelectionChange = handleSelectionChange;

// API Interceptor
(function () {
  const originalFetch = window.fetch;
  window.fetch = function (...args) {
    const [url, options = {}] = args;
    const method = options.method || "GET";

    let bodyData = null;
    if (options.body) {
      if (options.body instanceof FormData) bodyData = "[FormData]";
      else if (typeof options.body === "string") {
        try { bodyData = JSON.parse(options.body); } catch (e) { bodyData = options.body; }
      } else bodyData = options.body;
    }
    AppLogger.api(method, url, bodyData);

    const csrfToken = ApiClient.getCsrfToken();
    if (csrfToken && method !== "GET") {
        options.headers = options.headers || {};
        options.headers["X-CSRFToken"] = csrfToken;
    }

    return originalFetch.apply(this, args).then((response) => {
        const clonedResponse = response.clone();
        clonedResponse.json().then((data) => {
            AppLogger.apiResponse(url, response.status, data);
        }).catch(() => {
            AppLogger.apiResponse(url, response.status, "Non-JSON response");
        });
        return response;
    }).catch((error) => {
        AppLogger.error(`Ошибка fetch запроса к ${url}:`, error);
        throw error;
    });
  };
})();
