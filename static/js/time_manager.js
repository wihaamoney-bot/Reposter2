/**
 * Timezone and Date Management Module
 */
const TimezoneManager = {
    getOffsetMinutes() {
        return new Date().getTimezoneOffset();
    },
    
    getOffsetHours() {
        return -this.getOffsetMinutes() / 60;
    },
    
    setTimezoneCookie() {
        const offsetMinutes = this.getOffsetMinutes();
        // Set cookie with explicit domain and path to ensure it's sent
        document.cookie = `tz_offset=${offsetMinutes};path=/;max-age=31536000;SameSite=Lax`;
        console.debug(`[TimezoneManager] Offset set: ${offsetMinutes} minutes`);
    },
    
    localToUTC(localDateStr) {
        const localDate = new Date(localDateStr);
        // Correct conversion: Local + (Offset in minutes) * 60000
        // JS getTimezoneOffset() returns -180 for UTC+3, so 20:45 + (-180 * 60000) = 17:45 UTC
        return new Date(localDate.getTime() + localDate.getTimezoneOffset() * 60000);
    },
    
    utcToLocal(utcDateStr) {
        if (!utcDateStr) return null;
        
        // Ensure the string has a 'Z' to be parsed correctly as UTC
        let formattedStr = utcDateStr;
        if (!formattedStr.includes('Z') && !formattedStr.includes('+')) {
            // Replace space with T if needed (YYYY-MM-DD HH:MM:SS -> YYYY-MM-DDTHH:MM:SS)
            formattedStr = formattedStr.replace(' ', 'T') + 'Z';
        }
        
        const date = new Date(formattedStr);
        if (isNaN(date.getTime())) {
            console.error(`[TimezoneManager] Invalid date: ${utcDateStr}`);
            return null;
        }
        return date;
    },
    
    formatLocalDateTime(utcDateStr) {
        if (!utcDateStr || utcDateStr === 'N/A' || utcDateStr === 'Завершено') {
            return utcDateStr;
        }
        try {
            const date = this.utcToLocal(utcDateStr);
            if (isNaN(date.getTime())) return utcDateStr;
            
            const options = { 
                day: 'numeric', 
                month: 'short', 
                hour: '2-digit', 
                minute: '2-digit' 
            };
            
            // Format: "10 янв., 18:23"
            let formatted = date.toLocaleString('ru-RU', options);
            // Ensure consistency in format (remove year if present and add comma/dot if needed)
            return formatted.replace(/ г\./, '');
        } catch (e) {
            return utcDateStr;
        }
    }
};

function startDateTimeUpdater(dateId, timeId) {
    function update() {
        const now = new Date();
        const dateOptions = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
        const timeOptions = { hour: '2-digit', minute: '2-digit', second: '2-digit' };
        
        const dateEl = document.getElementById(dateId);
        const timeEl = document.getElementById(timeId);
        
        if (dateEl) dateEl.textContent = now.toLocaleDateString('ru-RU', dateOptions);
        if (timeEl) timeEl.textContent = now.toLocaleTimeString('ru-RU', timeOptions);
    }
    setInterval(update, 1000);
    update();
}

// Initialize on load
TimezoneManager.setTimezoneCookie();
window.TimezoneManager = TimezoneManager;
window.startDateTimeUpdater = startDateTimeUpdater;
