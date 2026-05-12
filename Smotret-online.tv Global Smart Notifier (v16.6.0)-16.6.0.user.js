// ==UserScript==
// @name          Smotret-online.tv Global Smart Notifier (v16.6.0)
// @namespace     http://tampermonkey.net/
// @version       16.6.0
// @run-at        document-start
// @description   Умные уведомления. Версия без прозрачности и блюра (закомментировано).
// @author        Gemini
// @match         https://smotret-online.tv/*
// @icon          https://raw.githubusercontent.com/VitalSkib/files/refs/heads/main/Clock.svg
// @grant         GM_notification
// @grant         GM_setValue
// @grant         GM_getValue
// @grant         GM_registerMenuCommand
// @grant         GM_openInTab
// ==/UserScript==

(function() {
    'use strict';
    if (window.self !== window.top) {
        // Разрешаем работу внутри iframe плеера fresh-rating — перехватываем .ts там
        if (!location.pathname.includes('fresh-rating')) return;
    }

    // Псевдоэлемент резервирует точно такое же место как реальный колокольчик.
    // Когда bell вставлен — класс tv-bell-ready убирает псевдоэлемент: текст не прыгает.
    const bellReserveStyle = document.createElement('style');
    bellReserveStyle.textContent = `
        .programme[data-start-time]::before, #channel-schedule > div[data-start-time]::before,
        .schedule-item[data-start-time]::before, .schedule-program-item[data-start-time]::before {
            content: '🔔';
            visibility: hidden;
            font-size: 13px;
            padding-right: 8px;
        }
        .tv-bell-ready::before { display: none; }
    `;
    (document.head || document.documentElement).appendChild(bellReserveStyle);

    // Одноразовый MutationObserver — ждёт появления первой строки с data-start-time,
    // сразу вызывает injectBells() и отключается навсегда.
    const READY_SELECTOR = '.programme[data-start-time], #channel-schedule > div[data-start-time], .schedule-item[data-start-time], .schedule-program-item[data-start-time]';
    const bellObserver = new MutationObserver(() => {
        if (document.querySelector(READY_SELECTOR)) {
            bellObserver.disconnect();
            injectBells();
        }
    });

    // Инжектируем перехватчик fetch в контекст страницы на document-start.
    // Ловит: (1) JSON расписания → tv-json-loaded, (2) .ts сегменты → tv-m3u8-found
    const pageInterceptor = document.createElement('script');
    pageInterceptor.textContent = `
        (function() {
            const _orig = window.fetch;
            window.fetch = function(...args) {
                const url = (args[0] || '').toString();
                const promise = _orig.apply(this, args);
                // JSON расписания
                if (url.includes('/json/')) {
                    promise.then(() => window.dispatchEvent(new CustomEvent('tv-json-loaded')));
                }
                // .ts сегменты — восстанавливаем m3u8 URL и шлём на основную страницу
                if (url.includes('tvcdnpotok.com') && url.includes('.ts')) {
                    const m = url.match(/^(https:\\/\\/[^\\/]+\\/[^\\/]+\\/[^\\/]+\\/[^\\/]+)\\//);
                    if (m) {
                        const target = window.top || window;
                        target.dispatchEvent(new CustomEvent('tv-m3u8-found', { detail: m[1] + '/index.m3u8' }));
                    }
                }
                return promise;
            };
            // XHR для .ts
            const _origOpen = XMLHttpRequest.prototype.open;
            XMLHttpRequest.prototype.open = function(method, url, ...rest) {
                if (typeof url === 'string' && url.includes('tvcdnpotok.com') && url.includes('.ts')) {
                    const m = url.match(/^(https:\\/\\/[^\\/]+\\/[^\\/]+\\/[^\\/]+\\/[^\\/]+)\\//);
                    if (m) {
                        const target = window.top || window;
                        target.dispatchEvent(new CustomEvent('tv-m3u8-found', { detail: m[1] + '/index.m3u8' }));
                    }
                }
                return _origOpen.call(this, method, url, ...rest);
            };
        })();
    `;
    (document.head || document.documentElement).appendChild(pageInterceptor);
    pageInterceptor.remove();

    // JSON расписания — вызываем injectBells когда данные пришли
    window.addEventListener('tv-json-loaded', () => {
        let attempts = 0;
        const tryInject = () => {
            if (document.querySelector(READY_SELECTOR)) {
                injectBells();
            } else if (attempts++ < 100) {
                setTimeout(tryInject, 50);
            }
        };
        tryInject();
    });

    GM_registerMenuCommand("📋 Менеджер напоминаний", () => showActiveAlarms());

    let settings = { leadTime: 5 };
    const activeTimeouts = new Map();
    const sessionFired = new Set();
    // Загружаем список отмен
    let userCancelled = GM_getValue('tv_cancelled', {});
    const dayInMs = 24 * 60 * 60 * 1000;
    const nowTime = Date.now();

    // Чистим записи старше 24 часов
    for (let id in userCancelled) {
        if (nowTime - userCancelled[id] > dayInMs) {
            delete userCancelled[id];
        }
    }
    GM_setValue('tv_cancelled', userCancelled);

    // --- ЛОГИКА ОБРАБОТКИ ДАТ (v14.7) ---
    const parseSiteDate = (timeAttr) => {
        if (!timeAttr) return null;
        const y = parseInt(timeAttr.substring(0, 4)),
              mo = parseInt(timeAttr.substring(4, 6)) - 1,
              d = parseInt(timeAttr.substring(6, 8)),
              h = parseInt(timeAttr.substring(8, 10)),
              m = parseInt(timeAttr.substring(10, 12));
        const dt = new Date(y, mo, d, h, m);
        dt.setHours(dt.getHours() + 2);
        return dt;
    };

    function getAlarmDateTime(alarm, id) {
        if (alarm.timestamp) return new Date(alarm.timestamp);
        const parts = id.split('_'), [d, mo, y] = alarm.date.split('.').map(Number), [h, m] = (parts[1] || "00:00").split(':').map(Number);
        return new Date(y, mo - 1, d, h, m);
    }

    // --- ЛОГИКА УВЕДОМЛЕНИЙ (v15.0) ---
    function fire(id, alarm, statusTitle, isFinal = false) {
        const fireKey = id + (alarm.channel || "") + statusTitle;
        if (sessionFired.has(fireKey)) return;

        let alarms = GM_getValue('tv_alarms', {});
        if (!statusTitle.startsWith("УСТАНОВЛЕНО") && !alarms[id]) return;
        if (isFinal && alarms[id]?.firedFinal) return;
        if (statusTitle === "СКОРО В ЭФИРЕ" && alarms[id]?.notifiedPre) return;

        if (statusTitle === "СКОРО В ЭФИРЕ") alarms[id].notifiedPre = true;
        if (isFinal) alarms[id].firedFinal = true;

        GM_setValue('tv_alarms', alarms);
        sessionFired.add(fireKey);
        const timeStr = new Date(alarm.timestamp).toLocaleTimeString('ru-RU', {hour:'2-digit', minute:'2-digit'});

        GM_notification({
            title: statusTitle,
            text: `${timeStr} - ${alarm.title}\n${alarm.channel}`,
            image: alarm.logo,
            highlight: false,
            timeout: isFinal ? 0 : 10000,
            requireInteraction: isFinal,
            onclick: () => {
                GM_openInTab(alarm.url, { active: true, insert: true, setParent: true });
            }
        });

        if (isFinal) {
            const doCleanup = () => {
                let current = GM_getValue('tv_alarms', {});
                if (current[id]) {
                    delete current[id];
                    GM_setValue('tv_alarms', current);
                    window.dispatchEvent(new CustomEvent('tv-mgr-update'));
                }
            };
            if (document.getElementById('tv-mgr-modal')) {
                setTimeout(doCleanup, 10000);
            } else {
                doCleanup();
            }
        }
    }

    function checkMissedEvents() {
        const alarms = GM_getValue('tv_alarms', {});
        const now = Date.now();
        let changed = false;
        for (let id in alarms) {
            if (now > (alarms[id].timestamp + 30000) && !alarms[id].firedFinal) {
                fire(id, alarms[id], "УЖЕ В ЭФИРЕ (ПРОПУЩЕНО)", true);
                changed = true;
            }
        }
        if (changed) window.dispatchEvent(new CustomEvent('tv-mgr-update'));
    }

    function scheduleAlarm(id, alarm) {
        if (activeTimeouts.has(id)) activeTimeouts.get(id).forEach(t => clearTimeout(t));
        activeTimeouts.set(id, []);
        const now = Date.now();
        const preMs = alarm.timestamp - (settings.leadTime * 60000);
        if (preMs > now && !alarm.notifiedPre) {
            activeTimeouts.get(id).push(setTimeout(() => {
                const current = GM_getValue('tv_alarms', {});
                if (current[id] && !current[id].notifiedPre) {
                    fire(id, alarm, "СКОРО В ЭФИРЕ");
                    current[id].notifiedPre = true;
                    GM_setValue('tv_alarms', current);
                }
            }, preMs - now));
        }
        if (alarm.timestamp > now) {
            activeTimeouts.get(id).push(setTimeout(() => fire(id, alarm, "УЖЕ В ЭФИРЕ", true), alarm.timestamp - now));
        }
    }

    // --- ЛОГИКА КОЛОКОЛЬЧИКОВ (v15.3.0 - Persistent Blacklist) ---

    // --- JSON-СКАНЕР (v16.5.0) ---
    // Вычисляем дельту МСК→локальное время автоматически через браузер.
    // Москва всегда UTC+3 (летнее время отменено в 2014г.).
    const mskToLocal = (-new Date().getTimezoneOffset() / 60) - 3; // +2 для UTC+5

    // Парсим время из JSON-формата "20260314230000 +0300" в локальный Date
    const parseJsonDate = (str) => {
        if (!str) return null;
        const s = str.replace(/\s.*/, ''); // убираем " +0300"
        const y = +s.substring(0,4), mo = +s.substring(4,6)-1,
              d = +s.substring(6,8), h = +s.substring(8,10), m = +s.substring(10,12);
        const dt = new Date(y, mo, d, h, m);
        dt.setHours(dt.getHours() + mskToLocal);
        return dt;
    };

    // Строим карту каналов из DOM текущей страницы
    function buildChannelMapFromDOM() {
        const map = {};
        document.querySelectorAll('.channel-cat, .allp_item, .chan-block, .schedule-item-wrap').forEach(container => {
            const nameEl = container.querySelector('.channel-name-cat, .allp_title, .chan-title, .schedule-channel-title');
            if (!nameEl) return;
            const name = nameEl.innerText.trim();
            if (!name || map[name]) return;
            const url = container.querySelector('.channel-link a')?.href || window.location.origin + window.location.pathname;
            let logo = container.querySelector('img')?.getAttribute('src') || '';
            if (logo && !logo.startsWith('http')) logo = window.location.origin + (logo.startsWith('/') ? '' : '/') + logo;
            map[name] = { url, logo };
        });
        // Фолбэк для страниц одного канала
        if (!Object.keys(map).length) {
            const chanName = document.querySelector('h1')?.innerText.split(' смотреть')[0].trim() || "Телеканал";
            const logo = document.querySelector('.img-block img, .chan-logo img')?.getAttribute('src') || "https://smotret-online.tv/templates/sotv/favicon.svg";
            map[chanName] = { url: window.location.href, logo };
        }
        return map;
    }

    // Дополняем карту каналов из HTML страниц-каталогов — для логотипов каналов не на текущей странице
    async function enrichChannelMapFromPages(map) {
        const CATALOG_PAGES = [
            'https://smotret-online.tv/kinozals.html',
            'https://smotret-online.tv/educat.html',
            'https://smotret-online.tv/films.html',
            'https://smotret-online.tv/poznavatelnye-telekanaly.html'
        ];
        const parser = new DOMParser();
        for (const pageUrl of CATALOG_PAGES) {
            try {
                const resp = await fetch(pageUrl);
                if (!resp.ok) continue;
                const html = await resp.text();
                const doc = parser.parseFromString(html, 'text/html');
                doc.querySelectorAll('.channel-cat, .allp_item, .chan-block, .schedule-item-wrap').forEach(container => {
                    const nameEl = container.querySelector('.channel-name-cat, .allp_title, .chan-title, .schedule-channel-title');
                    if (!nameEl) return;
                    const name = nameEl.innerText.trim();
                    if (!name || map[name]) return; // не перезаписываем уже найденные
                    const url = container.querySelector('.channel-link a')?.href || pageUrl;
                    let logo = container.querySelector('img')?.getAttribute('src') || '';
                    if (logo && !logo.startsWith('http')) logo = 'https://smotret-online.tv' + (logo.startsWith('/') ? '' : '/') + logo;
                    if (logo) map[name] = { url, logo };
                });
                console.log(`[TV] Логотипы из ${pageUrl.split('/').pop()}: карта теперь ${Object.keys(map).length} каналов`);
            } catch(e) {
                console.log(`[TV] Не удалось загрузить ${pageUrl.split('/').pop()}:`, e.message);
            }
        }
        return map;
    }

    // Сканируем JSON расписания на предмет совпадений с autoWatchList.
    // Запускается один раз при старте страницы.
    async function scanJsonSchedule(watchList) {
        const JSON_URLS = [
            'https://smotret-online.tv/json/educat/selected_channels_educat.json',
            'https://smotret-online.tv/json/kinozals/kinozals_channels.json',
            'https://smotret-online.tv/json/films/selected_channels_films.json',
            'https://smotret-online.tv/json/epgtt/search_channels.json'
        ];

        let allData = {};
        for (const url of JSON_URLS) {
            try {
                const resp = await fetch(url);
                const data = await resp.json();
                Object.assign(allData, data);
                console.log(`[TV] JSON загружен: ${url.split('/').pop()}, каналов: ${Object.keys(data).length}`);
            } catch(e) {
                console.log('[TV] Ошибка загрузки', url.split('/').pop(), e.message);
            }
        }
        console.log('[TV] Всего каналов для сканирования:', Object.keys(allData).length);

        // Строим полную карту: DOM текущей страницы + HTML каталогов
        let channelMap = buildChannelMapFromDOM();
        channelMap = await enrichChannelMapFromPages(channelMap);

        const now = Date.now();
        let alarms = GM_getValue('tv_alarms', {});
        let notifyIndex = 0;

        for (const [displayName, chData] of Object.entries(allData)) {
            for (const prog of (chData.programmes || [])) {
                const title = (prog.title || '').trim();
                const isTarget = watchList.some(w => title.toLowerCase().includes(w.toLowerCase()));
                if (!isTarget) continue;

                const startDate = parseJsonDate(prog.start);
                if (!startDate || startDate.getTime() <= now) continue;

                const timePart = startDate.toLocaleTimeString('ru-RU', {hour:'2-digit', minute:'2-digit'});
                const showId = `${startDate.getDate()}_${timePart}_${title}`;

                if (alarms[showId] || userCancelled[showId]) continue;

                // Ищем канал: точное совпадение, потом нечёткое
                const displayNameLower = displayName.toLowerCase();
                let ch = channelMap[displayName];
                if (!ch) {
                    const fuzzyKey = Object.keys(channelMap).find(k =>
                                                                  k.toLowerCase().includes(displayNameLower) || displayNameLower.includes(k.toLowerCase())
                                                                 );
                    ch = fuzzyKey ? channelMap[fuzzyKey] : null;
                }
                const resolvedCh = ch || {
                    url: window.location.origin,
                    logo: 'https://smotret-online.tv/templates/sotv/favicon.svg'
                };

                const newAlarm = {
                    channel: displayName, logo: resolvedCh.logo, title,
                    url: resolvedCh.url, notifiedPre: false, firedFinal: false,
                    timestamp: startDate.getTime(), date: startDate.toLocaleDateString('ru-RU')
                };
                alarms[showId] = newAlarm;
                GM_setValue('tv_alarms', alarms);
                scheduleAlarm(showId, newAlarm);

                // 3500мс между уведомлениями — Windows буферизует очередь, нужно давать время на отображение
                const delay = notifyIndex * 3500;
                const alarmSnap = { ...newAlarm };
                const idSnap = showId;
                setTimeout(() => fire(idSnap, alarmSnap, "УСТАНОВЛЕНО (АВТО)"), delay);
                notifyIndex++;

                console.log(`[TV] → ${showId} | лого: ${resolvedCh.logo.split('/').pop()}`);
            }
        }
        if (notifyIndex) window.dispatchEvent(new CustomEvent('tv-mgr-update'));
        console.log(`[TV] scanJsonSchedule завершён: найдено ${notifyIndex} совпадений`);
    }

    function injectBells() {
        checkMissedEvents();

        const rows = document.querySelectorAll('.programme, #channel-schedule > div, .schedule-item, .schedule-program-item');
        const currentAlarms = GM_getValue('tv_alarms', {});
        const now = Date.now();

        rows.forEach(row => {
            const timeAttr = row.getAttribute('data-start-time') || row.closest('[data-start-time]')?.getAttribute('data-start-time');
            const exactDate = parseSiteDate(timeAttr);
            if (!exactDate) return;

            const hasProgress = row.querySelector('.current-progress, .progress, .progress-bar, .progress-fill');
            const isActive = row.classList.contains('active') || row.classList.contains('current');
            const isPastTime = exactDate.getTime() <= now;

            if (hasProgress || isActive || isPastTime) {
                row.querySelector('.tv-bell')?.remove();
                row.classList.add('tv-bell-ready'); // убираем псевдоэлемент-заглушку
                return;
            }

            const timePart = exactDate.toLocaleTimeString('ru-RU', {hour: '2-digit', minute:'2-digit'});
            let titlePart = row.innerText.replace(/\d{2}:\d{2}/, '').replace(/🔔/g, '').trim().split('\n')[0];
            const showId = `${exactDate.getDate()}_${timePart}_${titlePart}`;

            let bell = row.querySelector('.tv-bell');
            if (!bell) {
                bell = document.createElement('span');
                bell.className = 'tv-bell';
                bell.innerHTML = '🔔';
                bell.style.cssText = `cursor:pointer; padding-right:8px; font-size:13px; transition: 0.2s; user-select:none;`;
                row.prepend(bell);
                row.classList.add('tv-bell-ready');

                const toggleAlarm = (isAuto = false) => {
                    let alarms = GM_getValue('tv_alarms', {});
                    if (alarms[showId]) {
                        // --- УДАЛЕНИЕ БУДИЛЬНИКА ---
                        delete alarms[showId];
                        if (activeTimeouts.has(showId)) activeTimeouts.get(showId).forEach(t => clearTimeout(t));

                        // Если выключил вручную — добавляем в черный список на 24ч
                        if (!isAuto) {
                            userCancelled[showId] = Date.now();
                            GM_setValue('tv_cancelled', userCancelled);
                        }
                    } else {
                        // --- УСТАНОВКА БУДИЛЬНИКА ---
                        const container = row.closest('.channel-cat, .allp_item, .chan-block, .schedule-item-wrap');
                        let chanUrl = container?.querySelector('.channel-link a')?.href || window.location.origin + window.location.pathname;
                        let chanName = container?.querySelector('.channel-name-cat, .allp_title, .chan-title, .schedule-channel-title')?.innerText.trim()
                        || document.querySelector('h1')?.innerText.split(' смотреть')[0].trim() || "Телеканал";
                        let img = container?.querySelector('img') || document.querySelector('.img-block img') || document.querySelector('.chan-logo img');
                        let logoUrl = img ? img.getAttribute('src') : "https://smotret-online.tv/templates/sotv/favicon.svg";
                        if (logoUrl && !logoUrl.startsWith('http')) logoUrl = window.location.origin + (logoUrl.startsWith('/') ? '' : '/') + logoUrl;

                        const newAlarm = { channel: chanName, logo: logoUrl, title: titlePart, url: chanUrl, notifiedPre: false, firedFinal: false, timestamp: exactDate.getTime(), date: exactDate.toLocaleDateString('ru-RU') };
                        alarms[showId] = newAlarm;

                        // Если включил вручную — убираем из черного списка (вдруг передумал)
                        if (!isAuto && userCancelled[showId]) {
                            delete userCancelled[showId];
                            GM_setValue('tv_cancelled', userCancelled);
                        }

                        GM_setValue('tv_alarms', alarms);
                        scheduleAlarm(showId, newAlarm);
                        fire(showId, newAlarm, isAuto ? "УСТАНОВЛЕНО (АВТО)" : "УСТАНОВЛЕНО");
                    }
                    GM_setValue('tv_alarms', alarms);
                    window.dispatchEvent(new CustomEvent('tv-mgr-update'));
                };

                bell.onclick = (e) => {
                    e.preventDefault(); e.stopPropagation();
                    toggleAlarm(false);
                };
            }
            bell.style.filter = currentAlarms[showId] ? 'none' : 'grayscale(1)';
            bell.style.opacity = currentAlarms[showId] ? '1' : '0.4';
        });
    }

    // --- МЕНЕДЖЕР (v15.0 - NO BLUR/NO TRANSPARENCY) ---
    function showActiveAlarms() {
        if (document.getElementById('tv-mgr-modal')) return;

        const MGR_STYLE = `
            #tv-mgr-modal {
                --bg-main: rgb(33, 35, 35, 0.85); /* Убрана прозрачность */
                --bg-card: rgb(40, 42, 42);
                --header-edge: rgb(28, 29, 31);
                --header-center: rgb(29, 33, 36, 0.85); /* Убрана прозрачность */
                --bg-button: rgb(45, 47, 47);
                --accent-color: #60cdff;
                --text-main: #ffffff;
                --text-dim: rgba(255, 255, 255, 0.5);
                --border-color: rgba(255, 255, 255, 0.1);
                --radius-window: 10px;
                --radius-item: 6px;
                --hover-bg: rgba(255, 255, 255, 0.07);
                --hover-bg-button: #60cdff;
            }
            #tv-mgr-modal {
                position: fixed; z-index: 999999;
                background: var(--bg-main);
                backdrop-filter: blur(50px) saturate(150%);
                -webkit-backdrop-filter: blur(50px) saturate(150%);
                border-radius: var(--radius-window);
                box-shadow: 0 10px 40px rgba(0, 0, 0, 0.6);
                border: 1px solid var(--border-color);
                width: 540px; height: 650px;
                display: flex; flex-direction: column;
                font-family: "Segoe UI Variable Display", "Segoe UI", sans-serif;
                color: var(--text-main); resize: both; overflow:hidden;
            }
            .tv-mgr-header {
                display:flex; justify-content:space-between; align-items:center;
                height:38px; cursor:move; user-select:none; flex-shrink:0;
                background: linear-gradient(90deg, var(--header-edge) 0%, var(--header-center) 50%, var(--header-edge) 100%);
            }
            .tv-mgr-content { flex-grow:1; overflow-y:auto; padding:10px 0; }
            .tv-mgr-footer { padding:14px; background: var(--bg-main); border-top: 1px solid var(--border-color); display:flex; gap:10px; }
            .tv-mgr-date-header {
                margin: 4px 10px 8px; padding: 10px 16px;
                background: var(--bg-card);
                border-left: 2.5px solid var(--accent-color);
                border-radius: 4px;
                color: var(--text-main);
                font-size: 14px; font-weight: 500;
            }
            /* Основной контейнер карточки (оставляем обязательно) */
            .tv-mgr-item {
                display:grid; grid-template-columns: 70px 80px 1fr 40px;
                align-items:center; margin: 2px 10px; padding:6px 0;
                border-radius: var(--radius-item); cursor:pointer;
                transition: background 0.1s;
                position: relative;
                overflow: hidden;
            }

            /* --- НАЧАЛО ЗАМЕНЫ --- */
            /* Левая полоска */
            .tv-mgr-item::before {
                content: "";
                position: absolute;
                left: 0;
                top: 50%;
                transform: translateY(-50%);
                width: 3px;
                height: 0;
                background-color: var(--accent-color);
                border-radius: 0 2px 2px 0;
                transition: height 0.1s ease-in;
            }

            /* Правая полоска */
            .tv-mgr-item::after {
                content: "";
                position: absolute;
                right: 0;
                top: 50%;
                transform: translateY(-50%);
                width: 3px;
                height: 0;
                background-color: var(--accent-color);
                border-radius: 2px 0 0 2px;
                transition: height 0.1s ease-in;
            }

            /* Эффект при наведении (Фон и анимация обеих полосок) */
            .tv-mgr-item:hover {
                background: var(--hover-bg);
            }

            .tv-mgr-item:hover::before,
            .tv-mgr-item:hover::after {
                height: 40%;
                transition: height 0.4s cubic-bezier(0.1, 0.9, 0.2, 1);
            }
            /* --- КОНЕЦ ЗАМЕНЫ --- */

            .tv-mgr-logo-box {
                width:48px; height:48px; margin-left:12px;
                background: var(--bg-card); border-radius: var(--radius-item);
                display:flex; align-items:center; justify-content:center;
                overflow:hidden; border: 1px solid var(--border-color);
            }
            .tv-mgr-time { color: var(--text-main); font-size:15px; font-weight:600; text-align:center; }
            .tv-mgr-title { font-size:15px; color: #efefef; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
            .tv-mgr-chan-name { font-size:12px; color: var(--text-dim); }
            .win-btn {
                width:46px; height:38px; display:flex; align-items:center; justify-content:center;
                cursor:pointer; font-family:'Segoe MDL2 Assets'; color: var(--text-dim);
                transition: background 0.1s;
            }
            .win-btn:hover { background: var(--hover-bg); color: var(--text-main); }
            .close-btn:hover { background:#e81123 !important; color:#fff !important; }
            .win-btn span { display: flex; align-items: center; justify-content: center; transition: transform 0.1s ease; }
            .win-btn:active span { transform: scale(0.75); }
            .footer-btn {
                flex:1; padding:10px; background: var(--bg-button);
                color: var(--text-main); border: 1px solid var(--border-color);
                border-radius: var(--radius-item); cursor:pointer; font-size:13px;
                transition: background 0.2s, transform 0.1s;
            }
            .footer-btn:hover { background: var(--hover-bg-button); color: black; }
            .footer-btn:active { transform: scale(0.97); }
            .mgr-del-btn {
                background:none; border:none; color: var(--text-dim);
                cursor:pointer; font-size:20px; transition: 0.2s;
                display: flex; align-items: center; justify-content: center;
            }
            .mgr-del-btn:hover { color:#ff5f5f !important; transform: scale(1.2); }
        `;
        const styleTag = document.createElement('style');
        styleTag.id = 'tv-mgr-styles';
        styleTag.textContent = MGR_STYLE;
        document.head.appendChild(styleTag);

        const modal = document.createElement('div');
        modal.id = 'tv-mgr-modal';
        modal.style.left = `${window.innerWidth / 2 - 270}px`;
        modal.style.top = `${window.innerHeight / 2 - 325}px`;

        modal.innerHTML = `
            <div class="tv-mgr-header" id="tv-mgr-handle">
                <div style="display:flex; align-items: center; height: 38px; pointer-events:none; padding-left:10px;">
                    <span style="font-size:18px; margin-right:8px;">🕒</span>
                    <span style="font-size: 13px; color: rgba(255, 255, 255, 0.9);">Менеджер Напоминаний</span>
                </div>
                <div style="display:flex; height:38px;">
                    <div id="mgr-refresh" class="win-btn" title="Обновить"><span></span></div>
                    <div id="mgr-x-close" class="win-btn close-btn"><span></span></div>
                </div>
            </div>
            <div id="tv-mgr-content" class="tv-mgr-content"></div>
            <div class="tv-mgr-footer">
                <button id="mgr-clear-all" class="footer-btn" title="Shift + Клик для полной очистки">Очистить</button>
                <button id="mgr-close" class="footer-btn">Закрыть</button>
            </div>`;

        document.body.appendChild(modal);
        const content = modal.querySelector('#tv-mgr-content');

        const updateContent = () => {
            const alarms = GM_getValue('tv_alarms', {});
            const keys = Object.keys(alarms).sort((a, b) => getAlarmDateTime(alarms[a], a) - getAlarmDateTime(alarms[b], b));
            let html = keys.length === 0 ? '<p style="text-align:center; color:#666; margin-top:250px;">Список пуст</p>' : '';
            let lastHeader = null;
            keys.forEach(id => {
                const alarm = alarms[id];
                const dt = getAlarmDateTime(alarm, id);
                const datePart = dt.toLocaleDateString('ru-RU', { day: 'numeric', month: 'long', year: 'numeric' }).replace(' г.', '');
                let dayName = dt.toLocaleDateString('ru-RU', { weekday: 'long' });
                dayName = dayName.charAt(0).toUpperCase() + dayName.slice(1);
                let fullHeader = `${datePart}, ${dayName}`;
                if (fullHeader !== lastHeader) { html += `<div class="tv-mgr-date-header">${fullHeader}</div>`; lastHeader = fullHeader; }
                html += `
                <div class="tv-mgr-item" data-url="${alarm.url}">
                    <div class="tv-mgr-logo-box"><img src="${alarm.logo}" style="max-width:85%; max-height:85%; object-fit:contain;"></div>
                    <span class="tv-mgr-time">${dt.toLocaleTimeString('ru-RU', {hour:'2-digit', minute:'2-digit'})}</span>
                    <div style="display:flex; flex-direction:column; padding-left:12px; overflow:hidden;">
                        <span class="tv-mgr-title">${alarm.title}</span>
                        <span class="tv-mgr-chan-name">${alarm.channel}</span>
                    </div>
                    <button class="mgr-del-btn" data-id="${id}">&times;</button>
                </div>`;
            });
            content.innerHTML = html;
        };

        updateContent();
        const updateHandler = () => updateContent();
        window.addEventListener('tv-mgr-update', updateHandler);

        modal.onclick = (e) => {
            const delBtn = e.target.closest('.mgr-del-btn');
            const itemRow = e.target.closest('.tv-mgr-item');

            if (delBtn) {
                const id = delBtn.getAttribute('data-id');
                let current = GM_getValue('tv_alarms', {});

                // Добавляем в черный список, чтобы авто-клик не восстановил это при перезагрузке
                userCancelled[id] = Date.now();
                GM_setValue('tv_cancelled', userCancelled);

                delete current[id];
                GM_setValue('tv_alarms', current);
                updateContent();
                return;
            }

            if (e.target.closest('#mgr-refresh')) {
                checkMissedEvents();
                updateContent();
                return;
            }

            if (itemRow) {
                GM_openInTab(itemRow.getAttribute('data-url'), { active: true });
                return;
            }

            if (e.target.id === 'mgr-clear-all') {
                const isFullReset = e.shiftKey; // Проверяем, зажат ли Shift
                const msg = isFullReset
                ? "ПОЛНЫЙ СБРОС: Удалить все напоминания и ОЧИСТИТЬ черный список?"
                : "Очистить список напоминаний? (Shift+Click для полной очистки)";

                if (confirm(msg)) {
                    if (isFullReset) {
                        // Полная очистка
                        GM_setValue('tv_alarms', {});
                        GM_setValue('tv_cancelled', {});
                        userCancelled = {};
                        console.log("TV Script: Полный сброс выполнен");
                    } else {
                        // Обычная очистка (перенос текущих в бан-лист)
                        let current = GM_getValue('tv_alarms', {});
                        for (let id in current) {
                            userCancelled[id] = Date.now();
                        }
                        GM_setValue('tv_cancelled', userCancelled);
                        GM_setValue('tv_alarms', {});
                    }
                    updateContent();
                }
            }

            if (e.target.closest('#mgr-x-close') || e.target.id === 'mgr-close') {
                window.removeEventListener('tv-mgr-update', updateHandler);
                modal.remove();
                document.getElementById('tv-mgr-styles')?.remove();
            }
        };

        const handle = modal.querySelector('#tv-mgr-handle');
        handle.onmousedown = (e) => {
            if (e.target.closest('.win-btn')) return;
            e.preventDefault();
            const sX = e.clientX - modal.offsetLeft, sY = e.clientY - modal.offsetTop;
            const onMouseMove = (ev) => {
                modal.style.left = (ev.clientX - sX) + "px";
                modal.style.top = (ev.clientY - sY) + "px";
            };
            const onMouseUp = () => {
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
            };
            document.addEventListener('mousemove', onMouseMove);
            document.addEventListener('mouseup', onMouseUp);
        };
    }

    const alarms = GM_getValue('tv_alarms', {});
    const now = Date.now();
    for (let id in alarms) {
        if (alarms[id].timestamp > now - 600000) scheduleAlarm(id, alarms[id]);
        else delete alarms[id];
    }
    GM_setValue('tv_alarms', alarms);

    bellObserver.observe(document.documentElement, { childList: true, subtree: true });
    setInterval(injectBells, 5000); // страховка на случай если observer пропустил
    window.addEventListener('openTVManager', () => showActiveAlarms());

    // Запускаем JSON-сканер один раз при старте страницы
    const AUTO_WATCH_LIST = ["Назад в будущее", "Пираты Карибского моря", "Звезды ломбарда", "Мальчишник"];
    scanJsonSchedule(AUTO_WATCH_LIST);
})();