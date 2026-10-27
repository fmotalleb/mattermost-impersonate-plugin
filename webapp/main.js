/* Admin Impersonation UI — no third-party JavaScript dependencies.
 * Backend session tokens remain HttpOnly and are never handled in this file. */
(function () {
    'use strict';
    var PLUGIN_ID = 'com.fmotalleb.impersonate';

    function ImpersonationPlugin() {
        this.timer = null;
        this.banner = null;
    }

    ImpersonationPlugin.prototype.initialize = function (registry, store) {
        var self = this;
        var config = (((store.getState() || {}).entities || {}).general || {}).config || {};
        var site;
        try { site = new URL(config.SiteURL || window.location.origin); }
        catch (e) { site = new URL(window.location.origin); }
        var path = site.pathname.replace(/\/$/, '') + '/plugins/' + PLUGIN_ID;
        var myBase = path;

        // This main-menu shortcut does not grant permissions; the backend enforces system_admin.
        // Add only when the current user is known to be a system admin.
        var menuAdded = false;
        var unsubscribe = null;
        function ensureMenu() {
            if (menuAdded) { return; }
            var state = store.getState() || {};
            var users = ((state.entities || {}).users || {});
            var user = ((users.profiles || {})[users.currentUserId] || {});
            if (user.roles && user.roles.split(' ').indexOf('system_admin') !== -1) {
                registry.registerMainMenuAction('Impersonate user', function () {
                    window.location.assign(myBase + '/');
                });
                menuAdded = true;
                if (unsubscribe) { unsubscribe(); unsubscribe = null; }
            }
        }
        ensureMenu();
        if (!menuAdded) { unsubscribe = store.subscribe(ensureMenu); }
        this.unsubscribe = function () { if (unsubscribe) { unsubscribe(); } };

        function clearBanner() {
            if (self.banner) { self.banner.remove(); self.banner = null; }
        }
        function showBanner(data) {
            var bar = self.banner;
            if (!bar) {
                bar = document.createElement('div');
                bar.setAttribute('role', 'status');
                bar.style.cssText = 'position:fixed;left:0;right:0;top:0;z-index:2147483000;'+
                    'background:#742c08;color:#fff;display:flex;align-items:center;justify-content:center;'+
                    'gap:18px;padding:10px 15px;font:600 14px system-ui,sans-serif;box-shadow:0 2px 8px #3336';
                var label = document.createElement('span');
                label.className = 'mm-impersonation-label';
                var stop = document.createElement('a');
                stop.textContent = 'Stop impersonation';
                stop.href = myBase + '/session';
                stop.style.cssText = 'color:#fff;text-decoration:underline';
                bar.appendChild(label);
                bar.appendChild(stop);
                document.body.appendChild(bar);
                self.banner = bar;
            }
            bar.querySelector('.mm-impersonation-label').textContent =
                'IMPERSONATING @' + data.target + ' — admin @' + data.actor;
        }
        function check() {
            fetch(myBase + '/status', {credentials: 'same-origin', cache: 'no-store'})
                .then(function (response) {
                    if (!response.ok) { throw new Error('not authenticated'); }
                    return response.json();
                })
                .then(function (data) {
                    if (data.active) { showBanner(data); }
                    else { clearBanner(); }
                })
                .catch(clearBanner);
        }
        check();
        this.timer = window.setInterval(check, 15000);
    };

    ImpersonationPlugin.prototype.uninitialize = function () {
        if (this.timer) { window.clearInterval(this.timer); }
        if (this.unsubscribe) { this.unsubscribe(); }
        if (this.banner) { this.banner.remove(); }
    };

    window.registerPlugin(PLUGIN_ID, new ImpersonationPlugin());
}());
