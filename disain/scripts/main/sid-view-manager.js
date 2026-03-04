jQuery(function ($) {
    'use strict';

    (function () {
        const mainEl = $('[data-smart-id-login-form]');
        if (mainEl.length === 0) {
            return;
        }
        showEl(mainEl);
        const enabledFlows = getEnabledFlows();
        const primaryFlow = getPrimaryFlow(enabledFlows);
        const secondaryFlows = enabledFlows.filter(function (flow) {
            return flow !== primaryFlow;
        });

        const initViewComponents = [`primary-${primaryFlow}`];
        if (secondaryFlows.length > 0) {
            initViewComponents.push('secondaries');
            for (const secondaryFlow of secondaryFlows) {
                initViewComponents.push(`secondary-${secondaryFlow}`);
            }
        }

        setView(mainEl, 'init');
        setComponents(mainEl, 'init', initViewComponents);
        setClickHandler(mainEl, 'init-notificationBased', function () {
            setView(mainEl, 'init-notificationBased');
        });
        setClickHandler(mainEl, 'back', function () {
            setView(mainEl, 'init');
        });
    }());

    function setView(mainEl, viewName) {
        var viewEls = getViewElsByName(mainEl);
        for(const el of Object.values(viewEls)) {
            hideEl(el);
        }
        showEl(viewEls[viewName]);
    }

    function getViewElsByName(mainEl) {
        const els = mainEl.find('[data-smart-id-login-form-view]');
        const result = {};
        els.each(function () {
            result[$(this).attr('data-smart-id-login-form-view')] = $(this);
        });
        return result;
    }

    function setComponents(mainEl, viewName, componentNames) {
        const viewEl = getViewElsByName(mainEl)[viewName];
        const els = viewEl.find('[data-smart-id-login-form-component]');
        els.each(function () {
            let currentComponentName = $(this).attr('data-smart-id-login-form-component');
            if (componentNames.includes(currentComponentName)) {
                showEl($(this));
            } else {
                hideEl($(this));
            }
        });
    }

    function setClickHandler(mainEl, action, handler) {
        mainEl.find(`[data-smart-id-login-form-action="${action}"]`).on('click', handler);
    }

    function getEnabledFlows() {
        const enabledAuthMethodsElement = document.getElementById('enabled-auth-methods');
        if(enabledAuthMethodsElement == null) {
            throw new Error('`#enabled-auth-methods` not present.');
        }
        const enabledAuthMethods = JSON.parse(enabledAuthMethodsElement.textContent);
        if (enabledAuthMethods.smartId !== true) {
            return [];
        }
        const enabledFlows = enabledAuthMethods.smartIdFlows;
        if (!supportsSmartIdApp()) {
            enabledFlows.web2app = false;
        }
        return Object.entries(enabledFlows)
            .filter(function([_, enabled]) {
                return enabled;
            })
            .map(function([flowName, _]) {
                return flowName;
            });
    }

    function getPrimaryFlow(enabledFlows) {
        if (enabledFlows.includes('web2app')) {
            return 'web2app';
        }
        if (enabledFlows.includes('qrCode')) {
            return 'qrCode';
        }
        return 'notificationBased';
    }

    function hideEl(el) {
        el.addClass('hidden');
        el.attr('aria-hidden', 'true');
    }

    function showEl(el) {
        el.removeAttr('aria-hidden');
        el.removeClass('hidden');
    }

});
