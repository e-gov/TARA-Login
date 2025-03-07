jQuery(function ($) {
	'use strict';

    var clientLogoSrc = $('#client-logo').attr('src');
    if (clientLogoSrc) {
        $('#client-logo-wait').attr('src', clientLogoSrc);
    }

	// Hide nav bar in desktop mode and display authentication method content in mobile mode if less than 2 auth methods
	if ($('.c-tab-login__nav-link').length < 2) {
		$('.c-tab-login__header').addClass('hide-in-desktop');
        $('body').addClass('is-mobile-subview');
        $('.c-tab-login__nav-item').addClass('is-active');
	}

	// Show auth methods in mobile view, if we think the user is actually using a mobile device, keep ID-card hidden
	$('.c-tab-login__nav-item').each(function() {
		const linkElement = $(this).find('.c-tab-login__nav-link');
		const tabId = linkElement.attr('data-tab');
		if (tabId === 'id-card' && isProbablyMobileDevice()) {
			return;
		}
		$(this).removeClass('hide-on-mobile');
	})

	// Activate previously selected or first auth method
    try {

        // In some cases exception could be thrown while accessing localStorage, see https://github.com/Modernizr/Modernizr/blob/v3.11.6/feature-detects/storage/localstorage.js
        var active = localStorage.getItem('active-tab', active);

        if (!active || !/^[a-z]{2,10}-[a-z]{2,10}$/.test(active)) throw 2;

        if ($('.c-tab-login__nav-link[data-tab="' + active + '"]').length !== 1)
            throw 3;

        activateTab($('.c-tab-login__nav-link[data-tab="' + active + '"]'), $('.c-tab-login__content[data-tab="' + active + '"]'), $('.c-tab-login__warning[data-tab="' + active + '"]'));
    } catch (e) {
        activateTab($('.c-tab-login__nav-link').first(), $('.c-tab-login__content').first(), $('.c-tab-login__warning').first());
    }

	// Tab nav
	$(document).on('click', '.c-tab-login__nav-link', function(event){
		event.preventDefault();

		var docwidth = $(document).width();
		var active = $(this).data('tab');

		// Clear alert and feedback messages
		hideAlert($('.c-tab-login__content[data-tab="' + active + '"] [role="alert"]'));
		hideFeedback($('.c-tab-login__content[data-tab="' + active + '"] .invalid-feedback'));
		hideFeedback($('.c-tab-login__content[data-tab="' + active + '"] .invalid-feedback-warning'));
		$('.c-tab-login__content[data-tab="' + active + '"] .input-group').removeClass('is-invalid');
		$('.c-tab-login__content[data-tab="' + active + '"] .ts-input').removeClass('is-invalid');

		$('.c-tab-login__nav-item').removeClass('is-active');
		deActivateTab($('.c-tab-login__nav-link'), $('.c-tab-login__content'), $('.c-tab-login__warning'));

        activateTab($(this), $('.c-tab-login__content[data-tab="' + active + '"]'), $('.c-tab-login__warning[data-tab="' + active + '"]'));
		try {
            // In some cases exception could be thrown while accessing localStorage, see https://github.com/Modernizr/Modernizr/blob/v3.11.6/feature-detects/storage/localstorage.js
            localStorage.setItem('active-tab', active);
        } catch (e) {
        }

		$('body').removeClass('is-mobile-subview');
		if (docwidth <= 800 ) {
			$('body').addClass('is-mobile-subview');
			$(this).parent().addClass('is-active');
		}

		$('.c-tab-login__content[data-tab="' + active + '"]').find('.c-tab-login__content-wrap').first().attr('tabindex',-1).focus();
	});

	$(document).on('click', '#error-report-url', function(event){
	    var errorReportUrl = $('#error-report-url');
	    var errorReportNotification = $('#error-report-notification');
	    var processedErrorReportUrl = errorReportUrl.attr('href');
	    var processedErrorReportNotification = errorReportNotification.text();

        processedErrorReportUrl = processedErrorReportUrl.replace('(3)', getCurrentOperatingSystem())
        processedErrorReportUrl = processedErrorReportUrl.replace('(4)', getCurrentBrowser())
        processedErrorReportUrl = processedErrorReportUrl.replace('(5)', window.location.host)
        processedErrorReportNotification = processedErrorReportNotification.replace('{2}', window.location.host)

        errorReportUrl.attr('href', processedErrorReportUrl);
        errorReportNotification.text(processedErrorReportNotification);
        $('#error-report-notification').removeClass('hidden');
	});

	// Mobile back link
	$(document).on('click', '.c-tab-login__nav-back-link', function (event) {
		event.preventDefault();

		$('body').removeClass('is-mobile-subview');
		$('.c-tab-login__nav-item').removeClass('is-active');

	});

	// Country select
	if ($('#country-select').length){
		// Note that when updating tom-select, you have to convert tom-select.base.js from ecmascript-6 to ecmascript-5 for gulp compatibility and comment out the preventDefault(e) method under KEY_TAB settings to use regular tab behaviour.
        new TomSelect('#country-select',{
            onChange:function(){
                // Removes the placeholder text when a country has been selected and a placeholder exists. Also sets the input width to 0 so it wouldn't create a new line on narrow screens.
                if ($('#country-select-tomselected').is('[placeholder]')) {
                    $('#country-select-tomselected').removeAttr('placeholder');
                    $('#country-select-tomselected').css({'width':0, 'min-width':0});
                }
                // Places focus on the button that confirms country code choice after choosing your country. Otherwise the screenreader focus is placed at the top of the page.
                $('#confirmCountryChoice')[0].focus();
            },
            sortField: {
                field: 'text',
                direction: 'asc'
            },
            render:{
                // Removes the 'no results found' default message when using the search function.
                no_results:function(data,escape){
                    return '';
                }
            }
        });
	}
	
	function validateEstonianIdCode(field) {
		let value = field.val();
		if (value.length < 11) {
			displayFormFieldError(field, "personal-code-short");
			return false;
		} else if (!(/^[0-9]{11}$/.test(value))) {
			displayFormFieldError(field, "personal-code-invalid");
			return false;
		}
		clearFormFieldErrors(field)
		return true;
	}

	function validateEstonianPhoneNumber(field) {
		let value = field.val().replace(/\s+/g, '');
		if (value.length < 3) {
			displayFormFieldError(field, "phone-number-short");
			return false;
		} else if (!(/^[0-9]{3,15}$/.test(value))) {
			displayFormFieldError(field, "phone-number-invalid");
			return false;
		}
		clearFormFieldErrors(field)
		return true;
	}

	function clearFormFieldErrors(field) {
		field.removeClass('is-invalid');
		field.removeAttr('aria-invalid');
		field.parent('.input-group').removeClass('is-invalid');
		hideFeedback(field.parents('td').children('.invalid-feedback'));
		hideFeedback(field.siblings('.input-group-append').children('.invalid-feedback-warning'));
	}

	function displayFormFieldError(field, errorElementClass) {
		const errorId = errorElementClass + '-error';
		field.addClass('is-invalid')
		.attr({
			'aria-invalid': 'true',
			'aria-describedby': errorId
		});
		field.parent('.input-group').addClass('is-invalid');

		field.parents('td').children('.invalid-feedback').each(function() {
			if ($(this).hasClass(errorElementClass)) {
				showFeedback($(this), errorId);
				showFeedback(field.siblings('.input-group-append').children('.invalid-feedback-warning'));
				// Refresh text for screen reader to read out message
				$(this).html($(this).html());
			} else {
				hideFeedback($(this));
			}
		});
	}
	
	function validateSelectizeValue(selection, testFunc) {
		if (testFunc(selection.val())) {
			selection.parent('td').find('.ts-input').removeClass('is-invalid');
			hideFeedback(selection.parent('td').children('div.invalid-feedback'));
			return true;
		} else {
			selection.parent('td').find('.ts-input').addClass('is-invalid');
			var feedbackDiv = selection.parent('td').children('div.invalid-feedback');
			showFeedback(feedbackDiv);
			// Refresh text for screen reader to read out message
            feedbackDiv.html(feedbackDiv.html());
			return false;
		}
	}

	// ID-card form submit
	$('#idCardForm button.c-btn--primary').on('click', async function(event) {
		const csrfToken = document.querySelector("input[name='_csrf']").getAttribute('value');

		activateIdCardView('waitPopup');

		const webEidStatusPromise = detectWebEid();
		const nonceResponse = await fetchJson('/auth/id/init', {
			method: 'POST',
			headers: {
				'Accept': 'application/json',
				'X-CSRF-TOKEN': csrfToken
			}
		});
		if (!nonceResponse) {
			return;
		}
		// We are checking Web eID status in parallel with /auth/id/init request to reduce the total time the user
		// has to wait in a successful case. It might make the failure case of Web eID status check a bit slower,
		// though, as we will wait for both results before checking them, for the ease of error handling.
		const webEidInfo = await webEidStatusPromise;
		if (webEidInfo.code !== 'SUCCESS') {
			await handleWebEidJsError(csrfToken, webEidInfo);
			return;
		}
		const lang = document.documentElement.lang;
		let authToken;
		try {
			authToken = await webeid.authenticate(nonceResponse.nonce, {lang});
		} catch (error) {
			if (error.code === 'ERR_WEBEID_USER_CANCELLED') {
				activateIdCardView('form')
			} else {
				webEidInfo.code = error.code;
				await handleWebEidJsError(csrfToken, webEidInfo);
			}
			return;
		}

		activateIdCardView('waitLogin');
		const authTokenResponse = await fetchJson('/auth/id/login', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json',
				'X-CSRF-TOKEN': csrfToken
			},
			body: JSON.stringify({
				authToken: authToken,
				statusDurationMs: webEidInfo.statusDurationMs,
				extensionVersion: webEidInfo.extensionVersion,
				nativeAppVersion: webEidInfo.nativeAppVersion
			})
		});
		if (authTokenResponse) {
			$('#idCardForm').submit();
		}
	});

	async function fetchJson(resource, options = {}) {
		const { timeoutMs = 20000 } = options;
		const abortController = new AbortController();
		const timerId = setTimeout(() => abortController.abort(), timeoutMs);
		try {
			const response = await fetch(resource, {
				...options,
				signal: abortController.signal
			});
			const responseJson = await response.json();
			if (!response.ok) {
				// If the response is not OK, but JSON body was successfully retrieved and parsed, then show the error
				// page using the contents from the parsed response. The server has probably set the status to
				// AUTHENTICATION_FAILED already, so we need to start a new authentication after that.
				handleIdCardBackendError(responseJson);
				return null;
			}
			return responseJson;
		} catch (error) {
			// If the JSON body cannot be retrieved, show the general AJAX error page.
			activateIdCardView('ajaxError');
			return null;
		} finally {
			clearTimeout(timerId);
		}
	}

	async function handleWebEidJsError(csrfToken, webEidInfo) {
		// Response from /auth/id/error endpoint is never 200 OK,
		// but an HTTP error code with error details in the following format:
		// {
		// 	 'timestamp': '2022-12-01T10:26:14.599+00:00',
		// 	 'status': 400,
		// 	 'error': 'Bad Request',
		// 	 'message': 'Error message in HTML<br/>format',
		// 	 'path': '/auth/id/error',
		// 	 'locale': 'et',
		// 	 'login_challenge': 'c8422a5671614fadae13fc244b0d4aab',
		// 	 'incident_nr': 'a2ae9f4e7fa1f237b5b402c3c96c5f70',
		// 	 'reportable': true
		// }
		await fetchJson('/auth/id/error', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json',
				'X-CSRF-TOKEN': csrfToken
			},
			body: JSON.stringify({
				code: webEidInfo.code,
				extensionVersion: webEidInfo.extensionVersion,
				nativeAppVersion: webEidInfo.nativeAppVersion,
				errorStack: webEidInfo.errorStack,
				statusDurationMs: webEidInfo.statusDurationMs
			})
		});
	}

	function handleIdCardBackendError(responseJson) {
		$('#error-message').html(responseJson.message);

		if (responseJson.reportable === true) {
			$('#error-incident-number').text(responseJson.incident_nr);
			const plainTextMessage = $('#error-message').text();
			const os = navigator.platform;
			const browserInfo = navigator.appCodeName + '/' + navigator.appVersion;
			const hostName = location.hostname;
			const errorReportUrl = $('#error-report-url').attr('href')
				.replace('(1)', plainTextMessage)
				.replace('(2)', responseJson.incident_nr)
				.replace('(3)', os)
				.replace('(4)', browserInfo)
				.replace('(5)', hostName);
			$('#error-report-url').attr('href', errorReportUrl);

			const errorReportNotificationMessage = $('#error-report-notification').text()
				.replace('{1}', responseJson.incident_nr)
				.replace('{2}', hostName);
			$('#error-report-notification').text(errorReportNotificationMessage);
			activateIdCardView('reportableError');
		} else {
			activateIdCardView('notReportableError');
		}
	}

	// Mobile-ID limit max length
	$('#mobileIdForm input#mid-personal-code.form-control').on('keypress change input', function(event) {
		if ($(this).val().length >= 11) {
			$(this).val($(this).val().substring(0, 11));
			event.preventDefault();
			return false;
		}
	});
	
	// Mobile-ID form submit
	$('#mobileIdForm button.c-btn--primary').on('click', function() {
		if ($(this).prop('disabled')) {
			return;
		}
		$(this).prop('disabled', true);

		const phoneNumberInput = $('#mid-phone-number');
		const isIdCodeValid = validateEstonianIdCode($('#mid-personal-code'));
		const isPhoneNumberValid = validateEstonianPhoneNumber(phoneNumberInput);
		const valid = isIdCodeValid && isPhoneNumberValid;

		if (valid) {
			phoneNumberInput.val(phoneNumberInput.val().replace(/\s+/g, ''));
			$('#mobileIdForm').submit();
		} else {
			$(this).prop('disabled', false);
		}
	});
	
	// Mobile-ID form submit via input field
	$('#mobileIdForm input.form-control').on('keypress', function(event){
		if (event.keyCode === 13) { // Enter key
			$('#mobileIdForm button.c-btn--primary').trigger('click');
			event.preventDefault();
		}
	});


	// Smart-ID limit max length
	$('#smartIdForm input#sid-personal-code.form-control').on('keypress change input', function(event) {
		if ($(this).val().length >= 11) {
			$(this).val($(this).val().substring(0, 11));
			event.preventDefault();
			return false;
		}
	});

	// Smart-ID form submit
	$('#smartIdForm button.c-btn--primary').on('click', function(event){
		if ($(this).prop('disabled')) return;
		$(this).prop('disabled', true);
		
		if (validateEstonianIdCode($('#sid-personal-code'))) {
			$('#smartIdForm').submit();
		} else {
			$(this).prop('disabled', false);
		}
	});
	
	// Smart-ID form submit via input field
	$('#smartIdForm input.form-control').on('keypress', function(event){
		if (event.keyCode === 13) { // Enter key
			$('#smartIdForm button.c-btn--primary').trigger('click');
			event.preventDefault();
		}
	});


	// Smart-ID status polling form - submit cancel
    $('#authenticationCheckForm a.c-btn--from-link').on('click', function(event){

        event.preventDefault();

        if ($(this).prop('disabled')) return;
        $(this).prop('disabled', true);

        $('#_eventId').val('cancel');
        $('#authenticationCheckForm').submit();
    });

	// EU citizen form submit
	$('#eidasForm button.c-btn--primary').on('click', function(event){
		if ($(this).prop('disabled')) return;
		$(this).prop('disabled', true);
		
		if (validateSelectizeValue($('#eidasForm select'), function(value){return value;})) {
			$('#eidasForm').submit();
		} else {
			$(this).prop('disabled', false);
		}
	});
	
	// EU country selection validate on select
	$('#eidasForm select').on('change', function(){
		validateSelectizeValue($(this), function(){return true;});
	});

    function hideAlert(alert) {
        alert.removeAttr('role');
	    alert.attr('aria-hidden', 'true');
        alert.removeClass('show');
    }

    function showFeedback(feedback, errorId = null) {
		if (!feedback.hasClass('is-hidden')){
			hideFeedback(feedback);
		}
		if (errorId !== null) {
			feedback.attr('id', errorId);
		}
        feedback.removeClass('is-hidden');
		feedback.removeAttr('aria-hidden');
    }

    function hideFeedback(feedback) {
        feedback.addClass('is-hidden');
		feedback.attr('aria-hidden', true);
		feedback.removeAttr('id');
    }

	async function detectWebEid() {
		let webEidInfo = {
			code: '',
			extensionVersion: '',
			nativeAppVersion: '',
			errorStack: '',
			statusDurationMs: ''
		};
		const statusCheckStart = new Date().getTime();
		await webeid.status()
			.then(response => {
				webEidInfo.code = 'SUCCESS';
				webEidInfo.extensionVersion = response.extension;
				webEidInfo.nativeAppVersion = response.nativeApp;
			})
			.catch(err => {
				webEidInfo.code = err.code;
				webEidInfo.extensionVersion = err.extension;
				webEidInfo.nativeAppVersion = err.nativeApp;
				webEidInfo.errorStack = err.stack;
			})
			.finally(() => {
				webEidInfo.statusDurationMs = new Date().getTime() - statusCheckStart;
			});
		return webEidInfo;
	}

    function activateIdCardView(viewName) {
		const formSelector = '.c-layout--full > .container';
		const waitMessageSelector = '#id-card-wait';
		const waitPopupMessageSelector = '#id-card-wait-popup';
		const waitLoginMessageSelector = '#id-card-wait-login';
		const errorContainerSelector = '#id-card-error';
		const errorMessageSelector = '#error-message';
		const ajaxErrorSelector = '#idc-ajax-error-message';
		const errorReportUrlSelector = '#error-report-url';
		const errorIncidentNumberWrapperSelector = '#error-incident-number-wrapper';
		const languageSelectionSelector = '.c-header-bar nav[role=navigation]';
    	const visibleElementsInViews = {
    		form: [formSelector, languageSelectionSelector].join(','),
			waitPopup: [waitMessageSelector, waitPopupMessageSelector].join(','),
			waitLogin: [waitMessageSelector, waitLoginMessageSelector].join(','),
			reportableError: [errorContainerSelector, errorMessageSelector, errorReportUrlSelector, errorIncidentNumberWrapperSelector].join(','),
			notReportableError: [errorContainerSelector, errorMessageSelector].join(','),
			ajaxError: [errorContainerSelector, ajaxErrorSelector].join(',')
		}

    	if (! (viewName in visibleElementsInViews)) {
    		console.error('Invalid name for view: ' + viewName);
    		return;
		}

    	const hideList = [];
    	const unhideList = [];
		for (const [view, selector] of Object.entries(visibleElementsInViews)) {
			if (view === viewName) {
				unhideList.push($(selector));
			} else {
				hideList.push($(selector));
			}
		}
		hideElements(hideList);
		unhideElements(unhideList);
    }

    function activateTab(link, content, warning) {
		link.parent().attr('aria-selected', true);
		link.addClass('is-active');
        content.attr('aria-hidden', false);
        content.addClass('is-active');
        warning.attr('aria-hidden', false);
        warning.addClass('is-active');
    }

    function deActivateTab(link, content, warning) {
        link.parent().attr('aria-selected', false);
        link.removeClass('is-active');
        content.attr('aria-hidden', true);
        content.removeClass('is-active');
        warning.attr('aria-hidden', true);
        warning.removeClass('is-active');
    }

    function hideElements(elements) {
    	for (const element of elements) {
			element.attr('aria-hidden', 'true');
			element.addClass('hidden');
		}
	}

    function unhideElements(elements) {
    	for (const element of elements) {
			element.attr('aria-hidden', 'false');
			element.removeClass('hidden');
		}
	}

    function getCurrentBrowser() {
        return navigator.userAgent;
    }

    function getCurrentOperatingSystem() {
        return navigator.platform;
    }

	function isProbablyMobileDevice() {
		return /Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
	}

	$('.c-btn').on('click', function () {
		const button = $(this);
		const invalidInput = $('input[aria-invalid="true"]').first();

		if (invalidInput.length === 0) {
			// Only override browser default functionality when there are no aria-invalid inputs
			requestAnimationFrame(() => button.focus());
		} else {
			// Keeps button focus style on button after click for consistency across browsers,
			// overriding Chrome's default behaviour
			requestAnimationFrame(() => invalidInput.focus());
		}
	});

	$(document).ready(function () {
		let focusableElement = $('#focus-wrapper');
		if (focusableElement.length) {
			// Forcing focus on SID/MID confirmation code view for screen readers so important information is not missed
			// Needed for consistent functioning of different screen reader and browser combinations
			focusableElement.focus();
		}
	});
});
