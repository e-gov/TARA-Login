jQuery(function ($) {
	"use strict";

	var defaultErrorReportUrl;
    var defaultErrorReportNotification;
	
	// Hide nav bar in desktop mode and display authentication method content in mobile mode if less than 2 auth methods
	if ($('.c-tab-login__nav-link').length < 2) {
		$('.c-tab-login__header').addClass('hide-in-desktop');
        $('body').addClass('is-mobile-subview');
        $('.c-tab-login__nav-item').addClass('is-active');
	}

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
		$('.c-tab-login__content[data-tab="' + active + '"] .input-group').removeClass('is-invalid');
		$('.c-tab-login__content[data-tab="' + active + '"] .selectize-input').removeClass('is-invalid');

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

		$('.c-tab-login__content[data-tab="' + active + '"]').find(".c-tab-login__content-wrap").first().attr("tabindex",-1).focus();
	});

	$(document).on('click', '#error-report-url', function(event){
	    var errorReportUrl = $('#error-report-url');
	    var errorReportNotification = $('#error-report-notification');
	    var processedErrorReportUrl = errorReportUrl.attr('href');
	    var processedErrorReportNotification = errorReportNotification.text();
        processedErrorReportUrl = processedErrorReportUrl.replace("{3}", getCurrentOperatingSystem())
        processedErrorReportUrl = processedErrorReportUrl.replace("{4}", getCurrentBrowser())
        processedErrorReportUrl = processedErrorReportUrl.replace("{5}", window.location.host)
        processedErrorReportNotification = processedErrorReportNotification.replace("{2}", window.location.host)
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
	
	// Close alert
	$(document).on('click', '.alert-popup .close', function(event){
		event.preventDefault();
		hideAlert($(this).closest('.alert'));
	});

	// Country select
	if ($('#country-select').length){
		// Note that when updating tom-select, you have to convert tom-select.base.js from ecmascript-6 to ecmascript-5 for gulp compatibility and comment out the preventDefault(e) method under KEY_TAB settings to use regular tab behaviour.
        new TomSelect("#country-select",{
            selectOnTab: true,
            onChange:function(){
                // Removes the placeholder text when a country has been selected and a placeholder exists. Also sets the input width to 0 so it wouldn't create a new line on narrow screens.
                if ($('#country-select-tomselected').is("[placeholder]")) {
                    $('#country-select-tomselected').removeAttr('placeholder');
                    $('#country-select-tomselected').css({"width":0, "min-width":0});
                }
            },
            sortField: {
                field: "text",
                direction: "asc"
            },
            render:{
                // Removes the "no results found" default message when using the search function.
                no_results:function(data,escape){
                    return '';
                }
            }
        });
	}
	
	function validateEstonianIdCode(value){
		return value && /^[0-9]{11}$/.test(value);
	}
	
	function validateEstonianPhoneNumber(value){
		return value && /^[0-9]{3,15}$/.test(value);
	}
	
	function validateFormFieldValue(field, testFunc){
		if (testFunc(field.val())) {
			field.removeClass('is-invalid');
			field.parent('div.input-group').removeClass('is-invalid');
			hideFeedback(field.parents('td').children('div.invalid-feedback'));
			return true;
		} else {
			field.addClass('is-invalid');
			field.parent('div.input-group').addClass('is-invalid');
			
			var errorIndex = field.val() ? 1 : 0;
			field.parents('td').children('div.invalid-feedback').each(function(index){
				if (index === errorIndex) {
				    showFeedback($(this));
				    // Refresh text for screen reader to read out message
				    $(this).text($(this).text());
				} else {
				    hideFeedback($(this));
				}
			});
			
			return false;
		}
	}
	
	function validateSelectizeValue(selection, testFunc){
		if (testFunc(selection.val())) {
			selection.parent('td').find('.selectize-input').removeClass('is-invalid');
			hideFeedback(selection.parent('td').children('div.invalid-feedback'));
			return true;
		} else {
			selection.parent('td').find('.selectize-input').addClass('is-invalid');
			var feedbackDiv = selection.parent('td').children('div.invalid-feedback');
			showFeedback(feedbackDiv);
			// Refresh text for screen reader to read out message
            feedbackDiv.text(feedbackDiv.text());
			return false;
		}
	}
	
	// ID-card form submit
	$('#idCardForm button.c-btn--primary').on('click', function(event){
		event.preventDefault();

        hideAlert($('#idCardForm .alert-popup'));
		if ($(this).prop('disabled')) return;
		$(this).prop('disabled', true);
		var _this = $(this);
		
		var xhttp = new XMLHttpRequest();
		xhttp.onreadystatechange = function() {
			if (this.readyState !== 4) return;
			if (this.status == 200 || this.responseText == '{"status":"COMPLETED"}') {
			    $('#idCardForm').submit();
			} else if (this.status == 400 || this.status == 502) {
			    var jsonResponse = JSON.parse(this.responseText);

			    showAlert($('#idCardForm .alert-popup'));
                var errorMessageTitle = $('#idCardForm .alert-popup #error-message-title');
                var errorMessage = $('#idCardForm .alert-popup #error-message');
                var incidentNumber = $('#idCardForm .alert-popup #error-incident-number');
                var errorReportUrl = $('#idCardForm .alert-popup #error-report-url');
                var errorReportNotification = $('#idCardForm .alert-popup #error-report-notification');

                errorMessageTitle.text(errorMessageTitle.text());
                errorMessage.text(jsonResponse.message);
                incidentNumber.text(jsonResponse.incident_nr);

                if (defaultErrorReportUrl == null) {
                    defaultErrorReportUrl = errorReportUrl.attr('href');
                }

                var processedErrorReportUrl = defaultErrorReportUrl;
                processedErrorReportUrl = processedErrorReportUrl.replace("{1}", jsonResponse.message)
                processedErrorReportUrl = processedErrorReportUrl.replace("{2}", jsonResponse.incident_nr)
                errorReportUrl.attr('href', processedErrorReportUrl);

                if (defaultErrorReportNotification == null) {
                    defaultErrorReportNotification = errorReportNotification.text();
                }

                var proccessedErrorReportNotification = defaultErrorReportNotification;
                proccessedErrorReportNotification = proccessedErrorReportNotification.replace("{1}", jsonResponse.incident_nr);
                errorReportNotification.text(proccessedErrorReportNotification);

                $('#idCardForm .alert-popup #error-report-url').show();
                $('#idCardForm .alert-popup #error-incident-number-wrapper').show();
                $('#error-report-notification').addClass('hidden');
                _this.prop('disabled', false);
			} else {
			    var errorMessageTitle = $('#idCardForm .alert-popup #error-message-title');
                var errorMessage = $('#idCardForm .alert-popup #error-message');
                var incidentNumber = $('#idCardForm .alert-popup #error-incident-number');
                var errorReportUrl = $('#idCardForm .alert-popup #error-report-url');
                var errorReportNotification = $('#idCardForm .alert-popup #error-report-notification');

			    showAlert($('#idCardForm .alert-popup'));
			    if (this.responseText) {
			        var jsonResponse = JSON.parse(this.responseText);
                    errorMessageTitle.text(errorMessageTitle.text());
                    errorMessage.text(jsonResponse.message);
                    incidentNumber.text(jsonResponse.incident_nr);

                    if (defaultErrorReportUrl == null) {
                        defaultErrorReportUrl = errorReportUrl.attr('href');
                    }

                    var processedErrorReportUrl = defaultErrorReportUrl;
                    processedErrorReportUrl = processedErrorReportUrl.replace("{1}", jsonResponse.message)
                    processedErrorReportUrl = processedErrorReportUrl.replace("{2}", jsonResponse.incident_nr)
                    errorReportUrl.attr('href', processedErrorReportUrl);

                    if (defaultErrorReportNotification == null) {
                        defaultErrorReportNotification = errorReportNotification.text();
                    }

                    var proccessedErrorReportNotification = defaultErrorReportNotification;
                    proccessedErrorReportNotification = proccessedErrorReportNotification.replace("{1}", jsonResponse.incident_nr);
                    errorReportNotification.text(proccessedErrorReportNotification);

                    $('#idCardForm .alert-popup #error-report-url').show();
                    $('#idCardForm .alert-popup #error-incident-number-wrapper').show();
                    $('#error-report-notification').addClass('hidden');
			    } else {
                    errorMessageTitle.text(errorMessageTitle.text());
                    errorMessage.text(errorMessage.text());
                    $('#idCardForm .alert-popup #error-incident-number-wrapper').hide();
                    $('#idCardForm .alert-popup #error-report-url').hide();
                    $('#error-report-notification').addClass('hidden');
			    }

                _this.prop('disabled', false);
			}
		};
		xhttp.open('GET', '/auth/id', true);
		xhttp.setRequestHeader('Content-type', 'application/json;charset=UTF-8');
		xhttp.send();
	});

	// Mobile-ID limit max length
	$('#mobileIdForm input#mid-personal-code.form-control').on('keypress change input', function(event) {
		if ($(this).val().length >= 11) {
			$(this).val($(this).val().substring(0, 11));
			event.preventDefault();
			return false;
		}
	});
	
	// Mobile-ID form submit
	$('#mobileIdForm button.c-btn--primary').on('click', function(event){
		event.preventDefault();
		
		if ($(this).prop('disabled')) return;
		$(this).prop('disabled', true);
		
		var valid = true;
		valid = validateFormFieldValue($('#mid-personal-code'), validateEstonianIdCode) && valid;
		valid = validateFormFieldValue($('#mid-phone-number'), validateEstonianPhoneNumber) && valid;
		
		if (valid) {
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
	
	// Mobile-ID fields validate on focus
	$('#mobileIdForm input.form-control').on('focus', function(){
		validateFormFieldValue($(this), function(){return true;});
	});

	// Bank-link form submit
	$('#bankForm a.c-logo-list__link').on('click', function(event){
		event.preventDefault();
		
		$('#bankForm input[name="bank"]').val($(this).attr('id'));
		$('#bankForm').submit();
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
		event.preventDefault();
		
		if ($(this).prop('disabled')) return;
		$(this).prop('disabled', true);
		
		if (validateFormFieldValue($('#sid-personal-code'), validateEstonianIdCode)) {
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
	
	// Smart-ID fields validate on focus
	$('#smartIdForm input.form-control').on('focus', function(){
		validateFormFieldValue($(this), function(){return true;});
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
		event.preventDefault();
		
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

	function showAlert(alert) {
        alert.attr("role", "alert");
	    alert.removeAttr("aria-hidden");
	    alert.addClass('show');
	}

    function hideAlert(alert) {
        alert.removeAttr("role");
	    alert.attr("aria-hidden", "true");
        alert.removeClass('show');
    }

    function showFeedback(feedback) {
        feedback.attr("role", "alert");
        feedback.removeClass('is-hidden');
    }

    function hideFeedback(feedback) {
        feedback.removeAttr("role");
        feedback.addClass('is-hidden');
    }

    function activateTab(link, content, warning) {
		link.parent().attr("aria-selected", true);
		link.addClass('is-active');
        content.attr("aria-hidden", false);
        content.addClass('is-active');
        warning.attr("aria-hidden", false);
        warning.addClass('is-active');
    }

    function deActivateTab(link, content, warning) {
        link.parent().attr("aria-selected", false);
        link.removeClass('is-active');
        content.attr("aria-hidden", true);
        content.removeClass('is-active');
        warning.attr("aria-hidden", true);
        warning.removeClass('is-active');
    }

    function getCurrentBrowser() {
        return navigator.userAgent;
    }

    function getCurrentOperatingSystem() {
        return navigator.platform;
    }
});
