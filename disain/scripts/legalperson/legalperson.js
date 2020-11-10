jQuery(function ($) {
    "use strict";

    $( document ).ready(function() {
        $.ajax({
            type: "GET",
            dataType: "json",
            url: "/auth/legal_person",
            beforeSend: function() {setup();}
        }).done( function (json) {
            handleSuccessfulResult(json);
        }).fail ( function (jqXHR, textStatus) {
            handleErrorResult(jqXHR, textStatus);
        });
    });

    function setup(){
        $('#results-loading').removeClass('hidden');
        $('#btn-select-legal-person').hide();
    }

    function handleSuccessfulResult(json) {
        $('#results-loading').addClass('hidden');
        $('#results-summary').removeClass('hidden');
        $('#results-legal-person-list').empty();

        var length = json.legalPersons.length;
        $.each(json.legalPersons, function(idx, legalperson){
            var legalPersonItem = $(
                '<li><input type="radio" name="legalperson" value="' + legalperson.legalPersonIdentifier
                    + '" id="' + legalperson.legalPersonIdentifier + '" /> <label for="'
                    + legalperson.legalPersonIdentifier + '">' + legalperson.legalName + ', '
                    + legalperson.legalPersonIdentifier + '</label></li>'
            ).on('click', function() {
                setSelectedLegalPerson();
            });

            $('#results-legal-person-list').append(legalPersonItem);
        })

        if (length == 1) {
            $('#' + json.legalPersons[0].legalPersonIdentifier).prop("checked", true);
            $('input[name="legalPersonId"]').val(json.legalPersons[0].legalPersonIdentifier);
            $('#legalperson-count').text(length);
            $('#btn-select-legal-person').show();
        } else {
            $('#legalperson-count').text(length);
        }
    }

    function handleErrorResult(jqXHR, textStatus) {
        $('#error-controls-container').removeClass('hidden');
        $('#error-results-container').removeClass('hidden');

        $('#results-loading').addClass('hidden');
        $('#results-container').addClass('hidden');
        $('#btn-select-legal-person').hide();

        if(jqXHR.status&&jqXHR.status == 404) {
            $('#error-no-results').removeClass('hidden');
        } else if(jqXHR.status&&jqXHR.status == 502) {
            $('#error-service-not-available').removeClass('hidden');
        } else {
            $('#error-technical-problem').removeClass('hidden');
        }
    }

    function setSelectedLegalPerson() {
        $('input[name="legalPersonId"]').val($("input[name='legalperson']:checked").val());
        $('#btn-select-legal-person').show();
    }
});
