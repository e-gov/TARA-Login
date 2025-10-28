document.addEventListener('DOMContentLoaded', () => {
    const incidentTimeElement = document.getElementById('incident-time');
    if (!incidentTimeElement) return;

    const serverTimeString = incidentTimeElement.dataset.serverTime;
    if (!serverTimeString) return;

    const timeFormat = incidentTimeElement.dataset.timeFormat;
    const formattedDateTimeWithBrowserOffset = formatDateTimeWithBrowserOffset(serverTimeString, timeFormat);

    incidentTimeElement.innerHTML = formattedDateTimeWithBrowserOffset;
});

function formatDateTimeWithBrowserOffset(dateString, format) {
  const formattedDateTime = formatDateTime(dateString, format);
  const browserTimeOffset = formatBrowserTimeOffset();

  const formattedDateTimeWithBrowserOffset = `${formattedDateTime} ${browserTimeOffset}`;

  return formattedDateTimeWithBrowserOffset;
}

function formatDateTime(dateString, format = 'dd.MM.yyyy HH:mm') {
  const d = new Date(dateString);
  const map = {
    yyyy: d.getFullYear(),
    MM: String(d.getMonth() + 1).padStart(2, '0'),
    M: d.getMonth() + 1,
    dd: String(d.getDate()).padStart(2, '0'),
    d: d.getDate(),
    HH: String(d.getHours()).padStart(2, '0'),
    H: d.getHours(),
    h: ((d.getHours() + 11) % 12) + 1,
    mm: String(d.getMinutes()).padStart(2, '0'),
    m: d.getMinutes(),
    a: d.getHours() < 12 ? 'AM' : 'PM',
  };

  return format.replace(/yyyy|MM|M|dd|d|HH|H|h|mm|m|a/g, match => map[match]);
}

function formatBrowserTimeOffset() {
  const d = new Date();

  const offsetMinutes = d.getTimezoneOffset();
  const offsetHours = -offsetMinutes / 60;

  const offsetSign = offsetHours >= 0 ? '+' : '-';
  const absoluteHours = Math.floor(Math.abs(offsetHours));
  const absoluteMinutes = Math.abs(offsetMinutes) % 60;

  const formattedUtcOffset = `UTC${offsetSign}${absoluteHours.toString().padStart(2, '0')}:${absoluteMinutes.toString().padStart(2, '0')}`
  return formattedUtcOffset;
}

