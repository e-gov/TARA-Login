function supportsSmartIdApp() {
    const agent = navigator.userAgent || navigator.vendor || window.opera;
    const isStandardMobile = /android|iphone|ipad|ipod/i.test(agent);
    // iPadOS 13 and later claim to be Macintosh and have touch screen.
    const isNewerIPad = (navigator.platform === 'MacIntel' || /Macintosh/i.test(agent)) && navigator.maxTouchPoints > 1;
    return isStandardMobile || isNewerIPad;
}
