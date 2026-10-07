self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));
// Verification needs current revocation state, so this worker does not cache requests.
