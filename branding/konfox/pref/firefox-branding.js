/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Könfox Nightly branding preferences.

pref("startup.homepage_override_url", "");
pref("startup.homepage_welcome_url", "about:home");
pref("startup.homepage_welcome_url.additional", "");

// IMPORTANT: Disable Mozilla's automatic updater so Windows 7 users are never
// overwritten by an official Windows 10+-only Mozilla Nightly binary.
pref("app.update.enabled", false);
pref("app.update.auto", false);
pref("app.update.silent", false);
pref("app.update.interval", 86400);
pref("app.update.promptWaitTime", 43200);
pref("app.update.url.manual", "https://github.com/konfox-browser/konfox/releases");
pref("app.update.url.details", "https://github.com/konfox-browser/konfox/releases");

pref("app.releaseNotesURL", "https://github.com/konfox-browser/konfox/releases");
pref("app.releaseNotesURL.aboutDialog", "https://github.com/konfox-browser/konfox/releases");
pref("app.releaseNotesURL.prompt", "https://github.com/konfox-browser/konfox/releases");

pref("app.update.checkInstallTime.days", 30);
pref("app.update.badgeWaitTime", 0);

// Keep Nightly developer ergonomics.
pref("devtools.selfxss.count", 5);
