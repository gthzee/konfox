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
pref("app.update.url.manual", "https://github.com/gthzee/konfox/releases");
pref("app.update.url.details", "https://github.com/gthzee/konfox/releases");

pref("app.releaseNotesURL", "https://github.com/gthzee/konfox/releases");
pref("app.releaseNotesURL.aboutDialog", "https://github.com/gthzee/konfox/releases");
pref("app.releaseNotesURL.prompt", "https://github.com/gthzee/konfox/releases");

pref("app.update.checkInstallTime.days", 30);
pref("app.update.badgeWaitTime", 0);

// Keep Nightly developer ergonomics.
pref("devtools.selfxss.count", 5);

// Windows 7 SP1 networking reliability:
// - disable Nightly-only experimental WinRegistry/WinINet proxy change watcher
// - disable HTTP/3 (QUIC/UDP) so Win7 uses fast, reliable HTTP/2 & HTTP/1.1 TCP
pref("network.proxy.detect_system_proxy_changes", false);
pref("network.http.http3.enable", false);

// ---------------------------------------------------------------------------
// Könfox: Completely disable all AI / ML / GenAI features and "AI Controls" UI
// ---------------------------------------------------------------------------
pref("browser.preferences.aiControls", false);
pref("browser.preferences.aiControls.showUnavailable", false);

pref("browser.ai.control.default", "blocked");
pref("browser.ai.control.sidebarChatbot", "blocked");
pref("browser.ai.control.translations", "blocked");
pref("browser.ai.control.pdfjsAltText", "blocked");
pref("browser.ai.control.smartTabGroups", "blocked");
pref("browser.ai.control.linkPreviewKeyPoints", "blocked");
pref("browser.ai.control.smartWindow", "blocked");
pref("browser.ai.control.speechRecognition", "blocked");
pref("browser.ai.control.generatedWidgets", "blocked");

pref("browser.ml.enable", false);
pref("browser.ml.llama.hwInference", false);
pref("extensions.ml.enabled", false);

pref("browser.ml.chat.enabled", false);
pref("browser.ml.chat.menu", false);
pref("browser.ml.chat.page", false);
pref("browser.ml.chat.page.footerBadge", false);
pref("browser.ml.chat.page.menuBadge", false);
pref("browser.ml.chat.provider", "");
pref("browser.ml.chat.shortcuts", false);
pref("browser.ml.chat.shortcuts.custom", false);
pref("browser.ml.chat.shortcuts.smartwindow", false);
pref("browser.ml.chat.sidebar", false);

pref("browser.ml.linkPreview.enabled", false);
pref("browser.ml.linkPreview.longPress", false);
pref("browser.ml.linkPreview.optin", false);
pref("browser.ml.pageAssist.enabled", false);

pref("browser.smartwindow.enabled", false);
pref("browser.smartwindow.aitab.enabled", false);
pref("browser.smartwindow.aitab.menus", false);
pref("browser.smartwindow.actionsToolbar.enabled", false);
pref("browser.smartwindow.agent.enabled", false);
pref("browser.smartwindow.agent.toolbar.enabled", false);
pref("browser.smartwindow.agent.suggestions.enabled", false);
pref("browser.smartwindow.autoTabGrouping.enabled", false);
pref("browser.smartwindow.autoTabGrouping.preloadModels", false);
pref("browser.smartwindow.smartformfill.enabled", false);
pref("browser.smartwindow.memories.generateFromHistory", false);
pref("browser.smartwindow.memories.generateFromConversation", false);
pref("browser.smartwindow.resumeActivity.enabled", false);
pref("browser.smartwindow.sidebar.openByDefault", false);
pref("places.semanticHistory.smartwindow.featureGate", false);
pref("places.semanticHistory.featureGate", false);

pref("browser.tabs.groups.smart.enabled", false);
pref("browser.tabs.groups.smart.userEnabled", false);
pref("browser.tabs.groups.smart.optin", false);

pref("pdfjs.enableAltText", false);
pref("pdfjs.enableAltTextForEnglish", false);
pref("pdfjs.enableAltTextModelDownload", false);

pref("browser.translations.enable", false);
pref("browser.translations.select.enable", false);
pref("browser.translations.quickAction.enabled", false);
pref("browser.translations.automaticallyPopup", false);

pref("sidebar.main.tools", "opentabs,bookmarks,history,syncedtabs,passwords");

// ---------------------------------------------------------------------------
// Könfox: Disable Win10+ launcher process & ALL Telemetry / Glean / Studies
// ---------------------------------------------------------------------------
pref("browser.launcherProcess.enabled", false);

// Data reporting / healthreport / Glean / usage telemetry
pref("datareporting.policy.dataSubmissionEnabled", false);
pref("datareporting.policy.dataSubmissionPolicyBypassNotification", true);
pref("datareporting.healthreport.uploadEnabled", false);
pref("datareporting.usage.uploadEnabled", false);

// Legacy Telemetry & LateWriteChecks (prevents Telemetry.LateWriteFinal-* & Telemetry.ShutdownTime.txt)
pref("toolkit.telemetry.enabled", false);
pref("toolkit.telemetry.unified", false);
pref("toolkit.telemetry.archive.enabled", false);
pref("toolkit.telemetry.newProfilePing.enabled", false);
pref("toolkit.telemetry.shutdownPingSender.enabled", false);
pref("toolkit.telemetry.shutdownPingSender.enabledFirstSession", false);
pref("toolkit.telemetry.updatePing.enabled", false);
pref("toolkit.telemetry.bhrPing.enabled", false);
pref("toolkit.telemetry.firstShutdownPing.enabled", false);
pref("toolkit.telemetry.pioneer-new-studies-available", false);
pref("toolkit.telemetry.server", "");
pref("toolkit.telemetry.coverage.opt-out", true);
pref("toolkit.coverage.opt-out", true);
pref("toolkit.coverage.endpoint.base", "");
pref("toolkit.shutdown.lateWriteChecksStage", 0);

// Glean / FOG
pref("telemetry.fog.test.localhost_port", 0);
pref("telemetry.fog.enable_store_submitted_pings", false);
pref("telemetry.glean.internal.finalInactive", false);

// Normandy / Shield Studies / Nimbus / PingCentre / Activity Stream telemetry
pref("app.shield.optoutstudies.enabled", false);
pref("app.normandy.enabled", false);
pref("app.normandy.api_url", "");
pref("browser.ping-centre.telemetry", false);
pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
pref("browser.newtabpage.activity-stream.telemetry", false);
pref("browser.newtabpage.activity-stream.telemetry.structuredIngestion.endpoint", "");
pref("browser.discovery.enabled", false);

// Crash reporter & default browser agent telemetry
pref("breakpad.reportURL", "");
pref("browser.tabs.crashReporting.sendReport", false);
pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false);
pref("default-browser-agent.enabled", false);
