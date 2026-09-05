def icon_sprite() -> str:
    return """
<svg class="icon-sprite" aria-hidden="true" focusable="false">
  <symbol id="i-logo" viewBox="0 0 24 24"><path d="m12 2 8 4.6v9L12 20l-8-4.4v-9L12 2Z"/><path d="m4 6.6 8 4.6 8-4.6M12 11.2V20M8 4.3l8 4.6v4.7"/></symbol>
  <symbol id="i-dashboard" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/></symbol>
  <symbol id="i-users" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3"/><path d="M3.5 20v-2.2A4.8 4.8 0 0 1 8.3 13h1.4a4.8 4.8 0 0 1 4.8 4.8V20M16 5.5a3 3 0 0 1 0 5.8M16.7 13.2a4.8 4.8 0 0 1 3.8 4.6V20"/></symbol>
  <symbol id="i-session" viewBox="0 0 24 24"><path d="M5 7h9M5 17h9M16 4l3 3-3 3M16 14l3 3-3 3"/><circle cx="5" cy="7" r="1"/><circle cx="5" cy="17" r="1"/></symbol>
  <symbol id="i-certificate" viewBox="0 0 24 24"><path d="M7 3h10a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z"/><path d="m9 16-1 5 4-2 4 2-1-5M9 8h6M9 11h4"/></symbol>
  <symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 3 20 6v5c0 5.2-3.2 8.2-8 10-4.8-1.8-8-4.8-8-10V6l8-3Z"/><path d="m8.5 12 2.2 2.2 4.8-5"/></symbol>
  <symbol id="i-log" viewBox="0 0 24 24"><path d="M5 4h14v16H5zM8 8h8M8 12h8M8 16h5"/></symbol>
  <symbol id="i-folder" viewBox="0 0 24 24"><path d="M3 6h7l2 2h9v11H3z"/></symbol>
  <symbol id="i-system" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.4-2.4 1A8 8 0 0 0 15 6.2L14.7 4h-4L10.4 6.2A8 8 0 0 0 8.8 7l-2.3-1-2 3.4L6.3 11a7 7 0 0 0 0 2l-1.9 1.5 2 3.4 2.4-1a8 8 0 0 0 1.6.9l.3 2.2h4l.3-2.2a8 8 0 0 0 1.6-.9l2.3 1 2-3.4-2-1.5a7 7 0 0 0 .1-1Z"/></symbol>
  <symbol id="i-plus" viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></symbol>
  <symbol id="i-enable" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="m10 8 6 4-6 4Z"/></symbol>
  <symbol id="i-disable" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9.5 8.5v7M14.5 8.5v7"/></symbol>
  <symbol id="i-remove" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="m8.5 8.5 7 7M15.5 8.5l-7 7"/></symbol>
  <symbol id="i-comment" viewBox="0 0 24 24"><path d="M4 4h16v12H9l-5 4z"/><path d="M8 8h8M8 12h5"/></symbol>
  <symbol id="i-search" viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6.5"/><path d="m15.5 15.5 5 5"/></symbol>
  <symbol id="i-filter" viewBox="0 0 24 24"><path d="M4 5h16l-6.5 7v6l-3 1v-7Z"/></symbol>
  <symbol id="i-refresh" viewBox="0 0 24 24"><path d="M20 7v5h-5M4 17v-5h5"/><path d="M18.5 10A7 7 0 0 0 6 7.5L4 12M5.5 14A7 7 0 0 0 18 16.5l2-4.5"/></symbol>
  <symbol id="i-user" viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4.5 21a7.5 7.5 0 0 1 15 0"/></symbol>
  <symbol id="i-logout" viewBox="0 0 24 24"><path d="M10 4H5v16h5M14 8l4 4-4 4M8 12h10"/></symbol>
  <symbol id="i-download" viewBox="0 0 24 24"><path d="M12 3v12M7 10l5 5 5-5M5 20h14"/></symbol>
  <symbol id="i-qr" viewBox="0 0 24 24"><path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2v2h-2zM18 14h2v2h-2zM18 18h2v2h-2zM14 18h2v2h-2z"/></symbol>
  <symbol id="i-copy" viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12"/><path d="M16 8V4H4v12h4"/></symbol>
  <symbol id="i-edit" viewBox="0 0 24 24"><path d="m4 20 4.5-1 10-10-3.5-3.5-10 10L4 20ZM13.5 7l3.5 3.5"/></symbol>
  <symbol id="i-trash" viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3M7 7l1 13h8l1-13M10 10v7M14 10v7"/></symbol>
  <symbol id="i-device" viewBox="0 0 24 24"><rect x="6" y="2" width="12" height="20" rx="1"/><path d="M10 18h4"/></symbol>
  <symbol id="i-traffic" viewBox="0 0 24 24"><path d="M8 4v16M4 8l4-4 4 4M16 20V4M12 16l4 4 4-4"/></symbol>
  <symbol id="i-lock" viewBox="0 0 24 24"><rect x="5" y="10" width="14" height="11"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></symbol>
  <symbol id="i-check" viewBox="0 0 24 24"><path d="m5 12 4 4L19 6"/></symbol>
  <symbol id="i-chevron" viewBox="0 0 24 24"><path d="m8 10 4 4 4-4"/></symbol>
  <symbol id="i-menu" viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"/></symbol>
  <symbol id="i-terminal" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16"/><path d="m7 9 3 3-3 3M12 16h5"/></symbol>
</svg>"""
