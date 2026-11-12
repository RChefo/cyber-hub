; Cyber Hub's additions to Tauri's NSIS installer (bundle.windows.nsis.installerHooks), Mission 11.
;
; Tauri's installer saves the install folder as the default value of
; HKCU\Software\<publisher>\<product>, and its uninstaller keeps that key unless "Delete the
; application data" is ticked. Tauri's MSI looks there for a previous folder, so an MSI installed
; after the NSIS copy was removed went into the removed copy's per-user folder instead of
; Program Files.
;
; After a real uninstall, the folder is forgotten. Nothing else is removed: the database, settings,
; logs and backups in %APPDATA%\dev.cyberhub.workstation stay, and so do other values in the key,
; such as the MSI's. An update keeps the folder ($UpdateMode = 1). A newer installer that removes
; the old copy first has already read the folder, and writes it again when it installs.

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $UpdateMode <> 1
    DeleteRegValue SHCTX "${MANUPRODUCTKEY}" ""
    ; only when nothing else is left in them (NSIS 3: no values and no subkeys)
    DeleteRegKey /ifempty SHCTX "${MANUPRODUCTKEY}"
    DeleteRegKey /ifempty SHCTX "${MANUKEY}"
  ${EndIf}
!macroend
