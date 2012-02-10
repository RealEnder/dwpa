; hcinstall.nsi
;--------------------------------

; The name of the installer
Name "help_crack_install"

; The file to write
OutFile "help_crack_.exe"

; The default installation directory
InstallDir c:\wpa

SetCompressor /SOLID lzma

; Request application privileges for Windows Vista and up
RequestExecutionLevel user
ShowInstDetails show

VIProductVersion "1.0.0.1"
VIAddVersionKey "FileVersion" "1.0.0.1"
VIAddVersionKey "ProductName" "help_crack"
VIAddVersionKey "FileDescription" "http://wpa-sec.stanev.org"

!include x64.nsh
!include FileFunc.nsh
!include WordFunc.nsh

!define CONFIG_FILE "hc.ini"
!define CONFIG_URL "http://wpa-sec.stanev.org/hc/${CONFIG_FILE}"

!define SOFTURL "URL"
!define PYTHONCFG "Python"
!define PYWINCFG  "PyWin"
!define HCCFG     "help_crack"
!define ACCFG     "Aircrack-ng"
!define HCPCFG    "oclHashCat-plus"

;--------------------------------
; Pages
  Page components
  Page directory
  Page instfiles
;--------------------------------

var HCConfig
var HCTemp

var PythonUrl
var PyWinUrl
var AircrackUrl
var help_crackUrl
var hcpUrl

!macro GetConfig
  StrCpy $HCConfig "$PLUGINSDIR\${CONFIG_FILE}"
  inetc::get ${CONFIG_URL} $HCConfig /end
  Pop $0 ;Get the return value
  ${If} $0 != "OK"
    MessageBox MB_OK "Cannot load config from ${CONFIG_URL}: $0"
    Abort
  ${EndIf}

  ;Running on Win64?
  var /GLOBAL x64p
  ${If} ${RunningX64}
    StrCpy $x64p "64"
  ${EndIf}

  ;Read download urls from config
  ReadINIStr $PythonUrl $HCConfig ${SOFTURL} "${PYTHONCFG}$x64p"
  ReadINIStr $PyWinUrl $HCConfig ${SOFTURL} "${PYWINCFG}$x64p"
  ReadINIStr $AircrackUrl $HCConfig ${SOFTURL} "${ACCFG}"
  ReadINIStr $help_crackUrl $HCConfig ${SOFTURL} "${HCCFG}"
  ReadINIStr $hcpUrl $HCConfig ${SOFTURL} "${HCPCFG}"
!macroend

!macro GetComponent SrcUrl SrcName
  ;download
  inetc::get ${SrcUrl} "$HCTemp\${SrcName}" /end
  Pop $0 ;Get the return value
  ${If} $0 != "OK"
    DetailPrint "Cannot download ${SrcName}: $0"
    Abort
  ${EndIf}
!macroend

Function .onInit
  InitPluginsDir
  StrCpy $HCTemp $PLUGINSDIR
  
  ; download and parse config
  !insertmacro GetConfig
FunctionEnd

; install sections
Section "Python" SecPython
  ;SectionIn RO
  ;download
  !insertmacro GetComponent $PythonUrl "${PYTHONCFG}.msi"

  ;install
  DetailPrint "installing ${PYTHONCFG}..."
  SetDetailsPrint none
  ExecWait 'msiexec /quiet /i "$HCTemp\${PYTHONCFG}.msi"' $0
  SetDetailsPrint both
  ${If} ${Errors}
    DetailPrint "Error installing ${PYTHONCFG}"
    Abort
  ${EndIf}
SectionEnd

Section "PyWin" SecPyWin
  ;SectionIn RO
  ;download
  !insertmacro GetComponent $PyWinUrl "${PYWINCFG}.exe"

  ;PyWin - no silent install :(
  DetailPrint "installing ${PYWINCFG}..."
  SetDetailsPrint none
  ExecWait '"$HCTemp\${PYWINCFG}.exe"' $0
  SetDetailsPrint both
  ${If} ${Errors}
    DetailPrint "Error installing ${PYWINCFG}"
    Abort
  ${EndIf}
SectionEnd

Section "Aircrack-ng" SecAirCrack
  ;SectionIn RO
  ;download
  !insertmacro GetComponent $AircrackUrl ${ACCFG}

  CreateDirectory $INSTDIR
  ;extract
  DetailPrint "extracting ${ACCFG}..."
  nsisunz::UnzipToLog "$HCTemp\${ACCFG}" "$INSTDIR"
SectionEnd

Section "help_crack" SecHC
  SectionIn RO
  ;download
  !insertmacro GetComponent $help_crackUrl ${HCCFG}
  ;install
  DetailPrint "installing ${HCCFG}..."
  CopyFiles /SILENT "$HCTemp\${HCCFG}" "$INSTDIR\help_crack.py"
SectionEnd

;TODO: download oclHashCat-plus
