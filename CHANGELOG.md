## Main changes
- SubGHz:
    - Frequency analyzer fixes and improvements:
        - **Enforce int module** (like in OFW) usage due to lack of required hardware on external boards (PathIsolate (+rf switch for multiple paths)) and incorrect usage and/or understanding the purpose of frequency analyzer app by users, it should be used only to get frequency of the remote placed around 1-10cm around flipper's left corner
        - **Fix possible GSM mobile towers signal interference** by limiting upper frequency to 920mhz max
        - Fix buttons logic, **fix crash**
    - Protocol improvements: 
        - **Keeloq: Monarch full support, with add manually option** (thanks @ashphx !)
        - **Princeton support for second button encoding type** (8bit)
        - GangQi fix serial check and remove broken check from UI
        - Hollarm add more button codes (thanks to @mishamyte for captures)
    - Misc:
        - Add extra settings to disable GPIO pins control used for external modules amplifiers and/or LEDs (in radio settings menu with debug ON)
- NFC:
    - Read Ultralight block by block (**fix password protected MFUL reading issue**) (by @mishamyte | PR #825 #826)
    - **Update NDEF parser** (SLIX and MFC support) (by @luu176 and @jaylikesbunda and @Willy-JL)
    - OFW PR 3822: **MIFARE Classic Key Recovery Improvements** (by @noproto)
    - OFW PR 3930: NFC Emulation freeze fix (by @RebornedBrain)
    - OFW: H World Hotel Chain Room Key Parser
    - OFW: Parser for Tianjin Railway Transit
    - New keys in system dict
- Infrared: 
    - **Add LEDs universal remote** (DB by @amec0e)
    - Update universal remote assets (by @amec0e | PR #813 #816)
- JS:
    - OFW: JS modules & SDK -> **Breaking API change**
    - **Backporting custom features** (read about most of the changes after other changes section) (by @xMasterX and @Willy-JL)
    - Add i2c & SPI module (by @jamisonderek)
* OFW: FuriHal, drivers: rework gauge initialization routine -> **Downgrade to older releases may break battery UI percent indicator, upgrade to this or newer version to restore**
* OFW: heap: increased size -> **More free RAM!!**
* OFW: New layout for BadUSB (es-LA)
* OFW: Require PIN on boot
* Apps: **Check out more Apps updates and fixes by following** [this link](https://github.com/xMasterX/all-the-plugins/commits/dev)
## Other changes
* SubGHz: Freq analyzer - Fix duplicated frequency lists and use user config for nearest frequency selector too
* SubGHz: Code cleanup and fix for rare dupicated (Data) field cases
* OFW: NFC TRT Parser: Additional checks to prevent false positives
* OFW PR 3885: NFC: Add API to enforce ISO15693 mode (by @aaronjamt)
* OFW: NFC: iso14443_4a improvements (by @RebornedBrain)
* OFW: NFC: Plantain parser improvements (by @assasinfil) & fixes (by @mxcdoam)
* OFW: NFC: Moscow social card parser (by @assasinfil)
* OFW: fix: npm deps
* OFW: 目覚め時計 (Added alarm option and clock settings)
* OFW: JS: Backport and more additions & fixes 
* OFW: nfc: add Caltrain zones for Clipper
* OFW: Update unit tests docs
* OFW: Fix JS memory corruption (in gpio module)
* OFW: Full-fledged JS SDK + npm packages 
* OFW: FurEventLoop: add support for FuriEventFlag, simplify API
* OFW: lib: digital_signal: digital_sequence: add furi_hal.h wrapped in ifdefs
* OFW: Add warning about stealth mode in vibro CLI
* OFW: Small fixes in the wifi devboard docs
* OFW: BadUSB - Improve ChromeOS and GNOME demo scripts
* OFW: Small JS fixes
* OFW: Canvas: extended icon draw.
* OFW: Fixes Mouse Clicker Should have a "0" value setting for "as fast as possible"
* OFW: Wi-Fi Devboard documentation rework
* OFW: Furi: A Lot of Fixes
* OFW PR 3933: furi_hal_random: Wait for ready state and no errors before sampling (by @n1kolasM)
* OFW: nfc/clipper: Update BART station codes 
* OFW: FuriThread: Improve state callbacks
* OFW: Documentation: update and cleanup
* OFW: Improve bit_buffer.h docs
* OFW: Prevent idle priority threads from potentially starving the FreeRTOS idle task
* OFW: IR universal remote additions
* OFW: Fix EM4100 T5577 writing block order (was already done in UL)
* OFW: kerel typo
* OFW: Folder rename fails
* OFW: Put errno into TCB
* OFW: Fix USB-UART bridge exit screen stopping the bridge prematurely
**More details on JS changes** (js changelog written by @Willy-JL , thanks!):
- Non-exhaustive list of changes to help you fix your scripts:
    - `badusb`:
      - `setup()`: `mfr_name`, `prod_name`, `layout_path` parameters renamed to `mfrName`, `prodName`, `layoutPath`
      - effort required to update old scripts using badusb: very minimal
    - `dialog`:
      - removed, now replaced by `gui/dialog` and `gui/file_picker` (see below)
    - `event_loop`:
      - new module, allows timer functionality, callbacks and event-driven programming, used heavily alongside gpio and gui modules
    - `gpio`:
      - fully overhauled, now you `get()` pin instances and perform actions on them like `.init()`
      - now supports interrupts, callbacks and more cool things
      - effort required to update old scripts using gpio: moderate
    - `gui`:
      - new module, fully overhauled, replaces dialog, keyboard, submenu, textbox modules
      - higher barrier to entry than older modules (requires usage of `event_loop` and `gui.viewDispatcher`), but much more flexible, powerful and easier to extend
      - includes all previously available js gui functionality (except `widget`), and also adds `gui/loading` and `gui/empty_screen` views
      - currently `gui/file_picker` works different than other new view objects, it is a simple `.pickFile()` synchronous function, but this [may change later](https://github.com/flipperdevices/flipperzero-firmware/pull/3961#discussion_r1805579153)
      - effort required to update old scripts using gui: extensive
    - `keyboard`:
      - removed, now replaced by `gui/text_input` and `gui/byte_input` (see above)
    - `math`:
      - `is_equal()` renamed to `isEqual()`
    - `storage`:
      - fully overhauled, now you `openFile()`s and perform actions on them like `.read()`
      - now supports many more operations including different open modes, directories and much more
      - effort required to update old scripts using storage: moderate
    - `submenu`:
      - removed, now replaced by `gui/submenu` (see above)
    - `textbox`:
      - removed, now replace by `gui/text_box` (see above)
    - `widget`:
      - only gui functionality not ported to new gui module, remains unchanged for now but likely to be ported later on
    - globals:
      - `__filepath` and `__dirpath` renamed to `__filename` and `__dirname` like in nodejs
      - `to_string()` renamed and moved to number class as `n.toString()`, now supports optional base parameter
      - `to_hex_string()` removed, now use `n.toString(16)`
      - `parse_int()` renamed to `parseInt()`, now supports optional base parameter
      - `to_upper_case()` and `to_lower_case()` renamed and moved to string class as `s.toUpperCase()` and `s.toLowerCase()`
      - effort required to update old scripts using these: minimal
  - Added type definitions (typescript files for type checking in IDE, Flipper does not run typescript)
  - Documentation is incomplete and deprecated, from now on you should refer to type definitions (`applications/system/js_app/types`), those will always be correct
  - Type definitions for extra modules we have that OFW doesn't will come later
<br><br>
#### Known NFC post-refactor regressions list: 
- Mifare Mini clones reading is broken (original mini working fine) (OFW)
- NFC CLI was removed with refactoring (OFW) (will be back soon)

----

[-> How to install firmware](https://github.com/DarkFlippers/unleashed-firmware/blob/dev/documentation/HowToInstall.md)

[-> Download qFlipper (official link)](https://flipperzero.one/update)

## Please support development of the project
|Service|Remark|QR Code|Link/Wallet|
|-|-|-|-|
|**Patreon**||<div align="center"><a href="https://github.com/user-attachments/assets/a88a90a5-28c3-40b4-864a-0c0b79494a42"><img src="https://github.com/user-attachments/assets/da3a864d-d1c7-42cc-8a86-6fcaf26663ec" alt="QR image"/></a></div>|https://patreon.com/mmxdev|
|**Boosty**|patreon alternative|<div align="center"><a href="https://github.com/user-attachments/assets/893c0760-f738-42c1-acaa-916019a7bdf8"><img src="https://github.com/user-attachments/assets/da3a864d-d1c7-42cc-8a86-6fcaf26663ec" alt="QR image"/></a></div>|https://boosty.to/mmxdev|
|cloudtips|only RU payments accepted|<div align="center"><a href="https://github.com/user-attachments/assets/5de31d6a-ef24-4d30-bd8e-c06af815332a"><img src="https://github.com/user-attachments/assets/da3a864d-d1c7-42cc-8a86-6fcaf26663ec" alt="QR image"/></a></div>|https://pay.cloudtips.ru/p/7b3e9d65|
|YooMoney|only RU payments accepted|<div align="center"><a href="https://github.com/user-attachments/assets/33454f79-074b-4349-b453-f94fdadc3c68"><img src="https://github.com/user-attachments/assets/da3a864d-d1c7-42cc-8a86-6fcaf26663ec" alt="QR image"/></a></div>|https://yoomoney.ru/fundraise/XA49mgQLPA0.221209|
|USDT|(TRC20)|<div align="center"><a href="https://github.com/user-attachments/assets/0500498d-18ed-412d-a1a4-8a66d0b6f057"><img src="https://github.com/user-attachments/assets/da3a864d-d1c7-42cc-8a86-6fcaf26663ec" alt="QR image"/></a></div>|`TSXcitMSnWXUFqiUfEXrTVpVewXy2cYhrs`|
|ETH|(BSC/ERC20-Tokens)|<div align="center"><a href="https://github.com/user-attachments/assets/0f323e98-c524-4f41-abb2-f4f1cec83ab6"><img src="https://github.com/user-attachments/assets/da3a864d-d1c7-42cc-8a86-6fcaf26663ec" alt="QR image"/></a></div>|`0xFebF1bBc8229418FF2408C07AF6Afa49152fEc6a`|
|BTC||<div align="center"><a href="https://github.com/user-attachments/assets/5a904d45-947e-4b92-9f0f-7fbaaa7b37f8"><img src="https://github.com/user-attachments/assets/da3a864d-d1c7-42cc-8a86-6fcaf26663ec" alt="QR image"/></a></div>|`bc1q0np836jk9jwr4dd7p6qv66d04vamtqkxrecck9`|
|SOL|(Solana/Tokens)|<div align="center"><a href="https://github.com/user-attachments/assets/ab33c5e0-dd59-497b-9c91-ceb89c36b34d"><img src="https://github.com/user-attachments/assets/da3a864d-d1c7-42cc-8a86-6fcaf26663ec" alt="QR image"/></a></div>|`DSgwouAEgu8iP5yr7EHHDqMNYWZxAqXWsTEeqCAXGLj8`|
|DOGE||<div align="center"><a href="https://github.com/user-attachments/assets/2937edd0-5c85-4465-a444-14d4edb481c0"><img src="https://github.com/user-attachments/assets/da3a864d-d1c7-42cc-8a86-6fcaf26663ec" alt="QR image"/></a></div>|`D6R6gYgBn5LwTNmPyvAQR6bZ9EtGgFCpvv`|
|LTC||<div align="center"><a href="https://github.com/user-attachments/assets/441985fe-f028-4400-83c1-c215760c1e74"><img src="https://github.com/user-attachments/assets/da3a864d-d1c7-42cc-8a86-6fcaf26663ec" alt="QR image"/></a></div>|`ltc1q3ex4ejkl0xpx3znwrmth4lyuadr5qgv8tmq8z9`|
|BCH||<div align="center"><a href="https://github.com/user-attachments/assets/7f365976-19a3-4777-b17e-4bfba5f69eff"><img src="https://github.com/user-attachments/assets/da3a864d-d1c7-42cc-8a86-6fcaf26663ec" alt="QR image"/></a></div>|`qquxfyzntuqufy2dx0hrfr4sndp0tucvky4sw8qyu3`|
|XMR|(Monero)|<div align="center"><a href="https://github.com/user-attachments/assets/96186c06-61e7-4b4d-b716-6eaf1779bfd8"><img src="https://github.com/user-attachments/assets/da3a864d-d1c7-42cc-8a86-6fcaf26663ec" alt="QR image"/></a></div>|`41xUz92suUu1u5Mu4qkrcs52gtfpu9rnZRdBpCJ244KRHf6xXSvVFevdf2cnjS7RAeYr5hn9MsEfxKoFDRSctFjG5fv1Mhn`|
|TON||<div align="center"><a href="https://github.com/user-attachments/assets/92a57e57-7462-42b7-a342-6f22c6e600c1"><img src="https://github.com/user-attachments/assets/da3a864d-d1c7-42cc-8a86-6fcaf26663ec" alt="QR image"/></a></div>|`UQCOqcnYkvzOZUV_9bPE_8oTbOrOF03MnF-VcJyjisTZmsxa`|

#### Thanks to our sponsors who supported project in the past and special thanks to sponsors who supports us on regular basis:
@mishamyte, ClaraCrazy, Pathfinder [Count Zero cDc], callmezimbra, Quen0n, MERRON, grvpvl (lvpvrg), art_col, ThurstonWaffles, Moneron, UterGrooll, LUCFER, Northpirate, zloepuzo, T.Rat, Alexey B., ionelife, ...
and all other great people who supported our project and me (xMasterX), thanks to you all!


## **Recommended update option - Web Updater**

### What `r`, `e`, ` `, `c` means? What I need to download if I don't want to use Web updater?
What build I should download and what this name means - `flipper-z-f7-update-(version)(r / e / c).tgz` ? <br>
`flipper-z` = for Flipper Zero device<br>
`f7` = Hardware version - same for all flipper zero devices<br>
`update` = Update package, contains updater, all assets (plugins, IR libs, etc.), and firmware itself<br>
`(version)` = Firmware version<br>
| Designation | [Base Apps](https://github.com/xMasterX/all-the-plugins#default-pack) | [Extra Apps](https://github.com/xMasterX/all-the-plugins#extra-pack) | ⚠️RGB mode* |
|-----|:---:|:---:|:---:|
| ` ` | ✅ |  |  |
| `c` |  |  |  |
| `e` | ✅ | ✅ |  |
| `r` | ✅ | ✅ | ⚠️ |

⚠️This is [hardware mod](https://github.com/quen0n/flipperzero-firmware-rgb#readme), works only on modded flippers! do not install on non modded device!

Firmware Self-update package (update from microSD) - `flipper-z-f7-update-(version).tgz` for mobile app / qFlipper / web<br>
Archive of `scripts` folder (contains scripts for FW/plugins development) - `flipper-z-any-scripts-(version).tgz`<br>
SDK files for plugins development and uFBT - `flipper-z-f7-sdk-(version).zip`



