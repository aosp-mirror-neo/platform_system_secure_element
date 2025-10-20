# Native OMAPI service

This is an implementation of the [Android
binding](https://globalplatform.org/specs-library/open-mobile-api-omapi-android-binding-v1-0-for-omapi-v3-3/)
for the [Global Platform OMAPI
specification](https://globalplatform.org/specs-library/open-mobile-api-specification-v3-3/) used to
provide the backend of the Android [SEService
API](https://developer.android.com/reference/android/se/omapi/SEService).  OMAPI specifies an
interface for device applications and system components to communicate with a set of [ISO
7816-4](https://en.wikipedia.org/wiki/ISO/IEC_7816) secure elements (SEs), multiplexing access to
the SEs so that multiple apps can communicate with one secure element, and controlling which apps
are allowed to communicate with which SE applets.

This implementation is modeled on and intended to replace the Java APK-based implementation that was
contributed by partners in Android 10.  That implementation cannot start in early boot, but because
the platform needs to be able to communicate with StrongBox and perform SE updates during early
boot, we need an OMAPI service that run and be used earlier.  This implementation also optimizes
early accesses by providing a mechanism to avoid reading the access control rules from the SE for
system components whose access is statically authorized by the platform.

## Terminals

An Android device can have any number of secure element terminals, divided into two categories, SIMs
and ESEs.  SIMs are typically, but not always, removable smart card chips.  ESEs are typically
discrete secure element chips soldered into the mainboard, but may also be integrated into the
system on a chip.  There is no significant diffence in the way the OMAPI service treats SIMs and
ESEs, but they're divided into separate namespaces by the underlying service naming conventions.

The OMAPI service finds available terminals by enumerating the available `ISecureElement` HAL
service names.  Only AIDL services are supported (the Java implementation also supports HIDL
services, but those have been deprecated for several Android releases).  The service names all
follow the pattern `android.hardware.secure_element.ISecureElement/{name}`, where `{name}` is
replaced by a string of the form `SIM#` or `ESE#`, with the `#` replaced by a terminal number.
Terminal numbers must be consecutive and start with 1, so a device with two SIM slots and one
embedded SE would have services with terminal names "SIM1", "SIM2", and "ESE1".

The service will block on the availability of SIM1 and ESE1, if their HALs are registered.  This
mirrors the behavior of the Java implementation but may not be correct for a service that starts
early in boot.  See the section "Unsupported features" below.

## Access control

Five access control mechanisms are supported, two relying on rules provided by the SE and three
relying on configuration provided by the host Android platform:

-  ARA-M rules provided by SE;
-  ARA-M rules provided by the platform;
-  ARA-D rules provided by SE;
-  Android permission `SECURE_ELEMENT_PRIVILEGED_OPERATION`; and
-  Platform security profile (applicable only to debug builds).

### ARA-M rules provided by the SE

[ARA-M](https://globalplatform.org/specs-library/secure-element-access-control_gpd_spe_013/)
specifies an APDU-based API for retrieving access control rules from the secure element and an
encoding for the rule data.

ARA-M rules consist of two parts: matching criteria and an action.  The matching criteria specify a
host (the Android device) application or system component and an SE applet.  Host applications are
identified by SHA-1 or SHA-256 hashes of the application signing certificate.  Host system
components are identified by UUID.  Because Android system components do not have UUIDs the platform
must provide an XML file specifying how to map platform uids to UUIDs.  See the "UUID mapping"
section below.  Applets are identified by AID.  Wildcards are supported for both host
application/component and applet. The specification includes rules for handling conflicting ARA-M
rules.

The action part of a rule specifies whether the access is allowed and, if so, may optionally specify
a filter that defines the set of APDUs the application is allowed to send to the applet.

Note that although ARA-M rules can also specify whether NFC event messages should be sent to the
specified host application, this OMAPI implemntation does not do anything with that information.
The Java implementation does support notifying clients of NFC events by sending intents, but the
framework API does not expose this functionality so apps shouldn't be able to use it.

### ARA-M rules provided by the platform

The platform can specify rules in the style of ARA-M by placing them in an XML file.  These rules
are appended to the list of rules retrieved from the SE and handled the same as the SE-provided
ARA-M rules, except in one respect: If a client makes an OMAPI request before the SE rules have been
read and if the platform-specified rules authorize the request, the request is carried out without
first retrieving rules from the applet.  This reduces latency for early requests from platform
components.  The first access request that is not authorized by platform rules (or [Android
permission](#android-permission)) will trigger the ARA-M rules to be read.

The platform-provided rules are defined in an XML format that mirrors the ARA-M TLV structure used
to encode the SE-provided rules.  For example:

```xml
<rules>
  <ref-ar-do>         <!-- Each ref-ar-do contains a single rule. -->
    <ref-do>          <!-- First part of a rule is the match criteria, ref-do -->
      <aid-ref-do>    <!-- Match an AID -->
        A00000015141434C00   <!-- AIDs are hex-encoded.  Empty means "all" -->
      </aid-ref-do>
      <deviceappid-ref-do>   <!-- Match a device app hash, 0, 20 or 32 bytes, in hex.
                                  0 bytes means "any app", 20 bytes is a SHA-1 hash or
                                  UUID, 32 bytes is a SHA-256 hash. -->
        00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
      </deviceappid-ref-do>
    </ref-do>

    <ar-do>           <!-- Second part of a rule is the access specification, ar-do -->
      <apdu-ar-do>    <!-- APDU access specification -->
        01            <!-- Content is hex-encoded 0, 1 or filter value. -->
      </apdu-ar-do>
    </ar-do>
  </ref-ar-do>
</rules>
```

To specify rules for a given SE, create an XML file named `se_access_rules_NAME.xml`, replacing
`NAME` with the relevant SE name (e.g. SIM2, ESE6, etc.), and place it in any of the following
locations on the device:

-  /etc/
-  /vendor/etc
-  /odm/etc

### ARA-D rules provided by the SE

[ARA-D](https://globalplatform.org/specs-library/globalplatform-device-technology-device-api-access-control-v1/)
specifies an APDU-based API for retrieving acess control rules from the secure element and an
encoding for the rule data.

ARA-D is similar to ARA-M, but allows host applications to be specified by package name in addition
to certificate hash, and applies to all "sensitive APIs", rather than specifying allowed applets and
APDUs.  Android mostly doesn't know what APIs may be sensitive, so this implementation interprets
ARA-D rules as allowing matching applications full access to all applets on the SE plus permission
to execute privileged ISO commands (MANAGE CHANNEL and SELECT by DF name).  ARA-D rules do not grant
permission to reset the SE.

### Android permission

Android apps with the `SECURE_ELEMENT_PRIVILEGED_OPERATION` permission are allowed full
access to all applets on the SE, and allowed to reset the SE.

### Platform security profile (applicable only to debug builds)

For debuggable builds (userdebug or eng), there are two system properties that affect access
control:

1.  security.seek
2.  persist.security.seek

The service checks the properties in order, using the first available.  The properties contain a
string which can contain one or more of the substrings:

-  "useara".  If present, the service uses ARA-M and ARA-D rules from the SE.  If not present, the
   SE will not use the SE ARA rules.
-  "usearf".  This is not supported and has no effect.
-  "fullaccess".  If present the service will bypass all access control checks.

On production builds the system properties have no effect, ARA rules are always used, and access
control is always enforced.

## UUID mapping

System components in Android do not have UUIDs or signing certificates, but are identified by
their Linux uids, specified in
[android_filesystem_config.h](https://cs.android.com/android/platform/superproject/main/+/main:system/core/libcutils/include/private/android_filesystem_config.h)
Since ARA-M and ARA-D rules need UUIDs as identifiers it's necessary to provide a mapping from uid
to UUID.  This is done with an XML file named `hal_uuid_map_NAME.xml`, with "NAME" replaced with
an appropriate SE name, e.g. SIM3 or ESE6, which must be placed in any of the following
directories on the device:

-  `/etc`
-  `/vendor/etc`
-  `/odm/etc`

The format is simple and self-explanatory, easily understood with an example:

```xml
<ref_do>
  <uuid_ref_do>
    <uids>
      <uid>0</uid>
    </uids>
    <uuid>
      9f36407ead0639fc966f14dde7970f68
    </uuid>
  </uuid_ref_do>

  <uuid_ref_do>
    <uids>
      <uid>2901</uid>
      <uid>2902</uid>
      <uid>2903</uid>
    </uids>
    <uuid>
      636F6D2E6E78702E7365637572697479
    </uuid>
  </uuid_ref_do>
</ref_do>
```

The specified UUID values must be 32-digit hexadecimal numbers, providing 16 bytes.  The OMAPI
implementation will prefix them with 0xFFFFFFFF to produce a 20-byte value.

## Unsupported features

This implementation does not support:

-  Access Rule Files.  Both the ARA-M and ARA-D specifications provide an alternative mechanism for
   secure elements to provide rules, Access Rule Files (ARF).
-  NFC event control.  The ARA-M specification provides a way for rules to specify that a host
   application can be authorized to receive NFC events related to a particular applet.  The prior
   Java implementation did not support this, and neither does this one.  If ARA-M rules contain NFC
   even authorization it is silently ignored.  Should this feature be needed at some point, much of
   the necessary infrastructure is in place.
-  Dynamic addition or removal of terminals.  Note that this is addition or removal of terminals,
   not SEs.  SIMs can be inserted and removed from SIM slot terminals and the service handles this
   correctly.  The Java implementation also supported dynamically adding and removing terminals to
   support devices with dynamic numbers of SIM slots, but it appears that this feature was used on
   only one device which is long out of support -- and which didn't actually have a dynamic number
   of SIM slots but could dynamically update the number of SIM slots that were active and usable
   for some reason.  If it becomes necessary, this feature is non-trivial to add because it
   requires the OMAPI service to be able to receive and react to a broadcast intent, which is
   something that native services can't really do.
-  Blocking on availability of all registered secure element HAL services.  Like the Java
   implementation, this implemention will wait only on ESE1 and SIM1.  Any other registered
   ISecureElement HAL services that are unavailable at the time the OMAPI service starts will be
   ignored.  This seems incorrect but is left as-is pending feedback from partners.

## Code structure overview

The code is divided into two distinct layers, AIDL and implementation.  There is also a main
function, `secure_element_service_main::main` which is responsible for setting up logging,
creating an `android_system_services::AndroidSystemServices` instance and the
`omapi::SecureElementService` instance and starting the threadpool.

### Implementation layer

`terminal::Terminal` is the struct that provides communication with the `ISecureElement` HAL
service and handles the low-level details of APDU validation and error handling.  It also tracks
the "channels" opened with the SE, which allow "concurrent" access to multiple SE applets.  SEs are
single-threaded and can only handle one APDU at a time, but this allows apps to take turns sending
commands.  The channels are SE-level virtual constructs.

`reader::Reader` is the struct that owns the `Terminal`.  It's responsible for host-side
functionality related to the owned terminal, particularly access control. It has an
`access_enforcer::AccessEnforcer` instance which is responsible for managing access control rules
and determining whether a given access is allowed.  `AccessEnforcer` uses the ARA rule parser and
engine found in the `ara` module.  `Reader` also tracks the "sessions" opened with the SE, each of
which represents an app that has an open communication session with the SE.

To do its work, `Reader` needs access to various system functions, which it gets through a
reference to a `system_services::SystemServices` instance.  `SystemServices` provides methods that
allow the caller to retrieve a HAL service by name, get information about binder cliets (the apps
using OMAPI) and get system configuration information.  `SystemServices` is implemented as a trait
mostly to make it easy to mock it for unit testing.  The "real" implementation is found in
`android_system_services::AndroidSystemServices`.

### AIDL layer

The AIDL layer provides the binder interfaces used by the framework (or perhaps by apps directly).

-  `omapi::SecureElementService` provides the
   [`ISecureElementService`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/omapi/aidl/android/se/omapi/ISecureElementService.aidl)
   binder interface.  It is also responsible for enumerating the availalbe readers during startup
   and managing the set of available `Reader` instances.
-  `aidl_reader::AidlReader` provides the
   [`ISecureElementReader`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/omapi/aidl/android/se/omapi/ISecureElementReader.aidl)
   binder interface which is handed to clients when they ask `ISecureElementService` for a
   specific reader.  `AidlReader` contains a reference to the underlying `Mutex`-wrapped
   `Reader`.  This mutex is the point of synchronization that protects concurrent access to the
   underlying `Reader` and everything it contains.
-  `aidl_session::AidlSession` provides the
   [`ISecureElementSession`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/omapi/aidl/android/se/omapi/ISecureElementSession.aidl)
   binder interface which is handed to clients when they ask `ISecureElementReader` for a new
   session.  Like `AidlReader`, `AidlSession` also contains a reference to the underlying
   `Mutex`-wrapped `Reader`, which it uses to communicate with the reader to create channels.
-  `aidl_channel::AidlChannel` provides the
   [`ISecureElementChannel`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/omapi/aidl/android/se/omapi/ISecureElementChannel.aidl)
   binder interface which is handed to clients when they ask `ISecureElementSession` for a new
   channel.  Like `AidlReader` and `AidlSession`, `AidlChannel` also contains reference to the
   underlying `Mutex`-wrapped `Reader`, which it uses to transmit APDUs.  In addition,
    `AidlChannel` sets up a death listener for the client, so it can automatically close the
   underlying SE channel when the client dies.  The death listener holds a weak reference to the
   `Mutex`-wrapped `Reader`.

### Logging

On production builds, log level is set to `log::LevelFilter::Info`, so messages logged with
`info!`, `warn!` and `error!` are written to logcat.

On debug builds, log level is set to `log::LevelFilter::Debug`, so messages logged with `debug!`,
`info!`, `warn!` and `error!` are written to logcat.

If the `log_sensitive_data` feature is enabled in `Android.bp`, log level is set to
`log::LevelFilter::Trace`, so all messages are written to logcat, including those logged with the
`utils::sensitive!` macro.  *This will log sensitive information*, like APDU contents.

Take care to log potentially-sensitive information with the `sensitive!` macro.
