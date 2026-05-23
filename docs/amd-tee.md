# AMD TEE

Trusted Execution Environment on AMD processors is feasible by a set of related
technologies: SEV, SEV-ES, SEV-SNP - [1]. The whole concept is similar to Intel
TDX although implementation details are very different.

## Host preparation

### BIOS

Enable related features(SMEE, SEV SNP NB, SNP Memory) in machine BIOS. Please
refer to [2] for the details.
NB!
1. BIOS and BMC update migth be required.
2. SNP Memory (RMP Table) Configuration - Enabled (no Custom)

Check dmesg if all the required technologies are enabled e.g.:
[   16.178090] kvm_amd: SEV enabled (ASIDs 32 - 1006)
[   16.178093] kvm_amd: SEV-ES enabled (ASIDs 1 - 31)
[   16.178095] kvm_amd: SEV-SNP enabled (ASIDs 1 - 31)

### Kernel

Update Linux Kernel to the latest available version. 6.12.43+deb12-amd64 was
verified to work.

### SEV Firmware

Check if Secure Processor has latest firmware. Refer to [1] for the actual
versions.

### QEMU

Update Qemu to the latest available version. Qemu 10.1.3 was verified to work.

## KDS

AMD has KDS service to access ARK, ASK, its CRLs and VCEK certificate.  Please
refer to [3] for the details. AMD doesn't provide an analogue to Intels PCCS
service and even HTTP responses explicitly contain 'Cache-Control: no-cache'
header to prevent caching. [3] requires clients to honor HTTP Error Code 429
and Retry-After value. Given that the simplest way is to download ARK, ASK, its
CRL and VCEK on vm init and update CRL by cron.

## Key Sealing

Seal key is used to protect sensitive persistent data used by guest from host
access. The seal key is unique to a combination of: chip unique secret, guest
measurement at the launch, family ID, Image ID, Guest Policy. Please refer to
[4] for the details, "7.2. Key Derivation". This is used as a master key and
various keys are derived from it through KDF.

## RA-TLS

RA-TLS for AMD SEV conceptually is organized the same way as it is for Intel
TDX. The difference is in TLS extensions for self signed certificate. In
addition to extensions which pass nonce and report there is one more that
presents the machine VCEK certificate. This allows to avoid download of
machine's VCEK certificate from KDS while establishing TLS handshake. The
different set of OIDs is used to distinguish AMD vs Intel TEE.


## Links

1. AMD Secure Encrypted Virtualization (SEV) -  https://www.amd.com/en/developer/sev.html
2. Using SEV with AMD EPYC Processors - https://www.amd.com/content/dam/amd/en/documents/developer/58207-using-sev-with-amd-epyc-processors.pdf
3. Versioned Chip Endorsement Key (VCEK) Certificate and KDS Interface Specification - https://docs.amd.com/v/u/en-US/57230
4. SEV Secure Nested Paging Firmware ABI Specification - https://docs.amd.com/v/u/en-US/56860
