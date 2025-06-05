# Exploit for eneio64.sys Kernel Driver - Turning Physical Memory R/W into Virtual Memory R/W

- This exploit targets [eneio64.sys](https://www.loldrivers.io/drivers/90ecbbf7-b02f-424d-8b7d-56cc9e3b5873/), a vulnerable driver offering read/write primitives on the system's physical memory. The associated CVE is CVE-2020-12446. I'm not the one behind this CVE discovery, all credit goes to [@ihack4falafel](https://github.com/ihack4falafel).
- This exploit targets Windows 11 22H2. Check the ``nt!HalpLMStub`` & `EPROCESS`/`KTHREAD` offsets if you're targeting another Windows version/build.
- eneio64.sys is currently (March 8, 2025) tolerated by HVCI which reinforces the Vulnerable Driver Blocklist. eneio64.sys can be loaded on Windows 11 23H2 and 24H2 as well.
- The main purpose of this exploit is to demonstrate how to map virtual addresses to physical addresses using the same virtual-to-physical translation process as the OS. [A walkthrough of this POC is published here](https://xacone.github.io/eneio-driver.html).
- The exploit presented here enables privilege elevation via token theft.
- For educational purposes only.

---



https://github.com/user-attachments/assets/aa57cb23-4bbf-4b69-995e-beca123c9904

