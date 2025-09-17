# AS608 Fingerprint Sensor Driver

This repository provides a Linux kernel module driver for the AS608 optical fingerprint sensor. The AS608 is a low-cost, compact fingerprint module commonly used in embedded systems for biometric authentication. It communicates via UART and supports operations like capturing fingerprint images, extracting features, storing templates, matching fingerprints, and more. This driver exposes the sensor as a character device (`/dev/as608`) for user-space interaction, using read/write for raw data and ioctl for specific commands.

The driver is designed for platforms like Raspberry Pi (using device tree overlays) and assumes a UART connection. It handles interrupts, timeouts, and sysfs attributes for configuration.

## Features

The AS608 sensor and this driver support the following functionalities:
- **Image Capture**: Collect raw fingerprint images.
- **Feature Extraction**: Generate characteristic data from images (e.g., using buffers 1 or 2).
- **Matching and Searching**: Compare fingerprints for verification or identification, with high-speed search options.
- **Template Management**: Store, load, upload, download, and delete fingerprint templates (up to 1000 templates).
- **Notepad Operations**: Read/write to the module's internal notepad (32 bytes per page, up to 32 pages).
- **System Parameters**: Read/write module parameters like baud rate, security level, packet size.
- **Random Number Generation**: Generate pseudo-random numbers.
- **Flash Information**: Retrieve flash memory details.
- **GPIO Control**: Set and read GPIO levels (limited to 2 GPIOs).
- **Index Table**: Get fingerprint index tables.
- **Enrollment and Identification**: Simplified workflows for registering and identifying fingerprints.
- **Image and Feature Upload/Download**: Transfer binary images or features to/from the module.
- **Error Handling**: Comprehensive status codes (e.g., no fingerprint detected, match failure).

The driver uses UART for communication, supports baud rate configuration via sysfs, and handles timeouts with a timer. It includes interrupt-driven reading for efficient data handling.

## Code Structure

The code is organized as a Linux kernel module with multiple source files for modularity. It uses standard kernel APIs for device drivers, including platform drivers, misc devices, workqueues, timers, interrupts, mutexes, and completions. The module registers as a platform driver matching the "synochip,as608" compatible string in the device tree.

### File Explanations

- **as608_core.c**: Core driver file handling module initialization, probe/remove for platform devices, and character device setup (`/dev/as608`) using `misc_register`. Defines file operations (`fops`) for open, release, read, write, poll, and ioctl.
  - Knowledge: Kernel device model (`platform_driver`, `of_device_id`), interrupt handling (`request_irq`), workqueues (`alloc_workqueue`), timers (`timer_setup`), mutexes, completions, UART port retrieval (`serial8250_get_port`).

- **as608_sysfs.c**: Manages sysfs attributes for runtime configuration, exposing a `baud_rate` attribute to read/set UART baud rate.
  - Knowledge: Sysfs API (`sysfs_create_group`, `DEVICE_ATTR_RW`), string parsing (`kstrtoul`), UART configuration.

- **as608.h**: Header file with constants, enums, structs, and function prototypes for commands, status codes (e.g., `AS608_STATUS_OK`), and ioctl data structures (e.g., `as608_fingerprint_data`).
  - Knowledge: Kernel types, enums for readability, macro definitions (e.g., `AS608_MAX_BUF_SIZE`).

- **as608_uart.c**: Implements low-level UART operations, including driver registration and functions for reading, writing, and configuring the port.
  - Knowledge: Serial core APIs (`uart_register_driver`, `inb/outb`), baud rate calculation, line control register setup.

- **as608_user.c**: User-space example program demonstrating driver interaction. Opens `/dev/as608`, issues ioctls for sensor operations, and prints results. Shows raw read/write usage.
  - Knowledge: C libraries (`open`, `ioctl`, `read`, `write`), error handling (`perror`), struct initialization.

- **as608_commands.c**: Implements AS608-specific commands (e.g., `as608_get_image`, `as608_verify`). Handles frame encoding/decoding, checksums, and response parsing.
  - Knowledge: Protocol handling (header `0xEF 0x01`, checksum), timeout waits (`wait_for_completion_timeout`), error checking.

- **as608.dts**: Device tree overlay for Raspberry Pi (BCM2711), enabling UART0 and adding an `as608` node with compatible string and baud rate.
  - Knowledge: Device tree syntax, fragments, overlays, pinctrl for UART pins.

- **as608_ioctl.c**: Handles ioctl commands from user space, defining magic numbers and validating inputs (e.g., page numbers < 1000).
  - Knowledge: Ioctl API (`_IOR`, `_IOW`, `_IOWR`), safe data transfer (`copy_to/from_user`), input validation.

- **Makefile**: Builds the kernel module (`as608.ko`), with targets for install (insmod, mknod) and uninstall (rmmod, rm).
  - Knowledge: Kernel build system (`obj-m`, `KDIR`), module compilation, device node creation.

## Installation for Raspberry Pi

To install the AS608 driver on a Raspberry Pi, follow these steps:

### Step 1: Navigate to the `/boot` Directory
Access the Raspberry Pi's boot directory:
```
cd /boot
```

### Step 2: Convert Device Tree Blob to Source
Convert the appropriate `.dtb` file for your Raspberry Pi model to a `.dts` file:
```
dtc -I dtb -O dts -o bcm2711-rpi-4-b.dts bcm2711-rpi-4-b.dtb
```
**Note**: Replace `bcm2711-rpi-4-b.dtb` with the `.dtb` file for your Raspberry Pi model (e.g., `bcm2710-rpi-3-b.dtb` for Raspberry Pi 3).

### Step 3: Edit the Device Tree Source
Open the generated `.dts` file (e.g., `bcm2711-rpi-4-b.dts`) in a text editor. Locate the UART0 section (search for `uart0`) and ensure it is enabled:
```
&uart0 {
    pinctrl-0 = <&uart0_pins>;
    pinctrl-names = "default";
    status = "okay";
};
```
Add the AS608 node under the root (`/`):
```
/ {
    as608@0 {
        compatible = "synochip,as608";
        reg = <0>;
        baud-rate = <57600>;
        status = "okay";
    };
};
```

### Step 4: Recompile and Apply Device Tree
Recompile the `.dts` file back to `.dtb`:
```
dtc -I dts -O dtb -o bcm2711-rpi-4-b.dtb bcm2711-rpi-4-b.dts
```
Reboot the Raspberry Pi to apply changes:
```
sudo reboot
```
Alternatively, apply the provided `as608.dts` as an overlay:
```
dtc -@ -I dts -O dtb -o as608.dtbo as608.dts
sudo cp as608.dtbo /boot/overlays/
```
Edit `/boot/config.txt` to include:
```
dtoverlay=as608
```
Reboot:
```
sudo reboot
```

### Step 5: Build and Install the Driver
1. Ensure the kernel headers are installed:
   ```
   sudo apt install linux-headers-$(uname -r)
   ```
2. In the driver directory, build the module:
   ```
   make
   ```
   This generates `as608.ko`.
3. Install the module:
   ```
   sudo insmod as608.ko
   sudo mknod /dev/as608 c 10 $(grep as608 /proc/misc | awk '{print $1}')
   ```
4. Check installation status:
   ```
   dmesg | grep AS608
   ```
   Look for "AS608: Probed" to confirm success.
5. To remove the driver:
   ```
   sudo rmmod as608
   sudo rm /dev/as608
   ```

## Build

To build all artifacts:
```
make all
```
To build only the kernel module:
```
make driver
```
To build the test application:
```
make app
```
To clean generated files (except sources):
```
make clean
```
To clean all files (except sources and artifacts):
```
make cleanall
```

## Usage

1. **Kernel Module Usage**:
   - Interact with `/dev/as608` using read/write for raw UART data or ioctl for commands (see `as608.h`).
   - Configure baud rate via sysfs:
     ```
     echo 9600 > /sys/devices/platform/as608/baud_rate
     ```
     Check the exact sysfs path with `ls /sys`.

2. **User-Space Example**:
   - Compile the example:
     ```
     gcc as608_user.c -o as608_test
     ```
   - Run:
     ```
     ./as608_test
     ```
   - This executes operations like image capture, verification, and enrollment, printing results.

3. **Custom Applications**:
   - Include `as608.h` in your C program.
   - Open `/dev/as608` with `O_RDWR`.
   - Use structs (e.g., `struct as608_verify_data`) and call `ioctl(fd, AS608_IOCTL_VERIFY, &data)`.
   - Handle status codes in responses.

## Expected Results

With the AS608 sensor connected (UART TX/RX, IRQ pin) and a fingerprint placed when required:
- **Successful Operations**:
  - `AS608_IOCTL_GET_IMAGE`: Returns `AS608_STATUS_OK` if a fingerprint is detected.
  - `AS608_IOCTL_VERIFY`: If matching, `status = AS608_STATUS_OK`, `score` > 0 (e.g., 100-300), `found_page` indicates template ID.
  - `AS608_IOCTL_ENROLL`: Assigns a `page_number` with `status = AS608_STATUS_OK` after multiple presses.
  - `AS608_IOCTL_RANDOM`: Returns a random `uint32_t` (e.g., 123456789).
  - `AS608_IOCTL_PARAMS`: Returns `capacity = 1000`, `baud_rate = 57600`, etc.
  - `AS608_IOCTL_GET_VALID_TEMPLATE_NUM`: Returns `num` > 0 if templates are stored.

- **Error Cases**:
  - No fingerprint: `AS608_STATUS_NO_FINGERPRINT`.
  - Poor image: `AS608_STATUS_IMAGE_TOO_DRY` or `AS608_STATUS_IMAGE_TOO_CLUTTER`.
  - No match: `AS608_STATUS_NOT_MATCH` or `AS608_STATUS_NOT_FOUND`.
  - Invalid inputs: Ioctl returns -EINVAL or -EFAULT.
  - Timeout: Logs "AS608: Timeout occurred" and returns -EIO.

Example output from `as608_test`:
```
Score: 150, Page: 1, Status: 0
Found Page: 1, Score: 150, Status: 0
Random: 123456789
Capacity: 1000
Valid Templates: 5
```
Results depend on hardware and fingerprints. Check `dmesg` for errors if the sensor doesn't respond.