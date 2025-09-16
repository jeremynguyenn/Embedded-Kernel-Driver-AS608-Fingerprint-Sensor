#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include "as608.h"

int main() {
    int fd = open("/dev/as608", O_RDWR);
    if (fd < 0) { perror("Open failed"); return 1; }

    as608_status_t status;
    if (ioctl(fd, AS608_IOCTL_GET_IMAGE, &status) < 0) perror("IOCTL failed");

    struct as608_fingerprint_data fp_data = {0};
    if (ioctl(fd, AS608_IOCTL_INPUT_FINGERPRINT, &fp_data) < 0) perror("IOCTL failed");
    printf("Score: %d, Page: %d, Status: %d\n", fp_data.score, fp_data.page_number, fp_data.status);

    struct as608_verify_data verify_data = {0};
    if (ioctl(fd, AS608_IOCTL_VERIFY, &verify_data) < 0) perror("IOCTL failed");
    printf("Found Page: %d, Score: %d, Status: %d\n", verify_data.found_page, verify_data.score, verify_data.status);

    struct as608_delete_data delete_data = {.page_number = 1};
    if (ioctl(fd, AS608_IOCTL_DELETE_FINGERPRINT, &delete_data) < 0) perror("IOCTL failed");

    if (ioctl(fd, AS608_IOCTL_EMPTY_FINGERPRINT, &status) < 0) perror("IOCTL failed");

    struct as608_notepad_data notepad_data = {.page_number = 0};
    memset(notepad_data.data, 0xAA, 32);  // Example input data
    if (ioctl(fd, AS608_IOCTL_WRITE_NOTEPAD, &notepad_data) < 0) perror("IOCTL failed");
    memset(notepad_data.data, 0, 32);  // Clear for read
    if (ioctl(fd, AS608_IOCTL_READ_NOTEPAD, &notepad_data) < 0) perror("IOCTL failed");

    uint32_t randn;
    if (ioctl(fd, AS608_IOCTL_RANDOM, &randn) < 0) perror("IOCTL failed");
    printf("Random: %u\n", randn);

    struct as608_flash_data flash_data = {0};
    if (ioctl(fd, AS608_IOCTL_FLASH_INFORMATION, &flash_data) < 0) perror("IOCTL failed");

    as608_params_t params;
    if (ioctl(fd, AS608_IOCTL_PARAMS, &params) < 0) perror("IOCTL failed");
    printf("Capacity: %d\n", params.capacity);

    struct as608_enroll_data enroll_data = {0};
    if (ioctl(fd, AS608_IOCTL_ENROLL, &enroll_data) < 0) perror("IOCTL failed");

    struct as608_identify_data identify_data = {0};
    if (ioctl(fd, AS608_IOCTL_IDENTIFY, &identify_data) < 0) perror("IOCTL failed");

    struct as608_feature_data feature_data = {.page_number = 1};
    memset(feature_data.buffer, 0xBB, AS608_MAX_BUF_SIZE);  // Example
    feature_data.len = 512;
    if (ioctl(fd, AS608_IOCTL_UPLOAD_FLASH_FEATURE, &feature_data) < 0) perror("IOCTL failed");

    feature_data.len = 512;
    if (ioctl(fd, AS608_IOCTL_UPLOAD_IMAGE_FEATURE, &feature_data) < 0) perror("IOCTL failed");

    if (ioctl(fd, AS608_IOCTL_DOWNLOAD_FLASH_FEATURE, &feature_data) < 0) perror("IOCTL failed");

    struct as608_image_data image_data = {0};
    memset(image_data.buffer, 0xCC, AS608_MAX_BUF_SIZE);
    image_data.len = 256;
    if (ioctl(fd, AS608_IOCTL_UPLOAD_IMAGE, &image_data) < 0) perror("IOCTL failed");

    if (ioctl(fd, AS608_IOCTL_DOWNLOAD_IMAGE, &image_data) < 0) perror("IOCTL failed");

    as608_image_t image_type = AS608_IMAGE_BIN;
    if (ioctl(fd, AS608_IOCTL_GENERATE_BIN_IMAGE, &image_type) < 0) perror("IOCTL failed");

    uint16_t num;
    if (ioctl(fd, AS608_IOCTL_GET_VALID_TEMPLATE_NUM, &num) < 0) perror("IOCTL failed");
    printf("Valid Templates: %d\n", num);

    struct as608_gpio_data gpio_data = {.gpio = AS608_GPIO_NUMBER_0, .input_level = AS608_GPIO_LEVEL_HIGH};
    if (ioctl(fd, AS608_IOCTL_SET_GPIO_LEVEL, &gpio_data) < 0) perror("IOCTL failed");

    struct as608_index_table_data index_data = {.num = 1};
    if (ioctl(fd, AS608_IOCTL_GET_INDEX_TABLE, &index_data) < 0) perror("IOCTL failed");

    uint8_t buf[10] = {0x01, 0x02};
    write(fd, buf, sizeof(buf));
    read(fd, buf, sizeof(buf));

    close(fd);
    return 0;
}