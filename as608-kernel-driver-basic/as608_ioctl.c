#include <linux/ioctl.h>
#include <linux/compat.h>
#include "as608.h"

#define AS608_MAGIC 'A'
#define AS608_IOCTL_GET_IMAGE _IOR(AS608_MAGIC, 1, as608_status_t)
#define AS608_IOCTL_INPUT_FINGERPRINT _IOWR(AS608_MAGIC, 2, struct as608_fingerprint_data)
#define AS608_IOCTL_VERIFY _IOWR(AS608_MAGIC, 3, struct as608_verify_data)
#define AS608_IOCTL_HIGH_SPEED_VERIFY _IOWR(AS608_MAGIC, 4, struct as608_verify_data)
#define AS608_IOCTL_DELETE_FINGERPRINT _IOWR(AS608_MAGIC, 5, struct as608_delete_data)
#define AS608_IOCTL_EMPTY_FINGERPRINT _IOR(AS608_MAGIC, 6, as608_status_t)
#define AS608_IOCTL_WRITE_NOTEPAD _IOW(AS608_MAGIC, 7, struct as608_notepad_data)
#define AS608_IOCTL_READ_NOTEPAD _IOR(AS608_MAGIC, 8, struct as608_notepad_data)
#define AS608_IOCTL_RANDOM _IOR(AS608_MAGIC, 9, uint32_t)
#define AS608_IOCTL_FLASH_INFORMATION _IOWR(AS608_MAGIC, 10, struct as608_flash_data)
#define AS608_IOCTL_PARAMS _IOR(AS608_MAGIC, 11, as608_params_t)
#define AS608_IOCTL_ENROLL _IOWR(AS608_MAGIC, 12, struct as608_enroll_data)
#define AS608_IOCTL_IDENTIFY _IOWR(AS608_MAGIC, 13, struct as608_identify_data)
#define AS608_IOCTL_UPLOAD_FLASH_FEATURE _IOWR(AS608_MAGIC, 14, struct as608_feature_data)
#define AS608_IOCTL_UPLOAD_IMAGE_FEATURE _IOWR(AS608_MAGIC, 15, struct as608_feature_data)
#define AS608_IOCTL_DOWNLOAD_FLASH_FEATURE _IOW(AS608_MAGIC, 16, struct as608_feature_data)
#define AS608_IOCTL_UPLOAD_IMAGE _IOWR(AS608_MAGIC, 17, struct as608_image_data)
#define AS608_IOCTL_DOWNLOAD_IMAGE _IOW(AS608_MAGIC, 18, struct as608_image_data)
#define AS608_IOCTL_GENERATE_BIN_IMAGE _IOW(AS608_MAGIC, 19, as608_image_t)
#define AS608_IOCTL_GET_VALID_TEMPLATE_NUM _IOR(AS608_MAGIC, 20, uint16_t)
#define AS608_IOCTL_SET_GPIO_LEVEL _IOWR(AS608_MAGIC, 21, struct as608_gpio_data)
#define AS608_IOCTL_GET_INDEX_TABLE _IOWR(AS608_MAGIC, 22, struct as608_index_table_data)

long as608_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct as608_dev *dev = file->private_data;
    struct as608_fingerprint_data fp_data;
    struct as608_verify_data verify_data;
    struct as608_delete_data delete_data;
    struct as608_notepad_data notepad_data;
    struct as608_flash_data flash_data;
    as608_params_t params;
    struct as608_enroll_data enroll_data;
    struct as608_identify_data identify_data;
    struct as608_feature_data feature_data;
    struct as608_image_data image_data;
    struct as608_gpio_data gpio_data;
    struct as608_index_table_data index_data;
    uint32_t randn;
    uint16_t num;
    as608_image_t image_type;
    as608_status_t status;
    int res = 0;

    mutex_lock(&dev->lock);
    mod_timer(&dev->timeout_timer, jiffies + msecs_to_jiffies(AS608_TIMEOUT_MS));

    switch (cmd) {
        case AS608_IOCTL_GET_IMAGE:
            res = as608_get_image(dev, &status);
            if (res) goto out;
            if (copy_to_user((void __user *)arg, &status, sizeof(status))) res = -EFAULT;
            break;
        case AS608_IOCTL_INPUT_FINGERPRINT:
            if (copy_from_user(&fp_data, (void __user *)arg, sizeof(fp_data))) { res = -EFAULT; goto out; }
            if (fp_data.page_number > 1000) { res = -EINVAL; goto out; }
            res = as608_input_fingerprint(dev, &fp_data.score, &fp_data.page_number, &fp_data.status);
            if (copy_to_user((void __user *)arg, &fp_data, sizeof(fp_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_VERIFY:
            if (copy_from_user(&verify_data, (void __user *)arg, sizeof(verify_data))) { res = -EFAULT; goto out; }
            res = as608_verify(dev, &verify_data.found_page, &verify_data.score, &verify_data.status);
            if (copy_to_user((void __user *)arg, &verify_data, sizeof(verify_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_HIGH_SPEED_VERIFY:
            if (copy_from_user(&verify_data, (void __user *)arg, sizeof(verify_data))) { res = -EFAULT; goto out; }
            res = as608_high_speed_verify(dev, &verify_data.found_page, &verify_data.score, &verify_data.status);
            if (copy_to_user((void __user *)arg, &verify_data, sizeof(verify_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_DELETE_FINGERPRINT:
            if (copy_from_user(&delete_data, (void __user *)arg, sizeof(delete_data))) { res = -EFAULT; goto out; }
            if (delete_data.page_number >= 1000) { res = -EINVAL; goto out; }
            res = as608_delete_fingerprint(dev, delete_data.page_number, &delete_data.status);
            if (copy_to_user((void __user *)arg, &delete_data, sizeof(delete_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_EMPTY_FINGERPRINT:
            res = as608_empty_fingerprint(dev, &status);
            if (copy_to_user((void __user *)arg, &status, sizeof(status))) res = -EFAULT;
            break;
        case AS608_IOCTL_WRITE_NOTEPAD:
            if (copy_from_user(&notepad_data, (void __user *)arg, sizeof(notepad_data))) { res = -EFAULT; goto out; }
            if (notepad_data.page_number > 31) { res = -EINVAL; goto out; }
            res = as608_write_notepad(dev, notepad_data.page_number, notepad_data.data, &notepad_data.status);
            if (copy_to_user((void __user *)arg, &notepad_data, sizeof(notepad_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_READ_NOTEPAD:
            if (copy_from_user(&notepad_data, (void __user *)arg, sizeof(notepad_data))) { res = -EFAULT; goto out; }
            if (notepad_data.page_number > 31) { res = -EINVAL; goto out; }
            res = as608_read_notepad(dev, notepad_data.page_number, notepad_data.data, &notepad_data.status);
            if (copy_to_user((void __user *)arg, &notepad_data, sizeof(notepad_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_RANDOM:
            res = as608_random(dev, &randn, &status);
            if (copy_to_user((void __user *)arg, &randn, sizeof(randn))) res = -EFAULT;
            break;
        case AS608_IOCTL_FLASH_INFORMATION:
            if (copy_from_user(&flash_data, (void __user *)arg, sizeof(flash_data))) { res = -EFAULT; goto out; }
            if (flash_data.output_len > AS608_MAX_BUF_SIZE) { res = -EINVAL; goto out; }
            res = as608_flash_information(dev, flash_data.output_buffer, &flash_data.output_len, &flash_data.status);
            if (copy_to_user((void __user *)arg, &flash_data, sizeof(flash_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_PARAMS:
            res = as608_params(dev, &params, &status);
            if (copy_to_user((void __user *)arg, &params, sizeof(params))) res = -EFAULT;
            break;
        case AS608_IOCTL_ENROLL:
            if (copy_from_user(&enroll_data, (void __user *)arg, sizeof(enroll_data))) { res = -EFAULT; goto out; }
            if (enroll_data.page_number >= 1000) { res = -EINVAL; goto out; }
            res = as608_enroll(dev, &enroll_data.page_number, &enroll_data.status);
            if (copy_to_user((void __user *)arg, &enroll_data, sizeof(enroll_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_IDENTIFY:
            if (copy_from_user(&identify_data, (void __user *)arg, sizeof(identify_data))) { res = -EFAULT; goto out; }
            res = as608_identify(dev, &identify_data.page_number, &identify_data.score, &identify_data.status);
            if (copy_to_user((void __user *)arg, &identify_data, sizeof(identify_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_UPLOAD_FLASH_FEATURE:
            if (copy_from_user(&feature_data, (void __user *)arg, sizeof(feature_data))) { res = -EFAULT; goto out; }
            if (feature_data.len > AS608_MAX_BUF_SIZE || feature_data.page_number >= 1000) { res = -EINVAL; goto out; }
            res = as608_upload_flash_feature(dev, feature_data.page_number, feature_data.buffer, &feature_data.len, &feature_data.status);
            if (copy_to_user((void __user *)arg, &feature_data, sizeof(feature_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_UPLOAD_IMAGE_FEATURE:
            if (copy_from_user(&feature_data, (void __user *)arg, sizeof(feature_data))) { res = -EFAULT; goto out; }
            if (feature_data.len > AS608_MAX_BUF_SIZE) { res = -EINVAL; goto out; }
            res = as608_upload_image_feature(dev, feature_data.buffer, &feature_data.len, &feature_data.status);
            if (copy_to_user((void __user *)arg, &feature_data, sizeof(feature_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_DOWNLOAD_FLASH_FEATURE:
            if (copy_from_user(&feature_data, (void __user *)arg, sizeof(feature_data))) { res = -EFAULT; goto out; }
            if (feature_data.len > AS608_MAX_BUF_SIZE || feature_data.page_number >= 1000) { res = -EINVAL; goto out; }
            res = as608_download_flash_feature(dev, feature_data.page_number, feature_data.buffer, feature_data.len, &feature_data.status);
            if (copy_to_user((void __user *)arg, &feature_data, sizeof(feature_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_UPLOAD_IMAGE:
            if (copy_from_user(&image_data, (void __user *)arg, sizeof(image_data))) { res = -EFAULT; goto out; }
            if (image_data.len > AS608_MAX_BUF_SIZE) { res = -EINVAL; goto out; }
            res = as608_upload_image(dev, image_data.buffer, &image_data.len, &image_data.status);
            if (copy_to_user((void __user *)arg, &image_data, sizeof(image_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_DOWNLOAD_IMAGE:
            if (copy_from_user(&image_data, (void __user *)arg, sizeof(image_data))) { res = -EFAULT; goto out; }
            if (image_data.len > AS608_MAX_BUF_SIZE || image_data.page_number >= 1000) { res = -EINVAL; goto out; }
            res = as608_download_image(dev, image_data.page_number, image_data.buffer, image_data.len, &image_data.status);
            if (copy_to_user((void __user *)arg, &image_data, sizeof(image_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_GENERATE_BIN_IMAGE:
            if (copy_from_user(&image_type, (void __user *)arg, sizeof(image_type))) { res = -EFAULT; goto out; }
            res = as608_generate_bin_image(dev, image_type, &status);
            break;
        case AS608_IOCTL_GET_VALID_TEMPLATE_NUM:
            res = as608_get_valid_template_num(dev, &num, &status);
            if (copy_to_user((void __user *)arg, &num, sizeof(num))) res = -EFAULT;
            break;
        case AS608_IOCTL_SET_GPIO_LEVEL:
            if (copy_from_user(&gpio_data, (void __user *)arg, sizeof(gpio_data))) { res = -EFAULT; goto out; }
            if (gpio_data.gpio > AS608_GPIO_NUMBER_1) { res = -EINVAL; goto out; }
            res = as608_set_gpio_level(dev, gpio_data.gpio, gpio_data.input_level, &gpio_data.output_level, &gpio_data.status);
            if (copy_to_user((void __user *)arg, &gpio_data, sizeof(gpio_data))) res = -EFAULT;
            break;
        case AS608_IOCTL_GET_INDEX_TABLE:
            if (copy_from_user(&index_data, (void __user *)arg, sizeof(index_data))) { res = -EFAULT; goto out; }
            if (index_data.num > 3) { res = -EINVAL; goto out; }
            res = as608_get_index_table(dev, index_data.num, index_data.table, &index_data.status);
            if (copy_to_user((void __user *)arg, &index_data, sizeof(index_data))) res = -EFAULT;
            break;
        default:
            res = -ENOTTY;
    }

out:
    del_timer_sync(&dev->timeout_timer);
    mutex_unlock(&dev->lock);
    return res ? -EIO : 0;
}