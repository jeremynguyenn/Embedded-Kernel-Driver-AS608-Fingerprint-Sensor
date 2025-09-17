#include <linux/ioctl.h>
#include <linux/compat.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h>
#include "as608.h"

/* IOCTL handler for AS608 driver.
 * Provides user-space interface for controlling fingerprint sensor operations.
 */
/* Wait queue for IOCTL operations */
static DECLARE_WAIT_QUEUE_HEAD(ioctl_wait);

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
    as608_status_t *status = NULL;
    struct as608_fingerprint_data *fp_data = NULL;
    struct as608_verify_data *verify_data = NULL;
    struct as608_delete_data *delete_data = NULL;
    struct as608_notepad_data *notepad_data = NULL;
    uint32_t *randn = NULL;
    struct as608_flash_data *flash_data = NULL;
    as608_params_t *params = NULL;
    struct as608_enroll_data *enroll_data = NULL;
    struct as608_identify_data *identify_data = NULL;
    struct as608_feature_data *feature_data = NULL;
    struct as608_image_data *image_data = NULL;
    as608_image_t *image_type = NULL;
    uint16_t *num = NULL;
    struct as608_gpio_data *gpio_data = NULL;
    struct as608_index_table_data *index_data = NULL;
    long res = 0;
    unsigned long flags;

    spin_lock_irqsave(&dev->fast_lock, flags);
    switch (cmd) {
        case AS608_IOCTL_GET_IMAGE:
            status = kmalloc(sizeof(as608_status_t), GFP_KERNEL);
            if (!status) { res = -ENOMEM; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_get_image(dev, status);
            if (copy_to_user((void __user *)arg, status, sizeof(*status))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_INPUT_FINGERPRINT:
            fp_data = kmalloc(sizeof(struct as608_fingerprint_data), GFP_KERNEL);
            if (!fp_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(fp_data, (void __user *)arg, sizeof(*fp_data))) { res = -EFAULT; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_input_fingerprint(dev, &fp_data->score, &fp_data->page_number, &fp_data->status);
            if (copy_to_user((void __user *)arg, fp_data, sizeof(*fp_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_VERIFY:
            verify_data = kmalloc(sizeof(struct as608_verify_data), GFP_KERNEL);
            if (!verify_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(verify_data, (void __user *)arg, sizeof(*verify_data))) { res = -EFAULT; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_verify(dev, &verify_data->found_page, &verify_data->score, &verify_data->status);
            if (copy_to_user((void __user *)arg, verify_data, sizeof(*verify_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_HIGH_SPEED_VERIFY:
            verify_data = kmalloc(sizeof(struct as608_verify_data), GFP_KERNEL);
            if (!verify_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(verify_data, (void __user *)arg, sizeof(*verify_data))) { res = -EFAULT; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_high_speed_verify(dev, &verify_data->found_page, &verify_data->score, &verify_data->status);
            if (copy_to_user((void __user *)arg, verify_data, sizeof(*verify_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_DELETE_FINGERPRINT:
            delete_data = kmalloc(sizeof(struct as608_delete_data), GFP_KERNEL);
            if (!delete_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(delete_data, (void __user *)arg, sizeof(*delete_data))) { res = -EFAULT; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_delete_fingerprint(dev, delete_data->page_number, &delete_data->status);
            if (copy_to_user((void __user *)arg, delete_data, sizeof(*delete_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_EMPTY_FINGERPRINT:
            status = kmalloc(sizeof(as608_status_t), GFP_KERNEL);
            if (!status) { res = -ENOMEM; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_empty_fingerprint(dev, status);
            if (copy_to_user((void __user *)arg, status, sizeof(*status))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_WRITE_NOTEPAD:
            notepad_data = kmalloc(sizeof(struct as608_notepad_data), GFP_KERNEL);
            if (!notepad_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(notepad_data, (void __user *)arg, sizeof(*notepad_data))) { res = -EFAULT; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_write_notepad(dev, notepad_data->page_number, notepad_data->data, &notepad_data->status);
            if (copy_to_user((void __user *)arg, notepad_data, sizeof(*notepad_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_READ_NOTEPAD:
            notepad_data = kmalloc(sizeof(struct as608_notepad_data), GFP_KERNEL);
            if (!notepad_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(notepad_data, (void __user *)arg, sizeof(*notepad_data))) { res = -EFAULT; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_read_notepad(dev, notepad_data->page_number, notepad_data->data, &notepad_data->status);
            if (copy_to_user((void __user *)arg, notepad_data, sizeof(*notepad_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_RANDOM:
            randn = kmalloc(sizeof(uint32_t), GFP_KERNEL);
            if (!randn) { res = -ENOMEM; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_random(dev, randn, status);
            if (copy_to_user((void __user *)arg, randn, sizeof(*randn))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_FLASH_INFORMATION:
            flash_data = kmalloc(sizeof(struct as608_flash_data), GFP_KERNEL);
            if (!flash_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(flash_data, (void __user *)arg, sizeof(*flash_data))) { res = -EFAULT; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_flash_information(dev, flash_data->output_buffer, &flash_data->output_len, &flash_data->status);
            if (copy_to_user((void __user *)arg, flash_data, sizeof(*flash_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_PARAMS:
            params = kmalloc(sizeof(as608_params_t), GFP_KERNEL);
            if (!params) { res = -ENOMEM; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_params(dev, params, status);
            if (copy_to_user((void __user *)arg, params, sizeof(*params))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_ENROLL:
            enroll_data = kmalloc(sizeof(struct as608_enroll_data), GFP_KERNEL);
            if (!enroll_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(enroll_data, (void __user *)arg, sizeof(*enroll_data))) { res = -EFAULT; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_enroll(dev, &enroll_data->page_number, &enroll_data->status);
            if (copy_to_user((void __user *)arg, enroll_data, sizeof(*enroll_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_IDENTIFY:
            identify_data = kmalloc(sizeof(struct as608_identify_data), GFP_KERNEL);
            if (!identify_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(identify_data, (void __user *)arg, sizeof(*identify_data))) { res = -EFAULT; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_identify(dev, &identify_data->page_number, &identify_data->score, &identify_data->status);
            if (copy_to_user((void __user *)arg, identify_data, sizeof(*identify_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_UPLOAD_FLASH_FEATURE:
            feature_data = kmalloc(sizeof(struct as608_feature_data), GFP_KERNEL);
            if (!feature_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(feature_data, (void __user *)arg, sizeof(*feature_data))) { res = -EFAULT; goto out_signal; }
            if (feature_data->len > AS608_MAX_BUF_SIZE) { res = -EINVAL; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_upload_flash_feature(dev, feature_data->page_number, feature_data->buffer, &feature_data->len, &feature_data->status);
            if (copy_to_user((void __user *)arg, feature_data, sizeof(*feature_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_UPLOAD_IMAGE_FEATURE:
            feature_data = kmalloc(sizeof(struct as608_feature_data), GFP_KERNEL);
            if (!feature_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(feature_data, (void __user *)arg, sizeof(*feature_data))) { res = -EFAULT; goto out_signal; }
            if (feature_data->len > AS608_MAX_BUF_SIZE) { res = -EINVAL; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_upload_image_feature(dev, feature_data->buffer, &feature_data->len, &feature_data->status);
            if (copy_to_user((void __user *)arg, feature_data, sizeof(*feature_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_DOWNLOAD_FLASH_FEATURE:
            feature_data = kmalloc(sizeof(struct as608_feature_data), GFP_KERNEL);
            if (!feature_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(feature_data, (void __user *)arg, sizeof(*feature_data))) { res = -EFAULT; goto out_signal; }
            if (feature_data->len > AS608_MAX_BUF_SIZE) { res = -EINVAL; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_download_flash_feature(dev, feature_data->page_number, feature_data->buffer, feature_data->len, &feature_data->status);
            if (copy_to_user((void __user *)arg, feature_data, sizeof(*feature_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_UPLOAD_IMAGE:
            image_data = kmalloc(sizeof(struct as608_image_data), GFP_KERNEL);
            if (!image_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(image_data, (void __user *)arg, sizeof(*image_data))) { res = -EFAULT; goto out_signal; }
            if (image_data->len > AS608_MAX_BUF_SIZE) { res = -EINVAL; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_upload_image(dev, image_data->buffer, &image_data->len, &image_data->status);
            if (copy_to_user((void __user *)arg, image_data, sizeof(*image_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_DOWNLOAD_IMAGE:
            image_data = kmalloc(sizeof(struct as608_image_data), GFP_KERNEL);
            if (!image_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(image_data, (void __user *)arg, sizeof(*image_data))) { res = -EFAULT; goto out_signal; }
            if (image_data->len > AS608_MAX_BUF_SIZE) { res = -EINVAL; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_download_image(dev, image_data->page_number, image_data->buffer, image_data->len, &image_data->status);
            if (copy_to_user((void __user *)arg, image_data, sizeof(*image_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_GENERATE_BIN_IMAGE:
            image_type = kmalloc(sizeof(as608_image_t), GFP_KERNEL);
            if (!image_type) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(image_type, (void __user *)arg, sizeof(*image_type))) { res = -EFAULT; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_generate_bin_image(dev, *image_type, status);
            if (copy_to_user((void __user *)arg, image_type, sizeof(*image_type))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_GET_VALID_TEMPLATE_NUM:
            num = kmalloc(sizeof(uint16_t), GFP_KERNEL);
            if (!num) { res = -ENOMEM; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_get_valid_template_num(dev, num, status);
            if (copy_to_user((void __user *)arg, num, sizeof(*num))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_SET_GPIO_LEVEL:
            gpio_data = kmalloc(sizeof(struct as608_gpio_data), GFP_KERNEL);
            if (!gpio_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(gpio_data, (void __user *)arg, sizeof(*gpio_data))) { res = -EFAULT; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_set_gpio_level(dev, gpio_data->gpio, gpio_data->input_level, &gpio_data->output_level, &gpio_data->status);
            if (copy_to_user((void __user *)arg, gpio_data, sizeof(*gpio_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_GET_INDEX_TABLE:
            index_data = kmalloc(sizeof(struct as608_index_table_data), GFP_KERNEL);
            if (!index_data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(index_data, (void __user *)arg, sizeof(*index_data))) { res = -EFAULT; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_get_index_table(dev, index_data->num, index_data->table, &index_data->status);
            if (copy_to_user((void __user *)arg, index_data, sizeof(*index_data))) res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        default:
            res = -EINVAL;
            goto out_signal;
    }

    wake_up_all(&ioctl_wait);
    spin_unlock_irqrestore(&dev->fast_lock, flags);
    kfree(fp_data);
    kfree(verify_data);
    kfree(delete_data);
    kfree(notepad_data);
    kfree(flash_data);
    kfree(params);
    kfree(enroll_data);
    kfree(identify_data);
    kfree(feature_data);
    kfree(image_data);
    kfree(gpio_data);
    kfree(index_data);
    kfree(randn);
    kfree(num);
    kfree(image_type);
    kfree(status);
    return res;

out_signal:
    send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
    spin_unlock_irqrestore(&dev->fast_lock, flags);
    kfree(fp_data);
    kfree(verify_data);
    kfree(delete_data);
    kfree(notepad_data);
    kfree(flash_data);
    kfree(params);
    kfree(enroll_data);
    kfree(identify_data);
    kfree(feature_data);
    kfree(image_data);
    kfree(gpio_data);
    kfree(index_data);
    kfree(randn);
    kfree(num);
    kfree(image_type);
    kfree(status);
    return res;
}