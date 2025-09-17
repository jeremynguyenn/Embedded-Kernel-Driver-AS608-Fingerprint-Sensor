#include <linux/ioctl.h>
#include <linux/compat.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h>
#include "as608.h"
#include <linux/capability.h>  // For capable

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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
    void *data = NULL;
    long res = 0;
    unsigned long flags;

    if (!dev || !dev->uart_port) {
        pr_err("IOCTL: Invalid device or UART port\n");
        return -ENODEV;
    }

    spin_lock_irqsave(&dev->fast_lock, flags);
    switch (cmd) {
        case AS608_IOCTL_GET_IMAGE:
            data = kmalloc(sizeof(as608_status_t), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_get_image(dev, data);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(as608_status_t)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_INPUT_FINGERPRINT:
            data = kmalloc(sizeof(struct as608_fingerprint_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_fingerprint_data))) {
                res = -EFAULT; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_input_fingerprint(dev, &((struct as608_fingerprint_data *)data)->score,
                                          &((struct as608_fingerprint_data *)data)->page_number,
                                          &((struct as608_fingerprint_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_fingerprint_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_VERIFY:
            data = kmalloc(sizeof(struct as608_verify_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_verify_data))) {
                res = -EFAULT; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_verify(dev, &((struct as608_verify_data *)data)->found_page,
                               &((struct as608_verify_data *)data)->score,
                               &((struct as608_verify_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_verify_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_HIGH_SPEED_VERIFY:
            data = kmalloc(sizeof(struct as608_verify_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_verify_data))) {
                res = -EFAULT; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_high_speed_verify(dev, &((struct as608_verify_data *)data)->found_page,
                                          &((struct as608_verify_data *)data)->score,
                                          &((struct as608_verify_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_verify_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_DELETE_FINGERPRINT:
            data = kmalloc(sizeof(struct as608_delete_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_delete_data))) {
                res = -EFAULT; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_delete_fingerprint(dev, ((struct as608_delete_data *)data)->page_number,
                                           &((struct as608_delete_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_delete_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_EMPTY_FINGERPRINT:
            data = kmalloc(sizeof(as608_status_t), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_empty_fingerprint(dev, data);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(as608_status_t)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_WRITE_NOTEPAD:
            data = kmalloc(sizeof(struct as608_notepad_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_notepad_data))) {
                res = -EFAULT; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_write_notepad(dev, ((struct as608_notepad_data *)data)->page_number,
                                      ((struct as608_notepad_data *)data)->data,
                                      &((struct as608_notepad_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_notepad_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_READ_NOTEPAD:
            data = kmalloc(sizeof(struct as608_notepad_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_notepad_data))) {
                res = -EFAULT; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_read_notepad(dev, ((struct as608_notepad_data *)data)->page_number,
                                     ((struct as608_notepad_data *)data)->data,
                                     &((struct as608_notepad_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_notepad_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_RANDOM:
            data = kmalloc(sizeof(uint32_t), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_random(dev, data, status); // Assume status is defined locally if needed
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(uint32_t)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_FLASH_INFORMATION:
            data = kmalloc(sizeof(struct as608_flash_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_flash_data))) {
                res = -EFAULT; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_flash_information(dev, ((struct as608_flash_data *)data)->output_buffer,
                                          &((struct as608_flash_data *)data)->output_len,
                                          &((struct as608_flash_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_flash_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_PARAMS:
            data = kmalloc(sizeof(as608_params_t), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_params(dev, data, status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(as608_params_t)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_ENROLL:
            data = kmalloc(sizeof(struct as608_enroll_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_enroll_data))) {
                res = -EFAULT; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_enroll(dev, &((struct as608_enroll_data *)data)->page_number,
                               &((struct as608_enroll_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_enroll_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_IDENTIFY:
            data = kmalloc(sizeof(struct as608_identify_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_identify_data))) {
                res = -EFAULT; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_identify(dev, &((struct as608_identify_data *)data)->page_number,
                                 &((struct as608_identify_data *)data)->score,
                                 &((struct as608_identify_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_identify_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_UPLOAD_FLASH_FEATURE:
            data = kmalloc(sizeof(struct as608_feature_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_feature_data))) {
                res = -EFAULT; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_upload_flash_feature(dev, ((struct as608_feature_data *)data)->page_number,
                                             ((struct as608_feature_data *)data)->buffer,
                                             &((struct as608_feature_data *)data)->len,
                                             &((struct as608_feature_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_feature_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_UPLOAD_IMAGE_FEATURE:
            data = kmalloc(sizeof(struct as608_feature_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_feature_data))) {
                res = -EFAULT; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_upload_image_feature(dev, ((struct as608_feature_data *)data)->buffer,
                                             &((struct as608_feature_data *)data)->len,
                                             &((struct as608_feature_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_feature_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_DOWNLOAD_FLASH_FEATURE:
            data = kmalloc(sizeof(struct as608_feature_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_feature_data))) {
                res = -EFAULT; goto out_signal;
            }
            if (((struct as608_feature_data *)data)->len > AS608_MAX_BUF_SIZE) {
                res = -EINVAL; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_download_flash_feature(dev, ((struct as608_feature_data *)data)->page_number,
                                               ((struct as608_feature_data *)data)->buffer,
                                               ((struct as608_feature_data *)data)->len,
                                               &((struct as608_feature_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_feature_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_UPLOAD_IMAGE:
            data = kmalloc(sizeof(struct as608_image_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_image_data))) {
                res = -EFAULT; goto out_signal;
            }
            if (((struct as608_image_data *)data)->len > AS608_MAX_BUF_SIZE) {
                res = -EINVAL; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_upload_image(dev, ((struct as608_image_data *)data)->buffer,
                                     &((struct as608_image_data *)data)->len,
                                     &((struct as608_image_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_image_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_DOWNLOAD_IMAGE:
            data = kmalloc(sizeof(struct as608_image_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_image_data))) {
                res = -EFAULT; goto out_signal;
            }
            if (((struct as608_image_data *)data)->len > AS608_MAX_BUF_SIZE) {
                res = -EINVAL; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_download_image(dev, ((struct as608_image_data *)data)->page_number,
                                       ((struct as608_image_data *)data)->buffer,
                                       ((struct as608_image_data *)data)->len,
                                       &((struct as608_image_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_image_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_GENERATE_BIN_IMAGE:
            data = kmalloc(sizeof(as608_image_t), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(as608_image_t))) {
                res = -EFAULT; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_generate_bin_image(dev, *(as608_image_t *)data, status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(as608_image_t)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_GET_VALID_TEMPLATE_NUM:
            data = kmalloc(sizeof(uint16_t), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            mutex_lock(&dev->lock);
            res = as608_get_valid_template_num(dev, data, status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(uint16_t)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_SET_GPIO_LEVEL:
            data = kmalloc(sizeof(struct as608_gpio_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_gpio_data))) {
                res = -EFAULT; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_set_gpio_level(dev, ((struct as608_gpio_data *)data)->gpio,
                                       ((struct as608_gpio_data *)data)->input_level,
                                       &((struct as608_gpio_data *)data)->output_level,
                                       &((struct as608_gpio_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_gpio_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        case AS608_IOCTL_GET_INDEX_TABLE:
            data = kmalloc(sizeof(struct as608_index_table_data), GFP_KERNEL);
            if (!data) { res = -ENOMEM; goto out_signal; }
            if (copy_from_user(data, (void __user *)arg, sizeof(struct as608_index_table_data))) {
                res = -EFAULT; goto out_signal;
            }
            mutex_lock(&dev->lock);
            res = as608_get_index_table(dev, ((struct as608_index_table_data *)data)->num,
                                        ((struct as608_index_table_data *)data)->table,
                                        &((struct as608_index_table_data *)data)->status);
            if (res == 0 && copy_to_user((void __user *)arg, data, sizeof(struct as608_index_table_data)))
                res = -EFAULT;
            mutex_unlock(&dev->lock);
            break;
        default:
            pr_err("IOCTL: Invalid command %u\n", cmd);
            res = -ENOTTY;
            goto out_signal;
    }

    wake_up_all(&ioctl_wait);
    spin_unlock_irqrestore(&dev->fast_lock, flags);
    kfree(data);
    return res;

out_signal:
    pr_err("IOCTL: Error %ld in command %u\n", res, cmd);
    send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
    spin_unlock_irqrestore(&dev->fast_lock, flags);
    kfree(data);
    return res;
}

long as608_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    return as608_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}