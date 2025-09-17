#include <linux/sysfs.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include "as608.h"

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

static DEFINE_MUTEX(sysfs_lock);
static DECLARE_WAIT_QUEUE_HEAD(baud_change_wait);

static ssize_t baud_rate_show(struct device *dev, struct device_attribute *attr, char *buf) {
    struct as608_dev *as608_dev = dev_get_drvdata(dev);
    unsigned long flags;
    ssize_t ret;

    if (!as608_dev) {
        pr_err("Sysfs show: Invalid device data\n");
        return -EINVAL;
    }

    spin_lock_irqsave(&as608_dev->fast_lock, flags);
    ret = scnprintf(buf, PAGE_SIZE, "%u\n", as608_dev->baud_rate);
    spin_unlock_irqrestore(&as608_dev->fast_lock, flags);
    return ret;
}

static ssize_t baud_rate_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
    struct as608_dev *as608_dev = dev_get_drvdata(dev);
    unsigned long baud;
    char *kbuf = NULL;
    int ret = 0;

    if (!as608_dev || !as608_dev->uart_port) {
        pr_err("Sysfs store: Invalid device or UART port\n");
        return -EINVAL;
    }

    kbuf = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuf) return -ENOMEM;

    if (copy_from_user(kbuf, buf, count)) {
        ret = -EFAULT;
        goto out_free;
    }
    kbuf[count] = '\0';

    ret = kstrtoul(kbuf, 10, &baud);
    if (ret < 0) goto out_free;

    mutex_lock(&as608_dev->lock);
    as608_dev->baud_rate = baud;
    uart_configure(as608_dev->uart_port, baud, 8, 'N', 1);
    wake_up_all(&baud_change_wait);
    mutex_unlock(&as608_dev->lock);
    ret = count;

out_free:
    kfree(kbuf);
    return ret;
}

static DEVICE_ATTR_RW(baud_rate);

static struct attribute *as608_attrs[] = {
    &dev_attr_baud_rate.attr,
    NULL,
};

static const struct attribute_group as608_attr_group = {
    .attrs = as608_attrs,
};

void as608_sysfs_init(struct device *dev) {
    int ret = sysfs_create_group(&dev->kobj, &as608_attr_group);
    if (ret) pr_err("Sysfs: Create group failed %d\n", ret);
}

void as608_sysfs_cleanup(struct device *dev) {
    sysfs_remove_group(&dev->kobj, &as608_attr_group);
}