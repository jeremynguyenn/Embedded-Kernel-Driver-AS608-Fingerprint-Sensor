#include <linux/sysfs.h>
#include <linux/device.h>
#include "as608.h"

static ssize_t baud_rate_show(struct device *dev, struct device_attribute *attr, char *buf) {
    return scnprintf(buf, PAGE_SIZE, "%u\n", 57600);
}

static ssize_t baud_rate_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
    unsigned long baud;
    if (kstrtoul(buf, 10, &baud) < 0) return -EINVAL;
    uart_configure(global_dev->uart_port, baud, 8, 'N', 1);
    return count;
}

static DEVICE_ATTR_RW(baud_rate);

static struct attribute *as608_attrs[] = {
    &dev_attr_baud_rate.attr,
    NULL,
};

static struct attribute_group as608_attr_group = {
    .attrs = as608_attrs,
};

void as608_sysfs_init(struct device *dev) {
    sysfs_create_group(&dev->kobj, &as608_attr_group);
}

void as608_sysfs_cleanup(struct device *dev) {
    sysfs_remove_group(&dev->kobj, &as608_attr_group);
}