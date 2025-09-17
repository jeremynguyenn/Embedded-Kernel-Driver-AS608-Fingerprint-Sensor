#include <linux/sysfs.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include "as608.h"

/* Sysfs interface for AS608 driver.
 * Provides attributes to read/write device parameters like baud rate.
 */

static DEFINE_MUTEX(sysfs_lock); /* Mutex for sysfs operations */
static DECLARE_WAIT_QUEUE_HEAD(baud_change_wait); /* Wait queue for baud rate changes */

/* Sysfs attribute to show baud rate */
static ssize_t baud_rate_show(struct device *dev, struct device_attribute *attr, char *buf) {
    struct as608_dev *as608_dev = dev_get_drvdata(dev);
    unsigned long flags;
    ssize_t ret;
	/* Protect access to baud rate with spinlock */
    spin_lock_irqsave(&as608_dev->fast_lock, flags);
    ret = scnprintf(buf, PAGE_SIZE, "%u\n", as608_dev->baud_rate);
    spin_unlock_irqrestore(&as608_dev->fast_lock, flags);
    return ret;
}
/* Sysfs attribute to store baud rate */
static ssize_t baud_rate_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
    struct as608_dev *as608_dev = dev_get_drvdata(dev);
    unsigned long baud;
    char *kbuf = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuf) return -ENOMEM;
	
	/* Copy user input to kernel space */
    if (copy_from_user(kbuf, buf, count)) {
        kfree(kbuf);
        return -EFAULT;
    }
    kbuf[count] = '\0';
	
	/* Convert input string to unsigned long */
    if (kstrtoul(kbuf, 10, &baud) < 0) {
        kfree(kbuf);
        return -EINVAL;
    }
    kfree(kbuf);
	
	/* Update baud rate and reconfigure UART */
    mutex_lock(&as608_dev->lock);
    as608_dev->baud_rate = baud;
    uart_configure(as608_dev->uart_port, baud, 8, 'N', 1);
    wake_up_all(&baud_change_wait);
    mutex_unlock(&as608_dev->lock);
    return count;
}

static DEVICE_ATTR_RW(baud_rate);
/* Sysfs attribute array */
static struct attribute *as608_attrs[] = {
    &dev_attr_baud_rate.attr,
    NULL,
};
/* Sysfs attribute group */
static struct attribute_group as608_attr_group = {
    .attrs = as608_attrs,
};

void as608_sysfs_init(struct device *dev) {
    sysfs_create_group(&dev->kobj, &as608_attr_group);
}

void as608_sysfs_cleanup(struct device *dev) {
    sysfs_remove_group(&dev->kobj, &as608_attr_group);
}