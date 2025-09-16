#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/serial_core.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/poll.h>
#include <linux/completion.h>
#include <linux/sysfs.h>
#include <linux/device.h>
#include "as608.h"

#define AS608_TIMEOUT_MS 1000

struct as608_dev *global_dev;  // For single instance

static void as608_timeout_timer(struct timer_list *t) {
    struct as608_dev *dev = from_timer(dev, t, timeout_timer);
    pr_err("AS608: Timeout occurred\n");
    complete(&dev->response_complete);
}

static irqreturn_t as608_irq_handler(int irq, void *data) {
    struct as608_dev *dev = data;
    queue_work(dev->wq, &dev->work);
    return IRQ_HANDLED;
}

static void as608_read_work(struct work_struct *work) {
    struct as608_dev *dev = container_of(work, struct as608_dev, work);
    uint32_t addr_check;
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;

    mutex_lock(&dev->lock);
    dev->rx_len = uart_read(dev->uart_port, dev->rx_buf, sizeof(dev->rx_buf));
    if (as608_decode(dev->rx_buf, dev->rx_len, &addr_check, output, &out_len) == 0) {
        wake_up_interruptible(&dev->poll_queue);
        complete(&dev->response_complete);
    }
    mutex_unlock(&dev->lock);
}

static int as608_open(struct inode *inode, struct file *file) {
    file->private_data = global_dev;
    pr_info("AS608: Device opened\n");
    return 0;
}

static int as608_release(struct inode *inode, struct file *file) {
    pr_info("AS608: Device closed\n");
    return 0;
}

static unsigned int as608_poll(struct file *file, poll_table *wait) {
    struct as608_dev *dev = file->private_data;
    unsigned int mask = 0;
    poll_wait(file, &dev->poll_queue, wait);
    if (dev->rx_len > 0) mask |= POLLIN | POLLRDNORM;
    return mask;
}

static ssize_t as608_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos) {
    struct as608_dev *dev = file->private_data;
    uint16_t len;

    if (wait_for_completion_interruptible(&dev->response_complete)) return -EINTR;
    mutex_lock(&dev->lock);
    len = min(count, (size_t)dev->rx_len);
    if (copy_to_user(user_buf, dev->rx_buf, len)) {
        mutex_unlock(&dev->lock);
        return -EFAULT;
    }
    dev->rx_len = 0;
    mutex_unlock(&dev->lock);
    return len;
}

static ssize_t as608_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos) {
    struct as608_dev *dev = file->private_data;
    uint8_t buf[AS608_MAX_BUF_SIZE];

    if (count > sizeof(buf)) return -EINVAL;
    if (copy_from_user(buf, user_buf, count)) return -EFAULT;
    mutex_lock(&dev->lock);
    uart_write(dev->uart_port, buf, count);
    mutex_unlock(&dev->lock);
    return count;
}

static long as608_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    return as608_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}

static const struct file_operations as608_fops = {
    .owner = THIS_MODULE,
    .open = as608_open,
    .release = as608_release,
    .read = as608_read,
    .write = as608_write,
    .unlocked_ioctl = as608_ioctl,
    .compat_ioctl = as608_compat_ioctl,
    .poll = as608_poll,
};

static struct miscdevice as608_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "as608",
    .fops = &as608_fops,
};

static int as608_probe(struct platform_device *pdev) {
    struct device_node *np = pdev->dev.of_node;
    struct as608_dev *dev;
    int ret;

    dev = devm_kzalloc(&pdev->dev, sizeof(*dev), GFP_KERNEL);
    if (!dev) return -ENOMEM;

    platform_set_drvdata(pdev, dev);
    mutex_init(&dev->lock);
    init_completion(&dev->response_complete);
    timer_setup(&dev->timeout_timer, as608_timeout_timer, 0);
    init_waitqueue_head(&dev->poll_queue);
    dev->addr = 0xFFFFFFFF;

    np = of_find_node_by_type(NULL, "serial");
    if (!np) return -ENODEV;
    dev->uart_port = serial8250_get_port(np);

    uart_configure(dev->uart_port, 57600, 8, 'N', 1);

    dev->irq = irq_of_parse_and_map(np, 0);
    ret = request_irq(dev->irq, as608_irq_handler, IRQF_TRIGGER_RISING, "as608", dev);
    if (ret) return ret;

    dev->wq = alloc_workqueue("as608_wq", WQ_MEM_RECLAIM | WQ_HIGHPRI, 1);
    INIT_WORK(&dev->work, as608_read_work);

    global_dev = dev;
    misc_register(&as608_misc);
    as608_sysfs_init(&pdev->dev);

    pr_info("AS608: Probed\n");
    return 0;
}

static int as608_remove(struct platform_device *pdev) {
    struct as608_dev *dev = platform_get_drvdata(pdev);

    as608_sysfs_cleanup(&pdev->dev);
    free_irq(dev->irq, dev);
    misc_deregister(&as608_misc);
    destroy_workqueue(dev->wq);
    pr_info("AS608: Removed\n");
    return 0;
}

static const struct of_device_id as608_of_match[] = {
    { .compatible = "synochip,as608" },
    { }
};
MODULE_DEVICE_TABLE(of, as608_of_match);

static struct platform_driver as608_driver = {
    .probe = as608_probe,
    .remove = as608_remove,
    .driver = {
        .name = "as608",
        .of_match_table = as608_of_match,
    },
};

module_platform_driver(as608_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nguyen Nhan");
MODULE_DESCRIPTION("AS608 Fingerprint Driver");