#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/serial_core.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/poll.h>
#include <linux/completion.h>
#include <linux/sysfs.h>
#include <linux/device.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/mqueue.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>
#include "as608.h"

/* Core driver for AS608 fingerprint sensor.
 * Handles device initialization, file operations, and platform driver setup.
 */

#define AS608_TIMEOUT_MS 1000   /* Timeout for operations (ms) */
#define AS608_MQ_NAME "/as608_mq" /* POSIX message queue name */
#define AS608_MQ_MAXMSG 10      /* Max number of messages in queue */
#define AS608_MQ_MSGSIZE 256    /* Max size of each message */

/* File operation: Open the AS608 device */
static int as608_open(struct inode *inode, struct file *file) {
    struct as608_dev *dev = container_of(inode->i_cdev, struct as608_dev, cdev);
    unsigned long flags;

    spin_lock_irqsave(&dev->fast_lock, flags);
    if (atomic_inc_return(&dev->open_count) == 1) {
        dev->mq = mq_open(AS608_MQ_NAME, O_WRONLY | O_CREAT, 0644, NULL);
        if (dev->mq < 0) {
            spin_unlock_irqrestore(&dev->fast_lock, flags);
            return -ENOMEM;
        }
        if (pipe(dev->pipe_fd) < 0) {
            mq_close(dev->mq);
            spin_unlock_irqrestore(&dev->fast_lock, flags);
            return -ENOMEM;
        }
        dev->running = true;
        dev->read_thread = kthread_run(as608_read_thread, dev, "as608_read_thread");
        if (IS_ERR(dev->read_thread)) {
            mq_close(dev->mq);
            close(dev->pipe_fd[0]);
            close(dev->pipe_fd[1]);
            spin_unlock_irqrestore(&dev->fast_lock, flags);
            return PTR_ERR(dev->read_thread);
        }
    }
    file->private_data = dev;
    spin_unlock_irqrestore(&dev->fast_lock, flags);
    return 0;
}

static int as608_release(struct inode *inode, struct file *file) {
    struct as608_dev *dev = file->private_data;
    unsigned long flags;

    spin_lock_irqsave(&dev->fast_lock, flags);
    if (atomic_dec_and_test(&dev->open_count)) {
        dev->running = false;
        kthread_stop(dev->read_thread);
        mq_close(dev->mq);
        close(dev->pipe_fd[0]);
        close(dev->pipe_fd[1]);
    }
    spin_unlock_irqrestore(&dev->fast_lock, flags);
    return 0;
}

static ssize_t as608_read(struct file *file, char __user *buf, size_t len, loff_t *offset) {
    struct as608_dev *dev = file->private_data;
    unsigned long flags;
    ssize_t ret;

    if (len > AS608_MAX_BUF_SIZE) {
        pr_err("AS608: Read size %zu exceeds max buffer size %d\n", len, AS608_MAX_BUF_SIZE);
        return -EINVAL;
    }

    spin_lock_irqsave(&dev->fast_lock, flags);
    if (!dev->rx_len) {
        spin_unlock_irqrestore(&dev->fast_lock, flags);
        if (file->f_flags & O_NONBLOCK)
            return -EAGAIN;
        wait_event_interruptible(dev->poll_queue, dev->rx_len > 0);
        spin_lock_irqsave(&dev->fast_lock, flags);
    }

    ret = min_t(size_t, len, dev->rx_len);
    if (copy_to_user(buf, dev->rx_buf, ret)) {
        spin_unlock_irqrestore(&dev->fast_lock, flags);
        send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
        return -EFAULT;
    }

    dev->rx_len -= ret;
    memmove(dev->rx_buf, dev->rx_buf + ret, dev->rx_len);
    *offset += ret;
    spin_unlock_irqrestore(&dev->fast_lock, flags);
    return ret;
}

static ssize_t as608_write(struct file *file, const char __user *buf, size_t len, loff_t *offset) {
    struct as608_dev *dev = file->private_data;
    uint8_t *temp_buf;
    unsigned long flags;
    ssize_t ret;

    if (len > AS608_MAX_BUF_SIZE) {
        pr_err("AS608: Write size %zu exceeds max buffer size %d\n", len, AS608_MAX_BUF_SIZE);
        return -EINVAL;
    }

    temp_buf = kmalloc(len, GFP_KERNEL);
    if (!temp_buf) {
        send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
        return -ENOMEM;
    }

    if (copy_from_user(temp_buf, buf, len)) {
        kfree(temp_buf);
        send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
        return -EFAULT;
    }

    spin_lock_irqsave(&dev->fast_lock, flags);
    ret = uart_write(dev->uart_port, temp_buf, len);
    if (ret < 0) {
        spin_unlock_irqrestore(&dev->fast_lock, flags);
        kfree(temp_buf);
        send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
        return ret;
    }
    *offset += len;
    spin_unlock_irqrestore(&dev->fast_lock, flags);
    kfree(temp_buf);
    return len;
}

static loff_t as608_llseek(struct file *file, loff_t offset, int whence) {
    struct as608_dev *dev = file->private_data;
    loff_t newpos;

    mutex_lock(&dev->lock);
    switch (whence) {
        case SEEK_SET:
            newpos = offset;
            break;
        case SEEK_CUR:
            newpos = dev->data_offset + offset;
            break;
        case SEEK_END:
            newpos = AS608_MAX_BUF_SIZE + offset;
            break;
        default:
            mutex_unlock(&dev->lock);
            return -EINVAL;
    }

    if (newpos < 0 || newpos > AS608_MAX_BUF_SIZE) {
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    dev->data_offset = newpos;
    mutex_unlock(&dev->lock);
    return newpos;
}

static unsigned int as608_poll(struct file *file, poll_table *wait) {
    struct as608_dev *dev = file->private_data;
    unsigned int mask = 0;

    poll_wait(file, &dev->poll_queue, wait);
    mutex_lock(&dev->lock);
    if (dev->rx_len > 0)
        mask |= POLLIN | POLLRDNORM;
    if (dev->running)
        mask |= POLLOUT | POLLWRNORM;
    mutex_unlock(&dev->lock);
    return mask;
}

static void as608_timeout_timer(struct timer_list *t) {
    struct as608_dev *dev = from_timer(dev, t, timeout_timer);
    complete(&dev->response_complete);
    send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
}

static int as608_read_thread(void *data) {
    struct as608_dev *dev = data;
    uint8_t *buf = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    char *mq_buf = kmalloc(AS608_MQ_MSGSIZE, GFP_KERNEL);
    if (!buf || !mq_buf) {
        kfree(buf);
        kfree(mq_buf);
        send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
        return -ENOMEM;
    }

    while (!kthread_should_stop()) {
        uint16_t len = uart_read(dev->uart_port, buf, AS608_MAX_BUF_SIZE);
        if (len > 0) {
            mutex_lock(&dev->lock);
            if (dev->rx_len + len <= AS608_MAX_BUF_SIZE) {
                memcpy(dev->rx_buf + dev->rx_len, buf, len);
                dev->rx_len += len;
                wake_up_all(&dev->poll_queue);
                snprintf(mq_buf, AS608_MQ_MSGSIZE, "Received %u bytes", len);
                mq_send(dev->mq, mq_buf, strlen(mq_buf) + 1, 0);
                write(dev->pipe_fd[AS608_PIPE_WRITE], mq_buf, strlen(mq_buf) + 1);
            }
            mutex_unlock(&dev->lock);
        }
        msleep(100);
    }
    kfree(buf);
    kfree(mq_buf);
    return 0;
}

static irqreturn_t as608_irq_handler(int irq, void *dev_id) {
    struct as608_dev *dev = dev_id;
    complete(&dev->response_complete);
    return IRQ_HANDLED;
}

static struct as608_dev *as608_alloc_dev(void) {
    struct as608_dev *dev = kmalloc(sizeof(struct as608_dev), GFP_KERNEL);
    if (!dev) return NULL;
    mutex_init(&dev->lock);
    spin_lock_init(&dev->fast_lock);
    init_completion(&dev->response_complete);
    timer_setup(&dev->timeout_timer, as608_timeout_timer, 0);
    init_waitqueue_head(&dev->poll_queue);
    atomic_set(&dev->open_count, 0);
    dev->addr = 0xFFFFFFFF;
    dev->running = false;
    dev->data_offset = 0;
    return dev;
}

static void as608_free_dev(struct as608_dev *dev) {
    kfree(dev);
}

static struct file_operations as608_fops = {
    .owner = THIS_MODULE,
    .open = as608_open,
    .release = as608_release,
    .read = as608_read,
    .write = as608_write,
    .llseek = as608_llseek,
    .poll = as608_poll,
    .unlocked_ioctl = as608_ioctl,
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

    dev = as608_alloc_dev();
    if (!dev) return -ENOMEM;

    platform_set_drvdata(pdev, dev);
    dev->addr = 0xFFFFFFFF;

    np = of_find_node_by_type(NULL, "serial");
    if (!np) {
        as608_free_dev(dev);
        return -ENODEV;
    }
    dev->uart_port = serial8250_get_port(np);

    uart_configure(dev->uart_port, 57600, 8, 'N', 1);

    dev->irq = irq_of_parse_and_map(np, 0);
    ret = request_irq(dev->irq, as608_irq_handler, IRQF_TRIGGER_RISING, "as608", dev);
    if (ret) {
        as608_free_dev(dev);
        return ret;
    }

    ret = misc_register(&as608_misc);
    if (ret) {
        free_irq(dev->irq, dev);
        as608_free_dev(dev);
        return ret;
    }

    as608_sysfs_init(&pdev->dev);
    pr_info("AS608: Probed\n");
    return 0;
}

static int as608_remove(struct platform_device *pdev) {
    struct as608_dev *dev = platform_get_drvdata(pdev);

    as608_sysfs_cleanup(&pdev->dev);
    free_irq(dev->irq, dev);
    misc_deregister(&as608_misc);
    as608_free_dev(dev);
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