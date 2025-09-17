#include <linux/serial_core.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include "as608.h"

/* UART interface for AS608 driver.
 * Handles UART port initialization and read/write operations.
 */

static DEFINE_MUTEX(uart_lock); /* Mutex for UART configuration */
static DECLARE_WAIT_QUEUE_HEAD(uart_config_wait); /* Wait queue for configuration changes */

/* Initialize UART port */
struct uart_port *serial8250_get_port(struct device_node *np) {
    struct uart_port *port = kmalloc(sizeof(struct uart_port), GFP_KERNEL);
    if (!port) {
        send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
        return NULL;
    }
    /* Simulated UART port initialization */
    port->iobase = 0x3F8; /* Example base address */
    port->membase = NULL;
    port->irq = 4;
    port->uartclk = 1843200;
    pr_info("AS608 UART: Port initialized by PID %d\n", current->pid);
    return port;
}

/* Configure UART parameters */
void uart_configure(struct uart_port *port, unsigned int baud, unsigned char bits, char parity, unsigned char stop) {
    char *config_buf = kmalloc(128, GFP_KERNEL);
    if (!config_buf) {
        pr_err("AS608 UART: Memory allocation failed\n");
        send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
        return;
    }

    /* Protect configuration with mutex */
    mutex_lock(&uart_lock);
    snprintf(config_buf, 128, "Baud: %u, Bits: %u, Parity: %c, Stop: %u", baud, bits, parity, stop);
    pr_info("AS608 UART: Configuring port - %s by PID %d\n", config_buf, current->pid);
    /* Simulated UART configuration */
    port->baud = baud;
    port->bits = bits;
    port->parity = parity;
    port->stop = stop;
    wake_up_all(&uart_config_wait);
    mutex_unlock(&uart_lock);
    kfree(config_buf);
}

/* Read data from UART */
uint16_t uart_read(struct uart_port *port, uint8_t *buf, uint16_t len) {
    uint8_t *temp_buf;
    unsigned long flags;

    if (len > AS608_MAX_BUF_SIZE) {
        pr_err("AS608 UART: Read size %u exceeds max buffer size %d\n", len, AS608_MAX_BUF_SIZE);
        send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
        return 0;
    }

    temp_buf = kmalloc(len, GFP_KERNEL);
    if (!temp_buf) {
        pr_err("AS608 UART: Memory allocation failed\n");
        send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
        return 0;
    }

    /* Protect read operation with spinlock */
    spin_lock_irqsave(&port->lock, flags);
    pr_info("AS608 UART: Reading %u bytes by PID %d\n", len, current->pid);
    /* Simulated UART read */
    memset(temp_buf, 0xAA, len); /* Dummy data */
    if (copy_to_user(buf, temp_buf, len)) {
        spin_unlock_irqrestore(&port->lock, flags);
        kfree(temp_buf);
        send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
        return -EFAULT;
    }
    spin_unlock_irqrestore(&port->lock, flags);
    kfree(temp_buf);
    return len;
}

/* Write data to UART */
void uart_write(struct uart_port *port, uint8_t *buf, uint16_t len) {
    uint8_t *temp_buf;
    unsigned long flags;

    if (len > AS608_MAX_BUF_SIZE) {
        pr_err("AS608 UART: Write size %u exceeds max buffer size %d\n", len, AS608_MAX_BUF_SIZE);
        send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
        return;
    }

    temp_buf = kmalloc(len, GFP_KERNEL);
    if (!temp_buf) {
        pr_err("AS608 UART: Memory allocation failed\n");
        send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
        return;
    }

    /* Protect write operation with spinlock */
    spin_lock_irqsave(&port->lock, flags);
    if (copy_from_user(temp_buf, buf, len)) {
        spin_unlock_irqrestore(&port->lock, flags);
        kfree(temp_buf);
        send_sig_info(SIGUSR1, SEND_SIG_PRIV, current);
        return;
    }
    pr_info("AS608 UART: Writing %u bytes by PID %d\n", len, current->pid);
    /* Simulated UART write */
    spin_unlock_irqrestore(&port->lock, flags);
    kfree(temp_buf);
}