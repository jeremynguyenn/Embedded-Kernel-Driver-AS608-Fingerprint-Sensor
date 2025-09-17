#include <linux/serial_core.h>
#include <linux/serial_8250.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include "as608.h"

/* UART interface for AS608 driver.
 * Handles UART port initialization and read/write operations.
 */

static DEFINE_MUTEX(uart_lock);
static DECLARE_WAIT_QUEUE_HEAD(uart_config_wait);

static unsigned int as608_tx_empty(struct uart_port *port) {
    return serial_in(port, UART_LSR) & UART_LSR_TEMT ? TIOCSER_TEMT : 0;
}

static void as608_set_mctrl(struct uart_port *port, unsigned int mctrl) {
    if (mctrl & TIOCM_RTS) serial_out(port, UART_MCR, serial_in(port, UART_MCR) | UART_MCR_RTS);
}

static unsigned int as608_get_mctrl(struct uart_port *port) {
    return TIOCM_CTS;
}

static void as608_stop_tx(struct uart_port *port) {
    // Disable TX interrupt
    serial_out(port, UART_IER, serial_in(port, UART_IER) & ~UART_IER_THRI);
}

static void as608_start_tx(struct uart_port *port) {
    // Enable TX interrupt if transmitter is empty
    if (serial_in(port, UART_LSR) & UART_LSR_THRE) {
        serial_out(port, UART_IER, serial_in(port, UART_IER) | UART_IER_THRI);
    }
}

static const struct uart_ops as608_uart_ops = {
    .tx_empty = as608_tx_empty,
    .set_mctrl = as608_set_mctrl,
    .get_mctrl = as608_get_mctrl,
    .stop_tx = as608_stop_tx,
    .start_tx = as608_start_tx,
};

struct uart_port *serial8250_get_port(struct device_node *np) {
    struct uart_8250_port *up = NULL;
    struct uart_port *port;
    int ret;
    u32 iobase, irq;

    if (of_property_read_u32(np, "reg", &iobase)) {
        pr_err("AS608 UART: No reg in DT\n");
        return ERR_PTR(-EINVAL);
    }
    irq = irq_of_parse_and_map(np, 0);

    up = devm_kzalloc(np->dev.parent, sizeof(*up), GFP_KERNEL);
    if (!up) return ERR_PTR(-ENOMEM);

    port = &up->port;
    port->type = PORT_16550A;
    port->iotype = UPIO_PORT;
    port->iobase = iobase;
    port->irq = irq;
    port->uartclk = 1843200;
    port->ops = &as608_uart_ops;
    port->flags = UPF_SKIP_TEST | UPF_BOOT_AUTOCONF;
    port->dev = np->dev.parent;

    ret = uart_add_one_port(&serial8250_reg, port);
    if (ret) {
        pr_err("AS608 UART: uart_add_one_port failed %d\n", ret);
        return ERR_PTR(ret);
    }

    pr_info("AS608 UART: Port initialized (iobase=0x%x, irq=%d)\n", iobase, irq);
    return port;
}

void uart_configure(struct uart_port *port, unsigned int baud, unsigned char bits, char parity, unsigned char stop) {
    struct uart_8250_port *up = container_of(port, struct uart_8250_port, port);
    char *config_buf = kmalloc(128, GFP_KERNEL);
    if (!config_buf) {
        pr_err("AS608 UART: Memory allocation failed\n");
        return;
    }

    mutex_lock(&uart_lock);
    snprintf(config_buf, 128, "Baud: %u, Bits: %u, Parity: %c, Stop: %u", baud, bits, parity, stop);
    pr_info("AS608 UART: Configuring port - %s\n", config_buf);
    port->baud = baud;
    serial8250_do_set_termios(port, NULL, NULL);
    wake_up_all(&uart_config_wait);
    mutex_unlock(&uart_lock);
    kfree(config_buf);
}

uint16_t uart_read(struct uart_port *port, uint8_t *buf, uint16_t len) {
    struct uart_8250_port *up = container_of(port, struct uart_8250_port, port);
    unsigned long flags;
    int read_len = 0;

    if (len > AS608_MAX_BUF_SIZE) {
        pr_err("AS608 UART: Read size %u exceeds max %d\n", len, AS608_MAX_BUF_SIZE);
        return 0;
    }

    spin_lock_irqsave(&port->lock, flags);
    pr_info("AS608 UART: Reading %u bytes\n", len);
    while (read_len < len && (serial_in(port, UART_LSR) & UART_LSR_DR)) {
        buf[read_len++] = serial_in(port, UART_RX);
    }
    spin_unlock_irqrestore(&port->lock, flags);
    return read_len;
}

int uart_write(struct uart_port *port, uint8_t *buf, uint16_t len) {
    struct uart_8250_port *up = container_of(port, struct uart_8250_port, port);
    unsigned long flags;
    int written = 0;

    if (len > AS608_MAX_BUF_SIZE) {
        pr_err("AS608 UART: Write size %u exceeds max %d\n", len, AS608_MAX_BUF_SIZE);
        return -EINVAL;
    }

    spin_lock_irqsave(&port->lock, flags);
    while (written < len && (serial_in(port, UART_LSR) & UART_LSR_THRE)) {
        serial_out(port, UART_TX, buf[written++]);
    }
    pr_info("AS608 UART: Wrote %u bytes\n", written);
    spin_unlock_irqrestore(&port->lock, flags);
    return written;
}

int as608_uart_init(void) {
    struct uart_driver drv = {
        .owner = THIS_MODULE,
        .driver_name = "as608_uart",
        .dev_name = "ttyAS",
        .major = 0,
        .minor = 0,
        .nr = 1,
    };
    return uart_register_driver(&drv);
}

void as608_uart_exit(void) {
    uart_unregister_driver(&serial8250_reg);
}