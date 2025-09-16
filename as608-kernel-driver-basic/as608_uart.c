#include <linux/serial_core.h>
#include <linux/serial_reg.h>
#include <linux/tty.h>
#include "as608.h"

static struct uart_driver as608_uart_driver = {
    .owner = THIS_MODULE,
    .driver_name = "as608_uart",
    .nr = 1,
};

int __init as608_uart_init(void) {
    return uart_register_driver(&as608_uart_driver);
}

void __exit as608_uart_exit(void) {
    uart_unregister_driver(&as608_uart_driver);
}

uint16_t uart_read(struct uart_port *port, uint8_t *buf, uint16_t len) {
    int i;
    for (i = 0; i < len; i++) {
        if (!(inb(port->iobase + UART_LSR) & UART_LSR_DR)) break;
        buf[i] = inb(port->iobase + UART_RX);
    }
    return i;
}

void uart_write(struct uart_port *port, uint8_t *buf, uint16_t len) {
    int i;
    for (i = 0; i < len; i++) {
        while (!(inb(port->iobase + UART_LSR) & UART_LSR_THRE));
        outb(buf[i], port->iobase + UART_TX);
    }
}

void uart_configure(struct uart_port *port, uint32_t baud, uint8_t data_bits, char parity, uint8_t stop_bits) {
    unsigned int baud_div = port->uartclk / (16 * baud);
    outb(0x80, port->iobase + UART_LCR);
    outb(baud_div & 0xFF, port->iobase + UART_DLL);
    outb(baud_div >> 8, port->iobase + UART_DLM);
    uint8_t lcr = (data_bits - 5) | (stop_bits == 2 ? 0x04 : 0);
    outb(lcr, port->iobase + UART_LCR);
}