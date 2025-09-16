

#ifndef UART_H
#define UART_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup uart uart function
 * @brief    uart function modules
 * @{
 */

/**
 * @brief      uart init
 * @param[in]  *name pointer to a device name buffer
 * @param[out] *fd pointer to a uart handler buffer
 * @param[in]  baud_rate baud rate
 * @param[in]  data_bits data bits
 * @param[in]  parity data parity
 * @param[in]  stop_bits stop bits
 * @return     status code
 *             - 0 success
 *             - 1 uart init failed
 * @note       none
 */
uint8_t uart_init(char *name, int *fd, uint32_t baud_rate, uint8_t data_bits, char parity, uint8_t stop_bits);

/**
 * @brief     uart deinit
 * @param[in] fd uart handle
 * @return    status code
 *            - 0 success
 *            - 1 deinit failed
 * @note      none
 */
uint8_t uart_deinit(int fd);

/**
 * @brief     uart write data
 * @param[in] fd uart handle
 * @param[in] *buf pointer to a data buffer
 * @param[in] len length of the data buffer
 * @return    status code
 *            - 0 success
 *            - 1 write failed
 * @note      none
 */
uint8_t uart_write(int fd, uint8_t *buf, uint32_t len);

/**
 * @brief          uart read data
 * @param[in]      fd uart handle
 * @param[out]     *buf pointer to a data buffer
 * @param[in, out] *len pointer to a length of the data buffer
 * @return         status code
 *                 - 0 success
 *                 - 1 read failed
 * @note           none
 */
uint8_t uart_read(int fd, uint8_t *buf, uint32_t *len);

/**
 * @brief     uart flush
 * @param[in] fd uart handle
 * @return    status code
 *            - 0 success
 *            - 1 flush failed
 * @note      none
 */
uint8_t uart_flush(int fd);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif 
