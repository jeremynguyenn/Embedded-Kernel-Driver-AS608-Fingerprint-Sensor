

#ifndef DRIVER_AS608_INTERFACE_H
#define DRIVER_AS608_INTERFACE_H

#include "driver_as608.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @defgroup as608_interface_driver as608 interface driver function
 * @brief    as608 interface driver modules
 * @ingroup  as608_driver
 * @{
 */

/**
 * @brief  interface uart init
 * @return status code
 *         - 0 success
 *         - 1 uart init failed
 * @note   none
 */
uint8_t as608_interface_uart_init(void);

/**
 * @brief  interface uart deinit
 * @return status code
 *         - 0 success
 *         - 1 uart deinit failed
 * @note   none
 */
uint8_t as608_interface_uart_deinit(void);

/**
 * @brief      interface uart read
 * @param[out] *buf pointer to a data buffer
 * @param[in]  len length of the data buffer
 * @return     status code
 *             - 0 success
 *             - 1 read failed
 * @note       none
 */
uint16_t as608_interface_uart_read(uint8_t *buf, uint16_t len);

/**
 * @brief     interface uart write
 * @param[in] *buf pointer to a data buffer
 * @param[in] len length of the data buffer
 * @return    status code
 *            - 0 success
 *            - 1 write failed
 * @note      none
 */
uint8_t as608_interface_uart_write(uint8_t *buf, uint16_t len);

/**
 * @brief  interface uart flush
 * @return status code
 *         - 0 success
 *         - 1 uart flush failed
 * @note   none
 */
uint8_t as608_interface_uart_flush(void);

/**
 * @brief     interface delay ms
 * @param[in] ms time
 * @note      none
 */
void as608_interface_delay_ms(uint32_t ms);

/**
 * @brief     interface print format data
 * @param[in] fmt format data
 * @note      none
 */
void as608_interface_debug_print(const char *const fmt, ...);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
