
#ifndef DRIVER_AS608_BASIC_H
#define DRIVER_AS608_BASIC_H

#include "driver_as608_interface.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @defgroup as608_example_driver as608 example driver function
 * @brief    as608 example driver modules
 * @ingroup  as608_driver
 * @{
 */

/**
 * @brief as608 basic send command configure
 */
#ifndef AS608_BASIC_SEND_CONFIG
    #define AS608_BASIC_SEND_CONFIG      0        /**< don't send */
#endif

/**
 * @brief as608 basic example default definition
 */
#define AS608_BASIC_DEFAULT_PORT                AS608_BOOL_TRUE                      /**< enable */
#define AS608_BASIC_DEFAULT_BAUD_RATE           6                                    /**< 57600 bps */
#define AS608_BASIC_DEFAULT_LEVEL               AS608_LEVEL_3                        /**< level 3 */
#define AS608_BASIC_DEFAULT_PACKET_SIZE         AS608_PACKET_SIZE_128_BYTES          /**< 128 bytes */
#define AS608_BASIC_DEFAULT_PASSWORD            0x00000000                           /**< 0x00000000 */
#define AS608_BASIC_DEFAULT_ADDRESS             0xFFFFFFFF                           /**< 0xFFFFFFFF */
#define AS608_BASIC_DEFAULT_FEATURE             AS608_BUFFER_NUMBER_1                /**< buffer number 1 */
#define AS608_BASIC_DEFAULT_TIMEOUT             10                                   /**< 10s */

/**
 * @brief     basic example init
 * @param[in] addr chip address
 * @return    status code
 *            - 0 success
 *            - 1 init failed
 * @note      none
 */
uint8_t as608_basic_init(uint32_t addr);

/**
 * @brief  basic example deinit
 * @return status code
 *         - 0 success
 *         - 1 deinit failed
 * @note   none
 */
uint8_t as608_basic_deinit(void);

/**
 * @brief     basic example print status
 * @param[in] status print status
 * @return    status code
 *             - 0 success
 *             - 1 print failed
 * @note       none
 */
uint8_t as608_basic_print_status(as608_status_t status);

/**
 * @brief      basic example input fingerprint
 * @param[out] *callback pointer to a callback function
 * @param[out] *score pointer to a score buffer
 * @param[out] *page_number pointer to a page number buffer
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 input fingerprint failed
 *             - 2 timeout
 * @note       callback status
 *             - -1 error
 *             - 0 please put your finger on the sensor
 *             - 1 please put your finger on the sensor again
 *             - 2 generate feature success
 */
uint8_t as608_basic_input_fingerprint(void (*callback)(int8_t status, const char *const fmt, ...), 
                                      uint16_t *score,
                                      uint16_t *page_number,
                                      as608_status_t *status);

/**
 * @brief      basic example verify
 * @param[out] *found_page pointer to a found page buffer
 * @param[out] *score pointer to a score buffer
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 verify failed
 * @note       none
 */
uint8_t as608_basic_verify(uint16_t *found_page, uint16_t *score, as608_status_t *status);

/**
 * @brief      basic example high speed verify
 * @param[out] *found_page pointer to a found page buffer
 * @param[out] *score pointer to a score buffer
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 high speed verify failed
 * @note       none
 */
uint8_t as608_basic_high_speed_verify(uint16_t *found_page, uint16_t *score, as608_status_t *status);

/**
 * @brief      basic example delete fingerprint
 * @param[in]  page_number page number
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 delete fingerprint failed
 * @note       none
 */
uint8_t as608_basic_delete_fingerprint(uint16_t page_number, as608_status_t *status);

/**
 * @brief      basic example empty fingerprint
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 empty fingerprint failed
 * @note       none
 */
uint8_t as608_basic_empty_fingerprint(as608_status_t *status);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
