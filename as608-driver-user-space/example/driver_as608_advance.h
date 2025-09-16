/**
 * @file      driver_as608_advance.h
 * @brief     driver as608 advance header file
 * @version   1.0.0
 * @author    Nguyen Nhan
 *
 */

#ifndef DRIVER_AS608_ADVANCE_H
#define DRIVER_AS608_ADVANCE_H

#include "driver_as608_interface.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @addtogroup as608_example_driver
 * @{
 */

/**
 * @brief as608 advance send command configure
 */
#ifndef AS608_ADVANCE_SEND_CONFIG
    #define AS608_ADVANCE_SEND_CONFIG      0        /**< don't send */
#endif

/**
 * @brief as608 advance example default definition
 */
#define AS608_ADVANCE_DEFAULT_PORT                AS608_BOOL_TRUE                      /**< enable */
#define AS608_ADVANCE_DEFAULT_BAUD_RATE           6                                    /**< 57600 bps */
#define AS608_ADVANCE_DEFAULT_LEVEL               AS608_LEVEL_3                        /**< level 3 */
#define AS608_ADVANCE_DEFAULT_PACKET_SIZE         AS608_PACKET_SIZE_128_BYTES          /**< 128 bytes */
#define AS608_ADVANCE_DEFAULT_PASSWORD            0x00000000                           /**< 0x00000000 */
#define AS608_ADVANCE_DEFAULT_ADDRESS             0xFFFFFFFF                           /**< 0xFFFFFFFF */
#define AS608_ADVANCE_DEFAULT_FEATURE             AS608_BUFFER_NUMBER_1                /**< buffer number 1 */
#define AS608_ADVANCE_DEFAULT_TIMEOUT             10                                   /**< 10s */

/**
 * @brief     advance example init
 * @param[in] addr chip address
 * @return    status code
 *            - 0 success
 *            - 1 init failed
 * @note      none
 */
uint8_t as608_advance_init(uint32_t addr);

/**
 * @brief  advance example deinit
 * @return status code
 *         - 0 success
 *         - 1 deinit failed
 * @note   none
 */
uint8_t as608_advance_deinit(void);

/**
 * @brief     advance example print status
 * @param[in] status print status
 * @return    status code
 *             - 0 success
 *             - 1 print failed
 * @note       none
 */
uint8_t as608_advance_print_status(as608_status_t status);

/**
 * @brief      advance example input fingerprint
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
uint8_t as608_advance_input_fingerprint(void (*callback)(int8_t status, const char *const fmt, ...), 
                                        uint16_t *score,
                                        uint16_t *page_number,
                                        as608_status_t *status);

/**
 * @brief      advance example verify
 * @param[out] *found_page pointer to a found page buffer
 * @param[out] *score pointer to a score buffer
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 verify failed
 * @note       none
 */
uint8_t as608_advance_verify(uint16_t *found_page, uint16_t *score, as608_status_t *status);

/**
 * @brief      advance example high speed verify
 * @param[out] *found_page pointer to a found page buffer
 * @param[out] *score pointer to a score buffer
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 high speed verify failed
 * @note       none
 */
uint8_t as608_advance_high_speed_verify(uint16_t *found_page, uint16_t *score, as608_status_t *status);

/**
 * @brief      advance example delete fingerprint
 * @param[in]  page_number page number
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 delete fingerprint failed
 * @note       none
 */
uint8_t as608_advance_delete_fingerprint(uint16_t page_number, as608_status_t *status);

/**
 * @brief      advance example empty fingerprint
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 empty fingerprint failed
 * @note       none
 */
uint8_t as608_advance_empty_fingerprint(as608_status_t *status);

/**
 * @brief      advance example write notepad
 * @param[in]  page_number page number
 * @param[in]  *data pointer to an input buffer
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 write notepad failed
 * @note       none
 */
uint8_t as608_advance_write_notepad(uint8_t page_number, uint8_t data[32], as608_status_t *status);

/**
 * @brief      advance example read notepad
 * @param[in]  page_number page number
 * @param[out] *data pointer to an output buffer
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 read notepad failed
 * @note       none
 */
uint8_t as608_advance_read_notepad(uint8_t page_number, uint8_t data[32], as608_status_t *status);

/**
 * @brief      advance example get random
 * @param[out] *randn pointer to a random buffer
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 random failed
 * @note       none
 */
uint8_t as608_advance_random(uint32_t *randn, as608_status_t *status);

/**
 * @brief         advance example get flash information
 * @param[out]    *output_buffer pointer to an output buffer
 * @param[in,out] *output_len pointer to an output length buffer
 * @param[out]    *status pointer to a status buffer
 * @return        status code
 *                - 0 success
 *                - 1 get flash information failed
 * @note          none
 */
uint8_t as608_advance_flash_information(uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status);

/**
 * @brief      advance example get params
 * @param[out] *params pointer to a param structure
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 get params failed
 * @note       none
 */
uint8_t as608_advance_params(as608_params_t *params, as608_status_t *status);

/**
 * @brief      advance example enroll
 * @param[out] *page_number pointer to a page number buffer
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 enroll failed
 * @note       none
 */
uint8_t as608_advance_enroll(uint16_t *page_number, as608_status_t *status);

/**
 * @brief      advance example identify
 * @param[out] *page_number pointer to a page number buffer
 * @param[out] *score pointer to a score buffer
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 identify failed
 * @note       none
 */
uint8_t as608_advance_identify(uint16_t *page_number, uint16_t *score, as608_status_t *status);

/**
 * @brief         advance example upload flash feature
 * @param[in]     page_number page number
 * @param[out]    *output_buffer pointer to an output buffer
 * @param[in,out] *output_len pointer to an output length buffer
 * @param[out]    *status pointer to a status buffer
 * @return        status code
 *                - 0 success
 *                - 1 upload flash feature failed
 * @note          none
 */
uint8_t as608_advance_upload_flash_feature(uint16_t page_number, uint8_t *output_buffer, 
                                           uint16_t *output_len, as608_status_t *status);

/**
 * @brief         advance example upload image feature
 * @param[out]    *output_buffer pointer to an output buffer
 * @param[in,out] *output_len pointer to an output length buffer
 * @param[out]    *status pointer to a status buffer
 * @return        status code
 *                - 0 success
 *                - 1 upload image feature failed
 * @note          none
 */
uint8_t as608_advance_upload_image_feature(uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status);

/**
 * @brief      advance example download flash feature
 * @param[in]  page_number page number
 * @param[in]  *input_buffer pointer to an input buffer
 * @param[in]  input_len input length
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 download flash feature failed
 * @note       none
 */
uint8_t as608_advance_download_flash_feature(uint16_t page_number, uint8_t *input_buffer, 
                                             uint16_t input_len, as608_status_t *status);

/**
 * @brief         advance example upload image
 * @param[out]    *output_buffer pointer to an output buffer
 * @param[in,out] *output_len pointer to an output length buffer
 * @param[out]    *status pointer to a status buffer
 * @return        status code
 *                - 0 success
 *                - 1 upload image failed
 * @note          none
 */
uint8_t as608_advance_upload_image(uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status);

/**
 * @brief      advance example download image
 * @param[in]  page_number page number
 * @param[in]  *input_buffer pointer to an input buffer
 * @param[in]  input_len input length
 * @param[out] *status pointer to a status buffer
 * @return     status code
 *             - 0 success
 *             - 1 download image failed
 * @note       none
 */
uint8_t as608_advance_download_image(uint16_t page_number, uint8_t *input_buffer, uint16_t input_len, as608_status_t *status);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
