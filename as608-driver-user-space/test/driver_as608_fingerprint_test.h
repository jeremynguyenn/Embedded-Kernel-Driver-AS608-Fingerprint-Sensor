

#ifndef DRIVER_AS608_FINGERPRINT_TEST_H
#define DRIVER_AS608_FINGERPRINT_TEST_H

#include "driver_as608_interface.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @addtogroup as608_test_driver
 * @{
 */

/**
 * @brief     fingerprint test
 * @param[in] addr chip address
 * @return    status code
 *            - 0 success
 *            - 1 test failed
 * @note      none
 */
uint8_t as608_fingerprint_test(uint32_t addr);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
