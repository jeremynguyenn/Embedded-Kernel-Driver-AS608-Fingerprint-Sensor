

#ifndef DRIVER_AS608_REGISTER_TEST_H
#define DRIVER_AS608_REGISTER_TEST_H

#include "driver_as608_interface.h"

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @defgroup as608_test_driver as608 test driver function
 * @brief    as608 test driver modules
 * @ingroup  as608_driver
 * @{
 */


/**
 * @brief     register test
 * @param[in] addr chip address
 * @return    status code
 *            - 0 success
 *            - 1 test failed
 * @note      none
 */
uint8_t as608_register_test(uint32_t addr);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
