#ifndef AS608_H
#define AS608_H

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/timer.h>
#include <linux/wait.h>

// Commands từ documents gốc
#define AS608_COMMAND_GET_IMAGE             0x01
#define AS608_COMMAND_GEN_CHAR              0x02
#define AS608_COMMAND_MATCH                 0x03
#define AS608_COMMAND_SEARCH                0x04
#define AS608_COMMAND_REG_MODEL             0x05
#define AS608_COMMAND_STORE_CHAR            0x06
#define AS608_COMMAND_LOAD_CHAR             0x07
#define AS608_COMMAND_UP_CHAR               0x08
#define AS608_COMMAND_DOWN_CHAR             0x09
#define AS608_COMMAND_UP_IMAGE              0x0A
#define AS608_COMMAND_DOWN_IMAGE            0x0B
#define AS608_COMMAND_WRITE_NOTEPAD         0x18
#define AS608_COMMAND_READ_NOTEPAD          0x19
#define AS608_COMMAND_TEMPLATE_COUNT        0x1B
#define AS608_COMMAND_READ_SYS_PARA         0x1F
#define AS608_COMMAND_WRITE_SYS_PARA        0x1E
#define AS608_COMMAND_RANDOM                0x1C
#define AS608_COMMAND_BURN_FIRST            0x1D
#define AS608_COMMAND_BURN_SECOND           0x1E
#define AS608_COMMAND_GET_FLASH_INFO        0x0F

typedef enum {
    AS608_BOOL_FALSE = 0x00,
    AS608_BOOL_TRUE  = 0x01,
} as608_bool_t;

typedef enum {
    AS608_LEVEL_1 = 0x0001,
    AS608_LEVEL_2 = 0x0002,
    AS608_LEVEL_3 = 0x0003,
    AS608_LEVEL_4 = 0x0004,
    AS608_LEVEL_5 = 0x0005,
} as608_level_t;

typedef enum {
    AS608_PACKET_SIZE_32_BYTES  = 0x0000,
    AS608_PACKET_SIZE_64_BYTES  = 0x0001,
    AS608_PACKET_SIZE_128_BYTES = 0x0002,
    AS608_PACKET_SIZE_256_BYTES = 0x0003,
} as608_packet_size_t;

typedef enum {
    AS608_BUFFER_NUMBER_1 = 0x01,
    AS608_BUFFER_NUMBER_2 = 0x02,
} as608_buffer_number_t;

typedef enum {
    AS608_SENSOR_TYPE_FPC1011C = 0x0000,
    AS608_SENSOR_TYPE_C500     = 0x0002,
    AS608_SENSOR_TYPE_S500     = 0x0003,
    AS608_SENSOR_TYPE_XWSEMI   = 0x0007,
    AS608_SENSOR_TYPE_CUSTOM   = 0x0009,
} as608_sensor_type_t;

typedef enum {
    AS608_BURN_CODE_MODE_INFO = 0x00,
    AS608_BURN_CODE_MODE_FULL = 0x01,
} as608_burn_code_mode_t;

typedef enum {
    AS608_IMAGE_BIN        = 0x00,
    AS608_IMAGE_NO_FEATURE = 0x01,
    AS608_IMAGE_FEATURE    = 0x02,
} as608_image_t;

typedef enum {
    AS608_GPIO_NUMBER_0 = 0x00,
    AS608_GPIO_NUMBER_1 = 0x01,
} as608_gpio_number_t;

typedef enum {
    AS608_GPIO_LEVEL_LOW  = 0x00,
    AS608_GPIO_LEVEL_HIGH = 0x01,
} as608_gpio_level_t;

typedef enum {
    AS608_STATUS_OK                          = 0x00,
    AS608_STATUS_FRAME_ERROR                 = 0x01,
    AS608_STATUS_NO_FINGERPRINT              = 0x02,
    AS608_STATUS_INPUT_ERROR                 = 0x03,
    AS608_STATUS_IMAGE_TOO_DRY               = 0x04,
    AS608_STATUS_IMAGE_TOO_WET               = 0x05,
    AS608_STATUS_IMAGE_TOO_CLUTTER           = 0x06,
    AS608_STATUS_IMAGE_TOO_FEW_FEATURE       = 0x07,
    AS608_STATUS_NOT_MATCH                   = 0x08,
    AS608_STATUS_NOT_FOUND                   = 0x09,
    AS608_STATUS_FEATURE_MERGE_ERROR         = 0x0A,
    AS608_STATUS_ADDR_OVER                   = 0x0B,
    AS608_STATUS_FLASH_READ_ERROR            = 0x0C,
    AS608_STATUS_TEMPLATE_EMPTY              = 0x0D,
    AS608_STATUS_TEMPLATE_READ_ERROR         = 0x0E,
    AS608_STATUS_FEATURE_UPLOAD_ERROR        = 0x0F,
    AS608_STATUS_PACKET_RESPONSE_ERROR       = 0x10,
    AS608_STATUS_FEATURE_DOWNLOAD_ERROR      = 0x11,
    AS608_STATUS_DELETE_ERROR                = 0x12,
    AS608_STATUS_DB_CLEAR_ERROR              = 0x13,
    AS608_STATUS_PASSWORD_ERROR              = 0x14,
    AS608_STATUS_TEMPLATE_INVALID            = 0x15,
    AS608_STATUS_FEATURE_READ_ERROR          = 0x16,
    AS608_STATUS_RANDOM_ERROR                = 0x17,
    AS608_STATUS_SEARCH_ERROR                = 0x18,
    AS608_STATUS_COUNT_INVALID               = 0x19,
    AS608_STATUS_TEMPLATE_INVALID_2          = 0x1A,
    AS608_STATUS_BUFFER_READ_ERROR           = 0x1B,
    AS608_STATUS_FLASH_WRITE_ERROR           = 0x1C,
    AS608_STATUS_UNKNOWN                     = 0x1D,
    AS608_STATUS_REG_INVALID                 = 0x1E,
    AS608_STATUS_DATA_INVALID                = 0x1F,
    AS608_STATUS_NOTE_PAGE_INVALID           = 0x20,
    AS608_STATUS_PORT_INVALID                = 0x21,
    AS608_STATUS_ENROOL_ERROR                = 0x22,
    AS608_STATUS_LIB_FULL                    = 0x23,
} as608_status_t;

typedef struct {
    uint16_t status_register;
    uint16_t system_id;
    uint16_t capacity;
    uint16_t level;
    uint32_t addr;
    uint16_t packet_size;
    uint16_t baud_rate;
} as608_params_t;

#define AS608_MAX_BUF_SIZE 1024
#define AS608_TIMEOUT_MS 1000

struct as608_dev {
    struct uart_port *uart_port;
    struct mutex lock;
    struct completion response_complete;
    struct timer_list timeout_timer;
    uint8_t rx_buf[AS608_MAX_BUF_SIZE];
    uint16_t rx_len;
    int irq;
    wait_queue_head_t poll_queue;
    uint32_t addr;
    struct work_struct work;
    struct workqueue_struct *wq;
};

struct as608_fingerprint_data {
    uint16_t score;
    uint16_t page_number;
    as608_status_t status;
};

struct as608_verify_data {
    uint16_t found_page;
    uint16_t score;
    as608_status_t status;
};

struct as608_delete_data {
    uint16_t page_number;
    as608_status_t status;
};

struct as608_notepad_data {
    uint8_t page_number;
    uint8_t data[32];
    as608_status_t status;
};

struct as608_flash_data {
    uint8_t output_buffer[AS608_MAX_BUF_SIZE];
    uint16_t output_len;
    as608_status_t status;
};

struct as608_enroll_data {
    uint16_t page_number;
    as608_status_t status;
};

struct as608_identify_data {
    uint16_t page_number;
    uint16_t score;
    as608_status_t status;
};

struct as608_feature_data {
    uint16_t page_number;
    uint8_t buffer[AS608_MAX_BUF_SIZE];
    uint16_t len;
    as608_status_t status;
};

struct as608_image_data {
    uint16_t page_number;
    uint8_t buffer[AS608_MAX_BUF_SIZE];
    uint16_t len;
    as608_status_t status;
};

struct as608_gpio_data {
    as608_gpio_number_t gpio;
    as608_gpio_level_t input_level;
    as608_gpio_level_t output_level;
    as608_status_t status;
};

struct as608_index_table_data {
    uint8_t num;
    uint8_t table[32];
    as608_status_t status;
};

// UART functions
uint16_t uart_read(struct uart_port *port, uint8_t *buf, uint16_t len);
void uart_write(struct uart_port *port, uint8_t *buf, uint16_t len);
void uart_configure(struct uart_port *port, uint32_t baud, uint8_t data_bits, char parity, uint8_t stop_bits);

// Command functions
uint8_t as608_decode(uint8_t *buf, uint16_t len, uint32_t *addr, uint8_t *output, uint16_t *out_len);
uint8_t as608_write_frame(uint32_t addr, uint8_t type, uint8_t *data, uint16_t len);
uint8_t as608_get_image(struct as608_dev *dev, as608_status_t *status);
uint8_t as608_input_fingerprint(struct as608_dev *dev, uint16_t *score, uint16_t *page_number, as608_status_t *status);
uint8_t as608_verify(struct as608_dev *dev, uint16_t *found_page, uint16_t *score, as608_status_t *status);
uint8_t as608_high_speed_verify(struct as608_dev *dev, uint16_t *found_page, uint16_t *score, as608_status_t *status);
uint8_t as608_delete_fingerprint(struct as608_dev *dev, uint16_t page_number, as608_status_t *status);
uint8_t as608_empty_fingerprint(struct as608_dev *dev, as608_status_t *status);
uint8_t as608_write_notepad(struct as608_dev *dev, uint8_t page_number, uint8_t data[32], as608_status_t *status);
uint8_t as608_read_notepad(struct as608_dev *dev, uint8_t page_number, uint8_t data[32], as608_status_t *status);
uint8_t as608_random(struct as608_dev *dev, uint32_t *randn, as608_status_t *status);
uint8_t as608_flash_information(struct as608_dev *dev, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status);
uint8_t as608_params(struct as608_dev *dev, as608_params_t *params, as608_status_t *status);
uint8_t as608_enroll(struct as608_dev *dev, uint16_t *page_number, as608_status_t *status);
uint8_t as608_identify(struct as608_dev *dev, uint16_t *page_number, uint16_t *score, as608_status_t *status);
uint8_t as608_upload_flash_feature(struct as608_dev *dev, uint16_t page_number, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status);
uint8_t as608_upload_image_feature(struct as608_dev *dev, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status);
uint8_t as608_download_flash_feature(struct as608_dev *dev, uint16_t page_number, uint8_t *input_buffer, uint16_t input_len, as608_status_t *status);
uint8_t as608_upload_image(struct as608_dev *dev, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status);
uint8_t as608_download_image(struct as608_dev *dev, uint16_t page_number, uint8_t *input_buffer, uint16_t input_len, as608_status_t *status);
uint8_t as608_generate_bin_image(struct as608_dev *dev, as608_image_t image, as608_status_t *status);
uint8_t as608_get_valid_template_num(struct as608_dev *dev, uint16_t *num, as608_status_t *status);
uint8_t as608_set_gpio_level(struct as608_dev *dev, as608_gpio_number_t gpio, as608_gpio_level_t input_level, as608_gpio_level_t *output_level, as608_status_t *status);
uint8_t as608_get_index_table(struct as608_dev *dev, uint8_t num, uint8_t table[32], as608_status_t *status);

// Sysfs functions
void as608_sysfs_init(struct device *dev);
void as608_sysfs_cleanup(struct device *dev);

#endif