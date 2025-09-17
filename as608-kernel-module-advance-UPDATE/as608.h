#ifndef __AS608_H__
#define __AS608_H__
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/completion.h>
#include <linux/wait.h>
#include <linux/kthread.h>
#include <linux/mqueue.h>
#include <linux/spinlock.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

#define AS608_MAX_BUF_SIZE 1024
#define AS608_TIMEOUT_MS 1000
#define AS608_MQ_NAME "/as608_mq"
#define AS608_MQ_MAXMSG 10
#define AS608_MQ_MSGSIZE 256
#define AS608_SEM_NAME "/as608_sem"
#define AS608_SHM_NAME "/as608_shm"
#define AS608_PIPE_READ 0
#define AS608_PIPE_WRITE 1

typedef enum {
    AS608_STATUS_OK = 0x00,
    AS608_STATUS_ERROR = 0x01,
    AS608_STATUS_NO_FINGER = 0x02,
    AS608_STATUS_FAIL = 0x03,
    AS608_STATUS_NO_MATCH = 0x09,
} as608_status_t;

typedef enum {
    AS608_IMAGE_RAW = 0x01,
    AS608_IMAGE_BIN = 0x02,
} as608_image_t;

typedef enum {
    AS608_GPIO_NUMBER_0 = 0x00,
    AS608_GPIO_NUMBER_1 = 0x01,
} as608_gpio_number_t;

typedef enum {
    AS608_GPIO_LEVEL_LOW = 0x00,
    AS608_GPIO_LEVEL_HIGH = 0x01,
} as608_gpio_level_t;

typedef struct {
    uint16_t status_register;
    uint16_t system_id;
    uint16_t capacity;
    uint16_t level;
    uint32_t addr;
    uint16_t packet_size;
    uint16_t baud_rate;
} as608_params_t;

typedef struct {
    uint16_t page_number;
    as608_status_t status;
} as608_enroll_data;

typedef struct {
    uint16_t page_number;
    uint16_t score;
    as608_status_t status;
} as608_identify_data;

typedef struct {
    uint8_t buffer[AS608_MAX_BUF_SIZE];
    uint16_t len;
    as608_status_t status;
} as608_image_data;

typedef struct {
    uint8_t buffer[AS608_MAX_BUF_SIZE];
    uint16_t len;
    uint16_t page_number;
    as608_status_t status;
} as608_feature_data;

typedef struct {
    uint8_t output_buffer[AS608_MAX_BUF_SIZE];
    uint16_t output_len;
    as608_status_t status;
} as608_flash_data;

typedef struct {
    uint8_t data[32];
    uint8_t page_number;
    as608_status_t status;
} as608_notepad_data;

typedef struct {
    uint16_t page_number;
    as608_status_t status;
} as608_delete_data;

typedef struct {
    uint16_t found_page;
    uint16_t score;
    as608_status_t status;
} as608_verify_data;

typedef struct {
    uint16_t score;
    uint16_t page_number;
    as608_status_t status;
} as608_fingerprint_data;

typedef struct {
    as608_gpio_number_t gpio;
    as608_gpio_level_t input_level;
    as608_gpio_level_t output_level;
    as608_status_t status;
} as608_gpio_data;

typedef struct {
    uint8_t num;
    uint8_t table[32];
    as608_status_t status;
} as608_index_table_data;

struct as608_dev {
    struct uart_port *uart_port;
    struct mutex lock;
    spinlock_t fast_lock;
    struct completion response_complete;
    struct timer_list timeout_timer;
    uint8_t rx_buf[AS608_MAX_BUF_SIZE];
    uint16_t rx_len;
    int irq;
    wait_queue_head_t poll_queue;
    uint32_t addr;
    struct task_struct *read_thread;
    mqd_t mq;
    atomic_t open_count;
    loff_t data_offset;
    volatile bool running;
    unsigned int baud_rate;
    int pipe_fd[2];
    struct device *dev;
    struct ida minor_ida;
    struct dentry *debug_dir;
};

uint8_t as608_write_frame(struct as608_dev *dev, uint32_t addr, uint8_t type, uint8_t *data, uint16_t len);
uint8_t as608_decode(uint8_t *buf, uint16_t len, uint32_t *addr, uint8_t *output, uint16_t *out_len);
uint8_t as608_get_image(struct as608_dev *dev, as608_status_t *status);
uint8_t as608_input_fingerprint(struct as608_dev *dev, uint16_t *score, uint16_t *page_number, as608_status_t *status);
uint8_t as608_verify(struct as608_dev *dev, uint16_t *found_page, uint16_t *score, as608_status_t *status);
uint8_t as608_high_speed_verify(struct as608_dev *dev, uint16_t *found_page, uint16_t *score, as608_status_t *status);
uint8_t as608_delete_fingerprint(struct as608_dev *dev, uint16_t page_number, as608_status_t *status);
uint8_t as608_empty_fingerprint(struct as608_dev *dev, as608_status_t *status);
uint8_t as608_write_notepad(struct as608_dev *dev, uint8_t page_number, uint8_t *data, as608_status_t *status);
uint8_t as608_read_notepad(struct as608_dev *dev, uint8_t page_number, uint8_t *data, as608_status_t *status);
uint8_t as608_random(struct as608_dev *dev, uint32_t *randn, as608_status_t *status);
uint8_t as608_flash_information(struct as608_dev *dev, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status);
uint8_t as608_read_sys_para(struct as608_dev *dev, as608_params_t *params, as608_status_t *status);
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

struct uart_port *serial8250_get_port(struct device_node *np);
void uart_configure(struct uart_port *port, unsigned int baud, unsigned char bits, char parity, unsigned char stop);
uint16_t uart_read(struct uart_port *port, uint8_t *buf, uint16_t len);
void uart_write(struct uart_port *port, uint8_t *buf, uint16_t len);

void as608_sysfs_init(struct device *dev);
void as608_sysfs_cleanup(struct device *dev);

void as608_debugfs_init(struct device *dev);
void as608_debugfs_cleanup(struct device *dev);

long as608_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

#endif /* __AS608_H__ */