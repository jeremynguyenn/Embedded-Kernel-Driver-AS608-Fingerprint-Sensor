#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include "as608.h"

uint8_t as608_write_frame(uint32_t addr, uint8_t type, uint8_t *data, uint16_t len) {
    uint8_t frame[AS608_MAX_BUF_SIZE];
    uint16_t frame_len = 0;
    frame[0] = 0xEF; frame[1] = 0x01;  // Header
    frame[2] = (addr >> 24) & 0xFF; frame[3] = (addr >> 16) & 0xFF;
    frame[4] = (addr >> 8) & 0xFF; frame[5] = addr & 0xFF;
    frame[6] = type;
    frame[7] = (len >> 8) & 0xFF; frame[8] = len & 0xFF;
    memcpy(&frame[9], data, len);
    uint16_t checksum = 0;
    for (int i = 6; i < 9 + len; i++) checksum += frame[i];
    frame[9 + len] = (checksum >> 8) & 0xFF;
    frame[10 + len] = checksum & 0xFF;
    frame_len = 11 + len;
    uart_write(global_dev->uart_port, frame, frame_len);
    return 0;
}

uint8_t as608_decode(uint8_t *buf, uint16_t len, uint32_t *addr, uint8_t *output, uint16_t *out_len) {
    if (len < 9 || buf[0] != 0xEF || buf[1] != 0x01) return -EINVAL;
    *addr = (buf[2] << 24) | (buf[3] << 16) | (buf[4] << 8) | buf[5];
    *out_len = (buf[7] << 8) | buf[8];
    if (len < 9 + *out_len + 2) return -EINVAL;
    memcpy(output, &buf[9], *out_len);
    uint16_t checksum = 0;
    for (int i = 6; i < 9 + *out_len; i++) checksum += buf[i];
    if (((checksum >> 8) & 0xFF) != buf[9 + *out_len] || (checksum & 0xFF) != buf[10 + *out_len]) return -EINVAL;
    return 0;
}

uint8_t as608_get_image(struct as608_dev *dev, as608_status_t *status) {
    uint8_t data[1] = {AS608_COMMAND_GET_IMAGE};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_input_fingerprint(struct as608_dev *dev, uint16_t *score, uint16_t *page_number, as608_status_t *status) {
    uint8_t data[2] = {AS608_COMMAND_GEN_CHAR, 0x01};  // Buffer 1
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 2);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                data[0] = AS608_COMMAND_MATCH;
                as608_write_frame(dev->addr, 0x07, data, 1);
                if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
                    if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
                        *score = (output[1] << 8) | output[2];
                        *page_number = (output[3] << 8) | output[4];
                        *status = output[0];
                        return 0;
                    }
                }
            }
        }
    }
    return -EIO;
}

uint8_t as608_verify(struct as608_dev *dev, uint16_t *found_page, uint16_t *score, as608_status_t *status) {
    uint8_t data[1] = {AS608_COMMAND_MATCH};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *score = (output[1] << 8) | output[2];
                *found_page = (output[3] << 8) | output[4];
            }
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_high_speed_verify(struct as608_dev *dev, uint16_t *found_page, uint16_t *score, as608_status_t *status) {
    uint8_t data[5] = {AS608_COMMAND_SEARCH, 0x01, 0x00, 0x00, 0xFF};  // Search all
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 5);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *found_page = (output[1] << 8) | output[2];
                *score = (output[3] << 8) | output[4];
            }
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_delete_fingerprint(struct as608_dev *dev, uint16_t page_number, as608_status_t *status) {
    uint8_t data[4] = {AS608_COMMAND_DELETE_CHAR, page_number >> 8, page_number & 0xFF, 0x01};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 4);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_empty_fingerprint(struct as608_dev *dev, as608_status_t *status) {
    uint8_t data[1] = {AS608_COMMAND_TEMPLATE_COUNT};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_write_notepad(struct as608_dev *dev, uint8_t page_number, uint8_t data[32], as608_status_t *status) {
    uint8_t frame_data[33] = {AS608_COMMAND_WRITE_NOTEPAD, page_number};
    memcpy(&frame_data[1], data, 32);
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, frame_data, 33);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_read_notepad(struct as608_dev *dev, uint8_t page_number, uint8_t data[32], as608_status_t *status) {
    uint8_t frame_data[2] = {AS608_COMMAND_READ_NOTEPAD, page_number};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, frame_data, 2);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) memcpy(data, &output[1], 32);
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_random(struct as608_dev *dev, uint32_t *randn, as608_status_t *status) {
    uint8_t data[1] = {AS608_COMMAND_RANDOM};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) *randn = (output[1] << 24) | (output[2] << 16) | (output[3] << 8) | output[4];
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_flash_information(struct as608_dev *dev, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status) {
    uint8_t data[1] = {AS608_COMMAND_GET_FLASH_INFO};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                memcpy(output_buffer, &output[1], out_len - 1);
                *output_len = out_len - 1;
            }
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_params(struct as608_dev *dev, as608_params_t *params, as608_status_t *status) {
    uint8_t data[1] = {AS608_COMMAND_READ_SYS_PARA};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                params->status_register = (output[1] << 8) | output[2];
                params->system_id = (output[3] << 8) | output[4];
                params->capacity = (output[5] << 8) | output[6];
                params->level = (output[7] << 8) | output[8];
                params->addr = (output[9] << 24) | (output[10] << 16) | (output[11] << 8) | output[12];
                params->packet_size = (output[13] << 8) | output[14];
                params->baud_rate = (output[15] << 8) | output[16];
            }
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_enroll(struct as608_dev *dev, uint16_t *page_number, as608_status_t *status) {
    uint8_t data[3] = {AS608_COMMAND_REG_MODEL};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                data[0] = AS608_COMMAND_STORE_CHAR;
                data[1] = *page_number >> 8;
                data[2] = *page_number & 0xFF;
                as608_write_frame(dev->addr, 0x07, data, 3);
                if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
                    if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
                        *status = output[0];
                        return 0;
                    }
                }
            }
        }
    }
    return -EIO;
}

uint8_t as608_identify(struct as608_dev *dev, uint16_t *page_number, uint16_t *score, as608_status_t *status) {
    uint8_t data[5] = {AS608_COMMAND_SEARCH, 0x01, 0x00, 0x00, 0xFF};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 5);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *page_number = (output[1] << 8) | output[2];
                *score = (output[3] << 8) | output[4];
            }
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_upload_flash_feature(struct as608_dev *dev, uint16_t page_number, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status) {
    uint8_t data[3] = {AS608_COMMAND_UP_CHAR, 0x01};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 2);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                memcpy(output_buffer, &output[1], out_len - 1);
                *output_len = out_len - 1;
            }
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_upload_image_feature(struct as608_dev *dev, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status) {
    uint8_t data[1] = {AS608_COMMAND_UP_IMAGE};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                memcpy(output_buffer, &output[1], out_len - 1);
                *output_len = out_len - 1;
            }
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_download_flash_feature(struct as608_dev *dev, uint16_t page_number, uint8_t *input_buffer, uint16_t input_len, as608_status_t *status) {
    uint8_t data[AS608_MAX_BUF_SIZE] = {AS608_COMMAND_DOWN_CHAR, 0x01};
    memcpy(&data[2], input_buffer, input_len);
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, input_len + 2);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_upload_image(struct as608_dev *dev, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status) {
    uint8_t data[1] = {AS608_COMMAND_UP_IMAGE};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                memcpy(output_buffer, &output[1], out_len - 1);
                *output_len = out_len - 1;
            }
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_download_image(struct as608_dev *dev, uint16_t page_number, uint8_t *input_buffer, uint16_t input_len, as608_status_t *status) {
    uint8_t data[AS608_MAX_BUF_SIZE] = {AS608_COMMAND_DOWN_IMAGE};
    memcpy(&data[1], input_buffer, input_len);
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, input_len + 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_generate_bin_image(struct as608_dev *dev, as608_image_t image, as608_status_t *status) {
    uint8_t data[2] = {AS608_COMMAND_DOWN_IMAGE, image};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 2);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_get_valid_template_num(struct as608_dev *dev, uint16_t *num, as608_status_t *status) {
    uint8_t data[1] = {AS608_COMMAND_TEMPLATE_COUNT};
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) *num = (output[1] << 8) | output[2];
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_set_gpio_level(struct as608_dev *dev, as608_gpio_number_t gpio, as608_gpio_level_t input_level, as608_gpio_level_t *output_level, as608_status_t *status) {
    uint8_t data[3] = {0x12, gpio, input_level};  // Custom command for GPIO
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 3);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) *output_level = output[1];
            return 0;
        }
    }
    return -EIO;
}

uint8_t as608_get_index_table(struct as608_dev *dev, uint8_t num, uint8_t table[32], as608_status_t *status) {
    uint8_t data[2] = {0x1F, num};  // Custom command for index table
    uint8_t output[AS608_MAX_BUF_SIZE];
    uint16_t out_len;
    as608_write_frame(dev->addr, 0x07, data, 2);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) memcpy(table, &output[1], 32);
            return 0;
        }
    }
    return -EIO;
}