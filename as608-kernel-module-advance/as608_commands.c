#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/shm.h>
#include <linux/syscalls.h>
#include "as608.h"

static int shm_id = -1;
static uint8_t *shm_buf = NULL;

static int as608_init_shm(void) {
    shm_id = shmget(IPC_PRIVATE, AS608_MAX_BUF_SIZE, IPC_CREAT | 0666);
    if (shm_id < 0) return -ENOMEM;
    shm_buf = shmat(shm_id, NULL, 0);
    if (shm_buf == (void *)-1) {
        shmctl(shm_id, IPC_RMID, NULL);
        return -ENOMEM;
    }
    return 0;
}

static void as608_cleanup_shm(void) {
    if (shm_buf) shmdt(shm_buf);
    if (shm_id >= 0) shmctl(shm_id, IPC_RMID, NULL);
}

uint8_t as608_write_frame(struct as608_dev *dev, uint32_t addr, uint8_t type, uint8_t *data, uint16_t len) {
    uint8_t *frame = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    unsigned long flags;
    if (!frame || len > AS608_MAX_BUF_SIZE - 11) return -ENOMEM;

    spin_lock_irqsave(&dev->fast_lock, flags);
    frame[0] = 0xEF; frame[1] = 0x01;
    frame[2] = (addr >> 24) & 0xFF; frame[3] = (addr >> 16) & 0xFF;
    frame[4] = (addr >> 8) & 0xFF; frame[5] = addr & 0xFF;
    frame[6] = type;
    frame[7] = (len >> 8) & 0xFF; frame[8] = len & 0xFF;
    memcpy(&frame[9], data, len);
    uint16_t checksum = 0;
    for (int i = 6; i < 9 + len; i++) checksum += frame[i];
    frame[9 + len] = (checksum >> 8) & 0xFF;
    frame[10 + len] = checksum & 0xFF;
    uint16_t frame_len = 11 + len;
    uart_write(dev->uart_port, frame, frame_len);
    spin_unlock_irqrestore(&dev->fast_lock, flags);
    kfree(frame);
    return 0;
}

uint8_t as608_decode(uint8_t *buf, uint16_t len, uint32_t *addr, uint8_t *output, uint16_t *out_len) {
    if (len < 9 || len > AS608_MAX_BUF_SIZE) return -EINVAL;
    *addr = (buf[2] << 24) | (buf[3] << 16) | (buf[4] << 8) | buf[5];
    *out_len = (buf[7] << 8) | buf[8];
    if (*out_len > len - 11 || *out_len > AS608_MAX_BUF_SIZE) return -EINVAL;
    memcpy(output, buf + 9, *out_len);
    return 0;
}

uint8_t as608_get_image(struct as608_dev *dev, as608_status_t *status) {
    uint8_t data = 0x01;
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_input_fingerprint(struct as608_dev *dev, uint16_t *score, uint16_t *page_number, as608_status_t *status) {
    uint8_t data[2] = {0x02, 0x01};
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, data, 2);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *page_number = (output[1] << 8) | output[2];
                *score = (output[3] << 8) | output[4];
            }
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_verify(struct as608_dev *dev, uint16_t *found_page, uint16_t *score, as608_status_t *status) {
    uint8_t data = 0x04;
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *found_page = (output[1] << 8) | output[2];
                *score = (output[3] << 8) | output[4];
            }
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_high_speed_verify(struct as608_dev *dev, uint16_t *found_page, uint16_t *score, as608_status_t *status) {
    uint8_t data = 0x05;
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *found_page = (output[1] << 8) | output[2];
                *score = (output[3] << 8) | output[4];
            }
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_delete_fingerprint(struct as608_dev *dev, uint16_t page_number, as608_status_t *status) {
    uint8_t data[3] = {0x0C, (page_number >> 8) & 0xFF, page_number & 0xFF};
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, data, 3);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_empty_fingerprint(struct as608_dev *dev, as608_status_t *status) {
    uint8_t data = 0x0D;
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_write_notepad(struct as608_dev *dev, uint8_t page_number, uint8_t *data, as608_status_t *status) {
    uint8_t *frame_data = kmalloc(33, GFP_KERNEL);
    uint16_t out_len;
    if (!frame_data) return -ENOMEM;

    frame_data[0] = 0x18;
    frame_data[1] = page_number;
    memcpy(&frame_data[2], data, 32);
    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, frame_data, 33);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
        if (!output) {
            mutex_unlock(&dev->lock);
            kfree(frame_data);
            return -ENOMEM;
        }
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            mutex_unlock(&dev->lock);
            kfree(output);
            kfree(frame_data);
            return 0;
        }
        kfree(output);
    }
    mutex_unlock(&dev->lock);
    kfree(frame_data);
    return -EIO;
}

uint8_t as608_read_notepad(struct as608_dev *dev, uint8_t page_number, uint8_t *data, as608_status_t *status) {
    uint8_t data_cmd[2] = {0x18, page_number};
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, data_cmd, 2);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) memcpy(data, &output[1], 32);
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_random(struct as608_dev *dev, uint32_t *randn, as608_status_t *status) {
    uint8_t data = 0x14;
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK)
                *randn = (output[1] << 24) | (output[2] << 16) | (output[3] << 8) | output[4];
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_flash_information(struct as608_dev *dev, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status) {
    uint8_t data = 0x1A;
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *output_len = out_len - 1;
                memcpy(output_buffer, &output[1], *output_len);
            }
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_params(struct as608_dev *dev, as608_params_t *params, as608_status_t *status) {
    uint8_t data = 0x0E;
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, &data, 1);
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
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_enroll(struct as608_dev *dev, uint16_t *page_number, as608_status_t *status) {
    uint8_t data = 0x10;
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) *page_number = (output[1] << 8) | output[2];
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_identify(struct as608_dev *dev, uint16_t *page_number, uint16_t *score, as608_status_t *status) {
    uint8_t data = 0x11;
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *page_number = (output[1] << 8) | output[2];
                *score = (output[3] << 8) | output[4];
            }
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_upload_flash_feature(struct as608_dev *dev, uint16_t page_number, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status) {
    uint8_t data[3] = {0x07, (page_number >> 8) & 0xFF, page_number & 0xFF};
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, data, 3);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *output_len = out_len - 1;
                memcpy(output_buffer, &output[1], *output_len);
                memcpy(shm_buf, &output[1], *output_len);
            }
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_upload_image_feature(struct as608_dev *dev, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status) {
    uint8_t data = 0x08;
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *output_len = out_len - 1;
                memcpy(output_buffer, &output[1], *output_len);
                memcpy(shm_buf, &output[1], *output_len);
            }
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_download_flash_feature(struct as608_dev *dev, uint16_t page_number, uint8_t *input_buffer, uint16_t input_len, as608_status_t *status) {
    uint8_t *data = kmalloc(input_len + 3, GFP_KERNEL);
    uint16_t out_len;
    if (!data || input_len > AS608_MAX_BUF_SIZE - 3) {
        kfree(data);
        return -ENOMEM;
    }

    data[0] = 0x09;
    data[1] = (page_number >> 8) & 0xFF;
    data[2] = page_number & 0xFF;
    memcpy(&data[3], input_buffer, input_len);
    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, data, input_len + 3);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
        if (!output) {
            mutex_unlock(&dev->lock);
            kfree(data);
            return -ENOMEM;
        }
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            mutex_unlock(&dev->lock);
            kfree(output);
            kfree(data);
            return 0;
        }
        kfree(output);
    }
    mutex_unlock(&dev->lock);
    kfree(data);
    return -EIO;
}

uint8_t as608_upload_image(struct as608_dev *dev, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status) {
    uint8_t data = 0x0A;
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *output_len = out_len - 1;
                output = krealloc(output, *output_len, GFP_KERNEL);
                if (!output) {
                    mutex_unlock(&dev->lock);
                    return -ENOMEM;
                }
                memcpy(output_buffer, &output[1], *output_len);
                memcpy(shm_buf, &output[1], *output_len);
            }
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_download_image(struct as608_dev *dev, uint16_t page_number, uint8_t *input_buffer, uint16_t input_len, as608_status_t *status) {
    uint8_t *data = kmalloc(input_len + 3, GFP_KERNEL);
    uint16_t out_len;
    if (!data || input_len > AS608_MAX_BUF_SIZE - 3) {
        kfree(data);
        return -ENOMEM;
    }

    data[0] = 0x0B;
    data[1] = (page_number >> 8) & 0xFF;
    data[2] = page_number & 0xFF;
    memcpy(&data[3], input_buffer, input_len);
    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, data, input_len + 3);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
        if (!output) {
            mutex_unlock(&dev->lock);
            kfree(data);
            return -ENOMEM;
        }
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            mutex_unlock(&dev->lock);
            kfree(output);
            kfree(data);
            return 0;
        }
        kfree(output);
    }
    mutex_unlock(&dev->lock);
    kfree(data);
    return -EIO;
}

uint8_t as608_generate_bin_image(struct as608_dev *dev, as608_image_t image, as608_status_t *status) {
    uint8_t data[2] = {0x03, image};
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, data, 2);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_get_valid_template_num(struct as608_dev *dev, uint16_t *num, as608_status_t *status) {
    uint8_t data = 0x1D;
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) *num = (output[1] << 8) | output[2];
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_set_gpio_level(struct as608_dev *dev, as608_gpio_number_t gpio, as608_gpio_level_t input_level, as608_gpio_level_t *output_level, as608_status_t *status) {
    uint8_t data[3] = {0x12, gpio, input_level};
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, data, 3);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) *output_level = output[1];
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}

uint8_t as608_get_index_table(struct as608_dev *dev, uint8_t num, uint8_t table[32], as608_status_t *status) {
    uint8_t data[2] = {0x1F, num};
    uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    uint16_t out_len;
    if (!output) return -ENOMEM;

    mutex_lock(&dev->lock);
    as608_write_frame(dev, dev->addr, 0x07, data, 2);
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        if (as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len) == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) memcpy(table, &output[1], 32);
            mutex_unlock(&dev->lock);
            kfree(output);
            return 0;
        }
    }
    mutex_unlock(&dev->lock);
    kfree(output);
    return -EIO;
}