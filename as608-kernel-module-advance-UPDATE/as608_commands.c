#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/shm.h>
#include <linux/syscalls.h>
#include "as608.h"

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

static int shm_id = -1;
static uint8_t *shm_buf = NULL;

static int as608_init_shm(void) {
    shm_id = shmget(IPC_PRIVATE, AS608_MAX_BUF_SIZE, IPC_CREAT | 0666);
    if (shm_id < 0) {
        pr_err("SHM: Failed to create shared memory\n");
        return -ENOMEM;
    }
    shm_buf = shmat(shm_id, NULL, 0);
    if (shm_buf == (void *)-1) {
        pr_err("SHM: Failed to attach shared memory\n");
        shmctl(shm_id, IPC_RMID, NULL);
        return -ENOMEM;
    }
    pr_debug("SHM: Initialized successfully, ID %d\n", shm_id);
    return 0;
}

static void as608_cleanup_shm(void) {
    if (shm_buf) shmdt(shm_buf);
    if (shm_id >= 0) shmctl(shm_id, IPC_RMID, NULL);
}

uint8_t as608_write_frame(struct as608_dev *dev, uint32_t addr, uint8_t type, uint8_t *data, uint16_t len) {
    uint8_t *frame = NULL;
    unsigned long flags;
    int res = 0;

    if (!dev || !dev->uart_port) {
        pr_err("Write frame: Invalid device or UART port\n");
        return -EINVAL;
    }
    if (len > AS608_MAX_BUF_SIZE - 11) {
        pr_err("Write frame: Data length %u exceeds max %d\n", len, AS608_MAX_BUF_SIZE - 11);
        return -EINVAL;
    }

    frame = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!frame) {
        pr_err("Write frame: Memory allocation failed\n");
        return -ENOMEM;
    }

    spin_lock_irqsave(&dev->fast_lock, flags);
    frame[0] = 0xEF; frame[1] = 0x01;
    frame[2] = (addr >> 24) & 0xFF; frame[3] = (addr >> 16) & 0xFF;
    frame[4] = (addr >> 8) & 0xFF; frame[5] = addr & 0xFF;
    frame[6] = type;
    frame[7] = (len >> 8) & 0xFF; frame[8] = len & 0xFF;
    if (data && len > 0) {
        memcpy(&frame[9], data, len);
    }
    uint16_t checksum = 0;
    for (int i = 6; i < 9 + len; i++) checksum += frame[i];
    frame[9 + len] = (checksum >> 8) & 0xFF;
    frame[10 + len] = checksum & 0xFF;
    uint16_t frame_len = 11 + len;
    res = uart_write(dev->uart_port, frame, frame_len);
    if (res < 0) pr_err("Write frame: UART write failed %d\n", res);
    spin_unlock_irqrestore(&dev->fast_lock, flags);
    kfree(frame);
    return res ? res : 0;
}

uint8_t as608_decode(uint8_t *buf, uint16_t len, uint32_t *addr, uint8_t *output, uint16_t *out_len) {
    if (!buf || !addr || !output || !out_len) {
        pr_err("Decode: NULL pointer argument\n");
        return -EINVAL;
    }
    if (len < 9 || len > AS608_MAX_BUF_SIZE) {
        pr_err("Decode: Invalid length %u\n", len);
        return -EINVAL;
    }
    *addr = (buf[2] << 24) | (buf[3] << 16) | (buf[4] << 8) | buf[5];
    *out_len = (buf[7] << 8) | buf[8];
    if (*out_len > len - 11 || *out_len > AS608_MAX_BUF_SIZE) {
        pr_err("Decode: Invalid output length %u\n", *out_len);
        return -EINVAL;
    }
    memcpy(output, buf + 9, *out_len);
    return 0;
}

uint8_t as608_get_image(struct as608_dev *dev, as608_status_t *status) {
    uint8_t data = 0x01;
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !status) {
        pr_err("Get image: Invalid device or status\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Get image: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (res < 0) {
        pr_err("Get image: Write frame failed %d\n", res);
        goto out_unlock;
    }
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0 && out_len > 0) {
            *status = output[0];
            res = 0;
        } else {
            pr_err("Get image: Decode failed %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Get image: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_input_fingerprint(struct as608_dev *dev, uint16_t *score, uint16_t *page_number, as608_status_t *status) {
    uint8_t data[2] = {0x02, 0x01};
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !score || !page_number || !status) {
        pr_err("Input fingerprint: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Input fingerprint: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, data, 2);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0 && out_len >= 5) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *page_number = (output[1] << 8) | output[2];
                *score = (output[3] << 8) | output[4];
            }
            res = 0;
        } else {
            pr_err("Input fingerprint: Decode failed or invalid out_len %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Input fingerprint: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_verify(struct as608_dev *dev, uint16_t *found_page, uint16_t *score, as608_status_t *status) {
    uint8_t data = 0x04;
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !found_page || !score || !status) {
        pr_err("Verify: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Verify: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0 && out_len >= 5) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *found_page = (output[1] << 8) | output[2];
                *score = (output[3] << 8) | output[4];
            }
            res = 0;
        } else {
            pr_err("Verify: Decode failed or invalid out_len %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Verify: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_high_speed_verify(struct as608_dev *dev, uint16_t *found_page, uint16_t *score, as608_status_t *status) {
    uint8_t data = 0x51;
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !found_page || !score || !status) {
        pr_err("High speed verify: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("High speed verify: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0 && out_len >= 5) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *found_page = (output[1] << 8) | output[2];
                *score = (output[3] << 8) | output[4];
            }
            res = 0;
        } else {
            pr_err("High speed verify: Decode failed or invalid out_len %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("High speed verify: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_delete_fingerprint(struct as608_dev *dev, uint16_t page_number, as608_status_t *status) {
    uint8_t data[3] = {0x0C, (page_number >> 8) & 0xFF, page_number & 0xFF};
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !status) {
        pr_err("Delete fingerprint: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Delete fingerprint: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, data, 3);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0) {
            *status = output[0];
            res = 0;
        } else {
            pr_err("Delete fingerprint: Decode failed %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Delete fingerprint: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_empty_fingerprint(struct as608_dev *dev, as608_status_t *status) {
    uint8_t data = 0x0D;
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !status) {
        pr_err("Empty fingerprint: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Empty fingerprint: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0) {
            *status = output[0];
            res = 0;
        } else {
            pr_err("Empty fingerprint: Decode failed %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Empty fingerprint: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_write_notepad(struct as608_dev *dev, uint8_t page_number, uint8_t *data, as608_status_t *status) {
    uint8_t *cmd_data = NULL;
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !data || !status) {
        pr_err("Write notepad: NULL pointer argument\n");
        return -EINVAL;
    }

    cmd_data = kmalloc(33, GFP_KERNEL);
    if (!cmd_data) {
        pr_err("Write notepad: Memory allocation failed\n");
        return -ENOMEM;
    }

    cmd_data[0] = 0x18;
    cmd_data[1] = page_number;
    memcpy(&cmd_data[2], data, 32);

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        kfree(cmd_data);
        pr_err("Write notepad: Memory allocation failed for output\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, cmd_data, 33);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0) {
            *status = output[0];
            res = 0;
        } else {
            pr_err("Write notepad: Decode failed %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Write notepad: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(cmd_data);
    kfree(output);
    return res;
}

uint8_t as608_read_notepad(struct as608_dev *dev, uint8_t page_number, uint8_t *data, as608_status_t *status) {
    uint8_t cmd_data[2] = {0x19, page_number};
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !data || !status) {
        pr_err("Read notepad: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Read notepad: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, cmd_data, 2);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0 && out_len >= 33) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) memcpy(data, &output[1], 32);
            res = 0;
        } else {
            pr_err("Read notepad: Decode failed or invalid out_len %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Read notepad: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_random(struct as608_dev *dev, uint32_t *randn, as608_status_t *status) {
    uint8_t data = 0x1B;
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !randn || !status) {
        pr_err("Random: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Random: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0 && out_len >= 5) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) *randn = (output[1] << 24) | (output[2] << 16) | (output[3] << 8) | output[4];
            res = 0;
        } else {
            pr_err("Random: Decode failed or invalid out_len %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Random: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_flash_information(struct as608_dev *dev, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status) {
    uint8_t data = 0x26;
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !output_buffer || !output_len || !status) {
        pr_err("Flash information: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Flash information: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *output_len = out_len - 1;
                memcpy(output_buffer, &output[1], *output_len);
            }
            res = 0;
        } else {
            pr_err("Flash information: Decode failed %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Flash information: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_read_sys_para(struct as608_dev *dev, as608_params_t *params, as608_status_t *status) {
    uint8_t data = 0x0F;  // Corrected from 0x1C based on datasheet
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !params || !status) {
        pr_err("Read sys para: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Read sys para: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0 && out_len >= 17) {
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
            res = 0;
        } else {
            pr_err("Read sys para: Decode failed or invalid out_len %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Read sys para: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_enroll(struct as608_dev *dev, uint16_t *page_number, as608_status_t *status) {
    uint8_t data = 0x10;
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !page_number || !status) {
        pr_err("Enroll: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Enroll: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0 && out_len >= 3) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) *page_number = (output[1] << 8) | output[2];
            res = 0;
        } else {
            pr_err("Enroll: Decode failed or invalid out_len %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Enroll: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_identify(struct as608_dev *dev, uint16_t *page_number, uint16_t *score, as608_status_t *status) {
    uint8_t data = 0x11;
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !page_number || !score || !status) {
        pr_err("Identify: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Identify: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0 && out_len >= 5) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *page_number = (output[1] << 8) | output[2];
                *score = (output[3] << 8) | output[4];
            }
            res = 0;
        } else {
            pr_err("Identify: Decode failed or invalid out_len %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Identify: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_upload_flash_feature(struct as608_dev *dev, uint16_t page_number, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status) {
    uint8_t data[3] = {0x06, (page_number >> 8) & 0xFF, page_number & 0xFF};
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !output_buffer || !output_len || !status) {
        pr_err("Upload flash feature: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Upload flash feature: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, data, 3);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *output_len = out_len - 1;
                memcpy(output_buffer, &output[1], *output_len);
            }
            res = 0;
        } else {
            pr_err("Upload flash feature: Decode failed %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Upload flash feature: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_upload_image_feature(struct as608_dev *dev, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status) {
    uint8_t data = 0x08;
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !output_buffer || !output_len || !status) {
        pr_err("Upload image feature: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Upload image feature: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *output_len = out_len - 1;
                memcpy(output_buffer, &output[1], *output_len);
            }
            res = 0;
        } else {
            pr_err("Upload image feature: Decode failed %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Upload image feature: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_download_flash_feature(struct as608_dev *dev, uint16_t page_number, uint8_t *input_buffer, uint16_t input_len, as608_status_t *status) {
    uint8_t *data = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !input_buffer || !status) {
        pr_err("Download flash feature: NULL pointer argument\n");
        return -EINVAL;
    }
    if (input_len > AS608_MAX_BUF_SIZE - 3) {
        pr_err("Download flash feature: Input length %u exceeds max %d\n", input_len, AS608_MAX_BUF_SIZE - 3);
        return -EINVAL;
    }

    data = kmalloc(input_len + 3, GFP_KERNEL);
    if (!data) {
        pr_err("Download flash feature: Memory allocation failed\n");
        return -ENOMEM;
    }

    data[0] = 0x09;
    data[1] = (page_number >> 8) & 0xFF;
    data[2] = page_number & 0xFF;
    memcpy(&data[3], input_buffer, input_len);
    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, data, input_len + 3);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
        if (!output) {
            res = -ENOMEM;
            goto out_unlock;
        }
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0) {
            *status = output[0];
            res = 0;
        } else {
            pr_err("Download flash feature: Decode failed %d\n", res);
            res = -EIO;
        }
        kfree(output);
    } else {
        pr_err("Download flash feature: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(data);
    return res;
}

uint8_t as608_upload_image(struct as608_dev *dev, uint8_t *output_buffer, uint16_t *output_len, as608_status_t *status) {
    uint8_t data = 0x0A;
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !output_buffer || !output_len || !status) {
        pr_err("Upload image: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Upload image: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) {
                *output_len = out_len - 1;
                memcpy(output_buffer, &output[1], *output_len);
            }
            res = 0;
        } else {
            pr_err("Upload image: Decode failed %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Upload image: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_download_image(struct as608_dev *dev, uint16_t page_number, uint8_t *input_buffer, uint16_t input_len, as608_status_t *status) {
    uint8_t *data = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !input_buffer || !status) {
        pr_err("Download image: NULL pointer argument\n");
        return -EINVAL;
    }
    if (input_len > AS608_MAX_BUF_SIZE - 3) {
        pr_err("Download image: Input length %u exceeds max %d\n", input_len, AS608_MAX_BUF_SIZE - 3);
        return -EINVAL;
    }

    data = kmalloc(input_len + 3, GFP_KERNEL);
    if (!data) {
        pr_err("Download image: Memory allocation failed\n");
        return -ENOMEM;
    }

    data[0] = 0x0B;
    data[1] = (page_number >> 8) & 0xFF;
    data[2] = page_number & 0xFF;
    memcpy(&data[3], input_buffer, input_len);
    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, data, input_len + 3);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        uint8_t *output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
        if (!output) {
            res = -ENOMEM;
            goto out_unlock;
        }
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0) {
            *status = output[0];
            res = 0;
        } else {
            pr_err("Download image: Decode failed %d\n", res);
            res = -EIO;
        }
        kfree(output);
    } else {
        pr_err("Download image: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(data);
    return res;
}

uint8_t as608_generate_bin_image(struct as608_dev *dev, as608_image_t image, as608_status_t *status) {
    uint8_t data[2] = {0x03, image};
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !status) {
        pr_err("Generate bin image: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Generate bin image: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, data, 2);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0) {
            *status = output[0];
            res = 0;
        } else {
            pr_err("Generate bin image: Decode failed %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Generate bin image: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_get_valid_template_num(struct as608_dev *dev, uint16_t *num, as608_status_t *status) {
    uint8_t data = 0x1D;
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !num || !status) {
        pr_err("Get valid template num: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Get valid template num: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, &data, 1);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0 && out_len >= 3) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) *num = (output[1] << 8) | output[2];
            res = 0;
        } else {
            pr_err("Get valid template num: Decode failed or invalid out_len %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Get valid template num: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_set_gpio_level(struct as608_dev *dev, as608_gpio_number_t gpio, as608_gpio_level_t input_level, as608_gpio_level_t *output_level, as608_status_t *status) {
    uint8_t data[3] = {0x12, gpio, input_level};
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !output_level || !status) {
        pr_err("Set GPIO level: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Set GPIO level: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, data, 3);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0 && out_len >= 2) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) *output_level = output[1];
            res = 0;
        } else {
            pr_err("Set GPIO level: Decode failed or invalid out_len %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Set GPIO level: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}

uint8_t as608_get_index_table(struct as608_dev *dev, uint8_t num, uint8_t table[32], as608_status_t *status) {
    uint8_t data[2] = {0x1F, num};
    uint8_t *output = NULL;
    uint16_t out_len;
    int res = 0;

    if (!dev || !table || !status) {
        pr_err("Get index table: NULL pointer argument\n");
        return -EINVAL;
    }

    output = kmalloc(AS608_MAX_BUF_SIZE, GFP_KERNEL);
    if (!output) {
        pr_err("Get index table: Memory allocation failed\n");
        return -ENOMEM;
    }

    mutex_lock(&dev->lock);
    res = as608_write_frame(dev, dev->addr, 0x07, data, 2);
    if (res < 0) goto out_unlock;
    if (wait_for_completion_timeout(&dev->response_complete, msecs_to_jiffies(AS608_TIMEOUT_MS))) {
        res = as608_decode(dev->rx_buf, dev->rx_len, &dev->addr, output, &out_len);
        if (res == 0 && out_len >= 33) {
            *status = output[0];
            if (*status == AS608_STATUS_OK) memcpy(table, &output[1], 32);
            res = 0;
        } else {
            pr_err("Get index table: Decode failed or invalid out_len %d\n", res);
            res = -EIO;
        }
    } else {
        pr_err("Get index table: Timeout\n");
        res = -ETIMEDOUT;
    }
out_unlock:
    mutex_unlock(&dev->lock);
    kfree(output);
    return res;
}