#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <mqueue.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "as608.h"

/* User-space program for interacting with AS608 kernel module.
 * Uses IOCTLs, message queues, pipes, and shared memory for communication.
 */

#define AS608_MQ_NAME "/as608_mq"  /* POSIX message queue name */
#define AS608_MQ_MSGSIZE 256       /* Max message size */
#define AS608_SEM_NAME "/as608_sem" /* POSIX semaphore name */
#define AS608_SHM_NAME "/as608_shm" /* Shared memory name */

static volatile sig_atomic_t running = 1; /* Flag to control thread execution */
static pthread_mutex_t mq_mutex = PTHREAD_MUTEX_INITIALIZER; /* Mutex for message queue */
static pthread_cond_t mq_cond = PTHREAD_COND_INITIALIZER; /* Condition variable for synchronization */
static sem_t *sem = NULL; /* POSIX semaphore for access control */

/* Signal handler for graceful shutdown */
static void signal_handler(int sig) {
    printf("User: Received signal %d (Thread ID: %lu)\n", sig, pthread_self());
    running = 0;
    pthread_cond_broadcast(&mq_cond);
}

static void *read_mq_thread(void *arg) {
    mqd_t mq = mq_open(AS608_MQ_NAME, O_RDONLY);
    if (mq < 0) {
        perror("User: Failed to open message queue");
        return NULL;
    }
    char *buf = malloc(AS608_MQ_MSGSIZE);
    if (!buf) {
        perror("User: Memory allocation failed");
        mq_close(mq);
        return NULL;
    }
    printf("User: Message queue thread started (Thread ID: %lu)\n", pthread_self());
    while (running) {
        pthread_mutex_lock(&mq_mutex);
        if (sem_wait(sem) < 0) {
            perror("User: sem_wait failed");
            pthread_mutex_unlock(&mq_mutex);
            break;
        }
        ssize_t len = mq_receive(mq, buf, AS608_MQ_MSGSIZE, NULL);
        if (len < 0) {
            perror("User: mq_receive failed");
            pthread_mutex_unlock(&mq_mutex);
            break;
        }
        buf[len] = '\0';
        printf("User: Received from MQ: %s (Thread ID: %lu)\n", buf, pthread_self());
        pthread_cond_signal(&mq_cond);
        if (sem_post(sem) < 0) {
            perror("User: sem_post failed");
        }
        pthread_mutex_unlock(&mq_mutex);
    }
    free(buf);
    mq_close(mq);
    return NULL;
}

static void *read_pipe_thread(void *arg) {
    int *pipe_fd = (int *)arg;
    char buf[AS608_MQ_MSGSIZE];
    printf("User: Pipe thread started (Thread ID: %lu)\n", pthread_self());
    while (running) {
        pthread_mutex_lock(&mq_mutex);
        ssize_t len = read(pipe_fd[AS608_PIPE_READ], buf, AS608_MQ_MSGSIZE);
        if (len <= 0) {
            if (len < 0) perror("User: Pipe read failed");
            pthread_mutex_unlock(&mq_mutex);
            break;
        }
        buf[len] = '\0';
        printf("User: Received from pipe: %s (Thread ID: %lu)\n", buf, pthread_self());
        pthread_cond_signal(&mq_cond);
        pthread_mutex_unlock(&mq_mutex);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    char *ioctl_cmd = (argc > 1) ? argv[1] : NULL;
    int exec_mode = (argc > 2) ? atoi(argv[2]) : 0;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGUSR1, signal_handler);

    pthread_t mq_thread, pipe_thread;
    int pipe_fd[2];
    if (pipe(pipe_fd) < 0) {
        perror("User: Pipe creation failed");
        return 1;
    }

    sem = sem_open(AS608_SEM_NAME, O_CREAT, 0644, 1);
    if (sem == SEM_FAILED) {
        perror("User: Semaphore open failed");
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return 1;
    }

    int shm_fd = shm_open(AS608_SHM_NAME, O_RDWR | O_CREAT, 0644);
    if (shm_fd < 0) {
        perror("User: Shared memory open failed");
        sem_close(sem);
        sem_unlink(AS608_SEM_NAME);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return 1;
    }
    if (ftruncate(shm_fd, AS608_MAX_BUF_SIZE) < 0) {
        perror("User: Shared memory truncate failed");
        close(shm_fd);
        sem_close(sem);
        sem_unlink(AS608_SEM_NAME);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return 1;
    }
    uint8_t *shm_buf = mmap(NULL, AS608_MAX_BUF_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (shm_buf == MAP_FAILED) {
        perror("User: Shared memory map failed");
        close(shm_fd);
        sem_close(sem);
        sem_unlink(AS608_SEM_NAME);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return 1;
    }

    if (pthread_create(&mq_thread, NULL, read_mq_thread, NULL) != 0) {
        perror("User: Message queue thread creation failed");
        munmap(shm_buf, AS608_MAX_BUF_SIZE);
        close(shm_fd);
        sem_close(sem);
        sem_unlink(AS608_SEM_NAME);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return 1;
    }
    if (pthread_create(&pipe_thread, NULL, read_pipe_thread, pipe_fd) != 0) {
        perror("User: Pipe thread creation failed");
        pthread_cancel(mq_thread);
        munmap(shm_buf, AS608_MAX_BUF_SIZE);
        close(shm_fd);
        sem_close(sem);
        sem_unlink(AS608_SEM_NAME);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return 1;
    }

    int fd = open("/dev/as608", O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        perror("Open failed");
        pthread_cancel(mq_thread);
        pthread_cancel(pipe_thread);
        munmap(shm_buf, AS608_MAX_BUF_SIZE);
        close(shm_fd);
        sem_close(sem);
        sem_unlink(AS608_SEM_NAME);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return 1;
    }

    as608_status_t *status = malloc(sizeof(as608_status_t));
    if (!status) {
        perror("Memory allocation failed");
        goto cleanup;
    }
    if (!ioctl_cmd || strcmp(ioctl_cmd, "GET_IMAGE") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_GET_IMAGE, status) < 0) perror("IOCTL GET_IMAGE failed");
        sem_post(sem);
    }

    struct as608_fingerprint_data *fp_data = calloc(1, sizeof(struct as608_fingerprint_data));
    if (!fp_data) {
        perror("Memory allocation failed");
        free(status);
        goto cleanup;
    }
    if (!ioctl_cmd || strcmp(ioctl_cmd, "INPUT_FINGERPRINT") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_INPUT_FINGERPRINT, fp_data) < 0) perror("IOCTL INPUT_FINGERPRINT failed");
        sem_post(sem);
    }

    struct as608_verify_data *verify_data = calloc(1, sizeof(struct as608_verify_data));
    if (!verify_data) {
        perror("Memory allocation failed");
        free(fp_data);
        free(status);
        goto cleanup;
    }
    if (!ioctl_cmd || strcmp(ioctl_cmd, "VERIFY") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_VERIFY, verify_data) < 0) perror("IOCTL VERIFY failed");
        sem_post(sem);
    }

    if (!ioctl_cmd || strcmp(ioctl_cmd, "HIGH_SPEED_VERIFY") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_HIGH_SPEED_VERIFY, verify_data) < 0) perror("IOCTL HIGH_SPEED_VERIFY failed");
        sem_post(sem);
    }

    struct as608_delete_data *delete_data = calloc(1, sizeof(struct as608_delete_data));
    if (!delete_data) {
        perror("Memory allocation failed");
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    delete_data->page_number = 1;
    if (!ioctl_cmd || strcmp(ioctl_cmd, "DELETE_FINGERPRINT") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_DELETE_FINGERPRINT, delete_data) < 0) perror("IOCTL DELETE_FINGERPRINT failed");
        sem_post(sem);
    }

    if (!ioctl_cmd || strcmp(ioctl_cmd, "EMPTY_FINGERPRINT") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_EMPTY_FINGERPRINT, status) < 0) perror("IOCTL EMPTY_FINGERPRINT failed");
        sem_post(sem);
    }

    struct as608_notepad_data *notepad_data = calloc(1, sizeof(struct as608_notepad_data));
    if (!notepad_data) {
        perror("Memory allocation failed");
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    notepad_data->page_number = 0;
    memset(notepad_data->data, 0xAA, 32);
    if (!ioctl_cmd || strcmp(ioctl_cmd, "WRITE_NOTEPAD") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_WRITE_NOTEPAD, notepad_data) < 0) perror("IOCTL WRITE_NOTEPAD failed");
        sem_post(sem);
    }

    struct as608_notepad_data *read_notepad_data = calloc(1, sizeof(struct as608_notepad_data));
    if (!read_notepad_data) {
        perror("Memory allocation failed");
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    read_notepad_data->page_number = 0;
    if (!ioctl_cmd || strcmp(ioctl_cmd, "READ_NOTEPAD") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_READ_NOTEPAD, read_notepad_data) < 0) perror("IOCTL READ_NOTEPAD failed");
        sem_post(sem);
    }

    uint32_t *randn = malloc(sizeof(uint32_t));
    if (!randn) {
        perror("Memory allocation failed");
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    if (!ioctl_cmd || strcmp(ioctl_cmd, "RANDOM") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_RANDOM, randn) < 0) perror("IOCTL RANDOM failed");
        sem_post(sem);
    }

    struct as608_flash_data *flash_data = calloc(1, sizeof(struct as608_flash_data));
    if (!flash_data) {
        perror("Memory allocation failed");
        free(randn);
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    if (!ioctl_cmd || strcmp(ioctl_cmd, "FLASH_INFORMATION") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_FLASH_INFORMATION, flash_data) < 0) perror("IOCTL FLASH_INFORMATION failed");
        sem_post(sem);
    }

    as608_params_t *params = malloc(sizeof(as608_params_t));
    if (!params) {
        perror("Memory allocation failed");
        free(flash_data);
        free(randn);
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    if (!ioctl_cmd || strcmp(ioctl_cmd, "PARAMS") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_PARAMS, params) < 0) perror("IOCTL PARAMS failed");
        sem_post(sem);
    }

    struct as608_enroll_data *enroll_data = calloc(1, sizeof(struct as608_enroll_data));
    if (!enroll_data) {
        perror("Memory allocation failed");
        free(params);
        free(flash_data);
        free(randn);
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    if (!ioctl_cmd || strcmp(ioctl_cmd, "ENROLL") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_ENROLL, enroll_data) < 0) perror("IOCTL ENROLL failed");
        sem_post(sem);
    }

    struct as608_identify_data *identify_data = calloc(1, sizeof(struct as608_identify_data));
    if (!identify_data) {
        perror("Memory allocation failed");
        free(enroll_data);
        free(params);
        free(flash_data);
        free(randn);
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    if (!ioctl_cmd || strcmp(ioctl_cmd, "IDENTIFY") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_IDENTIFY, identify_data) < 0) perror("IOCTL IDENTIFY failed");
        sem_post(sem);
    }

    struct as608_feature_data *feature_data = calloc(1, sizeof(struct as608_feature_data));
    if (!feature_data) {
        perror("Memory allocation failed");
        free(identify_data);
        free(enroll_data);
        free(params);
        free(flash_data);
        free(randn);
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    feature_data->page_number = 1;
    feature_data->len = 256;
    if (!ioctl_cmd || strcmp(ioctl_cmd, "UPLOAD_FLASH_FEATURE") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_UPLOAD_FLASH_FEATURE, feature_data) < 0) perror("IOCTL UPLOAD_FLASH_FEATURE failed");
        sem_post(sem);
    }

    struct as608_feature_data *image_feature_data = calloc(1, sizeof(struct as608_feature_data));
    if (!image_feature_data) {
        perror("Memory allocation failed");
        free(feature_data);
        free(identify_data);
        free(enroll_data);
        free(params);
        free(flash_data);
        free(randn);
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    image_feature_data->len = 256;
    if (!ioctl_cmd || strcmp(ioctl_cmd, "UPLOAD_IMAGE_FEATURE") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_UPLOAD_IMAGE_FEATURE, image_feature_data) < 0) perror("IOCTL UPLOAD_IMAGE_FEATURE failed");
        sem_post(sem);
    }

    struct as608_feature_data *download_feature_data = calloc(1, sizeof(struct as608_feature_data));
    if (!download_feature_data) {
        perror("Memory allocation failed");
        free(image_feature_data);
        free(feature_data);
        free(identify_data);
        free(enroll_data);
        free(params);
        free(flash_data);
        free(randn);
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    download_feature_data->page_number = 1;
    download_feature_data->len = 256;
    if (!ioctl_cmd || strcmp(ioctl_cmd, "DOWNLOAD_FLASH_FEATURE") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_DOWNLOAD_FLASH_FEATURE, download_feature_data) < 0) perror("IOCTL DOWNLOAD_FLASH_FEATURE failed");
        sem_post(sem);
    }

    struct as608_image_data *image_data = calloc(1, sizeof(struct as608_image_data));
    if (!image_data) {
        perror("Memory allocation failed");
        free(download_feature_data);
        free(image_feature_data);
        free(feature_data);
        free(identify_data);
        free(enroll_data);
        free(params);
        free(flash_data);
        free(randn);
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    image_data->len = 256;
    if (!ioctl_cmd || strcmp(ioctl_cmd, "UPLOAD_IMAGE") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_UPLOAD_IMAGE, image_data) < 0) perror("IOCTL UPLOAD_IMAGE failed");
        sem_post(sem);
    }

    struct as608_image_data *download_image_data = calloc(1, sizeof(struct as608_image_data));
    if (!download_image_data) {
        perror("Memory allocation failed");
        free(image_data);
        free(download_feature_data);
        free(image_feature_data);
        free(feature_data);
        free(identify_data);
        free(enroll_data);
        free(params);
        free(flash_data);
        free(randn);
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    download_image_data->len = 256;
    download_image_data->page_number = 1;
    if (!ioctl_cmd || strcmp(ioctl_cmd, "DOWNLOAD_IMAGE") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_DOWNLOAD_IMAGE, download_image_data) < 0) perror("IOCTL DOWNLOAD_IMAGE failed");
        sem_post(sem);
    }

    as608_image_t *image_type = malloc(sizeof(as608_image_t));
    if (!image_type) {
        perror("Memory allocation failed");
        free(download_image_data);
        free(image_data);
        free(download_feature_data);
        free(image_feature_data);
        free(feature_data);
        free(identify_data);
        free(enroll_data);
        free(params);
        free(flash_data);
        free(randn);
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    *image_type = AS608_IMAGE_BIN;
    if (!ioctl_cmd || strcmp(ioctl_cmd, "GENERATE_BIN_IMAGE") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_GENERATE_BIN_IMAGE, image_type) < 0) perror("IOCTL GENERATE_BIN_IMAGE failed");
        sem_post(sem);
    }

    uint16_t *num = malloc(sizeof(uint16_t));
    if (!num) {
        perror("Memory allocation failed");
        free(image_type);
        free(download_image_data);
        free(image_data);
        free(download_feature_data);
        free(image_feature_data);
        free(feature_data);
        free(identify_data);
        free(enroll_data);
        free(params);
        free(flash_data);
        free(randn);
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    if (!ioctl_cmd || strcmp(ioctl_cmd, "GET_VALID_TEMPLATE_NUM") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_GET_VALID_TEMPLATE_NUM, num) < 0) perror("IOCTL GET_VALID_TEMPLATE_NUM failed");
        sem_post(sem);
    }

    struct as608_gpio_data *gpio_data = calloc(1, sizeof(struct as608_gpio_data));
    if (!gpio_data) {
        perror("Memory allocation failed");
        free(num);
        free(image_type);
        free(download_image_data);
        free(image_data);
        free(download_feature_data);
        free(image_feature_data);
        free(feature_data);
        free(identify_data);
        free(enroll_data);
        free(params);
        free(flash_data);
        free(randn);
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    gpio_data->gpio = AS608_GPIO_NUMBER_0;
    gpio_data->input_level = AS608_GPIO_LEVEL_HIGH;
    if (!ioctl_cmd || strcmp(ioctl_cmd, "SET_GPIO_LEVEL") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_SET_GPIO_LEVEL, gpio_data) < 0) perror("IOCTL SET_GPIO_LEVEL failed");
        sem_post(sem);
    }

    struct as608_index_table_data *index_data = calloc(1, sizeof(struct as608_index_table_data));
    if (!index_data) {
        perror("Memory allocation failed");
        free(gpio_data);
        free(num);
        free(image_type);
        free(download_image_data);
        free(image_data);
        free(download_feature_data);
        free(image_feature_data);
        free(feature_data);
        free(identify_data);
        free(enroll_data);
        free(params);
        free(flash_data);
        free(randn);
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    index_data->num = 1;
    if (!ioctl_cmd || strcmp(ioctl_cmd, "GET_INDEX_TABLE") == 0) {
        sem_wait(sem);
        if (ioctl(fd, AS608_IOCTL_GET_INDEX_TABLE, index_data) < 0) perror("IOCTL GET_INDEX_TABLE failed");
        sem_post(sem);
    }

    uint8_t *buf = malloc(10);
    if (!buf) {
        perror("Memory allocation failed");
        free(index_data);
        free(gpio_data);
        free(num);
        free(image_type);
        free(download_image_data);
        free(image_data);
        free(download_feature_data);
        free(image_feature_data);
        free(feature_data);
        free(identify_data);
        free(enroll_data);
        free(params);
        free(flash_data);
        free(randn);
        free(read_notepad_data);
        free(notepad_data);
        free(delete_data);
        free(verify_data);
        free(fp_data);
        free(status);
        goto cleanup;
    }
    memset(buf, 0, 10);
    buf[0] = 0x01; buf[1] = 0x02;
    sem_wait(sem);
    if (write(fd, buf, 10) < 0) perror("Write failed");
    if (read(fd, buf, 10) < 0) perror("Read failed");
    sem_post(sem);

    free(index_data);
    free(gpio_data);
    free(num);
    free(image_type);
    free(download_image_data);
    free(image_data);
    free(download_feature_data);
    free(image_feature_data);
    free(feature_data);
    free(identify_data);
    free(enroll_data);
    free(params);
    free(flash_data);
    free(randn);
    free(read_notepad_data);
    free(notepad_data);
    free(delete_data);
    free(verify_data);
    free(fp_data);
    free(status);
    free(buf);

cleanup:
    munmap(shm_buf, AS608_MAX_BUF_SIZE);
    close(shm_fd);
    shm_unlink(AS608_SHM_NAME);
    sem_close(sem);
    sem_unlink(AS608_SEM_NAME);
    close(pipe_fd[0]);
    close(pipe_fd[1]);
    close(fd);
    pthread_join(mq_thread, NULL);
    pthread_join(pipe_thread, NULL);
    if (exec_mode) wait(NULL);
    return 0;
}