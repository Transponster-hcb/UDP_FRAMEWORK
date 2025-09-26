#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define _GNU_SOURCE

#include <stdio.h>  // 包含标准输入输出库，用于snprintf和print_log
#include <stdlib.h>  // 包含标准库，用于malloc和free
#include <string.h>  // 包含字符串处理库，用于memset、strncpy和memcpy
#include <sys/time.h>
#include <sys/socket.h>  // Linux套接字头文件，提供socket、bind、sendto、recvfrom等函数
#include <arpa/inet.h>  // 包含IP地址转换函数，如inet_pton和htons
#include <pthread.h>  // 包含POSIX线程库，用于pthread_mutex_t和pthread_cond_t
#include <time.h>  // 包含时间库，用于time和clock_gettime
#include <unistd.h>  // 包含Unix标准库，用于usleep和close
#include <fcntl.h>
#include <stddef.h>
#include <limits.h>
#include <errno.h>
#include <termios.h>
#include <inttypes.h>// 新增这行，支持PRIu64宏

#include "network.h"  // 包含自定义网络头文件，声明函数原型

#define BUF_SIZE 128




// 修正宏定义为复合字面量
#define GREEN_INIT_PATTERN (const unsigned char[]){0xFE,0x02,0x01,0x00,0x91,0x9C}
#define RED_INIT_PATTERN   (const unsigned char[]){0xFE,0x02,0x01,0x01,0x50,0x5C}
#define GREEN_STATUS_PATTERN (const unsigned char[]){0x40,0x57,0x01,0x00,0x00,0x43}
#define RED_STATUS_PATTERN   (const unsigned char[]){0x40,0x57,0x01,0x01,0x00,0x44}
#define CMD_PATTERN          (const unsigned char[]){0xFE,0x02,0x00,0x00,0x00,0x02,0xED,0xC4}

// 假设这些函数在其他地方已经实现
extern bool is_authentic();
extern int get_CMD_seq();
extern int redundant_send(uint8_t direction, const uint8_t* ciphertext, const Config* config);
extern int pack_message(MessageType message_type, uint8_t direction, uint32_t sequence_number,
                        uint64_t timestamp, uint32_t validity, const uint8_t* payload, Message* msg);
extern int aes_gcm_encrypt(const Message* msg, const uint8_t* aes_key, uint8_t* ciphertext);

extern bool is_valid_message(const Message* msg);
// 修复函数签名与common.h中声明一致
extern int is_queue_empty(PacketQueue* queue);
extern PacketNode* get_all_packets(PacketQueue* q);
extern void free_packet_list(PacketNode* head);
extern void updateLightColor(int lamp_id, int color);
// 修复函数签名与network.h中声明一致
extern void path_warning(char source_ipaddr[], char dest_ipaddr[]);


//1.心跳序列号管理函数
// 静态变量，用于维护心跳序列号，初始值为0x0000
static uint16_t seq_heartbeat = 0x0000;
/**
 * @brief 获取并维护心跳序列号，每次调用返回循环递增的序列号，范围为0x0000至0xFFFF（65535）
 * @param config 指向Config结构体的指针，用于存储加载的配置信息（当前未使用）
 * @param msg 指向Message结构体的指针，包含要发送的消息（将设置其sequence_number字段）
 * @return 返回当前心跳序列号，失败时返回-1
 */
int get_heartbeat_seq(Config* config, Message* msg) {
    // 检查输入参数是否为空
    if (config == NULL || msg == NULL) {
        return -1; // 参数为空，返回错误
    }
    
    // 验证消息类型是否为心跳类型
    if (msg->message_type != MSG_TYPE_HEARTBEAT) {
        return -1; // 无效的消息类型，返回错误
    }
    
    // 获取当前序列号并递增
    uint16_t current_seq = seq_heartbeat;
    seq_heartbeat = (seq_heartbeat + 1) % 0x10000; // 确保序列号在0x0000到0xFFFF范围内循环
    
    // 更新消息结构体中的序列号字段
    msg->sequence_number = current_seq;
    
    // 返回当前序列号
    return (int)current_seq;
}


//2.cmd序列号管理函数
// 静态变量，用于维护指令序列号，初始值为0x0000
static uint16_t seq_cmd = 0x0000;

/**
 * @brief 获取并维护指令序列号，每次调用返回循环递增的序列号，范围为0x0000至0xFFFF（65535）
 * @param config 指向Config结构体的指针，用于存储加载的配置信息（当前未使用）
 * @param msg 指向Message结构体的指针，包含要发送的消息（将设置其sequence_number字段）
 * @return 返回当前指令序列号，失败时返回-1
 */
int get_CMD_seq(Config* config, Message* msg) {
    // 检查输入参数是否为空
    if (config == NULL || msg == NULL) {
        return -1; // 参数为空，返回错误
    }
    
    // 验证消息类型是否为有效的指令类型
    if (msg->message_type != MSG_TYPE_CMD_POWER_CUT && 
        msg->message_type != MSG_TYPE_CMD_POWER_RESTORE &&
        msg->message_type != MSG_TYPE_CHANGE_KEY) {
        return -1; // 无效的消息类型，返回错误
    }
    
    // 获取当前序列号并递增
    uint16_t current_seq = seq_cmd;
    seq_cmd = (seq_cmd + 1) % 0x10000; // 确保序列号在0x0000到0xFFFF范围内循环
    
    // 更新消息结构体中的序列号字段
    msg->sequence_number = current_seq;
    
    // 返回当前序列号
    return (int)current_seq;
}


//3.ACK序列号管理函数
// 静态变量，用于维护ACK序列号，初始值为0x0000
static uint16_t seq_ack = 0x0000;

/**
 * @brief 获取并维护ACK序列号，每次调用返回循环递增的序列号，范围为0x0000至0xFFFF（65535）
 * @param config 指向Config结构体的指针，用于存储加载的配置信息（当前未使用）
 * @param msg 指向Message结构体的指针，包含要发送的消息（将设置其sequence_number字段）
 * @return 返回当前ACK序列号，失败时返回-1
 */
int get_ACK_seq(Config* config, Message* msg) {
    // 检查输入参数是否为空
    if (config == NULL || msg == NULL) {
        return -1; // 参数为空，返回错误
    }
    
    // 验证消息类型是否为ACK类型
    if (msg->message_type != MSG_TYPE_ACK) {
        return -1; // 无效的消息类型，返回错误
    }
    
    // 获取当前序列号并递增
    uint16_t current_seq = seq_ack;
    seq_ack = (seq_ack + 1) % 0x10000; // 确保序列号在0x0000到0xFFFF范围内循环
    
    // 更新消息结构体中的序列号字段
    msg->sequence_number = current_seq;
    
    // 返回当前序列号
    return (int)current_seq;
}


//4.有效性验证函数
/** 
 * @brief 根据时间戳和有效期验证消息的有效性，根据序列号判断是否重复消息（去重），并支持序列号重置
 * @param msg 指向待验证Message结构体的指针
 * @return 合法返回true，否则返回false
 */
bool is_valid_message(const Message* msg) {
    if (msg == NULL) {  // 检查指针是否为空，如果为空，直接返回 false
        return false;
    }

    // 获取当前时间戳（毫秒精度）
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    uint64_t current_time_ms = (uint64_t)(now.tv_sec) * 1000 + now.tv_nsec / 1000000;

    // 检查时间戳有效性
    if (current_time_ms - msg->timestamp > msg->validity || current_time_ms < msg->timestamp) {
        return false;  // 如果当前时间减去消息时间戳大于有效期（已过期），或当前时间小于消息时间戳（来自未来），则无效
    }

    // 静态变量，保存上一个有效消息的序列号和时间戳
    static uint32_t last_sequence = 0;
    static uint64_t last_timestamp = 0;

    // 重置机制
    if (msg->sequence_number == 0 && last_sequence > 0 && 
        (current_time_ms - last_timestamp > 3600000)) {  // 1小时（3600000毫秒）后序列号为0，视为新会话，重置
        last_sequence = 0;
    } else if (last_sequence == UINT32_MAX) {  // 序列号达到最大值，重置
        if (msg->sequence_number == 0) {  // 要求新消息序列号从0开始
            last_sequence = 0;
        } else {
            return false;  // 序列号溢出但未从0开始，视为无效
        }
    }

    // 根据序列号去重
    if (msg->sequence_number <= last_sequence) {  // 如果当前序列号小于或等于上一个，则视为重复或重放
        return false;
    }

    // 如果验证通过，更新上一个序列号和时间戳
    last_sequence = msg->sequence_number;
    last_timestamp = msg->timestamp;

    return true;  // 所有检查通过，返回 true
}


//5.冗余发送函数
/**
 * @brief controlled将加密后的密文通过UDP从四条路径发送出去
 * @param direction 消息方向(1: Controller->Controlled, 0: Controlled->Controller)
 * @param ciphertext 指向加密后数据的指针，数据长度应为52字节
 * @param config 用于存储加载的配置信息
 * @return 成功返回0，失败返回-1
 */
int redundant_send(uint8_t direction, const uint8_t* ciphertext, const Config* config) {
    // 参数检查
    if (!ciphertext || !config || !config->controller_ip1[0] || !config->controller_ip2[0] || 
        !config->controlled_ip3[0] || !config->controlled_ip4[0]) {
        fprintf(stderr, "Invalid parameters\n");
        return -1;
    }

    // 创建 UDP 套接字
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // 设置发送目标地址和端口
    struct sockaddr_in dest_addr[4];
    int path_count = 4; // 四条路径
    int i;

    // 根据 direction 设置四条路径的源和目标 IP/端口
    if (direction == 1) { // Controller -> Controlled
        // 路径1: controller_ip1 -> controlled_ip3, output_port -> input_port
        memset(&dest_addr[0], 0, sizeof(struct sockaddr_in));
        dest_addr[0].sin_family = AF_INET;
        dest_addr[0].sin_port = htons(config->input_port);
        inet_pton(AF_INET, config->controlled_ip3, &dest_addr[0].sin_addr);

        // 路径2: controller_ip1 -> controlled_ip4, output_port -> input_port
        memset(&dest_addr[1], 0, sizeof(struct sockaddr_in));
        dest_addr[1].sin_family = AF_INET;
        dest_addr[1].sin_port = htons(config->input_port);
        inet_pton(AF_INET, config->controlled_ip4, &dest_addr[1].sin_addr);

        // 路径3: controller_ip2 -> controlled_ip3, output_port -> input_port
        memset(&dest_addr[2], 0, sizeof(struct sockaddr_in));
        dest_addr[2].sin_family = AF_INET;
        dest_addr[2].sin_port = htons(config->input_port);
        inet_pton(AF_INET, config->controlled_ip3, &dest_addr[2].sin_addr);

        // 路径4: controller_ip2 -> controlled_ip4, output_port -> input_port
        memset(&dest_addr[3], 0, sizeof(struct sockaddr_in));
        dest_addr[3].sin_family = AF_INET;
        dest_addr[3].sin_port = htons(config->input_port);
        inet_pton(AF_INET, config->controlled_ip4, &dest_addr[3].sin_addr);
    } else if (direction == 0) { // Controlled -> Controller
        // 路径1: controlled_ip3 -> controller_ip1, input_port -> output_port
        memset(&dest_addr[0], 0, sizeof(struct sockaddr_in));
        dest_addr[0].sin_family = AF_INET;
        dest_addr[0].sin_port = htons(config->output_port);
        inet_pton(AF_INET, config->controller_ip1, &dest_addr[0].sin_addr);

        // 路径2: controlled_ip3 -> controller_ip2, input_port -> output_port
        memset(&dest_addr[1], 0, sizeof(struct sockaddr_in));
        dest_addr[1].sin_family = AF_INET;
        dest_addr[1].sin_port = htons(config->output_port);
        inet_pton(AF_INET, config->controller_ip2, &dest_addr[1].sin_addr);

        // 路径3: controlled_ip4 -> controller_ip1, input_port -> output_port
        memset(&dest_addr[2], 0, sizeof(struct sockaddr_in));
        dest_addr[2].sin_family = AF_INET;
        dest_addr[2].sin_port = htons(config->output_port);
        inet_pton(AF_INET, config->controller_ip1, &dest_addr[2].sin_addr);

        // 路径4: controlled_ip4 -> controller_ip2, input_port -> output_port
        memset(&dest_addr[3], 0, sizeof(struct sockaddr_in));
        dest_addr[3].sin_family = AF_INET;
        dest_addr[3].sin_port = htons(config->output_port);
        inet_pton(AF_INET, config->controller_ip2, &dest_addr[3].sin_addr);
    } else {
        fprintf(stderr, "Invalid direction value\n");
        close(sockfd);
        return -1;
    }

    // 通过四条路径发送密文
    for (i = 0; i < path_count; i++) {
        ssize_t sent_bytes = sendto(sockfd, ciphertext, 52, 0,
                                   (struct sockaddr*)&dest_addr[i], 
                                   sizeof(struct sockaddr_in));
        if (sent_bytes != 52) {
            perror("Failed to send data on path");
            close(sockfd);
            return -1;
        }
    }

    // 关闭套接字
    close(sockfd);
    return 0;
}


//6.主控端串口监听函数
/**
 * @brief 初始化串口设备
 */
int init_serial(const char *port) {
    int fd = open(port, O_RDWR | O_NOCTTY);
    if (fd < 0) {
        perror("Error opening serial port");
        return -1;
    }

    struct termios options;
    if (tcgetattr(fd, &options) != 0) {
        perror("tcgetattr failed");
        close(fd);
        return -1;
    }

    cfsetispeed(&options, B9600);
    cfsetospeed(&options, B9600);
    options.c_cflag |= (CLOCAL | CREAD);
    options.c_cflag &= ~PARENB;
    options.c_cflag &= ~CSTOPB;
    options.c_cflag &= ~CSIZE;
    options.c_cflag |= CS8;
    options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    options.c_oflag &= ~OPOST;
    options.c_cc[VMIN] = 1;  // 阻塞模式，至少读取1字节
    options.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSANOW, &options) != 0) {
        perror("Error configuring serial port");
        close(fd);
        return -1;
    }
    tcflush(fd, TCIOFLUSH);
    return fd;
}

/**
 * @brief 安全地在环形缓冲区上比较 pattern，避免越界读
 */
static int circular_memcmp(const unsigned char *buf, int buf_size, int pos,
                           const unsigned char *pattern, int pat_len) {
    for (int i = 0; i < pat_len; i++) {
        int idx = (pos + i) % buf_size;
        if (buf[idx] != pattern[i]) return 0;
    }
    return 1;
}

/**
 * @brief 检查设备初始状态（绿灯或红灯）
 * @param fd 串口文件描述符
 * @return 绿灯状态返回1，红灯状态返回0，错误返回-1
 */
int check_initial_state(int fd) {
    const unsigned char init_cmd[] = {0xFE,0x02,0x00,0x00,0x00,0x02,0xED,0xC4};
    unsigned char buffer[BUF_SIZE];
    int total_bytes = 0;

    if (write(fd, init_cmd, sizeof(init_cmd)) != (ssize_t)sizeof(init_cmd)) {
        perror("Failed to write init command to serial");
        return -1;
    }
    tcdrain(fd);

    while (1) {
        ssize_t bytes_read = read(fd, buffer + total_bytes, BUF_SIZE - total_bytes);
        if (bytes_read > 0) {
            total_bytes += (int)bytes_read;
            // 滑动窗口检测响应
            while (total_bytes >= 6) {
                // 检查从位置0开始的6字节（不断左移一位）
                if (memcmp(buffer, GREEN_INIT_PATTERN, 6) == 0) return 1;
                if (memcmp(buffer, RED_INIT_PATTERN, 6) == 0) return 0;

                // 将窗口向左移动一字节
                memmove(buffer, buffer + 1, total_bytes - 1);
                total_bytes -= 1;
            }

            // 如果缓冲区几乎满了但还没检测到，保留最后6字节以供下次继续检测
            if (total_bytes > BUF_SIZE - 6) {
                int keep = 6;
                memmove(buffer, buffer + total_bytes - keep, keep);
                total_bytes = keep;
            }
        } else if (bytes_read == 0) {
            // EOF 或设备关闭
            fprintf(stderr, "Serial port returned EOF\n");
            return -1;
        } else {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 非阻塞情况下没有数据，等待一下
                usleep(1000);
                continue;
            }
            perror("Error reading serial port");
            return -1;
        }
    }
}

/**
 * @brief 监听串口，处理CMD命令并做可靠重传
 * @param config 配置
 * @param ip_seq IP序号（1或2）
 * @param aes_key 32字节AES密钥
 * @param sharedACK ACK共享结构
 */
void controller_serial_listen(const Config* config, int ip_seq, const uint8_t aes_key[32], SharedData* sharedACK) {
    // 打开/dev/ttyS5串口设备
    int serial_fd = init_serial("/dev/ttyS5");
    if (serial_fd < 0) {
        printf("Failed to open serial port /dev/ttyS5\n");
        return;
    }

    // 等待绿灯初始化状态
    while (1) {
        int state = check_initial_state(serial_fd);
        if (state < 0) {
            // 读取失败，稍后重试
            usleep(100000);
            continue;
        }
        if (state == 1) break;
        // 若为红灯则重试等待变为绿灯
        usleep(100000);
    }

    tcflush(serial_fd, TCIFLUSH);

    // 消息和加密相关变量
    Message cmd_msg;
    uint8_t ciphertext[52];

    // 重传相关变量
    int retry_count = 0;
    bool ack_received = false;
    uint32_t current_seq_num = 0;

    // 环形缓冲区用于处理串口数据
    unsigned char circular_buf[BUF_SIZE];
    memset(circular_buf, 0, sizeof(circular_buf));
    int head = 0;

    printf("Controller serial listener started (IP sequence: %d), waiting for CMD commands...\n", ip_seq);

    while (1) {
        unsigned char byte;
        ssize_t bytes_read = read(serial_fd, &byte, 1);
        if (bytes_read == 1) {
            circular_buf[head] = byte;
            head = (head + 1) % BUF_SIZE;

            // 检查是否收到CMD命令：在环形缓冲区中从 head-1 向前查找最长为8的位置
            for (int offset = 0; offset < 8; offset++) {
                int check_pos = (head - 8 - offset + BUF_SIZE) % BUF_SIZE;
                // 使用安全的环形比较函数
                if (circular_memcmp(circular_buf, BUF_SIZE, check_pos, CMD_PATTERN, 8)) {
                    printf("CMD pattern detected, processing command...\n");

                    // 认证判断
                    if (!is_authentic()) {
                        printf("Authentication failed - cannot process CMD command\n");
                        break; // 中止此次检测，继续监听串口
                    }

                    // 生成CMD消息
                    uint8_t payload[6] = {0xFE, 0x02, 0x00, 0x00, 0x00, 0x02};
                    current_seq_num = (uint32_t)get_CMD_seq();
                    uint64_t timestamp = (uint64_t)time(NULL) * 1000ULL;

                    MessageType msg_type = MSG_TYPE_CMD_POWER_CUT;

                    if (pack_message(msg_type, 1, current_seq_num, timestamp,
                                     config->cmd_validity, payload, &cmd_msg) != 0) {
                        printf("Failed to pack CMD message\n");
                        break;
                    }

                    // 加密消息
                    if (aes_gcm_encrypt(&cmd_msg, aes_key, ciphertext) != 0) {
                        printf("Failed to encrypt CMD message\n");
                        break;
                    }

                    // 重置重传状态
                    retry_count = 0;
                    ack_received = false;

                    // 第一次发送CMD命令（直接发送）
                    printf("Sending CMD command with sequence number: %u (IP seq: %d)\n", current_seq_num, ip_seq);

                    if (redundant_send(1, ciphertext, config) != 0) {
                        printf("Failed to send CMD command\n");
                        //print_log("Failed to send CMD command");
                        break;
                    }

                    // 等待ACK响应，最多重试max_retry_count次
                    struct timespec start_monotonic;
                    clock_gettime(CLOCK_MONOTONIC, &start_monotonic);

                    while (retry_count <= config->max_retry_count && !ack_received) {
                        // 为 pthread_cond_timedwait 构造基于 CLOCK_REALTIME 的绝对超时
                        struct timespec abs_timeout;
                        clock_gettime(CLOCK_REALTIME, &abs_timeout);
                        abs_timeout.tv_sec += 3; // 3秒的超时窗口

                        pthread_mutex_lock(&sharedACK->mutex);

                        int wait_result = pthread_cond_timedwait(&sharedACK->cond_var,
                                                                 &sharedACK->mutex, &abs_timeout);
                        (void)wait_result; // 我们不直接使用返回值，而是在唤醒后检查队列

                        // 检查ACK队列中是否有对应的ACK消息
                        if (!is_queue_empty(&sharedACK->packet_queue)) {
                            PacketNode* packets = get_all_packets(&sharedACK->packet_queue);
                            PacketNode* current_packet = packets;

                            while (current_packet) {
                                if (is_valid_message(&current_packet->msg) &&
                                    current_packet->msg.message_type == MSG_TYPE_ACK &&
                                    current_packet->msg.sequence_number == current_seq_num) {
                                    ack_received = true;
                                    printf("ACK received for sequence number: %u\n", current_seq_num);
                                    //print_log("ACK received for CMD command");
                                    break;
                                }
                                current_packet = current_packet->next;
                            }

                            free_packet_list(packets);
                        }

                        pthread_mutex_unlock(&sharedACK->mutex);

                        // 计算是否超时（使用 MONOTONIC 计时）
                        struct timespec now_monotonic;
                        clock_gettime(CLOCK_MONOTONIC, &now_monotonic);
                        double elapsed_seconds = (now_monotonic.tv_sec - start_monotonic.tv_sec) +
                                                 (now_monotonic.tv_nsec - start_monotonic.tv_nsec) / 1e9;

                        // 如果超时且未收到ACK，进行重传
                        if (!ack_received && elapsed_seconds >= 3.0) {
                            if (retry_count < config->max_retry_count) {
                                retry_count++;
                                printf("ACK timeout, retrying... (%d/%d)\n",
                                       retry_count, config->max_retry_count);

                                // 重传CMD命令
                                if (redundant_send(1, ciphertext, config) != 0) {
                                    printf("Failed to re-send CMD command on retry %d\n", retry_count);
                                } else {
                                    printf("CMD command re-sent successfully (retry %d)\n", retry_count);
                                }
                                // 重新设定新的开始时间
                                clock_gettime(CLOCK_MONOTONIC, &start_monotonic);
                            } else {
                                // 达到最大重试次数
                                printf("Max retry count (%d) reached, no ACK received for sequence %u\n",
                                       config->max_retry_count, current_seq_num);
                                break;
                            }
                        } else if (ack_received) {
                            // 收到ACK，跳出重传循环
                            break;
                        }
                    }

                    if (ack_received) {
                        printf("CMD command processing completed successfully with ACK\n");
                        // 更新指示灯状态为绿色
                        updateLightColor(1, 1); // 假设灯1为命令状态灯，1为绿色
                    } else {
                        printf("CMD command processing failed - no ACK received after %d retries\n",
                               config->max_retry_count);
                        // 更新指示灯状态为黄色（告警）
                        updateLightColor(1, 2); // 假设灯1为命令状态灯，2为黄色
                    }

                    // 清空环形缓冲区中已处理的CMD命令
                    memset(circular_buf, 0, BUF_SIZE);
                    head = 0;
                    break; // 跳出 offset 检查循环
                }
            }
        } else if (bytes_read == 0) {
            // 串口被关闭或EOF，短暂休眠后继续尝试
            usleep(1000);
            continue;
        } else {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            }
            perror("Error reading serial port");
            break;
        }

        // 短暂休眠避免CPU过度占用
        usleep(1000);
    }

    // 关闭串口
    if (serial_fd >= 0) {
        close(serial_fd);
    }
}


//7.受控端串口监听（待实现）

/**
 * @brief 监听串口，判断是heartbeat消息还是IO-ACK消息，生成相应的数据包，加密后调用redundant_send发送
 * 串口参数待补充
 * @param config 用于存储加载的配置信息
 * @param aes_key[32] 用于存储AES-GCM加密所需的密钥
 */
void controlled_serial_listen(const Config* config, const uint8_t aes_key[32]);//4


//8.受控端监听输入端口
// 全局序列号计数器（用于生成心跳、CMD、ACK的序列号）
static uint32_t heartbeat_seq = 0;
static uint32_t cmd_seq = 0;
static uint32_t ack_seq = 0;
static pthread_mutex_t seq_mutex = PTHREAD_MUTEX_INITIALIZER;  // 保护序列号的锁

// 辅助函数：创建UDP socket（类似申请一个"信箱"）
static int create_udp_socket() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);  // AF_INET=IPv4，SOCK_DGRAM=UDP协议
    if (sockfd < 0) {
        perror("创建socket失败（类似信箱制作失败）");
        return -1;
    }
    return sockfd;
}

// 辅助函数：绑定socket到指定IP和端口（给"信箱"贴地址）
static int bind_socket(int sockfd, const char* ip, int port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(ip);  // 转换IP为网络格式
    addr.sin_port = htons(port);  // 转换端口为网络格式（大端字节序）

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("绑定IP和端口失败（类似地址贴错）");
        close(sockfd);
        return -1;
    }
    printf("已绑定到 %s:%d（信箱地址正确）\n", ip, port);
    return 0;
}
/**
 * @brief controlled主线程循环执行，监听输入端口，接收来自Controller的控制指令，调用aes_gcm_decrypt解密并验证，调用is_valid_message判断合法性
 *      通过验证后，加锁，入队，修改环境变量通知CMD处理线程，解锁，调用POWER_CUT/POWER_RESTORE执行控制指令
 * @param config 用于存储加载的配置信息
 * @param ip_seq 用于标识当前使用的IP地址(主进程中需启动两个线程分别调用此函数，因此ip_seq取值分别为1和2，用于监听config中本机的第一个和第二个IP地址)
 * @param aes_key 用于存储AES-GCM加密所需的密钥
 * @param sharedCMD 用于存储CMD消息的线程同步数据结构
 */
 // 被控端监听函数（核心！两个网口各启动一个线程执行此函数）
// 作用：监听指定IP的UDP端口，接收主控端发来的加密命令，解密后放入共享队列
void controlled_listen(const Config* config, int ip_seq, const uint8_t aes_key[32], SharedData* sharedCMD) {
    // 1. 检查参数合法性（防止传入空指针导致程序崩溃）
    if (config == NULL || sharedCMD == NULL) {
        printf("错误：配置或共享数据为空（参数无效）\n");
        return; // 直接退出函数，不继续执行
    }

    // 2. 打印调试信息，确认当前线程的IP序号和配置中的IP是否正确
    printf("调试：当前线程IP序号=%d，配置中30.2的IP=%s，配置中40.2的IP=%s\n",
           ip_seq, config->controlled_ip3, config->controlled_ip4);

    // 3. 根据IP序号选择要监听的IP（1对应30.2，2对应40.2）
    const char* listen_ip; // 存储当前线程要监听的IP地址
    if (ip_seq == 1) {
        listen_ip = config->controlled_ip3; // ip_seq=1 → 监听30.2
    } else if (ip_seq == 2) {
        listen_ip = config->controlled_ip4; // ip_seq=2 → 监听40.2
    } else {
        printf("错误：IP序号必须是1或2，当前传入%d（无效）\n", ip_seq);
        return; // 序号错误，退出函数
    }

    // 4. 打印线程启动信息，确认监听的IP正确
    printf("启动被控端监听线程（IP序号：%d，实际监听IP：%s）\n", ip_seq, listen_ip);

    // 5. 创建UDP socket（网络通信的"管道"）
    int sockfd = create_udp_socket(); // 调用工具函数创建UDP套接字
    if (sockfd < 0) { // 如果创建失败（返回-1）
        printf("线程%d：创建socket失败，无法监听\n", ip_seq);
        return; // 退出函数
    }

    // 6. 绑定socket到指定IP和端口（把"管道"接到指定的"信箱地址"）
    // 端口从配置文件读取（通常是50002）
    if (bind_socket(sockfd, listen_ip, config->input_port) < 0) {
        printf("线程%d：绑定到%s:%d失败\n", ip_seq, listen_ip, config->input_port);
        close(sockfd); // 关闭socket释放资源
        return; // 退出函数
    }
    printf("线程%d：已成功绑定到%s:%d（可以接收消息了）\n", ip_seq, listen_ip, config->input_port);

    // 7. 循环接收消息（死循环，一直运行）
    while (1) {
        // 存储接收到的加密消息（52字节固定格式：12字节IV + 24字节密文 + 16字节校验标签）
        uint8_t ciphertext[52]; 
        // 存储发送方（主控端）的地址信息
        struct sockaddr_in src_addr; 
        socklen_t addr_len = sizeof(src_addr); // 地址结构体的长度

        // 8. 接收数据（阻塞等待，直到收到消息）
        // recvfrom：从socket接收数据，并获取发送方地址
        ssize_t recv_len = recvfrom(sockfd, ciphertext, sizeof(ciphertext), 0,
                                   (struct sockaddr*)&src_addr, &addr_len);
        
        // 9. 检查接收的数据长度是否正确（必须是52字节，否则可能是非法消息）
        if (recv_len != sizeof(ciphertext)) {
            printf("线程%d：接收数据错误（预期52字节，实际收到%d字节），跳过\n", 
                   ip_seq, (int)recv_len);
            continue; // 跳过本次循环，继续等下一条消息
        }

        // 10. 解密消息（使用AES-GCM算法，密钥是aes_key）
        Message msg; // 存储解密后的明文消息
        if (aes_gcm_decrypt(ciphertext, aes_key, &msg) != 0) {
            printf("线程%d：消息解密失败（可能是密钥不对或消息被篡改），跳过\n", ip_seq);
            continue; // 解密失败，跳过
        }

        // 11. 验证消息有效性（检查是否过期、是否是重复消息等）
        // is_valid_message是工具函数，判断消息的时间戳是否在有效期内
        if (!is_valid_message(&msg)) {
            printf("线程%d：消息无效（可能已过期），类型：%d，序列号：%u，跳过\n",
                   ip_seq, msg.message_type, msg.sequence_number);
            continue; // 无效消息，跳过
        }

        // 12. 过滤非CMD命令（只处理断电和恢复供电命令）
        if (msg.message_type != MSG_TYPE_CMD_POWER_CUT && 
            msg.message_type != MSG_TYPE_CMD_POWER_RESTORE) {
            printf("线程%d：收到非CMD消息（类型：%d），不需要处理，跳过\n",
                   ip_seq, msg.message_type);
            continue; // 不是命令消息，跳过
        }

        // 13. 到这里，消息是"合法的CMD命令"，准备放入共享队列
        // 加互斥锁：保证同一时间只有一个线程操作队列（防止数据混乱）
        pthread_mutex_lock(&sharedCMD->mutex);

        // 14. 将消息入队（复制到队列中，供处理线程取用）
        // 入队前打印消息详情，确认入队的消息正确
        printf("线程%d：准备入队的消息 - 类型：%d（1=断电），序列号：%u\n",
               ip_seq, msg.message_type, msg.sequence_number);
        
        // 调用入队函数，将消息存入队列
        enqueue_packet(&sharedCMD->packet_queue, msg);

        // 15. 入队后打印队列状态，确认入队成功
        printf("线程%d：CMD消息入队成功（类型：%d，序列号：%u，当前队列长度：%d）\n",
               ip_seq, msg.message_type, msg.sequence_number, sharedCMD->packet_queue.count);

        // 16. 唤醒处理线程（如果处理线程在等待新消息）
        // 条件变量signal：按"门铃"通知处理线程"有新消息了"
        pthread_cond_signal(&sharedCMD->cond_var);

        // 17. 解锁：释放队列的"钥匙"，让其他线程（另一个监听线程或处理线程）可以操作队列
        pthread_mutex_unlock(&sharedCMD->mutex);
    }

    // 18. 关闭socket（实际不会执行到这里，因为上面是死循环）
    close(sockfd);
}


//9.主控端监听输入端口（待实现）
/**
 * @brief controller主线程循环执行，监听输入端口，接收来自Controlled的ACK消息和心跳消息，调用aes_gcm_decrypt解密并验证，调用is_valid_message判断合法性
 *      通过验证后，将心跳消息和ACK消息分别放入SharedData中等待处理(要加锁解锁)
 * @param config 用于存储加载的配置信息
 * @param ip_seq 用于标识当前使用的IP地址(主进程中需启动两个线程分别调用此函数，因此ip_seq取值分别为1和2，用于监听config中本机的第一个和第二个IP地址)
 * @param aes_key 用于存储AES-GCM加密所需的密钥
 * @param sharedACK 用于存储ACK消息的线程同步数据结构
 * @param sharedheartbeat 用于存储心跳消息的线程同步数据结构
 */
void controller_listen(const Config* config,int ip_seq, const uint8_t aes_key[32], SharedData* sharedACK, SharedData* sharedheartbeat);//3


//10.心跳线程函数
/**
 * @brief 处理心跳信息的线程函数，从心跳队列中取出心跳消息，调用is_valid_message判断合法性,去重
 *      通过验证后， 1.监测链路状态。更新对应路径的最后心跳时间，如果目前时间-最后心跳时间超过heartbeat_warn则认为路径不可用,调用warning函数告警
 *                  2.更新被控端空开状态（这里是否要闪灯？是否要在前端展示？）
 *                  3.更新空开状态，调用updateLightColor控制闪灯
 * @param config 用于存储加载的配置信息
 * @param heartbeat_queue 用于存储心跳消息的线程安全队列
 */
void controller_heartbeat_manager(const Config* config, SharedData* sharedheartbeat) {
    // 链路状态结构体
    typedef struct {
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        uint64_t last_heartbeat_time;
        int timeout_count;
        bool is_connected;
    } LinkStatus;

    // 四条链路的状态 (IP1->IP3, IP1->IP4, IP2->IP3, IP2->IP4)
    static LinkStatus link_status[4];
    static bool initialized = false;
    static time_t last_check_time = 0;

    // 初始化链路状态
    if (!initialized) {
        // 链路0: controller_ip1 -> controlled_ip3
        strncpy(link_status[0].src_ip, config->controller_ip1, INET_ADDRSTRLEN);
        strncpy(link_status[0].dst_ip, config->controlled_ip3, INET_ADDRSTRLEN);
        link_status[0].last_heartbeat_time = 0;
        link_status[0].timeout_count = 0;
        link_status[0].is_connected = true;

        // 链路1: controller_ip1 -> controlled_ip4
        strncpy(link_status[1].src_ip, config->controller_ip1, INET_ADDRSTRLEN);
        strncpy(link_status[1].dst_ip, config->controlled_ip4, INET_ADDRSTRLEN);
        link_status[1].last_heartbeat_time = 0;
        link_status[1].timeout_count = 0;
        link_status[1].is_connected = true;

        // 链路2: controller_ip2 -> controlled_ip3
        strncpy(link_status[2].src_ip, config->controller_ip2, INET_ADDRSTRLEN);
        strncpy(link_status[2].dst_ip, config->controlled_ip3, INET_ADDRSTRLEN);
        link_status[2].last_heartbeat_time = 0;
        link_status[2].timeout_count = 0;
        link_status[2].is_connected = true;

        // 链路3: controller_ip2 -> controlled_ip4
        strncpy(link_status[3].src_ip, config->controller_ip2, INET_ADDRSTRLEN);
        strncpy(link_status[3].dst_ip, config->controlled_ip4, INET_ADDRSTRLEN);
        link_status[3].last_heartbeat_time = 0;
        link_status[3].timeout_count = 0;
        link_status[3].is_connected = true;

        initialized = true;
    }

    while (1) {
        pthread_mutex_lock(&sharedheartbeat->mutex);

        // 等待心跳数据
        while (is_queue_empty(&sharedheartbeat->packet_queue)) {
            pthread_cond_wait(&sharedheartbeat->cond_var, &sharedheartbeat->mutex);
        }

        // 获取所有心跳包
        PacketNode* packets = get_all_packets(&sharedheartbeat->packet_queue);
        pthread_mutex_unlock(&sharedheartbeat->mutex);

        // 处理心跳包
        PacketNode* current = packets;
        bool first_in_batch = true;

        while (current) {
            Message* msg = &current->msg;

            // 验证消息有效性
            if (is_valid_message(msg)) {
                // 根据PacketNode中的src_ip_seq和dest_ip_seq确定链路
                PacketNode* node = current;
                int link_id = -1;

                if (node->src_ip_seq == 1 && node->dest_ip_seq == 3) {
                    link_id = 0;
                } else if (node->src_ip_seq == 1 && node->dest_ip_seq == 4) {
                    link_id = 1;
                } else if (node->src_ip_seq == 2 && node->dest_ip_seq == 3) {
                    link_id = 2;
                } else if (node->src_ip_seq == 2 && node->dest_ip_seq == 4) {
                    link_id = 3;
                }

                // 获取当前时间戳（秒）
                time_t current_time = time(NULL);

                // 只更新对应链路的状态时间戳
                if (link_id >= 0 && link_id < 4) {
                    link_status[link_id].last_heartbeat_time = (uint64_t)current_time;
                    link_status[link_id].timeout_count = 0;
                }

                // 只将同一批心跳中的第一条转发到RS485串口
                if (first_in_batch) {
                    // forward_heartbeat_to_serial(msg); // 如有实现可启用
                    first_in_batch = false;
                }

                // 更新被控端空开状态（如果需要）
                // updateLightColor(1, 1);
            }

            current = current->next;
        }

        // 释放内存
        free_packet_list(packets);

        // 监测链路状态
        time_t current_time = time(NULL);

        // 每秒检查一次链路状态
        if (current_time - last_check_time > 1) {
            for (int i = 0; i < 4; i++) {
                // 计算距离上次心跳的时间
                time_t time_diff = current_time - (time_t)link_status[i].last_heartbeat_time;

                // 如果超过警告阈值（config->heartbeat_warn 以毫秒为单位）
                if (time_diff > (time_t)(config->heartbeat_warn / 1000)) {
                    link_status[i].timeout_count++;

                    // 连续超时3次则标记为断开
                    if (link_status[i].timeout_count >= 3 && link_status[i].is_connected) {
                        link_status[i].is_connected = false;

                        // 调用告警函数
                        path_warning(link_status[i].src_ip, link_status[i].dst_ip);
                    }
                } else {
                    // 如果链路恢复正常
                    if (!link_status[i].is_connected) {
                        link_status[i].is_connected = true;
                        link_status[i].timeout_count = 0;
                    }
                }
            }
            last_check_time = current_time;
        }
    }
}


/*
以下为涉及串口与告警
*/
// 补充串口函数的空实现（避免编译报错，后续由团队完善）
/**
 * @brief 从串口将6字节的控制指令发出
 * @param msg 指向Message结构体的指针，包含要发送的控制指令
 * @return 成功返回0，失败返回-1
 */
int power_cut(Message* msg) {
    if (msg == NULL) return -1;
    // 实际逻辑：通过串口给电源控制器发断电指令
    printf("（串口模拟）发送断电指令，payload：%02X %02X %02X %02X %02X %02X\n",
           msg->payload[0], msg->payload[1], msg->payload[2],
           msg->payload[3], msg->payload[4], msg->payload[5]);
    return 0;
}

/**
 * @brief 从串口将6字节的控制指令发出
 * @param msg 指向Message结构体的指针，包含要发送的控制指令
 * @return 成功返回0，失败返回-1
 */
int power_restore(Message* msg) {
    if (msg == NULL) return -1;
    // 实际逻辑：通过串口给电源控制器发恢复指令
    printf("（串口模拟）发送恢复供电指令，payload：%02X %02X %02X %02X %02X %02X\n",
           msg->payload[0], msg->payload[1], msg->payload[2],
           msg->payload[3], msg->payload[4], msg->payload[5]);
    return 0;
}

/**
 * @brief 监听串口，接收来自电源控制器的状态反馈，收到指令后调用get_heartbeat_seq获取序列号，传入pack_message创建心跳数据包，调用controlled_redundant_send函数发送心跳数据包
 * @param msg 指向Message结构体的指针，用于储存状态反馈
 */
void controlled_power_listen() {
    while (1) {  // 无限循环
        // 假设从串口接收状态（公司接口），这里模拟
        Message msg;  // 定义消息
        uint8_t payload[6] = {0};  // 负载全0
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);  // 当前时间
        uint64_t timestamp = (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
        pack_message(MSG_TYPE_HEARTBEAT, 0, get_heartbeat_seq(), timestamp, 1000, payload, &msg);  // 打包心跳
        uint8_t ciphertext[52];  // 密文缓冲
        if (aes_gcm_encrypt(&msg, aes_key, ciphertext) == 0) {  // 加密
            controlled_redundant_send(ciphertext, config);  // 发送
        }
        usleep(1000000);  // 等待1秒（模拟间隔）
    }
}


/**
 * @brief 监听串口，接收来自电源控制器的状态反馈，收到钥匙指令后进行认证状态判断
 *      通过后调用get_CMD_seq获取序列号，传入pack_message创建指令，调用controller_redundant_send函数发送指令
 * @param msg 指向Message结构体的指针，用于储存状态反馈
 */
 void controller_power_listen() {
    while (1) {
        if (is_authentic()) {  // 检查授权（假设已定义）
            Message msg;
            uint8_t payload[6] = {0};
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            uint64_t timestamp = (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
            pack_message(MSG_TYPE_CMD_POWER_CUT, 1, get_CMD_seq(), timestamp, 2000, payload, &msg);
            uint8_t ciphertext[52];
            if (aes_gcm_encrypt(&msg, aes_key, ciphertext) == 0) {
                controller_redundant_send(ciphertext, config, NULL);
            }
        }
        usleep(1000000);  // 等待1秒
    }
}

/**
 * @brief 路径不可用告警，等待公司接口
 * @param source_ipaddr 不可用源路径IP地址
 * @param dest_ipaddr 不可用路径目的IP地址
 */
void path_warning(char source_ipaddr[], char dest_ipaddr[]) {
    char warning_text[100];  // 定义警告文本缓冲
    snprintf(warning_text, sizeof(warning_text), "路径 %s -> %s 不可用", source_ipaddr, dest_ipaddr);  // 格式化文本
    warning(1, warning_text);  // 调用警告函数（假设已定义，类型1）
}

/**
 * @brief 被控端CMD处理线程：从队列取消息，去重后执行命令
 * @param arg 传入SharedData*类型的指针（因为线程函数只能要1个参数）
 * @return 无实际返回（线程函数要求返回void*）
 */
void* controlled_cmd_handler(void* arg) {
    // 把参数转成SharedData指针（里面有队列和锁）
    SharedData* sharedCMD = (SharedData*)arg;
    if (sharedCMD == NULL) {
        printf("处理线程错误：参数为空\n");
        return NULL;
    }
    printf("\n=== CMD处理线程启动：开始等待命令 ===\n");

    while (1) {  // 一直运行，循环处理消息
        // 1. 加锁：操作队列前必须拿"钥匙"
        pthread_mutex_lock(&sharedCMD->mutex);

        // 2. 如果队列为空，就等待"门铃"（监听线程放消息后会按门铃）
        while (is_queue_empty(&sharedCMD->packet_queue) == 1) {
            // 等待时会自动释放锁，让监听线程能入队；被唤醒后会重新拿锁
            pthread_cond_wait(&sharedCMD->cond_var, &sharedCMD->mutex);
        }

        // 3. 出队：从队列取消息（关键修改点：传消息的地址&cmd_msg）
        Message cmd_msg;  // 定义一个变量存消息
        // 调用出队函数，传入队列地址和消息地址（用&取地址）
        int dequeue_res = dequeue_packet(&sharedCMD->packet_queue, &cmd_msg);
        if (dequeue_res != 0) {
            printf("处理线程：出队失败\n");
            pthread_mutex_unlock(&sharedCMD->mutex);  // 出队失败也要解锁
            continue;
        }

        // 打印取出的消息（验证是否正确，类型和序列号是否和入队时一致）
        printf("处理线程：取出消息（类型：%hhu，序列号：%u，队列剩余：%d）\n",
               cmd_msg.message_type,       // 消息类型（1=断电命令）
               cmd_msg.sequence_number,    // 序列号（1、2...）
               sharedCMD->packet_queue.count);  // 剩余消息数

        // 4. 解锁：取完消息，释放"钥匙"让其他线程用
        pthread_mutex_unlock(&sharedCMD->mutex);


        // 5. 消息去重：只处理比上次新的消息
        pthread_mutex_lock(&sharedCMD->mutex);  // 操作last_processed_seq也要锁
        if (cmd_msg.sequence_number <= sharedCMD->last_processed_seq) {
            printf("处理线程：消息重复（序列号：%u），跳过\n", cmd_msg.sequence_number);
            pthread_mutex_unlock(&sharedCMD->mutex);
            continue;
        }
        // 更新"最后处理的序列号"（标记为已处理）
        sharedCMD->last_processed_seq = cmd_msg.sequence_number;
        sharedCMD->last_processed_time = time(NULL);
        pthread_mutex_unlock(&sharedCMD->mutex);  // 解锁


        // 6. 执行命令（根据消息类型做对应操作）
        if (cmd_msg.message_type == MSG_TYPE_CMD_POWER_CUT) {
            printf("处理线程：执行【断电命令】\n");
            power_cut(&cmd_msg);  // 调用断电函数（模拟串口发送）
        } else if (cmd_msg.message_type == MSG_TYPE_CMD_POWER_RESTORE) {
            printf("处理线程：执行【恢复供电命令】\n");
            power_restore(&cmd_msg);
        } else {
            printf("处理线程：未知命令类型（%hhu），跳过\n", cmd_msg.message_type);
        }
    }
    return NULL;
}