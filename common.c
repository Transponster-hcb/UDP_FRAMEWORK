#include <stdio.h>  // 包含标准输入输出库，用于文件操作如fopen、fgets和打印函数
#include <string.h>  // 包含字符串处理库，用于strtok、strncpy、strlen、strcspn等函数
#include <stdlib.h>  // 包含标准库，用于内存分配和转换函数如atoi
#include <ctype.h>  // 包含字符处理库，用于isspace检查空格
#include <sys/socket.h>  // Linux套接字头文件，提供socket函数
#include <arpa/inet.h>  // 包含IP地址转换函数，如inet_pton
#include <pthread.h>  // 包含POSIX线程库，用于互斥锁pthread_mutex_t
#include "common.h"  // 包含自定义公共头文件，定义Config、Message等结构体
#include <openssl/rand.h> // 新增



/*
以下为线程安全队列功能函数
*/

/*
 * @param queue 要初始化的队列指针
 * @return 成功返回0，失败返回错误码
 */
int init_packet_queue(PacketQueue* queue) {
    if (!queue) return -1; // 检查队列指针是否为空

    // 初始化队列参数
    queue->head = NULL;
    queue->tail = NULL;
    queue->count = 0;

    // 初始化互斥锁
    if (pthread_mutex_init(&queue->lock, NULL) != 0) {
        return -2; // 互斥锁初始化失败
    }

    return 0; // 初始化成功
}


/**
 * 将数据包加入队列
 * @param queue 目标队列
 * @param msg 要加入的数据包
 * @return 成功返回0，失败返回错误码（-1: 无效指针，-2: 内存分配失败）
 */
int enqueue_packet(PacketQueue* queue, Message* msg) {
    if (!queue) return -1; // 检查队列指针是否为空

    // 创建新节点
    PacketNode* new_node = (PacketNode*)malloc(sizeof(PacketNode));
    if (!new_node) return -2; // 内存分配失败

    // 初始化新节点
    new_node->msg = msg;
    new_node->src_ip_seq = 0;  // 默认值，调用者可后续设置
    new_node->dest_ip_seq = 0; // 默认值，调用者可后续设置
    new_node->next = NULL;

    // 加锁以确保线程安全
    pthread_mutex_lock(&queue->lock);

    // 如果队列有尾节点，将新节点添加到尾部
    if (queue->tail) {
        queue->tail->next = new_node;
        queue->tail = new_node;
    } else {
        // 队列为空，新节点成为头尾节点
        queue->head = new_node;
        queue->tail = new_node;
    }
    queue->count++; // 更新队列大小

    // 解锁
    pthread_mutex_unlock(&queue->lock);

    return 0; // 入队成功
}


/**
 * 从队列中取出一个数据包
 * @param queue 源队列
 * @param msg 存储取出的数据包
 * @return 成功返回0，队列为空返回-1
 */
int dequeue_packet(PacketQueue* queue, Message* msg) {
    if (!queue || !msg) return -1; // 检查指针是否有效

    // 加锁以确保线程安全
    pthread_mutex_lock(&queue->lock);

    if (!queue->head) {
        pthread_mutex_unlock(&queue->lock);
        return -1; // 队列为空
    }

    // 获取头节点
    PacketNode* node = queue->head;
    *msg = node->msg; // 复制消息到输出参数
    queue->head = node->next; // 更新头指针

    if (!queue->head) {
        queue->tail = NULL; // 如果队列变空，尾指针置空
    }

    queue->count--; // 更新队列大小

    // 解锁
    pthread_mutex_unlock(&queue->lock);

    free(node); // 释放节点内存
    return 0; // 出队成功
}


/**
 * 检查队列是否为空
 * @param queue 要检查的队列
 * @return 队列为空返回1，否则返回0
 */
int is_queue_empty(PacketQueue* queue) {
    if (!queue) return 1; // 无效指针视为空队列

    // 加锁以确保线程安全
    pthread_mutex_lock(&queue->lock);

    int empty = (queue->count == 0) ? 1 : 0; // 检查队列大小

    // 解锁
    pthread_mutex_unlock(&queue->lock);

    return empty; // 返回队列状态
}


/**
 * 获取队列中的所有数据包并清空队列
 * @param queue 源队列
 * @return 包含所有数据包的链表头指针
 */
PacketNode* get_all_packets(PacketQueue* queue) {
    if (!queue) return NULL; // 检查队列指针是否为空

    // 加锁以确保线程安全
    pthread_mutex_lock(&queue->lock);

    PacketNode* head = queue->head; // 获取头指针

    // 重置队列
    queue->head = NULL;
    queue->tail = NULL;
    queue->count = 0;

    // 解锁
    pthread_mutex_unlock(&queue->lock);

    return head; // 返回整个链表
}


/**
 * 释放数据包链表
 * @param head 链表头指针
 */
void free_packet_list(PacketNode* head) {
    PacketNode* current = head;
    while (current) {
        PacketNode* next = current->next; // 保存下一个节点
        free(current); // 释放当前节点
        current = next; // 移动到下一个节点
    }
}


/**
 * @brief 从配置文件加载配置信息并校验参数合法性
 * @param config 用于存储加载的配置信息
 * @param aes_key 用于存储AES-GCM加密所需的密钥
 * @return 成功返回0，失败返回-1
 */
 // 实现 init_network 函数：初始化网络配置，包括加载、验证和获取密钥
// 参数：config - 配置结构体指针，aes_key - 密钥数组
// 返回：0成功，-1失败
int init_network(Config* config, uint8_t aes_key[32]) {
    // 加载配置文件"config.ini"
    if (load_config("config.ini", config) != 0) {
        print_log("加载配置失败");
        return -1;
    }

    // 验证配置有效性
    if (validate_config(config) != 0) {
        print_log("配置验证失败");
        return -1;
    }

    // 从UKEY或外部获取AES密钥（假设get_aes_key已定义）
    if (get_aes_key(aes_key) != 0) {
        print_log("获取 AES 密钥失败");
        return -1;
    }

    return 0;  // 初始化成功
}


/**
 * @brief 从UKEY读取密钥，公司实现
 * @param aes_key 输出参数，用于存储AES-GCM加密所需的密钥
 * @return 成功返回0，失败返回-1
 */
 int get_aes_key(uint8_t aes_key[32]) {
    // 检查参数有效性
    if (!aes_key) {
        print_log("密钥缓冲区指针无效");
        return -1;
    }

    // 使用 OpenSSL 的 RAND_bytes 生成 32 字节随机密钥
    if (RAND_bytes(aes_key, 32) != 1) {
        print_log("生成 AES 密钥失败");
        return -1;
    }

    return 0;
}


/**
 * @brief 从配置文件加载配置信息
 * @param filename 配置文件名(路径)
 * @param config 用于存储加载的配置信息
 * @return 成功返回0，失败返回-1
 */
 // 实现 load_config 函数：从配置文件加载配置信息
// 参数：filename - 配置文件路径，config - 配置结构体指针
// 返回：0成功，-1失败
int load_config(const char* filename, Config* config) {
    FILE* file = fopen(filename, "r");  // 以只读模式打开配置文件
    if (!file) {  // 检查文件是否打开成功
        print_log("无法打开配置文件");  // 如果失败，记录日志（假设print_log已定义）
        return -1;  // 返回失败码
    }

    char line[256];  // 定义缓冲区，用于存储每行内容
    while (fgets(line, sizeof(line), file)) {  // 循环读取文件每一行
        line[strcspn(line, "\n")] = 0;  // 去除行尾换行符
        if (line[0] == '\0' || line[0] == '#') continue;  // 跳过空行和注释行

        char* key = strtok(line, "=");  // 以"="分割，获取键
        char* value = strtok(NULL, "=");  // 获取值
        if (!key || !value) continue;  // 如果键或值为空，跳过

        while (isspace(*key)) key++;  // 去除键开头的空格
        while (isspace(*value)) value++;  // 去除值开头的空格
        char* end = key + strlen(key) - 1;  // 指向键末尾
        while (end > key && isspace(*end)) *end-- = '\0';  // 去除键末尾空格
        end = value + strlen(value) - 1;  // 指向值末尾
        while (end > value && isspace(*end)) *end-- = '\0';  // 去除值末尾空格

        // 根据键名解析并存储到config结构体
        if (strcmp(key, "controller_ip1") == 0) {  // Controller的第一个IP
            strncpy(config->controller_ip1, value, INET_ADDRSTRLEN);  // 复制字符串
        } else if (strcmp(key, "controller_ip2") == 0) {  // Controller的第二个IP
            strncpy(config->controller_ip2, value, INET_ADDRSTRLEN);
        } else if (strcmp(key, "controlled_ip3") == 0) {  // Controlled的第一个IP
            strncpy(config->controlled_ip3, value, INET_ADDRSTRLEN);
        } else if (strcmp(key, "controlled_ip4") == 0) {  // Controlled的第二个IP
            strncpy(config->controlled_ip4, value, INET_ADDRSTRLEN);
        } else if (strcmp(key, "output_port") == 0) {  // 输出端口
            config->output_port = atoi(value);  // 字符串转整数
        } else if (strcmp(key, "input_port") == 0) {  // 输入端口
            config->input_port = atoi(value);
        } else if (strcmp(key, "heartbeat_validity") == 0) {  // 心跳有效期
            config->heartbeat_validity = atoi(value);
        } else if (strcmp(key, "heartbeat_warn") == 0) {  // 心跳警告阈值
            config->heartbeat_warn = atoi(value);
        } else if (strcmp(key, "cmd_validity") == 0) {  // 命令有效期
            config->cmd_validity = atoi(value);
        } else if (strcmp(key, "ack_timeout") == 0) {  // ACK超时时间
            config->ack_timeout = atoi(value);
        } else if (strcmp(key, "max_retry_count") == 0) {  // 最大重传次数
            config->max_retry_count = atoi(value);
        } else if (strcmp(key, "auto_restore_interval") == 0) {  // 自动恢复间隔
            config->auto_restore_interval = atoi(value);
        }
    }

    fclose(file);  // 关闭文件
    return 0;  // 成功返回
}


/**
 * @brief 验证配置信息的有效性，包括IP地址格式、端口号范围等
 * 心跳发送间隔(毫秒)取值范围为[1000, 60000]
 * 心跳消息有效期(毫秒)取值范围为[1000, 60000]
 * 命令消息有效期(毫秒)取值范围为[2000, 10000]
 * ACK等待超时时间(毫秒)取值范围为[1000, 10000]
 * 最大重传次数取值范围为[0,5]
 * @param config 待验证的配置信息
 * @return 配置有效返回0，无效返回-1
 */
 // 实现 validate_config 函数：验证配置信息的有效性
// 参数：config - 配置结构体指针
// 返回：0有效，-1无效
int validate_config(const Config* config) {
    struct sockaddr_in sa;  // 定义地址结构，用于IP验证
    // 使用inet_pton验证IPv4地址格式
    if (inet_pton(AF_INET, config->controller_ip1, &sa.sin_addr) != 1 ||
        inet_pton(AF_INET, config->controller_ip2, &sa.sin_addr) != 1 ||
        inet_pton(AF_INET, config->controlled_ip3, &sa.sin_addr) != 1 ||
        inet_pton(AF_INET, config->controlled_ip4, &sa.sin_addr) != 1) {
        print_log("IP 地址格式无效");  // 记录无效IP日志
        return -1;  // 返回失败
    }

    // 验证端口号范围（1-65535）
    if (config->output_port < 1 || config->output_port > 65535 ||
        config->input_port < 1 || config->input_port > 65535) {
        print_log("端口号无效");
        return -1;
    }

    // 验证心跳有效期范围[1000, 60000]
    if (config->heartbeat_validity < 1000 || config->heartbeat_validity > 60000) {
        print_log("心跳有效期无效");
        return -1;
    }
    // 验证心跳警告阈值范围[1000, 60000]
    if (config->heartbeat_warn < 1000 || config->heartbeat_warn > 60000) {
        print_log("心跳警告阈值无效");
        return -1;
    }

    // 验证命令有效期范围[2000, 10000]
    if (config->cmd_validity < 2000 || config->cmd_validity > 10000) {
        print_log("命令有效期无效");
        return -1;
    }

    // 验证ACK超时范围[1000, 10000]
    if (config->ack_timeout < 1000 || config->ack_timeout > 10000) {
        print_log("ACK 超时时间无效");
        return -1;
    }

    // 验证最大重传次数[0,5]
    if (config->max_retry_count > 5) {
        print_log("最大重传次数无效");
        return -1;
    }

    // 验证自动恢复间隔非负
    if (config->auto_restore_interval < 0) {
        print_log("自动恢复间隔无效");
        return -1;
    }

    return 0;  // 所有验证通过
}


/**
 * @brief 封装消息
 * @param message_type 消息类型 
 * @param direction 消息方向(1: Controller->Controlled, 0: Controlled->Controller)
 * @param sequence_number 序列号
 * @param timestamp 时间戳 (毫秒)
 * @param validity 有效期 (毫秒)
 * @param payload 6字节的指令内容
 * @param msg 用于储存封装后的明文消息
 * @return 成功返回0，失败返回-1
 */
 // 实现 pack_message 函数：封装消息到Message结构体
// 参数：message_type - 消息类型，direction - 方向(0/1)，sequence_number - 序列号，timestamp - 时间戳，validity - 有效期，payload - 6字节负载，msg - 输出消息指针
// 返回：0成功，-1失败
int pack_message(MessageType message_type, uint8_t direction, uint32_t sequence_number, 
                 uint64_t timestamp, uint32_t validity, const uint8_t* payload, Message* msg) {
    if (!msg || !payload) {  // 检查输出指针和负载是否有效
        print_log("消息或负载指针无效");
        return -1;
    }

    // 验证消息类型是否在枚举范围内
    if (message_type != MSG_TYPE_CMD_POWER_CUT &&
        message_type != MSG_TYPE_CMD_POWER_RESTORE &&
        message_type != MSG_TYPE_CHANGE_KEY &&
        message_type != MSG_TYPE_ACK &&
        message_type != MSG_TYPE_HEARTBEAT) {
        print_log("消息类型无效");
        return -1;
    }

    // 验证方向是否为0或1
    if (direction != 0 && direction != 1) {
        print_log("消息方向无效");
        return -1;
    }

    // 填充Message结构体字段
    msg->message_type = message_type;  // 设置消息类型
    msg->direction = direction;  // 设置方向
    msg->sequence_number = sequence_number;  // 设置序列号
    msg->timestamp = timestamp;  // 设置时间戳
    msg->validity = validity;  // 设置有效期
    memcpy(msg->payload, payload, 6);  // 复制6字节负载

    return 0;  // 成功返回
}


/**
 * @brief 拧钥匙后，判断用户是否经过授权。等待公司接口
 * @return 合法返回true，不合法返回false
 */
//(待实现)
bool is_authentic();


/*
分别用于实现日志打印和告警功能，等待公司接口
*/
// 实现 print_log 函数：记录错误日志
void print_log(const char* text) {
    fprintf(stderr, "[错误] %s\n", text); // 输出到标准错误流，使用中文
}

//（待实现）
void warning(uint8_t warning_type,char warning_text);


/*
 * @brief 用于控制灯的颜色，等待公司接口
 * @param targetLight 目标灯编号
 * @param colorCode 颜色代码（0:关闭, 1:绿色，2黄色）
*/
//(待实现)
void updateLightColor(int targetLight, int colorCode);