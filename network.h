#ifndef NETWORK_H
#define NETWORK_H

#include "common.h"

typedef struct {
    Message* messages;        // 数据包数组 - 存储实际数据的环形缓冲区
    int capacity;           // 队列容量 - 队列最大能容纳的数据包数量
    int size;              // 当前大小 - 队列中当前存在的数据包数量
    int front;             // 队首索引 - 下一个要出队的数据包位置
    int rear;              // 队尾索引 - 下一个要入队的数据包位置
    pthread_mutex_t mutex; // 互斥锁 - 保护队列操作的线程安全
    pthread_cond_t cond;   // 条件变量 - 用于线程间同步和等待
} ThreadSafeQueue;         //定义线程安全队列

// 队列操作函数
ThreadSafeQueue* create_queue(int capacity);//创建队列
void destroy_queue(ThreadSafeQueue* queue);//销毁队列
int enqueue(ThreadSafeQueue* queue, const Message* message);//入队
int dequeue(ThreadSafeQueue* queue, Message* message, int timeout_ms);//出队，message用于保存待处理的数据包，timeout_ms为等待时间，单位毫秒，-1表示无限等待
int queue_size(ThreadSafeQueue* queue);//获取队列大小

/**
 * @brief 用于维护心跳序列号，每次调用返回循环递增的序列号，范围0x0000至0xFFFF（65535）
 * @param config 用于存储加载的配置信息
 * @param msg 指向Message结构体的指针，包含要发送的消息
 * @return 成功返回0，失败返回-1
 */
int get_heartbeat_seq();

/**
 * @brief 用于维护指令序列号，每次调用返回循环递增的序列号，范围0x0000至0xFFFF（65535）
 * @param config 用于存储加载的配置信息
 * @param msg 指向Message结构体的指针，包含要发送的消息
 * @return 成功返回0，失败返回-1
 */
int get_CMD_seq();

/**
 * @brief 用于维护ACK序列号，每次调用返回循环递增的序列号，范围0x0000至0xFFFF（65535）
 * @param config 用于存储加载的配置信息
 * @param msg 指向Message结构体的指针，包含要发送的消息
 * @return 成功返回0，失败返回-1
 */
int get_ACK_seq();

/**
 * @brief 根据时间戳和有效期验证消息的有效性，根据序列号判断是否重复消息
 * @param msg 指向待验证Message结构体的指针
 * @return 合法返回true，否则返回false
 */
bool is_valid_message(const Message* msg);

/**
 * @brief controlled将加密后的密文通过UDP从四条路径发送出去（IP3->IP1;IP3->IP2;IP4->IP1;IP4->IP2;output_port->input_port）
 * @param data 指向加密后数据的指针，数据长度应为52字节
 * @param config 用于存储加载的配置信息
 * @return 成功返回0，失败返回-1
 */
int controlled_redundant_send(const uint8_t* ciphertext, const Config* config);

/**
 * @brief controller将加密后的指令密文通过UDP从四条路径发送出去（IP1->IP3;IP1->IP4;IP2->IP3;IP2->IP4;output_port->input_port）
 *      发送成功后等待ACK消息，若在ack_timeout内未收到ACK则重传，重传次数不超过max_retry_count
 * @param data 指向加密后数据的指针，数据长度应为52字节
 * @param config 用于存储加载的配置信息
 * @return 成功返回0，失败返回-1
 */
int controller_redundant_send(const uint8_t* ciphertext, const Config* config, ThreadSafeQueue* heartbeat_queue);
//这里加入heartbeat_queue参数，用于在等待ACK时处理心跳消息，但传入时是否会被锁，导致ACK消息无法入队？
//另一思路是将等待ACK的逻辑放在controller_listen中，收到ACK后直接唤醒等待的线程


/**
 * @brief controlled主线程循环执行，监听输入端口，接收来自Controller的控制指令，调用aes_gcm_decrypt解密并验证，调用is_valid_message判断合法性
 *      通过验证后调用controlled_redundant_send发送ACK消息,调用POWER_CUT/POWER_RESTORE执行控制指令
 * @param aes_key 用于存储AES-GCM加密所需的密钥
 */
void controlled_listen(const Config* config, const uint8_t aes_key[32]);

/**
 * @brief controlled主线程循环执行，监听输入端口，接收来自Controlled的ACK消息和心跳消息，调用aes_gcm_decrypt解密并验证，调用is_valid_message判断合法性
 *      通过验证后，将心跳消息和ACK消息分别放入两个线程安全队列中等待处理
 * @param config 用于存储加载的配置信息
 * @param aes_key 用于存储AES-GCM加密所需的密钥
 * @param heartbeat_queue 用于存储心跳消息的线程安全队列
 * @param ack_queue 用于存储ACK消息的线程安全队列
 */
void controller_listen(const Config* config, const uint8_t aes_key[32], ThreadSafeQueue* heartbeat_queue, ThreadSafeQueue* ack_queue);

/**
 * @brief 处理心跳信息的线程函数，从心跳队列中取出心跳消息，调用is_valid_message判断合法性
 *      通过验证后，更新对应路径的最后心跳时间，如果目前时间-最后心跳时间超过heartbeat_warn则认为路径不可用,调用path_warning函数告警
 * @param config 用于存储加载的配置信息
 * @param heartbeat_queue 用于存储心跳消息的线程安全队列
 */
void heartbeat_manager(const Config* config, ThreadSafeQueue* heartbeat_queue);



/*
以下为涉及串口与告警
*/


/**
 * @brief 从串口将6字节的控制指令发出
 * @param msg 指向Message结构体的指针，包含要发送的控制指令
 * @return 成功返回0，失败返回-1
 */
int power_cut(Message* msg);

/**
 * @brief 从串口将6字节的控制指令发出
 * @param msg 指向Message结构体的指针，包含要发送的控制指令
 * @return 成功返回0，失败返回-1
 */
int power_restore(Message* msg);

/**
 * @brief 监听串口，接收来自电源控制器的状态反馈，收到指令后调用get_heartbeat_seq获取序列号，传入pack_message创建心跳数据包，调用controlled_redundant_send函数发送心跳数据包
 * @param msg 指向Message结构体的指针，用于储存状态反馈
 */
void controlled_power_listen();

/**
 * @brief 监听串口，接收来自电源控制器的状态反馈，收到钥匙指令后进行认证状态判断
 *      通过后调用get_CMD_seq获取序列号，传入pack_message创建指令，调用controller_redundant_send函数发送指令
 * @param msg 指向Message结构体的指针，用于储存状态反馈
 */
void controller_power_listen();

/**
 * @brief 路径不可用告警，等待公司接口
 * @param source_ipaddr 不可用源路径IP地址
 * @param dest_ipaddr 不可用路径目的IP地址
 */
void path_warning(char source_ipaddr[], char dest_ipaddr[]);


#endif