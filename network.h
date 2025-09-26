#ifndef NETWORK_H
#define NETWORK_H

#include "crypto.h"


/*
以下为序列号管理功能函数
*/
/**
 * @brief 用于维护心跳序列号，每次调用返回循环递增的序列号，范围0x0000至0xFFFF（65535）
 * @param config 用于存储加载的配置信息
 * @param msg 指向Message结构体的指针，包含要发送的消息
 * @return 返回心跳序列号
 */
int get_heartbeat_seq(Config* config, Message* msg);//2

/**
 * @brief 用于维护指令序列号，每次调用返回循环递增的序列号，范围0x0000至0xFFFF（65535）
 * @param config 用于存储加载的配置信息
 * @param msg 指向Message结构体的指针，包含要发送的消息
 * @return 返回指令序列号
 */
int get_CMD_seq(Config* config, Message* msg);//2

/**
 * @brief 用于维护ACK序列号，每次调用返回循环递增的序列号，范围0x0000至0xFFFF（65535）
 * @param config 用于存储加载的配置信息
 * @param msg 指向Message结构体的指针，包含要发送的消息
 * @return 成功ACK序列号
 */
int get_ACK_seq(Config* config, Message* msg);//2

/**
 * @brief 根据时间戳和有效期验证消息的有效性，根据序列号判断是否重复消息（去重）
 * @param msg 指向待验证Message结构体的指针
 * @return 合法返回true，否则返回false
 */
bool is_valid_message(const Message* msg);//2

/**
 * @brief controlled将加密后的密文通过UDP从四条路径发送出去（如果direction=1,则为IP3->IP1;IP3->IP2;IP4->IP1;IP4->IP2;output_port->input_port；direction=0则相反）
 * @param direction 消息方向(1: Controller->Controlled, 0: Controlled->Controller)
 * @param data 指向加密后数据的指针，数据长度应为52字节
 * @param config 用于存储加载的配置信息
 * @return 成功返回0，失败返回-1
 */
int redundant_send(uint8_t direction, const uint8_t* ciphertext, const Config* config);//2

/**
 * @brief 监听串口，逻辑判断，认证判断；通过后生成CMD消息，加密后调用redundant_send发送CMD，发送后等待条件变量唤醒，处理ACK队列，三秒内未收到ACK则重传，重传次数不超过max_retry_count
 * 串口参数待补充
 * @param config 用于存储加载的配置信息
 * @param ip_seq 用于标识当前使用的IP地址(主进程中需启动两个线程分别调用此函数，因此ip_seq取值分别为1和2，用于监听config中本机的第一个和第二个IP地址)
 * @param aes_key[32] 用于存储AES-GCM加密所需的密钥
 * @param sharedACK 用于存储ACK消息的线程同步数据结构
 */
void controller_serial_listen(const Config* config,int ip_seq, const uint8_t aes_key[32], SharedData* sharedACK);//4

/**
 * @brief 监听串口，判断是heartbeat消息还是IO-ACK消息，生成相应的数据包，加密后调用redundant_send发送
 * 串口参数待补充
 * @param config 用于存储加载的配置信息
 * @param aes_key[32] 用于存储AES-GCM加密所需的密钥
 */
void controlled_serial_listen(const Config* config, const uint8_t aes_key[32]);//4


/**
 * @brief controlled主线程循环执行，监听输入端口，接收来自Controller的控制指令，调用aes_gcm_decrypt解密并验证，调用is_valid_message判断合法性
 *      通过验证后，加锁，入队，修改环境变量通知CMD处理线程，解锁，调用POWER_CUT/POWER_RESTORE执行控制指令
 * @param config 用于存储加载的配置信息
 * @param ip_seq 用于标识当前使用的IP地址(主进程中需启动两个线程分别调用此函数，因此ip_seq取值分别为1和2，用于监听config中本机的第一个和第二个IP地址)
 * @param aes_key 用于存储AES-GCM加密所需的密钥
 * @param sharedCMD 用于存储CMD消息的线程同步数据结构
 */
void controlled_listen(const Config* config,int ip_seq, const uint8_t aes_key[32], SharedData* sharedCMD);//3

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

/**
 * @brief 处理心跳信息的线程函数，从心跳队列中取出心跳消息，调用is_valid_message判断合法性,去重
 *      通过验证后， 1.监测链路状态。更新对应路径的最后心跳时间，如果目前时间-最后心跳时间超过heartbeat_warn则认为路径不可用,调用warning函数告警
 *                  2.更新被控端空开状态（这里是否要闪灯？是否要在前端展示？）
 *                  3.更新空开状态，调用updateLightColor控制闪灯
 * @param config 用于存储加载的配置信息
 * @param heartbeat_queue 用于存储心跳消息的线程安全队列
 */
void controller_heartbeat_manager(const Config* config, SharedData* sharedheartbeat);//4



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


/**
 * @brief 被控端CMD处理线程：从队列取消息，去重后执行命令
 * @param arg 传入SharedData*类型的指针（因为线程函数只能要1个参数）
 * @return 无实际返回（线程函数要求返回void*）
 */
void* controlled_cmd_handler(void* arg);

#endif