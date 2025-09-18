#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

// 公共常量定义



// 消息类型枚举
typedef enum {
    MSG_TYPE_CMD_POWER_CUT = 0x01,
    MSG_TYPE_CMD_POWER_RESTORE = 0x02,
    MSG_TYPE_CHANGE_KEY = 0x03,
    MSG_TYPE_ACK = 0x04,
    MSG_TYPE_HEARTBEAT = 0x05
} MessageType;

typedef struct {
    char controller_ip1[INET_ADDRSTRLEN];  // Controller的第一个IP地址
    char controller_ip2[INET_ADDRSTRLEN];  // Controller的第二个IP地址
    char controlled_ip3[INET_ADDRSTRLEN];  // Controlled的第一个IP地址
    char controlled_ip4[INET_ADDRSTRLEN];  // Controlled的第二个IP地址
    int output_port;                     // 用来发送消息的端口号
    int input_port;                      // 用来接收消息的端口号
    int heartbeat_validity;              // 心跳消息有效期(毫秒)
    int heartbeat_warn;                  // 心跳超时警告阈值(毫秒)，最后心跳时间超过该值则认为路径不可用
    int cmd_validity;                    // 命令消息有效期(毫秒)
    int ack_timeout;                     // ACK等待超时时间(毫秒)
    uint8_t max_retry_count;             // 最大重传次数
    int auto_restore_interval;           // 自动恢复间隔时间(毫秒)，断电后经过该时间自动发送恢复供电指令
} Config;

typedef struct {
    uint8_t message_type;      // 消息类型(见MessageType枚举)
    uint8_t direction;         // 消息方向(1: Controller->Controlled, 0: Controlled->Controller)
    uint32_t sequence_number;  // 序列号(用于消息去重和排序)
    uint64_t timestamp;        // 时间戳(消息创建时间，毫秒精度)
    uint32_t validity;         // 有效期(毫秒)，超过此时长消息视为无效
    uint8_t payload[6];        // 消息内容,固定为6字节，不足6字节的消息使用0填充
} Message;

/**
 * @brief 从配置文件加载配置信息并校验参数合法性
 * @param config 用于存储加载的配置信息
 * @param aes_key 用于存储AES-GCM加密所需的密钥
 * @return 成功返回0，失败返回-1
 */
int init_network(Config* config, uint8_t aes_key[32]);

/**
 * @brief 从UKEY读取密钥，公司实现
 * @param aes_key 输出参数，用于存储AES-GCM加密所需的密钥
 * @return 成功返回0，失败返回-1
 */
int get_aes_key(uint8_t aes_key[32]);

/**
 * @brief 从配置文件加载配置信息
 * @param filename 配置文件名(路径)
 * @param config 用于存储加载的配置信息
 * @return 成功返回0，失败返回-1
 */
int load_config(const char* filename, Config* config);

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
int validate_config(const Config* config);


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
int pack_message(MessageType message_type,uint8_t direction,uint32_t sequence_number, uint64_t timestamp, uint32_t validity, const uint8_t* payload, Message* msg);

/**
 * @brief 解析消息
 * @param buf 待解析的字节流缓冲区
 * @param buf_len 缓冲区长度
 * @param msg 用于接收解析后的消息结构体
 * @return 成功返回0，失败返回-1
 */
int parse_message(const uint8_t* buf, size_t buf_len, Message* msg);


/*
分别用于实现日志打印和告警功能，等待公司接口
*/
void print_log(char text);
void warning(uint8_t warning_type,char warning_text);

/*
 * @brief 用于控制灯的颜色，等待公司接口
 * @param targetLight 目标灯编号
 * @param colorCode 颜色代码（0:关闭, 1:绿色，2黄色）
*/
void updateLightColor(int targetLight, int colorCode);




#endif