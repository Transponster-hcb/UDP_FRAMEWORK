#include <stdio.h>
#include "common.h"
#include <pthread.h>
#include "network.h"
#include <unistd.h>



#ifdef CONTROLLER_MODE//controller模式,加载配置文件，启动线程执行逻辑

volatile int g_terminate = 0;  // 全局退出标志
pthread_cond_t start_condition = PTHREAD_COND_INITIALIZER;  // 条件变量，控制线程启动
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;  // 互斥锁，保护共享资源

// 线程1执行的函数：监听串口并接收电源控制器的状态反馈
void* thread1_func(void* arg) {
    // 执行电源控制器状态接收与认证
    while (!g_terminate) {
        controller_power_listen();  // 直接调用controller_power_listen函数
        
        // 认证通过后通知其他线程启动
        pthread_mutex_lock(&mutex);  // 锁定互斥量，保护共享资源
        printf("Thread 1: Authentication successful, notifying other threads to start.\n");
        pthread_cond_broadcast(&start_condition);  // 通知其他线程
        pthread_mutex_unlock(&mutex);  // 解锁
        sleep(1);  // 模拟任务处理
    }
    return NULL;
}

// 线程2执行的函数：监听串口并进行认证
void* thread2_func(void* arg) {
    ThreadArgsCommon* args = (ThreadArgsCommon*)arg;
    while (!g_terminate) {  // 无限循环
        // 等待第一个线程的通知
        pthread_mutex_lock(&mutex);  // 锁定互斥量
        pthread_cond_wait(&start_condition, &mutex);  // 等待通知
        pthread_mutex_unlock(&mutex);  // 解锁

        // 监听串口，ip_seq = 1
        controller_serial_listen(args->config, 1, args->aes_key, args->sharedACK);

        // 消息去重：在加入队列前，确保消息有效
        Message msg;
        if (dequeue_packet(args->sharedACK->packet_queue, msg) == 0) {
            if (is_valid_message(&msg)) {
                enqueue_packet(args->sharedACK->packet_queue, msg);  // 如果消息有效，则加入队列
            }
        }
        sleep(1);  // 模拟任务处理
    }
    return NULL;
}

void* thread3_func(void* arg) {
    ThreadArgsCommon* args = (ThreadArgsCommon*)arg;
    while (!g_terminate) {  // 无限循环
        // 等待第一个线程的通知
        pthread_mutex_lock(&mutex);  // 锁定互斥量
        pthread_cond_wait(&start_condition, &mutex);  // 等待通知
        pthread_mutex_unlock(&mutex);  // 解锁

        // 监听串口，ip_seq = 2
        controller_serial_listen(args->config, 2, args->aes_key, args->sharedACK);

        // 消息去重：在加入队列前，确保消息有效
        Message msg;
        if (dequeue_packet(args->sharedACK->packet_queue, msg) == 0) {
            if (is_valid_message(&msg)) {
                enqueue_packet(args->sharedACK->packet_queue, msg);  // 如果消息有效，则加入队列
            }
        }
        sleep(1);  // 模拟任务处理
    }
    return NULL;
}

int main() {
     // 初始化配置和AES密钥
    Config config;
    uint8_t aes_key[32];

    // 获取配置和AES密钥
    if (init_network(&config, aes_key) != 0) {
        fprintf(stderr, "Failed to initialize network configuration\n");
        return -1;
    }

    // 初始化共享数据结构：用于 ACK 消息的线程同步数据结构
    SharedData sharedACK;
    if (init_shared_data(&sharedACK) != 0) {
        fprintf(stderr, "Failed to initialize sharedACK data structure\n");
        return -1;
    }

    // 创建线程并启动
    pthread_t thr1, thr2, thr3;
    int created = 0;

    // 为线程1（controller_power_listen）创建参数结构
    ThreadArgsCommon* arg1 = malloc(sizeof(ThreadArgsCommon));
    if (!arg1) {
        perror("malloc");
        return -1;
    }
    arg1->config = &config;
    arg1->aes_key = aes_key;
    arg1->sharedACK = &sharedACK;
    arg1->sharedHeartbeat = NULL;  // 线程1不需要sharedHeartbeat
    arg1->sharedCMD = NULL;  // 线程1不需要sharedCMD

    // 创建线程1（监听电源控制器的状态）
    if (pthread_create(&thr1, NULL, thread1_func, arg1) != 0) {
        perror("Failed to create thread 1");
        free(arg1);
        return -1;
    }
    created++;

    // 为线程2（controller_serial_listen，ip_seq=1）创建参数结构
    ThreadArgsCommon* arg2 = malloc(sizeof(ThreadArgsCommon));
    if (!arg2) {
        perror("malloc");
        return -1;
    }
    arg2->config = &config;
    arg2->aes_key = aes_key;
    arg2->sharedACK = &sharedACK;
    arg2->sharedHeartbeat = NULL;
    arg2->sharedCMD = NULL;

    // 创建线程2（监听ip_seq = 1）
    if (pthread_create(&thr2, NULL, thread2_func, arg2) != 0) {
        perror("Failed to create thread 2");
        free(arg2);
        return -1;
    }
    created++;

    // 为线程3（controller_serial_listen，ip_seq=2）创建参数结构
    ThreadArgsCommon* arg3 = malloc(sizeof(ThreadArgsCommon));
    if (!arg3) {
        perror("malloc");
        return -1;
    }
    arg3->config = &config;
    arg3->aes_key = aes_key;
    arg3->sharedACK = &sharedACK;
    arg3->sharedHeartbeat = NULL;
    arg3->sharedCMD = NULL;

    // 创建线程3（监听ip_seq = 2）
    if (pthread_create(&thr3, NULL, thread3_func, arg3) != 0) {
        perror("Failed to create thread 3");
        free(arg3);
        return -1;
    }
    created++;

    // 主线程等待所有线程结束
    pthread_join(thr1, NULL);
    pthread_join(thr2, NULL);
    pthread_join(thr3, NULL);

    // 清理资源
    free_shared_data(&sharedACK);

    return 0;
    
}
#endif


#ifdef CONTROLLED_MODE//controlled模式,加载配置文件，启动线程执行逻辑

volatile int g_terminate = 0;  // 全局退出标志

// 线程1执行的函数：监听串口并接收电源控制器的状态反馈，生成心跳数据包发送
void* thread1_func(void* arg) {
    while (!g_terminate) {
        controlled_power_listen();  // 调用现有函数，监听串口，生成心跳数据包并发送
        sleep(1);  // 模拟任务处理，延迟1秒后重新检测
    }
    return NULL;
}

// 线程2执行的函数：监听串口并接收来自Controller的控制指令，反馈ACK
void* thread2_func(void* arg) {
    ThreadArgsCommon* args = (ThreadArgsCommon*)arg;
    while (!g_terminate) {
        // 直接循环监听，不再等待线程1状态
        controlled_listen(args->config, 1, args->aes_key, args->sharedCMD);
        sleep(1);  // 模拟任务处理
    }
    return NULL;
}

// 线程3执行的函数：监听串口并接收来自Controller的控制指令，反馈ACK
void* thread3_func(void* arg) {
    ThreadArgsCommon* args = (ThreadArgsCommon*)arg;
    while (!g_terminate) {
        // 直接循环监听，不再等待线程1状态
        controlled_listen(args->config, 2, args->aes_key, args->sharedCMD);
        sleep(1);  // 模拟任务处理
    }
    return NULL;
}

int main() {
    // 初始化配置和AES密钥
    Config config;
    uint8_t aes_key[32];

    if (init_network(&config, aes_key) != 0) {
        fprintf(stderr, "Failed to initialize network configuration\n");
        return -1;
    }

    // 初始化共享数据结构：用于 CMD 消息
    SharedData sharedCMD;
    if (init_shared_data(&sharedCMD) != 0) {
        fprintf(stderr, "Failed to initialize sharedCMD data structure\n");
        return -1;
    }

    // 创建线程参数
    ThreadArgsCommon* arg1 = malloc(sizeof(ThreadArgsCommon));
    ThreadArgsCommon* arg2 = malloc(sizeof(ThreadArgsCommon));
    ThreadArgsCommon* arg3 = malloc(sizeof(ThreadArgsCommon));
    if (!arg1 || !arg2 || !arg3) { perror("malloc"); return -1; }

    arg1->config = &config; arg1->aes_key = aes_key; arg1->sharedCMD = &sharedCMD; arg1->sharedHeartbeat = NULL; arg1->sharedACK = NULL;
    arg2->config = &config; arg2->aes_key = aes_key; arg2->sharedCMD = &sharedCMD; arg2->sharedHeartbeat = NULL; arg2->sharedACK = NULL;
    arg3->config = &config; arg3->aes_key = aes_key; arg3->sharedCMD = &sharedCMD; arg3->sharedHeartbeat = NULL; arg3->sharedACK = NULL;

    // 创建线程
    pthread_t thr1, thr2, thr3;
    if (pthread_create(&thr1, NULL, thread1_func, arg1) != 0) { perror("Failed to create thread 1"); return -1; }
    if (pthread_create(&thr2, NULL, thread2_func, arg2) != 0) { perror("Failed to create thread 2"); return -1; }
    if (pthread_create(&thr3, NULL, thread3_func, arg3) != 0) { perror("Failed to create thread 3"); return -1; }

    // 等待线程结束
    pthread_join(thr1, NULL);
    pthread_join(thr2, NULL);
    pthread_join(thr3, NULL);

    // 清理资源
    free_shared_data(&sharedCMD);
    free(arg1); free(arg2); free(arg3);

    return 0;
}
#endif