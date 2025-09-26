#include <stdio.h>  // 包含标准输入输出库，用于打印日志函数
#include <stdlib.h>  // 包含标准库，用于内存分配函数如malloc
#include <string.h>  // 包含字符串处理库，用于memcpy等函数
#include <openssl/evp.h>  // 包含OpenSSL的EVP接口，用于AES-GCM加密/解密
#include <openssl/rand.h>  // 包含OpenSSL随机数生成器，用于生成IV
#include "crypto.h"  // 包含自定义加密头文件，声明函数原型

/**
 * @brief AES-GCM加密函数，随机向量由函数内部随机生成
 * @param msg 输入参数，Message结构体指针
 * @param aes_key 输入参数，加密密钥(32字节)
 * @param ciphertext 输出参数，存放加密后的数据，布局为：
 *                   [0-11]: 12字节随机IV
 *                   [12-35]: 24字节密文  
 *                   [36-51]: 16字节认证标签
 * @return 成功返回0，失败返回-1
 */
// 实现 aes_gcm_encrypt 函数：AES-GCM加密消息，生成随机IV
// 参数：msg - 输入Message指针，aes_key - 32字节密钥，ciphertext - 输出52字节密文（12IV + 24密文 + 16标签）
// 返回：0成功，-1失败
int aes_gcm_encrypt(const Message* msg, const uint8_t* aes_key, uint8_t* ciphertext) {
    if (!msg || !aes_key || !ciphertext) {  // 检查输入指针是否有效
        print_log("无效的输入指针");  // 记录错误日志
        return -1;  // 返回失败
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();  // 创建EVP加密上下文
    if (!ctx) {  // 检查上下文创建是否成功
        print_log("创建加密上下文失败");
        return -1;
    }

    // 初始化AES-256-GCM加密操作
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        print_log("初始化AES-GCM加密失败");  // 记录初始化失败
        EVP_CIPHER_CTX_free(ctx);  // 释放上下文
        return -1;
    }

    uint8_t iv[12];  // 定义12字节IV数组
    if (RAND_bytes(iv, 12) != 1) {  // 使用OpenSSL生成随机IV
        print_log("生成随机IV失败");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    // 设置密钥和IV
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv) != 1) {
        print_log("设置密钥和IV失败");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // 将Message结构体序列化为24字节明文
    uint8_t plaintext[24];  // 定义明文缓冲区（Message大小为24字节）
    plaintext[0] = msg->message_type;  // 序列化消息类型
    plaintext[1] = msg->direction;  // 序列化方向
    memcpy(plaintext + 2, &msg->sequence_number, 4);  // 序列化序列号
    memcpy(plaintext + 6, &msg->timestamp, 8);  // 序列化时间戳
    memcpy(plaintext + 14, &msg->validity, 4);  // 序列化有效期
    memcpy(plaintext + 18, msg->payload, 6);  // 序列化6字节负载

    int len, ciphertext_len;  // 定义长度变量
    // 执行加密更新，将明文加密到ciphertext + 12（偏移IV位置）
    if (EVP_EncryptUpdate(ctx, ciphertext + 12, &len, plaintext, 24) != 1) {
        print_log("AES-GCM加密失败");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;  // 更新密文长度

    // 完成加密操作
    if (EVP_EncryptFinal_ex(ctx, ciphertext + 12 + len, &len) != 1) {
        print_log("完成AES-GCM加密失败");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;  // 添加最终长度

    // 获取16字节认证标签，存储到ciphertext + 36
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext + 36) != 1) {
        print_log("获取认证标签失败");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // 复制IV到ciphertext开头
    memcpy(ciphertext, iv, 12);

    EVP_CIPHER_CTX_free(ctx);  // 释放加密上下文
    return 0;  // 成功返回
}

/*
 * @brief AES-GCM解密函数，校验认证标签，通过后进行解密
 * @param ciphertext 输入参数，加密数据（52字节：12IV + 24密文 + 16标签）
 * @param aes_key 输入参数，加密密钥(32字节)
 * @param msg 输出参数，存放解密后的Message结构体
 * @return 成功返回0，认证失败返回-1，其他错误返回-2
 */
// 实现 aes_gcm_decrypt 函数：AES-GCM解密并验证消息
// 参数：ciphertext - 52字节输入密文，aes_key - 32字节密钥，msg - 输出Message指针
// 返回：0成功，-1认证失败，-2其他错误
int aes_gcm_decrypt(const uint8_t* ciphertext, const uint8_t* aes_key, Message* msg) {
    if (!ciphertext || !aes_key || !msg) {  // 检查输入指针
        print_log("无效的输入指针");
        return -1;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();  // 创建EVP解密上下文
    if (!ctx) {
        print_log("创建解密上下文失败");
        return -1;
    }

    // 初始化AES-256-GCM解密操作
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        print_log("初始化AES-GCM解密失败");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // 设置密钥和IV（ciphertext前12字节为IV）
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, ciphertext) != 1) {
        print_log("设置密钥和IV失败");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // 设置16字节认证标签（ciphertext + 36位置）
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)(ciphertext + 36)) != 1) {
        print_log("设置认证标签失败");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    uint8_t plaintext[24];  // 定义明文缓冲区
    int len, plaintext_len;  // 定义长度变量
    // 执行解密更新，将密文（ciphertext + 12）解密到plaintext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext + 12, 24) != 1) {
        print_log("AES-GCM解密失败");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;  // 更新明文长度

    // 完成解密并验证标签（如果标签不匹配，返回0）
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        print_log("AES-GCM认证失败");  // 认证失败日志
        EVP_CIPHER_CTX_free(ctx);
        return -1;  // 返回认证失败
    }
    plaintext_len += len;  // 添加最终长度

    // 从明文解析回Message结构体
    msg->message_type = plaintext[0];  // 解析消息类型
    msg->direction = plaintext[1];  // 解析方向
    memcpy(&msg->sequence_number, plaintext + 2, 4);  // 解析序列号
    memcpy(&msg->timestamp, plaintext + 6, 8);  // 解析时间戳
    memcpy(&msg->validity, plaintext + 14, 4);  // 解析有效期
    memcpy(msg->payload, plaintext + 18, 6);  // 解析负载

    EVP_CIPHER_CTX_free(ctx);  // 释放解密上下文
    return 0;  // 成功返回
}