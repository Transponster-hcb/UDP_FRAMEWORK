#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"

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
int aes_gcm_encrypt(const Message* msg, const uint8_t* aes_key, uint8_t* ciphertext);//1

/*
 * @brief AES-GCM解密函数，校验认证标签，通过后进行解密
 * @param ciphertext 输入参数，加密数据（52字节：12IV + 24密文 + 16标签）
 * @param aes_key 输入参数，加密密钥(32字节)
 * @param msg 输出参数，存放解密后的Message结构体
 * @return 成功返回0，认证失败返回-1，其他错误返回-2
 */
int aes_gcm_decrypt(const uint8_t* ciphertext, const uint8_t* aes_key, Message* msg);//1


#endif