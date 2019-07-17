#ifndef MACRO_H_
#define MACRO_H_

/**
 * 日志
*/
enum Log_level{
    LOG_FATAL = 16,
    LOG_ERR = 8,
    LOG_WARN = 4,
    LOG_INFO = 2,
    LOG_DEBUG = 1,
};

enum Error_type{
    ERR_NSYS,
    ERR_SYS
};

enum Fatal_type{
    FAT_NSYS,
    FAT_SYS,
    FAT_DUMP
};

#define LOG_LINE_SZ 4096

/**
 * 配置文件
*/
#define CONF_LINE_SIZE 500
#define CONF_NAME_SIZE 50
#define CONF_CONTENT_SIZE 400

#define PREFIX_MAX_SZ 1024

/**
 * hello协议
*/
enum Route_state{
    ESTABLISH = 1,
    KEEP
};

enum HelloPkt_type{
    DETECT = 1,
    ASK,
    ACK
};

enum Nbr_state{
    ONLINE = 1,
    OFFLINE
};

#define TIMEOUT_NUM 3

/**
 * 线程池
*/
#define THREADS 10

/**
 * Interface网口
*/
enum Interface_type{
    NON_RUN,
    RUN
};

#define WAIT_TIME 10 // 拔出网线等待WAIT_TIME秒之后，destory face

#endif