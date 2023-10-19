#ifndef SEC_ABE_SSL_H
#define SEC_ABE_SSL_H

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rsa.h"      
#include "openssl/crypto.h"
#include "cJSON.h"

struct AbeSslConfig
{
    char *ca_cert_file;
    char *db_cert_file;
    char *db_key_file;
    char *kms_cert_file;
    char *kms_ip;
    ulong kms_port;
    char *uuid;

    ~AbeSslConfig();
    void set_ca_cert_file();
    void set_db_cert_file();
    void set_db_key_file();
    void set_kms_cert_file();
    void set_default_file();
    void set_kms_addr();
};

typedef struct _AbeInfoData
{
    char *user_name;
    char *attribute;
    char *db_signature;
    char *db_signature_type;
    char *abe_key;
    char *kms_signature;
    char *kms_signature_type;
} AbeInfoData, *AbeInfo;

struct Abe_ssl
{
public:
    static constexpr int BODY_LENGTH_BYTE = 2;
    static constexpr int BODY_LENGTH_BYTE_LENGTH = BODY_LENGTH_BYTE * 2;
    enum enum_event_type {ENUM_EVENT_USER_REGISTRATION, ENUM_EVENT_UNKOWN};
    enum enum_response_code {ENUM_RESPONSE_SUCCESS, ENUM_RESPONSE_USER_PK_NOT_FOUND, ENUM_RESPONSE_UNKOWN};

    //读取配置信息，建立SSL连接，完成注册流程后将信息写入abe_info中
    void generateABEInfo(AbeInfo abe_info);

private:
    //构造json数据包并发送
    void process_user_registration_request(SSL *ssl, AbeSslConfig &config, AbeInfo abe_info);

    void set_user_registration_request(cJSON *cjson, AbeSslConfig &config, const AbeInfo abe_info);
    void send_user_registration_request(SSL *ssl, const char *msg, size_t msg_length);
    void set_user_registration_uuid(cJSON *cjson, AbeSslConfig &config);
    void set_user_registration_db_signature(cJSON *cjson, const char *db_key_file, const AbeInfo abe_info);
    void set_abe_info_from_request_json(cJSON *cjson, AbeInfo abe_info);

    //接收KMS返回的数据包并解析
    void process_user_registration_response(SSL *ssl, const AbeSslConfig &config, AbeInfo abe_info);

    char *recv_user_registration_response(SSL *ssl);
    void parse_user_registration_response(const char *json_str, const char *uuid_str, AbeInfo abe_info);
    void verify_kms_signature(const AbeInfo abe_info, const char *kms_cert_file);

    int create_socket(const AbeSslConfig &config);
    SSL_CTX *init_ssl_context(const AbeSslConfig &config);
    SSL *create_ssl_connection(SSL_CTX *ssl_ctx, int sockfd);
    void read_msg(SSL *ssl, char *msg, size_t msg_length);
    void write_msg(SSL *ssl, const char *msg, size_t msg_length);
};

#endif // SEC_ABE_SSL_H