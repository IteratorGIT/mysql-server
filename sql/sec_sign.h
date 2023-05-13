/****************************************************************
 * 此头文件申明了链表的模型，包括链表节点的基本结构体组成
 * 和链表应该实现的方法，以及每个方法的具体要求。在编写过
 * 程中要严格注意指针的使用，对于任何要使用的指针，有必要
 * 检查是否为空，对于错误之处要给出详细的错误信息。对于所
 * 有方法的参数，在使用前应该检查参数的合法性。
  * 对于所有申请的栈空间在不使用时需要释放，避免内存溢出。
 * 对于源码在必要处要给出详细的注释。
 * 如果需要使用windows库，需要在使用前加上编译开关，并且
 * 找到linux下对应的方法供编译器选择。
 ****************************************************************/
#ifndef SEC_SIGN_H
#define SEC_SIGN_H
#include "tree_sec.h"

//定义一个安全标记的组成
//由密级和范畴组成
struct sec_sign
{
	char* level;	//密级
	uint len_l;
	char* domain;	//范畴
	uint len_d;
};

typedef struct sec_sign SEC_SIGN;
typedef struct sec_sign* SEC_PTR;

/*****************************************
 * 函数功能：比较两个密级之间的大小关系
 * 参数：第一个密级：level1，及字符长度；
 *				第二个密级：level2,及字符长度;
 * 返回值：-1表示level1小于level2, 
 *					0表示level1等于level2，
 *					1表示level1大于level2.
 ****************************************/
int levelcmp(const char* level1, uint len1, const char* level2, uint len2);

/*****************************************
 * 函数功能：比较两个范畴之间的包含关系
 * 参数：第一个范畴：domain1，及字符长度；
 *				第二个范畴：domain2,及字符长度;
 * 返回值：			-2表示两者不可比
 * 					-1表示domain1 in domain2，
 *					0表示domain1 == domain2，
 *					1表示domain1 contain domain2.
 ****************************************/
int domaincmp(const char* domain1, uint len1, const char* domain2, uint len2);

/*******************************************
 * 函数功能：添加一个新的密级
 * 参数：添加密级时需要指定添加的密级的位置
 * level_n表示新的密级，level_p表示新密级的
 * 直接上级。
 * 返回值：是否添加成功
 ******************************************/
bool add_level(const char* level_p, uint len_p,  const char* level_n, uint len_n);

/*******************************************
 * 函数功能：添加一个新的范畴
 * 参数：添加范畴时需要指定添加的范畴的位置
 * domain_n表示新的范畴，domain_p表示新范畴的
 * 直接上级。
 * 返回值：是否添加成功
 ******************************************/
bool add_domain(const char* domain_p, uint len_p, const char* domain_n, uint len_n);

/*********************************************
 * 函数功能：删除一个密级
 * 参数：需要删除的密级
 * 返回值：是否删除成功
 ********************************************/
bool delete_level(const char* level_h, uint len_h,const char* level, uint len);

/*********************************************
 * 函数功能：删除一个范畴
 * 参数：需要删除的范畴
 * 返回值：是否删除成功
 ********************************************/
bool delete_domain(const char* domain, uint len);

bool have_init();

#endif		//SEC_SIGN_H
